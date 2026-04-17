use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::execvp;
use nix::unistd::Pid;

use crate::network::rootless_internal::route;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NamespaceMode {
    Rootful,
    RootlessInternal,
}

impl NamespaceMode {
    fn unshare_flags(self) -> CloneFlags {
        match self {
            Self::Rootful => CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS,
            Self::RootlessInternal => {
                let mut flags = CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS;
                if unsafe { nix::libc::geteuid() } != 0 {
                    flags |= CloneFlags::CLONE_NEWUSER;
                }
                flags
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildNetworkBootstrap {
    RootlessInternal(RootlessChildBootstrap),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootlessChildBootstrap {
    pub tap_name: String,
    pub gateway_mac: [u8; 6],
    pub child_ipv4: Ipv4Addr,
    pub gateway_ipv4: Ipv4Addr,
    pub child_ipv6: Ipv6Addr,
    pub gateway_ipv6: Ipv6Addr,
    pub child_ipv4_prefix_len: u8,
    pub child_ipv6_prefix_len: u8,
}

pub struct ChildExecParams<'a> {
    pub mode: NamespaceMode,
    pub release_pipe: File,
    pub ready_pipe: Option<File>,
    pub tap_transfer: Option<UnixStream>,
    pub resolv_conf: Option<&'a Path>,
    pub network_bootstrap: Option<&'a ChildNetworkBootstrap>,
    pub extra_env: &'a [(String, String)],
    pub command: &'a [String],
}

pub fn child_enter_and_exec(params: ChildExecParams<'_>) -> Result<()> {
    let ChildExecParams {
        mode,
        mut release_pipe,
        mut ready_pipe,
        tap_transfer,
        resolv_conf,
        network_bootstrap,
        extra_env,
        command,
    } = params;

    if command.is_empty() {
        bail!("missing command");
    }

    unshare(mode.unshare_flags())
        .context("unshare(CLONE_NEWNET|CLONE_NEWNS) failed. Check CAP_SYS_ADMIN and whether the runtime permits creating Linux network/mount namespaces")?;

    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("failed to make mount propagation private")?;

    if let Some(resolv_conf) = resolv_conf {
        mount(
            Some(resolv_conf),
            "/etc/resolv.conf",
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "failed to bind-mount {} over /etc/resolv.conf",
                resolv_conf.display()
            )
        })?;
    }

    wait_for_parent_release(
        &mut release_pipe,
        "failed to wait for parent namespace setup. The parent side may have aborted before namespace bootstrap completed",
        "parent closed bootstrap pipe before namespace setup completed",
    )?;

    let _network_guard = if let Some(bootstrap) = network_bootstrap {
        let guard = apply_child_network_bootstrap(bootstrap)?;

        if let (Some(tap_transfer), Some(tap_file)) = (tap_transfer.as_ref(), guard.as_ref()) {
            crate::network::rootless_internal::tap::send_fd_over_stream(tap_transfer, tap_file)
                .context("failed to pass the rootless tap fd back to the parent")?;
        }

        if let Some(ready_pipe) = ready_pipe.as_mut() {
            use std::io::Write;

            ready_pipe
                .write_all(&[1])
                .context("failed to notify the parent that rootless tap bootstrap completed")?;
        }

        wait_for_parent_release(
            &mut release_pipe,
            "failed while waiting for the parent to finish starting the rootless userspace networking engine",
            "parent closed bootstrap pipe before the rootless userspace networking engine was ready",
        )?;
        guard
    } else {
        None
    };

    for (key, value) in extra_env {
        std::env::set_var(key, value);
    }

    let argv = command
        .iter()
        .map(|arg| {
            CString::new(arg.as_str()).map_err(|_| anyhow!("argument contains NUL byte: {arg:?}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let program = argv
        .first()
        .ok_or_else(|| anyhow!("missing program after parsing command"))?
        .clone();

    execvp(&program, &argv).with_context(|| {
        let command_name = command.first().map(String::as_str).unwrap_or("<missing>");
        format!(
            "execvp failed for `{command_name}`. Check that the target command exists in PATH and is executable inside the child namespace"
        )
    })?;
    unreachable!();
}

fn wait_for_parent_release(
    release_pipe: &mut File,
    read_context: &str,
    eof_message: &str,
) -> Result<()> {
    let mut ready = [0_u8; 1];
    let n = release_pipe
        .read(&mut ready)
        .with_context(|| read_context.to_string())?;
    if n == 0 {
        bail!(eof_message.to_string());
    }
    Ok(())
}

pub fn configure_user_namespace(child_pid: Pid) -> Result<()> {
    let pid = child_pid.as_raw();
    let uid = unsafe { nix::libc::geteuid() };
    let gid = unsafe { nix::libc::getegid() };

    if uid == 0 {
        crate::util::debug(
            "skipping user namespace id-map setup for rootful parent; `rootless-internal` will continue with mount/net namespaces only in this environment",
        );
        return Ok(());
    }

    let setgroups_path = format!("/proc/{pid}/setgroups");
    if Path::new(&setgroups_path).exists() {
        match std::fs::write(&setgroups_path, "deny\n") {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied && uid == 0 => {
                crate::util::debug(format!(
                    "skipping `{setgroups_path}` write for rootful parent because the kernel/container runtime rejected `deny`: {err}"
                ));
            }
            Err(err) => {
                return Err(anyhow::Error::new(err)).with_context(|| {
                    format!(
                        "failed to write `deny` to {setgroups_path}. Check whether this Linux environment permits configuring gid maps for new user namespaces"
                    )
                });
            }
        }
    }

    let uid_map_path = format!("/proc/{pid}/uid_map");
    std::fs::write(&uid_map_path, format!("0 {uid} 1\n")).with_context(|| {
        format!(
            "failed to configure {uid_map_path}. Check whether user namespace id mapping is allowed on this host"
        )
    })?;

    let gid_map_path = format!("/proc/{pid}/gid_map");
    std::fs::write(&gid_map_path, format!("0 {gid} 1\n")).with_context(|| {
        format!(
            "failed to configure {gid_map_path}. Check whether group id mapping is allowed on this host"
        )
    })?;

    Ok(())
}

fn apply_child_network_bootstrap(bootstrap: &ChildNetworkBootstrap) -> Result<Option<File>> {
    match bootstrap {
        ChildNetworkBootstrap::RootlessInternal(config) => {
            let (tap_file, actual_tap_name) = create_tap_device(&config.tap_name)?;
            bring_rootless_child_links_up(config, &actual_tap_name)?;
            Ok(Some(tap_file))
        }
    }
}

fn bring_rootless_child_links_up(config: &RootlessChildBootstrap, tap_name: &str) -> Result<()> {
    let gateway_mac = render_mac(config.gateway_mac);

    crate::util::run_command("ip", route::lo_up_args())
        .context("failed to bring loopback up inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::addr_add_v4_args(tap_name, config.child_ipv4, config.child_ipv4_prefix_len),
    )
    .context(
        "failed to assign IPv4 address to tap0 inside the rootless-internal child namespace",
    )?;

    crate::util::run_command(
        "ip",
        route::addr_add_v6_args(tap_name, config.child_ipv6, config.child_ipv6_prefix_len),
    )
    .context(
        "failed to assign IPv6 address to tap0 inside the rootless-internal child namespace",
    )?;

    crate::util::run_command("ip", route::link_up_args(tap_name))
        .context("failed to bring tap0 up inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::neigh_add_v4_args(config.gateway_ipv4, &gateway_mac, tap_name),
    )
    .context("failed to install the IPv4 gateway neighbor entry for tap0 inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::neigh_add_v6_args(config.gateway_ipv6, &gateway_mac, tap_name),
    )
    .context("failed to install the IPv6 gateway neighbor entry for tap0 inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::default_route_v4_args(config.gateway_ipv4, tap_name),
    )
    .context("failed to install IPv4 default route for the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::default_route_v6_args(config.gateway_ipv6, tap_name),
    )
    .context("failed to install IPv6 default route for the rootless-internal child namespace")?;

    Ok(())
}

fn render_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn create_tap_device(name: &str) -> Result<(File, String)> {
    if name.is_empty() {
        bail!("tap device name must not be empty");
    }
    if name.len() >= nix::libc::IFNAMSIZ {
        bail!(
            "tap device name `{name}` is too long for Linux IFNAMSIZ={}",
            nix::libc::IFNAMSIZ
        );
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context("failed to open `/dev/net/tun` while creating the rootless-internal tap inside the child namespace")?;

    let mut ifreq = nix::libc::ifreq {
        ifr_name: [0; nix::libc::IFNAMSIZ],
        ifr_ifru: nix::libc::__c_anonymous_ifr_ifru {
            ifru_flags: (nix::libc::IFF_TAP | nix::libc::IFF_NO_PI) as nix::libc::c_short,
        },
    };

    for (idx, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[idx] = *byte as nix::libc::c_char;
    }

    let rc = unsafe {
        nix::libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            nix::libc::TUNSETIFF as _,
            &mut ifreq,
        )
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())).context(
            format!(
                "failed to create tap device `{name}` inside the rootless-internal child namespace using TUNSETIFF"
            ),
        );
    }

    let actual_name = ifreq_name_to_string(&ifreq.ifr_name)?;
    if actual_name.is_empty() {
        bail!("kernel returned an empty tap device name after TUNSETIFF");
    }

    Ok((file, actual_name))
}

fn ifreq_name_to_string(raw_name: &[nix::libc::c_char; nix::libc::IFNAMSIZ]) -> Result<String> {
    let end = raw_name
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(raw_name.len());
    let bytes = raw_name[..end].to_vec();
    String::from_utf8(bytes)
        .map_err(|err| anyhow!("kernel returned a non-UTF8 tap device name: {err}"))
}
