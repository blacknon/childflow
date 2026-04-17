use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
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
                CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS
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
    pub tap_fd: RawFd,
    pub tap_name: String,
    pub child_ipv4: Ipv4Addr,
    pub gateway_ipv4: Ipv4Addr,
    pub child_ipv6: Ipv6Addr,
    pub gateway_ipv6: Ipv6Addr,
    pub child_ipv4_prefix_len: u8,
    pub child_ipv6_prefix_len: u8,
}

pub fn child_enter_and_exec(
    mode: NamespaceMode,
    mut release_pipe: File,
    resolv_conf: Option<&Path>,
    network_bootstrap: Option<&ChildNetworkBootstrap>,
    command: &[String],
) -> Result<()> {
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

    let mut ready = [0_u8; 1];
    let n = release_pipe
        .read(&mut ready)
        .context("failed to wait for parent namespace setup. The parent side may have aborted before namespace bootstrap completed")?;
    if n == 0 {
        bail!("parent closed bootstrap pipe before namespace setup completed");
    }

    if let Some(bootstrap) = network_bootstrap {
        apply_child_network_bootstrap(bootstrap)?;
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

pub fn configure_user_namespace(child_pid: Pid) -> Result<()> {
    let pid = child_pid.as_raw();
    let uid = unsafe { nix::libc::geteuid() };
    let gid = unsafe { nix::libc::getegid() };

    let setgroups_path = format!("/proc/{pid}/setgroups");
    if Path::new(&setgroups_path).exists() {
        std::fs::write(&setgroups_path, "deny\n").with_context(|| {
            format!(
                "failed to write `deny` to {setgroups_path}. Check whether this Linux environment permits configuring gid maps for new user namespaces"
            )
        })?;
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

fn apply_child_network_bootstrap(bootstrap: &ChildNetworkBootstrap) -> Result<()> {
    match bootstrap {
        ChildNetworkBootstrap::RootlessInternal(config) => {
            create_tap_device(config.tap_fd, &config.tap_name)?;
            bring_rootless_child_links_up(config)
        }
    }
}

fn bring_rootless_child_links_up(config: &RootlessChildBootstrap) -> Result<()> {
    crate::util::run_command("ip", route::lo_up_args())
        .context("failed to bring loopback up inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::addr_add_v4_args(
            &config.tap_name,
            config.child_ipv4,
            config.child_ipv4_prefix_len,
        ),
    )
    .context(
        "failed to assign IPv4 address to tap0 inside the rootless-internal child namespace",
    )?;

    crate::util::run_command(
        "ip",
        route::addr_add_v6_args(
            &config.tap_name,
            config.child_ipv6,
            config.child_ipv6_prefix_len,
        ),
    )
    .context(
        "failed to assign IPv6 address to tap0 inside the rootless-internal child namespace",
    )?;

    crate::util::run_command("ip", route::link_up_args(&config.tap_name))
        .context("failed to bring tap0 up inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::default_route_v4_args(config.gateway_ipv4, &config.tap_name),
    )
    .context("failed to install IPv4 default route for the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::default_route_v6_args(config.gateway_ipv6, &config.tap_name),
    )
    .context("failed to install IPv6 default route for the rootless-internal child namespace")?;

    Ok(())
}

fn create_tap_device(fd: RawFd, name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("tap device name must not be empty");
    }
    if name.len() >= nix::libc::IFNAMSIZ as usize {
        bail!(
            "tap device name `{name}` is too long for Linux IFNAMSIZ={}",
            nix::libc::IFNAMSIZ
        );
    }

    #[repr(C)]
    struct IfReq {
        name: [nix::libc::c_char; nix::libc::IFNAMSIZ],
        flags: nix::libc::c_short,
        padding: [u8; 22],
    }

    let mut ifreq = IfReq {
        name: [0; nix::libc::IFNAMSIZ],
        flags: (nix::libc::IFF_TAP | nix::libc::IFF_NO_PI) as nix::libc::c_short,
        padding: [0; 22],
    };

    for (idx, byte) in name.as_bytes().iter().enumerate() {
        ifreq.name[idx] = *byte as nix::libc::c_char;
    }

    let rc = unsafe { nix::libc::ioctl(fd, nix::libc::TUNSETIFF as _, &ifreq) };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())).context(
            format!(
                "failed to create tap device `{name}` inside the rootless-internal child namespace using TUNSETIFF"
            ),
        );
    }

    Ok(())
}
