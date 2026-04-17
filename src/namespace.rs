use std::ffi::CString;
use std::fmt::Write as _;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;

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
    pub hosts_file: Option<&'a Path>,
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
        hosts_file,
        network_bootstrap,
        extra_env,
        command,
    } = params;

    if command.is_empty() {
        bail!("missing command");
    }

    unshare(mode.unshare_flags()).map_err(|err| render_unshare_error(mode, err))?;

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

    if let Some(hosts_file) = hosts_file {
        mount(
            Some(hosts_file),
            "/etc/hosts",
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "failed to bind-mount {} over /etc/hosts",
                hosts_file.display()
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

    let mapping_mode = match try_configure_user_namespace_direct(pid, uid, gid) {
        Ok(()) => UserNamespaceMapping::DirectFull,
        Err(direct_full_err) => {
            match try_configure_user_namespace_with_uidmap_tools(pid, uid, gid) {
                Ok(()) => {
                    crate::util::debug(format!(
                        "configured rootless user namespace for pid {pid} via newuidmap/newgidmap fallback after direct map writes were rejected: {direct_full_err:#}"
                    ));
                    UserNamespaceMapping::HelperFull
                }
                Err(helper_full_err) => {
                    match try_configure_user_namespace_direct_uid_only(pid, uid) {
                        Ok(()) => {
                            crate::util::debug(
                                "configured the `rootless-internal` user namespace with a uid-only map because gid mapping was rejected on this host. Rootless networking will continue, but group-based file access inside the child may differ from the caller's primary gid.",
                            );
                            crate::util::debug(format!(
                            "configured rootless user namespace for pid {pid} with a direct uid-only map after full mapping failed.\ndirect full error: {direct_full_err:#}\nhelper full error: {helper_full_err:#}"
                        ));
                            UserNamespaceMapping::DirectUidOnly
                        }
                        Err(direct_uid_only_err) => {
                            match try_configure_user_namespace_with_uidmap_tools_uid_only(pid, uid)
                            {
                                Ok(()) => {
                                    crate::util::debug(
                                        "configured the `rootless-internal` user namespace through `newuidmap` with a uid-only map because gid mapping was rejected on this host. Rootless networking will continue, but group-based file access inside the child may differ from the caller's primary gid.",
                                    );
                                    crate::util::debug(format!(
                                    "configured rootless user namespace for pid {pid} with a helper-based uid-only map after full mapping failed.\ndirect full error: {direct_full_err:#}\nhelper full error: {helper_full_err:#}\ndirect uid-only error: {direct_uid_only_err:#}"
                                ));
                                    UserNamespaceMapping::HelperUidOnly
                                }
                                Err(helper_uid_only_err) => {
                                    return Err(build_user_namespace_error(
                                        pid,
                                        uid,
                                        gid,
                                        &direct_full_err,
                                        &helper_full_err,
                                        &direct_uid_only_err,
                                        &helper_uid_only_err,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    if matches!(
        mapping_mode,
        UserNamespaceMapping::DirectFull | UserNamespaceMapping::HelperFull
    ) {
        crate::util::debug(format!(
            "configured rootless user namespace for pid {pid} using {mapping_mode}"
        ));
    }

    Ok(())
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum UserNamespaceMapping {
    DirectFull,
    HelperFull,
    DirectUidOnly,
    HelperUidOnly,
}

impl std::fmt::Display for UserNamespaceMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectFull => f.write_str("direct uid/gid map writes"),
            Self::HelperFull => f.write_str("newuidmap/newgidmap full mapping"),
            Self::DirectUidOnly => f.write_str("direct uid-only mapping"),
            Self::HelperUidOnly => f.write_str("newuidmap uid-only mapping"),
        }
    }
}

fn try_configure_user_namespace_direct_uid_only(pid: i32, uid: u32) -> Result<()> {
    write_uid_map(pid, uid)?;
    Ok(())
}

fn try_configure_user_namespace_with_uidmap_tools_uid_only(pid: i32, uid: u32) -> Result<()> {
    run_uidmap_helper("newuidmap", pid, uid)?;
    Ok(())
}

fn try_configure_user_namespace_direct(pid: i32, uid: u32, gid: u32) -> Result<()> {
    write_setgroups_deny(pid)?;
    write_uid_map(pid, uid)?;
    write_gid_map(pid, gid)?;
    Ok(())
}

fn try_configure_user_namespace_with_uidmap_tools(pid: i32, uid: u32, gid: u32) -> Result<()> {
    write_setgroups_deny(pid)
        .context("failed to prepare `/proc/<pid>/setgroups` for the newgidmap fallback path")?;
    run_uidmap_helper("newuidmap", pid, uid)?;
    run_uidmap_helper("newgidmap", pid, gid)?;
    Ok(())
}

fn write_setgroups_deny(pid: i32) -> Result<()> {
    let setgroups_path = format!("/proc/{pid}/setgroups");
    if !Path::new(&setgroups_path).exists() {
        return Ok(());
    }

    std::fs::write(&setgroups_path, "deny\n").with_context(|| {
        format!(
            "failed to write `deny` to {setgroups_path}. Check whether this Linux environment permits configuring gid maps for new user namespaces"
        )
    })
}

fn write_uid_map(pid: i32, uid: u32) -> Result<()> {
    let uid_map_path = format!("/proc/{pid}/uid_map");
    std::fs::write(&uid_map_path, format!("0 {uid} 1\n")).with_context(|| {
        format!(
            "failed to configure {uid_map_path}. Check whether user namespace id mapping is allowed on this host"
        )
    })
}

fn write_gid_map(pid: i32, gid: u32) -> Result<()> {
    let gid_map_path = format!("/proc/{pid}/gid_map");
    std::fs::write(&gid_map_path, format!("0 {gid} 1\n")).with_context(|| {
        format!(
            "failed to configure {gid_map_path}. Check whether group id mapping is allowed on this host"
        )
    })
}

fn run_uidmap_helper(program: &str, pid: i32, host_id: u32) -> Result<()> {
    let output = Command::new(program)
        .args([
            pid.to_string(),
            "0".to_string(),
            host_id.to_string(),
            "1".to_string(),
        ])
        .output()
        .with_context(|| format!("failed to execute `{program}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        bail!(
            "`{program}` failed for pid {pid} with status {:?}\nstdout: {}\nstderr: {}",
            output.status.code().or_else(|| output.status.signal()),
            stdout,
            stderr
        );
    }

    Ok(())
}

fn build_user_namespace_error(
    pid: i32,
    uid: u32,
    gid: u32,
    direct_full_err: &anyhow::Error,
    helper_full_err: &anyhow::Error,
    direct_uid_only_err: &anyhow::Error,
    helper_uid_only_err: &anyhow::Error,
) -> anyhow::Error {
    let username = current_username().unwrap_or_else(|| format!("uid:{uid}"));
    let newuidmap_in_path = command_in_path("newuidmap");
    let newgidmap_in_path = command_in_path("newgidmap");
    let subuid_present = subid_entry_exists("/etc/subuid", &username);
    let subgid_present = subid_entry_exists("/etc/subgid", &username);
    let max_user_namespaces = read_proc_u64("/proc/sys/user/max_user_namespaces");
    let unprivileged_userns_clone = read_proc_u64("/proc/sys/kernel/unprivileged_userns_clone");

    let mut message = String::new();
    let _ = writeln!(
        message,
        "could not map the current non-root user into the `rootless-internal` child namespace after trying full uid/gid mapping and uid-only fallback paths."
    );
    let _ = writeln!(message, "direct full mapping error: {direct_full_err:#}");
    let _ = writeln!(message, "helper full mapping error: {helper_full_err:#}");
    let _ = writeln!(
        message,
        "direct uid-only mapping error: {direct_uid_only_err:#}"
    );
    let _ = writeln!(
        message,
        "helper uid-only mapping error: {helper_uid_only_err:#}"
    );
    let _ = writeln!(message, "diagnostics:");
    let _ = writeln!(message, "- child pid: {pid}");
    let _ = writeln!(message, "- current uid/gid: {uid}/{gid}");
    let _ = writeln!(message, "- detected username: {username}");
    let _ = writeln!(
        message,
        "- /proc/sys/user/max_user_namespaces: {}",
        format_proc_value(max_user_namespaces)
    );
    let _ = writeln!(
        message,
        "- /proc/sys/kernel/unprivileged_userns_clone: {}",
        format_proc_value(unprivileged_userns_clone)
    );
    let _ = writeln!(
        message,
        "- `newuidmap` in PATH: {}",
        yes_no(newuidmap_in_path)
    );
    let _ = writeln!(
        message,
        "- `newgidmap` in PATH: {}",
        yes_no(newgidmap_in_path)
    );
    let _ = writeln!(
        message,
        "- `/etc/subuid` entry for `{username}`: {}",
        yes_no(subuid_present)
    );
    let _ = writeln!(
        message,
        "- `/etc/subgid` entry for `{username}`: {}",
        yes_no(subgid_present)
    );

    if max_user_namespaces == Some(0) || unprivileged_userns_clone == Some(0) {
        let _ = writeln!(
            message,
            "unprivileged user namespaces appear to be disabled on this host. If that is intentional, use the `rootful` backend instead."
        );
    } else if !newuidmap_in_path || !newgidmap_in_path {
        let _ = writeln!(
            message,
            "direct uid/gid map writes were rejected, and the helper tools are missing. On Debian or Ubuntu, install the `uidmap` package."
        );
    } else if !subuid_present || !subgid_present {
        let _ = writeln!(
            message,
            "`newuidmap` / `newgidmap` are present, but no subuid/subgid entry was found for `{username}`. Check `/etc/subuid` and `/etc/subgid`."
        );
    } else {
        let _ = writeln!(
            message,
            "this host permits some user namespace setup, but id mapping for the current non-root user still failed. Check container seccomp/policy restrictions and whether `newuidmap` / `newgidmap` retain their expected privileges."
        );
    }

    anyhow!(message)
}

fn render_unshare_error(mode: NamespaceMode, err: nix::errno::Errno) -> anyhow::Error {
    match mode {
        NamespaceMode::Rootful => anyhow::Error::new(err).context(
            "unshare(CLONE_NEWNET|CLONE_NEWNS) failed. Check CAP_SYS_ADMIN and whether the runtime permits creating Linux network/mount namespaces",
        ),
        NamespaceMode::RootlessInternal => anyhow!(
            "unshare for the `rootless-internal` backend failed before user namespace mapping completed: {err}. Check whether unprivileged user namespaces are enabled on this host and whether the runtime permits CLONE_NEWUSER / CLONE_NEWNET / CLONE_NEWNS for non-root users."
        ),
    }
}

fn command_in_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let candidate = dir.join(program);
                candidate.exists() && candidate.is_file()
            })
        })
        .unwrap_or(false)
}

fn read_proc_u64(path: &str) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn current_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|user| !user.trim().is_empty())
        .or_else(|| {
            let uid = unsafe { nix::libc::geteuid() };
            let passwd = unsafe { nix::libc::getpwuid(uid) };
            if passwd.is_null() {
                return None;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*passwd).pw_name) };
            name.to_str().ok().map(|value| value.to_string())
        })
}

fn subid_entry_exists(path: &str, username: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .map(|contents| {
            contents
                .lines()
                .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
                .filter_map(|line| line.split(':').next())
                .any(|entry| entry == username)
        })
        .unwrap_or(false)
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_proc_value(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_string())
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
