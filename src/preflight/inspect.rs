// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::env;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::path::Path;

use anyhow::{bail, Result};

use crate::network::NetworkBackend;

use super::PreflightReport;

const ROOTFUL_REQUIRED_COMMANDS: &[&str] = &["ip", "iptables", "ip6tables"];
const ROOTLESS_INTERNAL_REQUIRED_COMMANDS: &[&str] = &["ip"];
const ROOTLESS_UIDMAP_HELPERS: &[&str] = &["newuidmap", "newgidmap"];
const ROOTFUL_REQUIRED_SYSCTLS: &[&str] = &[
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv6/conf/all/forwarding",
];
const ROOTLESS_INTERNAL_NAMESPACE_PATHS: &[&str] = &[
    "/proc/self/ns/user",
    "/proc/self/ns/net",
    "/proc/self/ns/mnt",
];
const ROOTLESS_IDMAP_FILES: &[&str] = &["/etc/subuid", "/etc/subgid"];

pub(super) fn inspect(backend: NetworkBackend, proxy_requested: bool) -> PreflightReport {
    match backend {
        NetworkBackend::Rootful => inspect_rootful(proxy_requested),
        NetworkBackend::RootlessInternal => inspect_rootless_internal(),
    }
}

fn inspect_rootful(proxy_requested: bool) -> PreflightReport {
    let path_env = env::var_os("PATH").unwrap_or_default();
    let missing_commands = find_missing_commands(ROOTFUL_REQUIRED_COMMANDS, &path_env);
    let unwritable_paths = find_unwritable_paths(ROOTFUL_REQUIRED_SYSCTLS);
    let mut report = PreflightReport::new("rootful");

    if current_euid() == 0 {
        report.push_ok("root privileges", "running as root");
    } else {
        report.push_fatal(
            "root privileges",
            "the `rootful` backend requires root on Linux",
            "rerun with `sudo -- childflow --root ...`, or use the default rootless backend",
        );
    }

    if missing_commands.is_empty() {
        report.push_ok(
            "external commands",
            "found `ip`, `iptables`, and `ip6tables` in PATH",
        );
    } else {
        report.push_fatal(
            "external commands",
            format!("missing required commands: {}", missing_commands.join(", ")),
            "install `iproute2` and an `iptables` / `ip6tables` userspace compatible with the host firewall backend",
        );
    }

    if unwritable_paths.is_empty() {
        report.push_ok(
            "forwarding sysctls",
            "required IPv4 and IPv6 forwarding sysctls are writable",
        );
    } else {
        report.push_fatal(
            "forwarding sysctls",
            format!("required sysctl files are not writable: {}", unwritable_paths.join(", ")),
            "check root privileges, container restrictions, and whether `/proc/sys` is mounted read-write",
        );
    }

    if proxy_requested {
        report.push_warning(
            "transparent proxy prerequisites",
            "transparent proxy mode still depends on Linux TPROXY support (`xt_TPROXY`, `xt_socket`, policy routing, and `IP_TRANSPARENT`) during setup",
            "if proxy startup fails, verify that the host kernel exposes the required TPROXY modules and capabilities",
        );
    }

    report
}

fn inspect_rootless_internal() -> PreflightReport {
    let path_env = env::var_os("PATH").unwrap_or_default();
    let mut report = PreflightReport::new("rootless-internal");

    let missing_commands = find_missing_commands(ROOTLESS_INTERNAL_REQUIRED_COMMANDS, &path_env);
    if missing_commands.is_empty() {
        report.push_ok("external commands", "found `ip` in PATH");
    } else {
        report.push_fatal(
            "external commands",
            format!("missing required commands: {}", missing_commands.join(", ")),
            "install `iproute2` so childflow can configure `tap0`, loopback, and default routes inside the child namespace",
        );
    }

    let missing_namespace_paths = find_missing_paths(ROOTLESS_INTERNAL_NAMESPACE_PATHS);
    if missing_namespace_paths.is_empty() {
        report.push_ok(
            "namespace handles",
            "found `/proc/self/ns/{user,net,mnt}` for rootless namespace setup",
        );
    } else {
        report.push_fatal(
            "namespace handles",
            format!(
                "missing required namespace handles: {}",
                missing_namespace_paths.join(", ")
            ),
            "verify that this Linux environment exposes user, network, and mount namespace handles",
        );
    }

    match parse_proc_u64("/proc/sys/user/max_user_namespaces") {
        Ok(Some(0)) => report.push_fatal(
            "user namespace quota",
            "`/proc/sys/user/max_user_namespaces` is `0`",
            "enable user namespaces before using the default rootless backend",
        ),
        Ok(Some(value)) => report.push_ok(
            "user namespace quota",
            format!("`/proc/sys/user/max_user_namespaces` is set to {value}"),
        ),
        Ok(None) => report.push_warning(
            "user namespace quota",
            "`/proc/sys/user/max_user_namespaces` is unavailable in this environment",
            "namespace availability will be determined during setup; rerun with `CHILDFLOW_DEBUG=1` if startup still fails",
        ),
        Err(err) => report.push_warning(
            "user namespace quota",
            err.to_string(),
            "namespace availability will be determined during setup",
        ),
    }

    if current_euid() != 0 {
        match parse_proc_u64("/proc/sys/kernel/unprivileged_userns_clone") {
            Ok(Some(0)) => report.push_fatal(
                "unprivileged user namespaces",
                "`/proc/sys/kernel/unprivileged_userns_clone` is disabled",
                "enable unprivileged user namespaces or run childflow with enough privileges to set up the namespace another way",
            ),
            Ok(Some(_)) => report.push_ok(
                "unprivileged user namespaces",
                "unprivileged user namespace cloning is enabled",
            ),
            Ok(None) => report.push_ok(
                "unprivileged user namespaces",
                "`/proc/sys/kernel/unprivileged_userns_clone` is unavailable in this environment; namespace setup will be determined during runtime",
            ),
            Err(err) => report.push_warning(
                "unprivileged user namespaces",
                err.to_string(),
                "non-root user-namespace setup may still fail later on this host",
            ),
        }
    } else {
        report.push_ok(
            "unprivileged user namespaces",
            "running as root, so the non-root clone gate does not apply",
        );
    }

    let missing_uidmap_helpers = find_missing_commands(ROOTLESS_UIDMAP_HELPERS, &path_env);
    if current_euid() == 0 {
        report.push_ok(
            "uidmap helpers",
            "running as root, so `newuidmap` / `newgidmap` fallback is not required",
        );
    } else if missing_uidmap_helpers.is_empty() {
        report.push_ok(
            "uidmap helpers",
            "found `newuidmap` and `newgidmap` for fallback user-namespace mapping",
        );
    } else {
        report.push_warning(
            "uidmap helpers",
            format!(
                "missing optional helpers: {}",
                missing_uidmap_helpers.join(", ")
            ),
            "install the `uidmap` package so childflow can fall back to helper-based uid/gid mapping when direct map writes are rejected",
        );
    }

    let missing_idmap_files = ROOTLESS_IDMAP_FILES
        .iter()
        .filter(|path| !Path::new(path).exists())
        .copied()
        .collect::<Vec<_>>();
    if current_euid() == 0 {
        report.push_ok(
            "subuid/subgid files",
            "running as root, so helper-based subordinate id mappings are not required",
        );
    } else if missing_idmap_files.is_empty() {
        report.push_ok(
            "subuid/subgid files",
            "found `/etc/subuid` and `/etc/subgid` for helper-based id mapping",
        );
    } else {
        report.push_warning(
            "subuid/subgid files",
            format!(
                "missing optional subordinate id mapping files: {}",
                missing_idmap_files.join(", ")
            ),
            "create `/etc/subuid` and `/etc/subgid` entries for the current user if helper-based uid/gid mapping is needed on this host",
        );
    }

    match check_tun_device("/dev/net/tun") {
        Ok(()) => report.push_ok(
            "TUN/TAP device",
            "`/dev/net/tun` is present and can be opened for rootless tap setup",
        ),
        Err(err) => report.push_fatal(
            "TUN/TAP device",
            err.to_string(),
            "load the `tun` kernel module, pass the device through to the container or VM, and verify the current user can open it",
        ),
    }

    report
}

fn check_tun_device(path: &str) -> Result<()> {
    let device = Path::new(path);
    if !device.exists() {
        bail!("`{path}` is missing");
    }

    OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .map(|_| ())
        .map_err(|err| anyhow::anyhow!("failed to open `{path}` ({err})"))
}

fn find_unwritable_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| {
            OpenOptions::new()
                .write(true)
                .open(path)
                .err()
                .map(|err| format!("{path} ({err})"))
        })
        .collect()
}

fn find_missing_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter(|path| !Path::new(path).exists())
        .map(|path| path.to_string())
        .collect()
}

pub(super) fn parse_proc_u64(path: &str) -> Result<Option<u64>> {
    if !Path::new(path).exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("failed to read `{path}` during preflight: {err}"))?;
    let value = raw.trim().parse::<u64>().map_err(|err| {
        anyhow::anyhow!("failed to parse `{path}` as an integer during preflight: {err}")
    })?;
    Ok(Some(value))
}

pub fn find_missing_commands(commands: &[&str], path_env: &OsStr) -> Vec<String> {
    let path_entries = env::split_paths(path_env).collect::<Vec<_>>();

    commands
        .iter()
        .filter(|command| {
            !path_entries
                .iter()
                .any(|dir| command_exists_in_dir(dir, command))
        })
        .map(|command| (*command).to_string())
        .collect()
}

fn command_exists_in_dir(dir: &Path, command: &str) -> bool {
    dir.join(command).is_file()
}

fn current_euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and reads no caller-provided memory.
    unsafe { nix::libc::geteuid() }
}
