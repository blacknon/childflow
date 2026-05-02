// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::env;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::path::Path;

use anyhow::Result;

use crate::cli::Cli;
use crate::network::NetworkBackend;
use crate::preflight::{self, CheckStatus};

pub fn run(cli: &Cli) -> Result<i32> {
    let report = preflight::inspect(cli.selected_backend(), false);
    let capability_report = inspect_capabilities(cli.selected_backend());
    let status_line = if report.has_fatal() {
        "blocked"
    } else if report.has_warnings() {
        "ready with warnings"
    } else {
        "ready"
    };

    println!("childflow doctor");
    println!("backend: {}", report.backend_name());
    println!(
        "user: uid {} / euid {}",
        unsafe { nix::libc::getuid() },
        unsafe { nix::libc::geteuid() }
    );
    println!("status: {status_line}");
    println!();

    println!("capabilities");
    for capability in capability_report.checks() {
        println!(
            "[{}] {}",
            render_capability_status(&capability.status),
            capability.label
        );
        println!("  {}", capability.detail);
    }
    println!();

    println!("preflight");
    for check in report.checks() {
        println!("[{}] {}", render_status(&check.status), check.label);
        println!("  {}", check.detail);
        if let Some(hint) = &check.hint {
            println!("  hint: {hint}");
        }
    }

    Ok(if report.has_fatal() { 1 } else { 0 })
}

fn render_status(status: &CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "OK",
        CheckStatus::Warning => "WARN",
        CheckStatus::Fatal => "FATAL",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilityStatus {
    Available,
    Limited,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapabilityCheck {
    label: String,
    status: CapabilityStatus,
    detail: String,
}

#[derive(Clone, Debug, Default)]
struct CapabilityReport {
    checks: Vec<CapabilityCheck>,
}

impl CapabilityReport {
    fn push(
        &mut self,
        label: impl Into<String>,
        status: CapabilityStatus,
        detail: impl Into<String>,
    ) {
        self.checks.push(CapabilityCheck {
            label: label.into(),
            status,
            detail: detail.into(),
        });
    }

    fn checks(&self) -> &[CapabilityCheck] {
        &self.checks
    }
}

fn inspect_capabilities(backend: NetworkBackend) -> CapabilityReport {
    match backend {
        NetworkBackend::Rootful => inspect_rootful_capabilities(),
        NetworkBackend::RootlessInternal => inspect_rootless_internal_capabilities(),
    }
}

fn inspect_rootful_capabilities() -> CapabilityReport {
    let mut report = CapabilityReport::default();

    let euid = unsafe { nix::libc::geteuid() };
    if euid == 0 {
        report.push(
            "root privileges",
            CapabilityStatus::Available,
            "running as root for the selected backend",
        );
    } else {
        report.push(
            "root privileges",
            CapabilityStatus::Unavailable,
            "the `rootful` backend needs root on Linux",
        );
    }

    let missing_commands = missing_commands(&["ip", "iptables", "ip6tables"]);
    if missing_commands.is_empty() {
        report.push(
            "external commands",
            CapabilityStatus::Available,
            "found `ip`, `iptables`, and `ip6tables` in PATH",
        );
    } else {
        report.push(
            "external commands",
            CapabilityStatus::Unavailable,
            format!("missing required commands: {}", missing_commands.join(", ")),
        );
    }

    let unwritable_sysctls = unwritable_paths(&[
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv6/conf/all/forwarding",
    ]);
    if unwritable_sysctls.is_empty() {
        report.push(
            "forwarding sysctls",
            CapabilityStatus::Available,
            "required IPv4 and IPv6 forwarding sysctls are writable",
        );
    } else {
        report.push(
            "forwarding sysctls",
            CapabilityStatus::Unavailable,
            format!(
                "required sysctl files are not writable: {}",
                unwritable_sysctls.join(", ")
            ),
        );
    }

    let (packet_status, packet_detail) = inspect_af_packet_capability();
    report.push("AF_PACKET capture", packet_status, packet_detail);

    report
}

fn inspect_rootless_internal_capabilities() -> CapabilityReport {
    let mut report = CapabilityReport::default();
    let euid = unsafe { nix::libc::geteuid() };

    let missing_required_commands = missing_commands(&["ip"]);
    if missing_required_commands.is_empty() {
        report.push(
            "external commands",
            CapabilityStatus::Available,
            "found `ip` in PATH",
        );
    } else {
        report.push(
            "external commands",
            CapabilityStatus::Unavailable,
            format!(
                "missing required commands: {}",
                missing_required_commands.join(", ")
            ),
        );
    }

    let namespace_handles = ["/proc/self/ns/user", "/proc/self/ns/net", "/proc/self/ns/mnt"];
    let missing_handles = missing_paths(&namespace_handles);
    if missing_handles.is_empty() {
        report.push(
            "namespace handles",
            CapabilityStatus::Available,
            "found `/proc/self/ns/{user,net,mnt}` for rootless setup",
        );
    } else {
        report.push(
            "namespace handles",
            CapabilityStatus::Unavailable,
            format!("missing namespace handles: {}", missing_handles.join(", ")),
        );
    }

    match read_proc_u64("/proc/sys/user/max_user_namespaces") {
        Some(0) => report.push(
            "user namespace quota",
            CapabilityStatus::Unavailable,
            "`/proc/sys/user/max_user_namespaces` is `0`",
        ),
        Some(value) => report.push(
            "user namespace quota",
            CapabilityStatus::Available,
            format!("`/proc/sys/user/max_user_namespaces` is set to {value}"),
        ),
        None => report.push(
            "user namespace quota",
            CapabilityStatus::Limited,
            "`/proc/sys/user/max_user_namespaces` is unavailable in this environment",
        ),
    }

    if euid == 0 {
        report.push(
            "unprivileged user namespaces",
            CapabilityStatus::Available,
            "running as root, so the non-root clone gate does not apply",
        );
    } else {
        match read_proc_u64("/proc/sys/kernel/unprivileged_userns_clone") {
            Some(0) => report.push(
                "unprivileged user namespaces",
                CapabilityStatus::Unavailable,
                "`/proc/sys/kernel/unprivileged_userns_clone` is disabled",
            ),
            Some(_) => report.push(
                "unprivileged user namespaces",
                CapabilityStatus::Available,
                "unprivileged user namespace cloning is enabled",
            ),
            None => report.push(
                "unprivileged user namespaces",
                CapabilityStatus::Limited,
                "`/proc/sys/kernel/unprivileged_userns_clone` is unavailable in this environment",
            ),
        }
    }

    report.push(
        "AppArmor userns policy",
        inspect_apparmor_userns_capability(euid),
        render_apparmor_userns_detail(euid),
    );

    if euid == 0 {
        report.push(
            "uidmap helpers",
            CapabilityStatus::Available,
            "running as root, so `newuidmap` / `newgidmap` fallback is not required",
        );
        report.push(
            "subuid/subgid entries",
            CapabilityStatus::Available,
            "running as root, so subordinate id mappings are not required",
        );
    } else {
        let missing_uidmap_helpers = missing_commands(&["newuidmap", "newgidmap"]);
        if missing_uidmap_helpers.is_empty() {
            report.push(
                "uidmap helpers",
                CapabilityStatus::Available,
                "found `newuidmap` and `newgidmap` for helper-based id mapping",
            );
        } else {
            report.push(
                "uidmap helpers",
                CapabilityStatus::Limited,
                format!(
                    "missing optional helpers: {}",
                    missing_uidmap_helpers.join(", ")
                ),
            );
        }

        let username = current_username().unwrap_or_else(|| format!("uid:{euid}"));
        let subuid_present = subid_entry_exists("/etc/subuid", &username);
        let subgid_present = subid_entry_exists("/etc/subgid", &username);
        if subuid_present && subgid_present {
            report.push(
                "subuid/subgid entries",
                CapabilityStatus::Available,
                format!("found subordinate id mappings for `{username}`"),
            );
        } else {
            let mut missing_locations = Vec::new();
            if !subuid_present {
                missing_locations.push("`/etc/subuid`");
            }
            if !subgid_present {
                missing_locations.push("`/etc/subgid`");
            }
            report.push(
                "subuid/subgid entries",
                CapabilityStatus::Limited,
                format!(
                    "missing subordinate id mappings for `{username}` in {}",
                    missing_locations.join(" and ")
                ),
            );
        }
    }

    let (tun_status, tun_detail) = inspect_tun_capability();
    report.push("TUN/TAP device", tun_status, tun_detail);

    let (packet_status, packet_detail) = inspect_af_packet_capability();
    report.push("AF_PACKET capture", packet_status, packet_detail);

    report
}

fn inspect_tun_capability() -> (CapabilityStatus, String) {
    let path = "/dev/net/tun";
    if !Path::new(path).exists() {
        return (
            CapabilityStatus::Unavailable,
            format!("`{path}` is missing"),
        );
    }

    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => (
            CapabilityStatus::Available,
            "`/dev/net/tun` is present and can be opened".to_string(),
        ),
        Err(err) => (
            CapabilityStatus::Unavailable,
            format!("failed to open `{path}` ({err})"),
        ),
    }
}

fn inspect_af_packet_capability() -> (CapabilityStatus, String) {
    let protocol = u16::to_be(nix::libc::ETH_P_ALL as u16) as i32;
    let fd = unsafe { nix::libc::socket(nix::libc::AF_PACKET, nix::libc::SOCK_RAW, protocol) };
    if fd >= 0 {
        unsafe {
            nix::libc::close(fd);
        }
        return (
            CapabilityStatus::Available,
            "raw AF_PACKET sockets can be opened for capture".to_string(),
        );
    }

    let err = std::io::Error::last_os_error();
    (
        CapabilityStatus::Limited,
        format!("raw AF_PACKET sockets are blocked for the current user ({err})"),
    )
}

fn inspect_apparmor_userns_capability(euid: u32) -> CapabilityStatus {
    if euid == 0 {
        return CapabilityStatus::Available;
    }

    match read_trimmed_file("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() {
        Some("1") => CapabilityStatus::Limited,
        Some("0") => CapabilityStatus::Available,
        Some(_) | None => CapabilityStatus::Limited,
    }
}

fn render_apparmor_userns_detail(euid: u32) -> String {
    let restriction = read_trimmed_file("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .unwrap_or_else(|| "unavailable".to_string());
    let profile =
        read_trimmed_file("/proc/self/attr/current").unwrap_or_else(|| "<unavailable>".to_string());

    if euid == 0 {
        return format!(
            "current AppArmor profile: {profile}; root bypasses the unprivileged userns gate"
        );
    }

    match restriction.as_str() {
        "1" => format!(
            "AppArmor unprivileged user-namespace restriction is enabled; current profile: {profile}"
        ),
        "0" => format!(
            "AppArmor unprivileged user-namespace restriction is disabled; current profile: {profile}"
        ),
        _ => format!(
            "AppArmor user-namespace restriction state is unavailable; current profile: {profile}"
        ),
    }
}

fn missing_commands(commands: &[&str]) -> Vec<String> {
    let path_env = env::var_os("PATH").unwrap_or_else(|| OsString::from(""));
    preflight::find_missing_commands(commands, &path_env)
}

fn unwritable_paths(paths: &[&str]) -> Vec<String> {
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

fn missing_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter(|path| !Path::new(path).exists())
        .map(|path| path.to_string())
        .collect()
}

fn read_trimmed_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_proc_u64(path: &str) -> Option<u64> {
    read_trimmed_file(path).and_then(|value| value.parse::<u64>().ok())
}

fn current_username() -> Option<String> {
    env::var("USER")
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

fn render_capability_status(status: &CapabilityStatus) -> &'static str {
    match status {
        CapabilityStatus::Available => "AVAILABLE",
        CapabilityStatus::Limited => "LIMITED",
        CapabilityStatus::Unavailable => "UNAVAILABLE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_capability_status_uses_stable_labels() {
        assert_eq!(render_capability_status(&CapabilityStatus::Available), "AVAILABLE");
        assert_eq!(render_capability_status(&CapabilityStatus::Limited), "LIMITED");
        assert_eq!(
            render_capability_status(&CapabilityStatus::Unavailable),
            "UNAVAILABLE"
        );
    }

    #[test]
    fn apparmor_userns_restriction_reports_limited_for_non_root() {
        let detail = render_apparmor_userns_detail(1000);
        assert!(!detail.is_empty());
    }
}
