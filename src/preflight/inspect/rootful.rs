// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::env;

use super::helpers::{current_euid, find_missing_commands, find_unwritable_paths};
use crate::preflight::PreflightReport;

const ROOTFUL_REQUIRED_COMMANDS: &[&str] = &["ip", "iptables", "ip6tables"];
const ROOTFUL_REQUIRED_SYSCTLS: &[&str] = &[
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv6/conf/all/forwarding",
];

pub(super) fn inspect_rootful(proxy_requested: bool) -> PreflightReport {
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
            format!(
                "required sysctl files are not writable: {}",
                unwritable_paths.join(", ")
            ),
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
