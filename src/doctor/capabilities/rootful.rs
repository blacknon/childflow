use crate::observability::doctor as observability_doctor;

use super::{
    current_euid, inspect_af_packet_capability, missing_commands, unwritable_paths,
    CapabilityReport, CapabilityStatus,
};

pub(super) fn inspect_rootful_capabilities() -> CapabilityReport {
    let mut report = CapabilityReport::default();

    let euid = current_euid();
    if euid == 0 {
        report.push(
            observability_doctor::ROOT_PRIVILEGES,
            "root privileges",
            CapabilityStatus::Available,
            "running as root for the selected backend",
        );
    } else {
        report.push(
            observability_doctor::ROOT_PRIVILEGES,
            "root privileges",
            CapabilityStatus::Unavailable,
            "the `rootful` backend needs root on Linux",
        );
    }

    let missing_commands = missing_commands(&["iptables", "ip6tables"]);
    if missing_commands.is_empty() {
        report.push(
            observability_doctor::EXTERNAL_COMMANDS,
            "external commands",
            CapabilityStatus::Available,
            "found `iptables` and `ip6tables` in PATH",
        );
    } else {
        report.push(
            observability_doctor::EXTERNAL_COMMANDS,
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
            observability_doctor::FORWARDING_SYSCTLS,
            "forwarding sysctls",
            CapabilityStatus::Available,
            "required IPv4 and IPv6 forwarding sysctls are writable",
        );
    } else {
        report.push(
            observability_doctor::FORWARDING_SYSCTLS,
            "forwarding sysctls",
            CapabilityStatus::Unavailable,
            format!(
                "required sysctl files are not writable: {}",
                unwritable_sysctls.join(", ")
            ),
        );
    }

    let (packet_status, packet_detail) = inspect_af_packet_capability();
    report.push(
        observability_doctor::AF_PACKET_CAPTURE,
        "AF_PACKET capture",
        packet_status,
        packet_detail,
    );

    report
}
