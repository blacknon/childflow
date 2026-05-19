use crate::observability::doctor as observability_doctor;

use super::{
    current_euid, current_username, inspect_af_packet_capability,
    inspect_apparmor_userns_capability, inspect_tun_capability, missing_commands, missing_paths,
    read_proc_u64, render_apparmor_userns_detail, subid_entry_exists, CapabilityReport,
    CapabilityStatus,
};

pub(super) fn inspect_rootless_internal_capabilities() -> CapabilityReport {
    let mut report = CapabilityReport::default();
    let euid = current_euid();

    let missing_required_commands = missing_commands(&["ip"]);
    if missing_required_commands.is_empty() {
        report.push(
            observability_doctor::EXTERNAL_COMMANDS,
            "external commands",
            CapabilityStatus::Available,
            "found `ip` in PATH",
        );
    } else {
        report.push(
            observability_doctor::EXTERNAL_COMMANDS,
            "external commands",
            CapabilityStatus::Unavailable,
            format!(
                "missing required commands: {}",
                missing_required_commands.join(", ")
            ),
        );
    }

    let namespace_handles = [
        "/proc/self/ns/user",
        "/proc/self/ns/net",
        "/proc/self/ns/mnt",
    ];
    let missing_handles = missing_paths(&namespace_handles);
    if missing_handles.is_empty() {
        report.push(
            observability_doctor::NAMESPACE_HANDLES,
            "namespace handles",
            CapabilityStatus::Available,
            "found `/proc/self/ns/{user,net,mnt}` for rootless setup",
        );
    } else {
        report.push(
            observability_doctor::NAMESPACE_HANDLES,
            "namespace handles",
            CapabilityStatus::Unavailable,
            format!("missing namespace handles: {}", missing_handles.join(", ")),
        );
    }

    match read_proc_u64("/proc/sys/user/max_user_namespaces") {
        Some(0) => report.push(
            observability_doctor::USER_NAMESPACE_QUOTA,
            "user namespace quota",
            CapabilityStatus::Unavailable,
            "`/proc/sys/user/max_user_namespaces` is `0`",
        ),
        Some(value) => report.push(
            observability_doctor::USER_NAMESPACE_QUOTA,
            "user namespace quota",
            CapabilityStatus::Available,
            format!("`/proc/sys/user/max_user_namespaces` is set to {value}"),
        ),
        None => report.push(
            observability_doctor::USER_NAMESPACE_QUOTA,
            "user namespace quota",
            CapabilityStatus::Limited,
            "`/proc/sys/user/max_user_namespaces` is unavailable in this environment",
        ),
    }

    if euid == 0 {
        report.push(
            observability_doctor::UNPRIVILEGED_USER_NAMESPACES,
            "unprivileged user namespaces",
            CapabilityStatus::Available,
            "running as root, so the non-root clone gate does not apply",
        );
    } else {
        match read_proc_u64("/proc/sys/kernel/unprivileged_userns_clone") {
            Some(0) => report.push(
                observability_doctor::UNPRIVILEGED_USER_NAMESPACES,
                "unprivileged user namespaces",
                CapabilityStatus::Unavailable,
                "`/proc/sys/kernel/unprivileged_userns_clone` is disabled",
            ),
            Some(_) => report.push(
                observability_doctor::UNPRIVILEGED_USER_NAMESPACES,
                "unprivileged user namespaces",
                CapabilityStatus::Available,
                "unprivileged user namespace cloning is enabled",
            ),
            None => report.push(
                observability_doctor::UNPRIVILEGED_USER_NAMESPACES,
                "unprivileged user namespaces",
                CapabilityStatus::Limited,
                "`/proc/sys/kernel/unprivileged_userns_clone` is unavailable in this environment",
            ),
        }
    }

    report.push(
        observability_doctor::APPARMOR_USERNS_POLICY,
        "AppArmor userns policy",
        inspect_apparmor_userns_capability(euid),
        render_apparmor_userns_detail(euid),
    );

    if euid == 0 {
        report.push(
            observability_doctor::UIDMAP_HELPERS,
            "uidmap helpers",
            CapabilityStatus::Available,
            "running as root, so `newuidmap` / `newgidmap` fallback is not required",
        );
        report.push(
            observability_doctor::SUBUID_SUBGID_ENTRIES,
            "subuid/subgid entries",
            CapabilityStatus::Available,
            "running as root, so subordinate id mappings are not required",
        );
    } else {
        let missing_uidmap_helpers = missing_commands(&["newuidmap", "newgidmap"]);
        if missing_uidmap_helpers.is_empty() {
            report.push(
                observability_doctor::UIDMAP_HELPERS,
                "uidmap helpers",
                CapabilityStatus::Available,
                "found `newuidmap` and `newgidmap` for helper-based id mapping",
            );
        } else {
            report.push(
                observability_doctor::UIDMAP_HELPERS,
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
                observability_doctor::SUBUID_SUBGID_ENTRIES,
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
                observability_doctor::SUBUID_SUBGID_ENTRIES,
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
    report.push(
        observability_doctor::TUN_TAP_DEVICE,
        "TUN/TAP device",
        tun_status,
        tun_detail,
    );

    let (packet_status, packet_detail) = inspect_af_packet_capability();
    report.push(
        observability_doctor::AF_PACKET_CAPTURE,
        "AF_PACKET capture",
        packet_status,
        packet_detail,
    );

    report
}
