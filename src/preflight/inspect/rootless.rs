// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::env;
use std::path::Path;

use super::helpers::{
    check_tun_device, current_euid, find_missing_commands, find_missing_paths, parse_proc_u64,
};
use crate::preflight::PreflightReport;

const ROOTLESS_UIDMAP_HELPERS: &[&str] = &["newuidmap", "newgidmap"];
const ROOTLESS_INTERNAL_NAMESPACE_PATHS: &[&str] = &[
    "/proc/self/ns/user",
    "/proc/self/ns/net",
    "/proc/self/ns/mnt",
];
const ROOTLESS_IDMAP_FILES: &[&str] = &["/etc/subuid", "/etc/subgid"];

pub(super) fn inspect_rootless_internal() -> PreflightReport {
    let path_env = env::var_os("PATH").unwrap_or_default();
    let mut report = PreflightReport::new("rootless-internal");

    report.push_ok(
        "external commands",
        "the rootless backend no longer requires `ip` for namespace network setup",
    );

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
