use std::fmt::Write as _;

use anyhow::anyhow;

use super::sysinfo::{
    command_in_path, current_username, format_optional_value, format_proc_value, read_proc_u64,
    read_root_mountinfo_line, read_trimmed_file, subid_entry_exists, yes_no,
};

pub(super) fn build_mount_private_error(err: nix::errno::Errno) -> anyhow::Error {
    let mut message = format!("failed to make mount propagation private: {err}\n");
    let euid = unsafe { nix::libc::geteuid() };
    let egid = unsafe { nix::libc::getegid() };

    let _ = writeln!(message, "diagnostics:");
    let _ = writeln!(message, "- effective uid/gid: {euid}/{egid}");
    let _ = writeln!(
        message,
        "- /proc/self/uid_map: {}",
        format_optional_value(read_trimmed_file("/proc/self/uid_map"))
    );
    let _ = writeln!(
        message,
        "- /proc/self/gid_map: {}",
        format_optional_value(read_trimmed_file("/proc/self/gid_map"))
    );
    let _ = writeln!(
        message,
        "- /proc/self/setgroups: {}",
        format_optional_value(read_trimmed_file("/proc/self/setgroups"))
    );
    let _ = writeln!(
        message,
        "- /proc/self/attr/current: {}",
        format_optional_value(read_trimmed_file("/proc/self/attr/current"))
    );
    let _ = writeln!(
        message,
        "- root mountinfo entry: {}",
        format_optional_value(read_root_mountinfo_line())
    );
    let _ = writeln!(
        message,
        "- /proc/sys/kernel/apparmor_restrict_unprivileged_userns: {}",
        format_optional_value(read_trimmed_file(
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
        ))
    );
    let _ = writeln!(
        message,
        "- /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined: {}",
        format_optional_value(read_trimmed_file(
            "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined",
        ))
    );

    if read_trimmed_file("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref()
        == Some("1")
    {
        let _ = writeln!(
            message,
            "this host has AppArmor's unprivileged user-namespace restriction enabled. On Ubuntu 24.04+, user namespace creation may succeed while CAP_SYS_ADMIN operations inside the transitioned AppArmor profile are still denied."
        );
    }

    anyhow!(message)
}

pub(super) fn build_user_namespace_error(
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
