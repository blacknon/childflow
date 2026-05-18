mod render;
mod sysinfo;

use self::sysinfo::{current_apparmor_profile, root_mount_propagates_outward};

pub(super) fn can_skip_mount_private(err: nix::errno::Errno) -> bool {
    matches!(err, nix::errno::Errno::EACCES | nix::errno::Errno::EPERM)
        && current_apparmor_profile()
            .as_deref()
            .is_some_and(|profile| profile.starts_with("unprivileged_userns"))
        && root_mount_propagates_outward() == Some(false)
}

pub(super) fn can_skip_resolv_conf_bind(err: nix::errno::Errno, required: bool) -> bool {
    !required
        && matches!(err, nix::errno::Errno::EACCES | nix::errno::Errno::EPERM)
        && current_apparmor_profile()
            .as_deref()
            .is_some_and(|profile| profile.starts_with("unprivileged_userns"))
}

pub(super) fn build_mount_private_error(err: nix::errno::Errno) -> anyhow::Error {
    render::build_mount_private_error(err)
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
    render::build_user_namespace_error(
        pid,
        uid,
        gid,
        direct_full_err,
        helper_full_err,
        direct_uid_only_err,
        helper_uid_only_err,
    )
}

pub(super) fn parse_mountinfo_propagates_outward(line: &str) -> bool {
    let Some((left, _)) = line.split_once(" - ") else {
        return true;
    };
    left.split_whitespace()
        .skip(6)
        .any(|field| field.starts_with("shared:"))
}
