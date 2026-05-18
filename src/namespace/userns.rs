use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use nix::unistd::Pid;

use super::diagnostics::build_user_namespace_error;

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
        Err(direct_full_err) => match try_configure_user_namespace_with_uidmap_tools(pid, uid, gid)
        {
            Ok(()) => {
                crate::util::debug(format!(
                    "configured rootless user namespace for pid {pid} via newuidmap/newgidmap fallback after direct map writes were rejected: {direct_full_err:#}"
                ));
                UserNamespaceMapping::HelperFull
            }
            Err(helper_full_err) => match try_configure_user_namespace_direct_uid_only(pid, uid) {
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
                    match try_configure_user_namespace_with_uidmap_tools_uid_only(pid, uid) {
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
            },
        },
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
            output
                .status
                .code()
                .or_else(|| std::os::unix::process::ExitStatusExt::signal(&output.status)),
            stdout,
            stderr
        );
    }

    Ok(())
}
