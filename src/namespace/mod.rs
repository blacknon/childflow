// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod diagnostics;
mod exec;
mod mounts;
mod rootless_network;
#[cfg(test)]
mod tests;
mod userns;

use std::fs::File;
use std::os::unix::net::UnixStream;
use std::path::Path;

pub use self::rootless_network::ChildNetworkBootstrap;
pub use self::rootless_network::RootlessChildBootstrap;
pub use self::userns::configure_user_namespace;
use anyhow::{anyhow, Result};
use nix::sched::CloneFlags;

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

pub struct ChildExecParams<'a> {
    pub mode: NamespaceMode,
    pub release_pipe: File,
    pub namespace_ready_pipe: Option<File>,
    pub ready_pipe: Option<File>,
    pub tap_transfer: Option<UnixStream>,
    pub resolv_conf: Option<&'a Path>,
    pub resolv_conf_required: bool,
    pub hosts_file: Option<&'a Path>,
    pub network_bootstrap: Option<&'a ChildNetworkBootstrap>,
    pub extra_env: &'a [(String, String)],
    pub command: &'a [String],
}

pub fn child_enter_and_exec(params: ChildExecParams<'_>) -> Result<()> {
    exec::child_enter_and_exec(params)
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
