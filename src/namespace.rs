use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::execvp;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NamespaceMode {
    Rootful,
}

impl NamespaceMode {
    fn unshare_flags(self) -> CloneFlags {
        match self {
            Self::Rootful => CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS,
        }
    }
}

pub fn child_enter_and_exec(
    mode: NamespaceMode,
    mut release_pipe: File,
    resolv_conf: Option<&Path>,
    command: &[String],
) -> Result<()> {
    if command.is_empty() {
        bail!("missing command");
    }

    unshare(mode.unshare_flags())
        .context("unshare(CLONE_NEWNET|CLONE_NEWNS) failed. Check CAP_SYS_ADMIN and whether the runtime permits creating Linux network/mount namespaces")?;

    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("failed to make mount propagation private")?;

    if let Some(resolv_conf) = resolv_conf {
        mount(
            Some(resolv_conf),
            "/etc/resolv.conf",
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "failed to bind-mount {} over /etc/resolv.conf",
                resolv_conf.display()
            )
        })?;
    }

    let mut ready = [0_u8; 1];
    let n = release_pipe
        .read(&mut ready)
        .context("failed to wait for parent namespace setup. The parent side may have aborted before namespace bootstrap completed")?;
    if n == 0 {
        bail!("parent closed bootstrap pipe before namespace setup completed");
    }

    let argv = command
        .iter()
        .map(|arg| {
            CString::new(arg.as_str()).map_err(|_| anyhow!("argument contains NUL byte: {arg:?}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let program = argv
        .first()
        .ok_or_else(|| anyhow!("missing program after parsing command"))?
        .clone();

    execvp(&program, &argv).with_context(|| {
        let command_name = command.first().map(String::as_str).unwrap_or("<missing>");
        format!(
            "execvp failed for `{command_name}`. Check that the target command exists in PATH and is executable inside the child namespace"
        )
    })?;
    unreachable!();
}
