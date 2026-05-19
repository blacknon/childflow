use std::ffi::CString;

use anyhow::{anyhow, bail, Context, Result};
use nix::sched::unshare;
use nix::unistd::execvp;

use super::{mounts, rootless_network, ChildExecParams};

pub(super) fn child_enter_and_exec(params: ChildExecParams<'_>) -> Result<()> {
    let ChildExecParams {
        mode,
        mut release_pipe,
        mut namespace_ready_pipe,
        mut ready_pipe,
        tap_transfer,
        resolv_conf,
        resolv_conf_required,
        hosts_file,
        network_bootstrap,
        extra_env,
        command,
    } = params;

    if command.is_empty() {
        bail!("missing command");
    }

    unshare(mode.unshare_flags()).map_err(|err| super::render_unshare_error(mode, err))?;

    if let Some(namespace_ready_pipe) = namespace_ready_pipe.as_mut() {
        use std::io::Write;

        namespace_ready_pipe
            .write_all(&[1])
            .context("failed to notify the parent that child namespace unshare completed")?;
    }

    mounts::wait_for_parent_release(
        &mut release_pipe,
        "failed to wait for parent namespace setup. The parent side may have aborted before namespace bootstrap completed",
        "parent closed bootstrap pipe before namespace setup completed",
    )?;

    mounts::make_mount_propagation_private()?;

    if let Some(resolv_conf) = resolv_conf {
        mounts::bind_mount_resolv_conf(resolv_conf, resolv_conf_required)?;
    }

    if let Some(hosts_file) = hosts_file {
        mounts::bind_mount_hosts_file(hosts_file)?;
    }

    let _network_guard = if let Some(bootstrap) = network_bootstrap {
        let guard = rootless_network::apply_child_network_bootstrap(bootstrap)?;

        if let (Some(tap_transfer), Some(tap_file)) = (tap_transfer.as_ref(), guard.as_ref()) {
            crate::network::rootless_internal::tap::send_fd_over_stream(tap_transfer, tap_file)
                .context("failed to pass the rootless tap fd back to the parent")?;
        }

        if let Some(ready_pipe) = ready_pipe.as_mut() {
            use std::io::Write;

            ready_pipe
                .write_all(&[1])
                .context("failed to notify the parent that rootless tap bootstrap completed")?;
        }

        mounts::wait_for_parent_release(
            &mut release_pipe,
            "failed while waiting for the parent to finish starting the rootless userspace networking engine",
            "parent closed bootstrap pipe before the rootless userspace networking engine was ready",
        )?;
        guard
    } else {
        None
    };

    for (key, value) in extra_env {
        std::env::set_var(key, value);
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
