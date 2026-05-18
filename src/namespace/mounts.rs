use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use nix::mount::{mount, MsFlags};

use super::diagnostics;

pub(super) fn wait_for_parent_release(
    release_pipe: &mut File,
    read_context: &str,
    eof_message: &str,
) -> Result<()> {
    let mut ready = [0_u8; 1];
    let n = release_pipe
        .read(&mut ready)
        .with_context(|| read_context.to_string())?;
    if n == 0 {
        bail!(eof_message.to_string());
    }
    if ready[0] == 0 {
        bail!(eof_message.to_string());
    }
    Ok(())
}

pub(super) fn make_mount_propagation_private() -> Result<()> {
    if let Err(err) = mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    ) {
        if diagnostics::can_skip_mount_private(err) {
            crate::util::warn(
                "AppArmor denied forcing mount propagation to private inside the rootless user namespace, but the root mount already avoids outward propagation. Continuing without the extra remount step.",
            );
            return Ok(());
        }
        return Err(diagnostics::build_mount_private_error(err));
    }

    Ok(())
}

pub(super) fn bind_mount_resolv_conf(resolv_conf: &Path, required: bool) -> Result<()> {
    if let Err(err) = mount(
        Some(resolv_conf),
        "/etc/resolv.conf",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    ) {
        if diagnostics::can_skip_resolv_conf_bind(err, required) {
            crate::util::warn(
                "AppArmor denied bind-mounting the generated resolv.conf inside the rootless user namespace. Continuing with the inherited resolv.conf, so hostname resolution may be limited in this environment.",
            );
            return Ok(());
        }
        return Err(anyhow::Error::new(err).context(format!(
            "failed to bind-mount {} over /etc/resolv.conf",
            resolv_conf.display()
        )));
    }

    Ok(())
}

pub(super) fn bind_mount_hosts_file(hosts_file: &Path) -> Result<()> {
    mount(
        Some(hosts_file),
        "/etc/hosts",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "failed to bind-mount {} over /etc/hosts",
            hosts_file.display()
        )
    })?;

    Ok(())
}
