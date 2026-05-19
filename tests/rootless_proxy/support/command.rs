use std::process::Command;

use anyhow::{Context, Result};

pub(crate) fn run_childflow_command(args: &[&str]) -> Result<std::process::Output> {
    let binary = env!("CARGO_BIN_EXE_childflow");
    let mut command = if unsafe { nix::libc::geteuid() } == 0 {
        let mut command = Command::new(binary);
        command.args(args);
        command
    } else {
        let mut command = Command::new("sudo");
        command.arg("-n").arg(binary).args(args);
        command
    };

    command.current_dir(env!("CARGO_MANIFEST_DIR"));
    command
        .output()
        .with_context(|| format!("failed to execute childflow command `{binary}`"))
}
