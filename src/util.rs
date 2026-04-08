use std::path::Path;
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

pub fn ensure_root() -> Result<()> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("failed to execute `id -u`")?;
    if !output.status.success() {
        bail!("`id -u` failed while checking privileges");
    }

    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uid != "0" {
        bail!("childflow PoC must run as root (or with equivalent CAP_NET_ADMIN/CAP_SYS_ADMIN/CAP_NET_RAW)");
    }

    Ok(())
}

pub fn run_entropy() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (process::id() ^ nanos) & 0x7fff_ffff
}

pub fn unique_run_id() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    format!("{:x}-{:x}", process::id(), micros)
}

pub fn run_command(program: &str, args: Vec<String>) -> Result<String> {
    let output = Command::new(program)
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute `{}`", render_command(program, &args)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "command failed: `{}` (status: {})\nstdout: {}\nstderr: {}",
            render_command(program, &args),
            output.status,
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn read_file_trimmed(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))
        .map(|s| s.trim().to_string())
}

fn render_command(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        return program.to_string();
    }
    format!("{} {}", program, args.join(" "))
}
