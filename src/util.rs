// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::path::Path;
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

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
    format!("{:08x}-{:016x}", process::id(), micros)
}

pub fn run_command(program: &str, args: Vec<String>) -> Result<String> {
    let output = Command::new(program)
        .args(&args)
        .output()
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "failed to execute `{}` because `{program}` was not found in PATH.\nHint: install the required Linux networking tools and rerun after satisfying the README preflight requirements.",
                render_command(program, &args)
            ),
            _ => anyhow::anyhow!(
                "failed to execute `{}`: {err}",
                render_command(program, &args)
            ),
        })?;

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

pub fn warn(message: impl AsRef<str>) {
    eprintln!("childflow: warning: {}", message.as_ref());
}

pub fn debug(message: impl AsRef<str>) {
    if debug_enabled() {
        eprintln!("childflow: debug: {}", message.as_ref());
    }
}

pub fn debug_enabled() -> bool {
    std::env::var_os("CHILDFLOW_DEBUG")
        .and_then(|value| value.into_string().ok())
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
}

pub fn render_command(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        return program.to_string();
    }
    let rendered = args
        .iter()
        .map(|arg| {
            if arg.is_empty()
                || arg
                    .chars()
                    .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\'' | '\\'))
            {
                format!("{arg:?}")
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("{program} {rendered}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_command_quotes_arguments_that_need_shell_safe_display() {
        let rendered = render_command(
            "ip",
            &[
                "route".into(),
                "add".into(),
                "default via 10.0.0.1".into(),
                "dev".into(),
                "eth 0".into(),
            ],
        );

        assert_eq!(
            rendered,
            r#"ip route add "default via 10.0.0.1" dev "eth 0""#
        );
    }

    #[test]
    fn unique_run_id_has_stable_hex_format() {
        let run_id = unique_run_id();
        let parts: Vec<_> = run_id.split('-').collect();

        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 16);
        assert!(parts
            .iter()
            .all(|part| part.chars().all(|ch| ch.is_ascii_hexdigit())));
    }
}
