// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::env;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::path::Path;

use anyhow::{bail, Result};

use crate::cli::Cli;
use crate::network::NetworkBackend;

const ROOTFUL_REQUIRED_COMMANDS: &[&str] = &["ip", "iptables", "ip6tables"];
const ROOTFUL_REQUIRED_SYSCTLS: &[&str] = &[
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv6/conf/all/forwarding",
];
const ROOTLESS_INTERNAL_NAMESPACE_PATHS: &[&str] = &[
    "/proc/self/ns/user",
    "/proc/self/ns/net",
    "/proc/self/ns/mnt",
];

#[derive(Default)]
struct PreflightReport {
    fatal: Vec<String>,
    warnings: Vec<String>,
}

impl PreflightReport {
    fn push_fatal(&mut self, message: impl Into<String>) {
        self.fatal.push(message.into());
    }

    fn push_warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    fn emit_warnings(&self) {
        for warning in &self.warnings {
            crate::util::warn(format!("preflight: {warning}"));
        }
    }

    fn finish(self, backend_name: &str) -> Result<()> {
        self.emit_warnings();

        if self.fatal.is_empty() {
            return Ok(());
        }

        bail!(
            "preflight checks failed for the `{backend_name}` backend:\n{}",
            render_issue_list(&self.fatal)
        );
    }
}

pub fn run(cli: &Cli) -> Result<()> {
    match cli.selected_backend() {
        NetworkBackend::Rootful => run_rootful_preflight(cli),
        NetworkBackend::RootlessInternal => run_rootless_internal_preflight(),
    }
}

fn run_rootful_preflight(cli: &Cli) -> Result<()> {
    crate::util::ensure_root()?;

    let path_env = env::var_os("PATH").unwrap_or_default();
    let missing_commands = find_missing_commands(ROOTFUL_REQUIRED_COMMANDS, &path_env);
    let unwritable_paths = find_unwritable_paths(ROOTFUL_REQUIRED_SYSCTLS);
    let mut report = build_rootful_report(&missing_commands, &unwritable_paths);

    if cli.proxy.is_some() {
        report.push_warning(
            "transparent proxy mode still depends on Linux TPROXY support (`xt_TPROXY`, `xt_socket`, policy routing, and `IP_TRANSPARENT`) during setup",
        );
    }

    report.finish("rootful")
}

fn run_rootless_internal_preflight() -> Result<()> {
    let path_env = env::var_os("PATH").unwrap_or_default();
    collect_rootless_internal_report(&path_env).finish("rootless-internal")
}

fn collect_rootless_internal_report(path_env: &OsStr) -> PreflightReport {
    let mut report = PreflightReport::default();
    let _ = path_env;

    for issue in find_missing_paths(ROOTLESS_INTERNAL_NAMESPACE_PATHS) {
        report.push_fatal(issue);
    }

    match parse_proc_u64("/proc/sys/user/max_user_namespaces") {
        Ok(Some(0)) => report.push_fatal(
            "`/proc/sys/user/max_user_namespaces` is `0`; enable user namespaces before using the `rootless-internal` backend",
        ),
        Ok(Some(_)) => {}
        Ok(None) => report.push_warning(
            "`/proc/sys/user/max_user_namespaces` is unavailable in this environment; namespace availability will be determined during setup",
        ),
        Err(err) => report.push_warning(err.to_string()),
    }

    if unsafe { nix::libc::geteuid() } != 0 {
        match parse_proc_u64("/proc/sys/kernel/unprivileged_userns_clone") {
            Ok(Some(0)) => report.push_fatal(
                "`/proc/sys/kernel/unprivileged_userns_clone` is disabled; enable unprivileged user namespaces or run with sufficient privileges",
            ),
            Ok(Some(_)) => {}
            Ok(None) => report.push_warning(
                "`/proc/sys/kernel/unprivileged_userns_clone` is unavailable; non-root user-namespace setup may still fail later on this host",
            ),
            Err(err) => report.push_warning(err.to_string()),
        }
    }

    match check_tun_device("/dev/net/tun") {
        Ok(()) => {}
        Err(err) => report.push_fatal(err.to_string()),
    }

    report
}

fn check_tun_device(path: &str) -> Result<()> {
    let device = Path::new(path);
    if !device.exists() {
        bail!(
            "`{path}` is missing; load the `tun` kernel module and ensure the device node is available for the `rootless-internal` backend"
        );
    }

    OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .map(|_| ())
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to open `{path}` ({err}). Check TUN/TAP permissions, container device passthrough, and LSM policy before using the `rootless-internal` backend"
            )
        })
}

fn find_unwritable_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| {
            OpenOptions::new()
                .write(true)
                .open(path)
                .err()
                .map(|err| format!("{path} ({err})"))
        })
        .collect()
}

fn find_missing_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter(|path| !Path::new(path).exists())
        .map(|path| {
            format!(
                "`{path}` is missing; verify that this Linux environment exposes the required namespace handles for `rootless-internal`"
            )
        })
        .collect()
}

fn build_rootful_report(
    missing_commands: &[String],
    unwritable_paths: &[String],
) -> PreflightReport {
    let mut report = PreflightReport::default();

    if !missing_commands.is_empty() {
        report.push_fatal(format!(
            "missing required external commands: {}. Install `iproute2` for `ip`, and install an `iptables` / `ip6tables` userspace compatible with your kernel firewall backend.",
            missing_commands.join(", ")
        ));
    }

    if !unwritable_paths.is_empty() {
        report.push_fatal(format!(
            "required sysctl files are not writable: {}. Check root privileges, container restrictions, and whether `/proc/sys` is mounted read-write.",
            unwritable_paths.join(", ")
        ));
    }

    report
}

fn render_issue_list(issues: &[String]) -> String {
    issues
        .iter()
        .map(|issue| format!("- {issue}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn find_missing_commands(commands: &[&str], path_env: &OsStr) -> Vec<String> {
    let path_entries = env::split_paths(path_env).collect::<Vec<_>>();

    commands
        .iter()
        .filter(|command| {
            !path_entries
                .iter()
                .any(|dir| command_exists_in_dir(dir, command))
        })
        .map(|command| (*command).to_string())
        .collect()
}

fn parse_proc_u64(path: &str) -> Result<Option<u64>> {
    if !Path::new(path).exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("failed to read `{path}` during preflight: {err}"))?;
    let value = raw.trim().parse::<u64>().map_err(|err| {
        anyhow::anyhow!("failed to parse `{path}` as an integer during preflight: {err}")
    })?;
    Ok(Some(value))
}

fn command_exists_in_dir(dir: &Path, command: &str) -> bool {
    dir.join(command).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn find_missing_commands_reports_only_missing_entries() {
        let base = PathBuf::from("/tmp/childflow-preflight-tests");
        let path_env = env::join_paths([base.join("bin-a"), base.join("bin-b")]).unwrap();

        assert_eq!(
            find_missing_commands(&["ip", "iptables"], &path_env),
            vec!["ip".to_string(), "iptables".to_string()]
        );
    }

    #[test]
    fn build_rootful_issue_messages_reports_only_real_failures() {
        let report = build_rootful_report(&["ip".into()], &[]);
        assert_eq!(report.fatal.len(), 1);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn rootless_internal_preflight_does_not_require_external_commands() {
        let report = collect_rootless_internal_report(OsStr::new(""));
        assert!(!report
            .fatal
            .iter()
            .any(|issue| issue.contains("missing required external commands")));
    }

    #[test]
    fn render_issue_list_formats_each_entry() {
        let rendered = render_issue_list(&["first".into(), "second".into()]);
        assert_eq!(rendered, "- first\n- second");
    }

    #[test]
    fn parse_proc_u64_returns_none_when_file_is_missing() {
        assert_eq!(
            parse_proc_u64("/tmp/childflow-preflight/definitely-missing").unwrap(),
            None
        );
    }

    #[test]
    fn preflight_report_finish_succeeds_with_only_warnings() {
        let mut report = PreflightReport::default();
        report.push_warning("heads up");

        report.finish("rootless-internal").unwrap();
    }
}
