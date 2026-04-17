use std::env;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::path::Path;

use anyhow::{bail, Result};

use crate::cli::Cli;
use crate::network::NetworkBackend;

const ROOTFUL_REQUIRED_COMMANDS: &[&str] = &["ip", "iptables", "ip6tables"];
const ROOTLESS_INTERNAL_REQUIRED_COMMANDS: &[&str] = &["ip"];
const ROOTFUL_REQUIRED_SYSCTLS: &[&str] = &[
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv6/conf/all/forwarding",
];
const ROOTLESS_INTERNAL_NAMESPACE_PATHS: &[&str] = &[
    "/proc/self/ns/user",
    "/proc/self/ns/net",
    "/proc/self/ns/mnt",
];

pub fn run(cli: &Cli) -> Result<()> {
    match cli.network_backend {
        NetworkBackend::Rootful => run_rootful_preflight(cli),
        NetworkBackend::RootlessInternal => run_rootless_internal_preflight(),
    }
}

fn run_rootful_preflight(cli: &Cli) -> Result<()> {
    crate::util::ensure_root()?;

    let path_env = env::var_os("PATH").unwrap_or_default();
    let missing_commands = find_missing_commands(ROOTFUL_REQUIRED_COMMANDS, &path_env);
    let unwritable_paths = find_unwritable_paths(ROOTFUL_REQUIRED_SYSCTLS);
    let issues = build_rootful_issue_messages(&missing_commands, &unwritable_paths);

    if issues.is_empty() {
        if cli.proxy.is_some() {
            crate::util::debug(
                "rootful preflight passed. Transparent proxy mode will still require Linux TPROXY support (`xt_TPROXY`, `xt_socket`, policy routing, and `IP_TRANSPARENT`) during setup",
            );
        }
        return Ok(());
    }

    bail!(
        "preflight checks failed for the `rootful` backend before childflow touched host networking:\n{}",
        render_issue_list(&issues)
    );
}

fn run_rootless_internal_preflight() -> Result<()> {
    let path_env = env::var_os("PATH").unwrap_or_default();
    let issues = collect_rootless_internal_issues(&path_env);

    if issues.is_empty() {
        return Ok(());
    }

    bail!(
        "preflight checks failed for the `rootless-internal` backend:\n{}",
        render_issue_list(&issues)
    );
}

fn collect_rootless_internal_issues(path_env: &OsStr) -> Vec<String> {
    let mut issues = Vec::new();

    let missing_commands = find_missing_commands(ROOTLESS_INTERNAL_REQUIRED_COMMANDS, path_env);
    if !missing_commands.is_empty() {
        issues.push(format!(
            "missing required external commands for the `rootless-internal` backend: {}. Install `iproute2` so childflow can configure `tap0`, loopback, and default routes inside the child namespace.",
            missing_commands.join(", ")
        ));
    }

    issues.extend(find_missing_paths(ROOTLESS_INTERNAL_NAMESPACE_PATHS));

    match parse_proc_u64("/proc/sys/user/max_user_namespaces") {
        Ok(Some(0)) => issues.push(
            "`/proc/sys/user/max_user_namespaces` is `0`; enable user namespaces before using the `rootless-internal` backend".to_string(),
        ),
        Ok(Some(_)) | Ok(None) => {}
        Err(err) => issues.push(err),
    }

    if unsafe { nix::libc::geteuid() } != 0 {
        match parse_proc_u64("/proc/sys/kernel/unprivileged_userns_clone") {
            Ok(Some(0)) => issues.push(
                "`/proc/sys/kernel/unprivileged_userns_clone` is disabled; enable unprivileged user namespaces or run with sufficient privileges".to_string(),
            ),
            Ok(Some(_)) | Ok(None) => {}
            Err(err) => issues.push(err),
        }
    }

    match check_tun_device("/dev/net/tun") {
        Ok(()) => {}
        Err(err) => issues.push(err),
    }

    issues
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

fn build_rootful_issue_messages(
    missing_commands: &[String],
    unwritable_paths: &[String],
) -> Vec<String> {
    let mut issues = Vec::new();

    if !missing_commands.is_empty() {
        issues.push(format!(
            "missing required external commands: {}. Install `iproute2` for `ip`, and install an `iptables` / `ip6tables` userspace compatible with your kernel firewall backend.",
            missing_commands.join(", ")
        ));
    }

    if !unwritable_paths.is_empty() {
        issues.push(format!(
            "required sysctl files are not writable: {}. Check root privileges, container restrictions, and whether `/proc/sys` is mounted read-write.",
            unwritable_paths.join(", ")
        ));
    }

    issues
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
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn find_missing_commands_reports_only_missing_entries() {
        let base = PathBuf::from("/tmp/childflow-preflight-tests");
        let path_env =
            OsString::from(env::join_paths([base.join("bin-a"), base.join("bin-b")]).unwrap());

        assert_eq!(
            find_missing_commands(&["ip", "iptables"], &path_env),
            vec!["ip".to_string(), "iptables".to_string()]
        );
    }

    #[test]
    fn build_rootful_issue_messages_reports_only_real_failures() {
        let issues = build_rootful_issue_messages(&["ip".into()], &[]);
        assert_eq!(issues.len(), 1);
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
}
