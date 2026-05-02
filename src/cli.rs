// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::network::NetworkBackend;
use crate::profile::Profile;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "childflow",
    version,
    about = "Run one command tree inside a controlled network sandbox",
    trailing_var_arg = true
)]
struct RawCli {
    /// Load effective defaults from a TOML profile file. Explicit CLI flags override the profile.
    #[arg(long = "profile")]
    profile: Option<PathBuf>,

    /// Print the effective profile as TOML and exit.
    #[arg(long = "dump-profile")]
    dump_profile: bool,

    /// Write only the target command tree's traffic as pcapng.
    #[arg(short = 'c', long = "capture")]
    output: Option<PathBuf>,

    /// Select which capture point or view `--capture` should write. `child` is the current stable view.
    #[arg(short = 'C', long = "capture-point", value_enum)]
    output_view: Option<OutputView>,

    /// Use the rootful backend. Without this flag, childflow uses the default rootless backend.
    #[arg(long = "root")]
    root: bool,

    /// Diagnose whether the current host is ready for the selected backend.
    #[arg(long = "doctor")]
    doctor: bool,

    /// Select the output format for `--doctor`.
    #[arg(long = "doctor-format", value_enum)]
    doctor_format: Option<DoctorFormat>,

    /// Read a structured flow log and print a text report.
    #[arg(long = "report")]
    report: Option<PathBuf>,

    /// Select the output format for `--report`.
    #[arg(long = "report-format", value_enum)]
    report_format: Option<ReportFormat>,

    /// Select the networking backend. This is kept as a hidden compatibility escape hatch; use `--root` for the public CLI.
    #[arg(long = "network-backend", value_enum, hide = true)]
    network_backend: Option<NetworkBackend>,

    /// Force DNS traffic for the child tree to this IPv4 or IPv6 resolver.
    #[arg(short = 'd', long = "dns")]
    dns: Option<IpAddr>,

    /// Bind-mount an `/etc/hosts`-format file over the child's `/etc/hosts` so those entries are consulted first during name resolution.
    #[arg(long = "hosts-file")]
    hosts_file: Option<PathBuf>,

    /// Configure an upstream proxy URI, for example http://127.0.0.1:8080, https://proxy.example.com:443, or socks5://host.docker.internal:10080. `--root` uses transparent interception, while the default rootless backend relays outbound TCP through the selected proxy from the parent-side engine.
    #[arg(short = 'p', long = "proxy")]
    proxy: Option<ProxySpec>,

    /// Username for upstream proxy authentication.
    #[arg(short = 'U', long = "proxy-user")]
    proxy_user: Option<String>,

    /// Password for upstream proxy authentication.
    #[arg(short = 'P', long = "proxy-password")]
    proxy_password: Option<String>,

    /// Ignore certificate trust errors for https:// upstream proxies while still validating the hostname.
    #[arg(long = "proxy-insecure")]
    proxy_insecure: bool,

    /// Print a post-run summary to stderr.
    #[arg(long = "summary")]
    summary: bool,

    /// Write structured flow events as JSON Lines. Currently supported only by the default rootless backend.
    #[arg(long = "flow-log")]
    flow_log: Option<PathBuf>,

    /// Block all outbound networking for the child tree, including DNS forwarding.
    #[arg(long = "offline")]
    offline: bool,

    /// Block child-tree traffic to private, loopback, link-local, and ULA-style destinations.
    #[arg(long = "block-private")]
    block_private: bool,

    /// Block common cloud metadata endpoints such as 169.254.169.254.
    #[arg(long = "block-metadata")]
    block_metadata: bool,

    /// Choose whether unmatched outbound destinations are allowed or denied.
    #[arg(long = "default-policy", value_enum)]
    default_policy: Option<DefaultPolicy>,

    /// Allow outbound destinations that fall within this IPv4 or IPv6 CIDR.
    #[arg(long = "allow-cidr")]
    allow_cidrs: Vec<IpNetwork>,

    /// Deny outbound destinations that fall within this IPv4 or IPv6 CIDR.
    #[arg(long = "deny-cidr")]
    deny_cidrs: Vec<IpNetwork>,

    /// Require outbound traffic to use the configured upstream proxy path.
    #[arg(long = "proxy-only")]
    proxy_only: bool,

    /// Exit non-zero if childflow blocks traffic that the child process did not treat as fatal. Currently supported only by the default rootless backend.
    #[arg(long = "fail-on-leak")]
    fail_on_leak: bool,

    /// Force the host-side egress interface for the child's direct traffic.
    #[arg(short = 'i', long = "iface")]
    iface: Option<String>,

    /// Command to execute.
    command: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Cli {
    pub dump_profile: bool,
    pub output: Option<PathBuf>,
    pub output_view: OutputView,
    pub root: bool,
    pub doctor: bool,
    pub doctor_format: DoctorFormat,
    pub report: Option<PathBuf>,
    pub report_format: ReportFormat,
    pub network_backend: NetworkBackend,
    pub dns: Option<IpAddr>,
    pub hosts_file: Option<PathBuf>,
    pub proxy: Option<ProxySpec>,
    pub proxy_user: Option<String>,
    pub proxy_password: Option<String>,
    pub proxy_insecure: bool,
    pub summary: bool,
    pub flow_log: Option<PathBuf>,
    pub offline: bool,
    pub block_private: bool,
    pub block_metadata: bool,
    pub default_policy: DefaultPolicy,
    pub allow_cidrs: Vec<IpNetwork>,
    pub deny_cidrs: Vec<IpNetwork>,
    pub proxy_only: bool,
    pub fail_on_leak: bool,
    pub iface: Option<String>,
    pub command: Vec<String>,
}

impl Cli {
    pub fn parse_effective() -> Result<Self> {
        Self::from_raw(RawCli::parse())
    }

    pub fn selected_backend(&self) -> NetworkBackend {
        if self.root {
            NetworkBackend::Rootful
        } else {
            self.network_backend
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.doctor {
            return Ok(());
        }

        if self.report.is_some() {
            if !self.command.is_empty() {
                bail!("`--report` does not accept a command to execute");
            }
            return Ok(());
        }

        if self.command.is_empty() {
            bail!("missing command to execute");
        }

        if matches!(self.selected_backend(), NetworkBackend::RootlessInternal)
            && self.iface.is_some()
        {
            bail!("`--iface` is not supported by the `rootless-internal` backend");
        }

        if let Some(path) = &self.hosts_file {
            if !path.exists() {
                bail!("`--hosts-file` path does not exist: {}", path.display());
            }
        }

        if self.output_view != OutputView::Child && self.output.is_none() {
            bail!("`--capture-point` requires `--capture`");
        }

        if self.proxy_user.is_some() != self.proxy_password.is_some() {
            bail!("`--proxy-user` and `--proxy-password` must be provided together");
        }

        if (self.proxy_user.is_some() || self.proxy_insecure) && self.proxy.is_none() {
            bail!("proxy authentication and TLS options require `--proxy`");
        }

        if self.proxy_only && self.proxy.is_none() {
            bail!("`--proxy-only` requires `--proxy`");
        }

        if self.proxy_insecure
            && !matches!(
                self.proxy.as_ref().map(|proxy| proxy.scheme),
                Some(ProxyScheme::Https)
            )
        {
            bail!("`--proxy-insecure` is only valid with an `https://` upstream proxy");
        }

        if self.fail_on_leak && matches!(self.selected_backend(), NetworkBackend::Rootful) {
            bail!(
                "`--fail-on-leak` is currently supported only by the `rootless-internal` backend"
            );
        }

        if self.flow_log.is_some() && matches!(self.selected_backend(), NetworkBackend::Rootful) {
            bail!("`--flow-log` is currently supported only by the `rootless-internal` backend");
        }

        Ok(())
    }

    fn from_raw(raw: RawCli) -> Result<Self> {
        let profile = raw.profile.as_deref().map(Profile::load).transpose()?;
        Ok(Self::merge(raw, profile.as_ref()))
    }

    fn merge(raw: RawCli, profile: Option<&Profile>) -> Self {
        let mut cli = Self {
            dump_profile: raw.dump_profile,
            output: profile.and_then(|value| value.capture.clone()),
            output_view: profile
                .and_then(|value| value.capture_point)
                .unwrap_or(OutputView::Child),
            root: false,
            doctor: raw.doctor,
            doctor_format: DoctorFormat::Text,
            report: raw.report,
            report_format: ReportFormat::Text,
            network_backend: profile
                .and_then(|value| value.backend)
                .unwrap_or(NetworkBackend::RootlessInternal),
            dns: profile.and_then(|value| value.dns),
            hosts_file: profile.and_then(|value| value.hosts_file.clone()),
            proxy: profile.and_then(|value| value.proxy.clone()),
            proxy_user: profile.and_then(|value| value.proxy_user.clone()),
            proxy_password: profile.and_then(|value| value.proxy_password.clone()),
            proxy_insecure: profile
                .and_then(|value| value.proxy_insecure)
                .unwrap_or(false),
            summary: profile.and_then(|value| value.summary).unwrap_or(false),
            flow_log: profile.and_then(|value| value.flow_log.clone()),
            offline: profile.and_then(|value| value.offline).unwrap_or(false),
            block_private: profile
                .and_then(|value| value.block_private)
                .unwrap_or(false),
            block_metadata: profile
                .and_then(|value| value.block_metadata)
                .unwrap_or(false),
            default_policy: profile
                .and_then(|value| value.default_policy)
                .unwrap_or(DefaultPolicy::Allow),
            allow_cidrs: profile
                .and_then(|value| value.allow_cidrs.clone())
                .unwrap_or_default(),
            deny_cidrs: profile
                .and_then(|value| value.deny_cidrs.clone())
                .unwrap_or_default(),
            proxy_only: profile.and_then(|value| value.proxy_only).unwrap_or(false),
            fail_on_leak: profile
                .and_then(|value| value.fail_on_leak)
                .unwrap_or(false),
            iface: profile.and_then(|value| value.iface.clone()),
            command: profile
                .and_then(|value| value.command.clone())
                .unwrap_or_default(),
        };

        if let Some(value) = raw.output {
            cli.output = Some(value);
        }
        if let Some(value) = raw.output_view {
            cli.output_view = value;
        }
        if raw.root {
            cli.root = true;
        }
        if let Some(value) = raw.network_backend {
            cli.network_backend = value;
        }
        if let Some(value) = raw.doctor_format {
            cli.doctor_format = value;
        }
        if let Some(value) = raw.report_format {
            cli.report_format = value;
        }
        if let Some(value) = raw.dns {
            cli.dns = Some(value);
        }
        if let Some(value) = raw.hosts_file {
            cli.hosts_file = Some(value);
        }
        if let Some(value) = raw.proxy {
            cli.proxy = Some(value);
        }
        if let Some(value) = raw.proxy_user {
            cli.proxy_user = Some(value);
        }
        if let Some(value) = raw.proxy_password {
            cli.proxy_password = Some(value);
        }
        if raw.proxy_insecure {
            cli.proxy_insecure = true;
        }
        if raw.summary {
            cli.summary = true;
        }
        if let Some(value) = raw.flow_log {
            cli.flow_log = Some(value);
        }
        if raw.offline {
            cli.offline = true;
        }
        if raw.block_private {
            cli.block_private = true;
        }
        if raw.block_metadata {
            cli.block_metadata = true;
        }
        if let Some(value) = raw.default_policy {
            cli.default_policy = value;
        }
        if !raw.allow_cidrs.is_empty() {
            cli.allow_cidrs = raw.allow_cidrs;
        }
        if !raw.deny_cidrs.is_empty() {
            cli.deny_cidrs = raw.deny_cidrs;
        }
        if raw.proxy_only {
            cli.proxy_only = true;
        }
        if raw.fail_on_leak {
            cli.fail_on_leak = true;
        }
        if let Some(value) = raw.iface {
            cli.iface = Some(value);
        }
        if !raw.command.is_empty() {
            cli.command = raw.command;
        }

        cli
    }

    #[cfg(test)]
    fn parse_from<I, T>(itr: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::from_raw(RawCli::parse_from(itr)).unwrap()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxySpec {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for ProxySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let scheme = match self.scheme {
            ProxyScheme::Http => "http",
            ProxyScheme::Https => "https",
            ProxyScheme::Socks5 => "socks5",
        };
        write!(f, "{scheme}://{host}:{}", self.port)
    }
}

impl FromStr for ProxySpec {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (scheme, rest) = value.split_once("://").ok_or_else(|| {
            "proxy must be a URI like http://host:port or socks5://host:port".to_string()
        })?;

        if rest.is_empty() {
            return Err("proxy URI is missing host:port".to_string());
        }

        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err("proxy URI must not contain a path, query, or fragment".to_string());
        }

        let scheme = match scheme {
            "http" => ProxyScheme::Http,
            "https" => ProxyScheme::Https,
            "socks5" => ProxyScheme::Socks5,
            other => {
                return Err(format!(
                    "unsupported proxy scheme `{other}`; expected `http`, `https`, or `socks5`"
                ))
            }
        };

        let (host, port) = parse_host_port(rest)?;

        Ok(Self { scheme, host, port })
    }
}

fn parse_host_port(input: &str) -> std::result::Result<(String, u16), String> {
    if let Some(rest) = input.strip_prefix('[') {
        let (host, remainder) = rest
            .split_once(']')
            .ok_or_else(|| "invalid proxy URI host".to_string())?;
        let port = remainder
            .strip_prefix(':')
            .ok_or_else(|| "proxy URI must include a port".to_string())?
            .parse::<u16>()
            .map_err(|_| "proxy URI has an invalid port".to_string())?;
        return Ok((host.to_string(), port));
    }

    if input.matches(':').count() > 1 {
        return Err("IPv6 proxy hosts must be enclosed in `[` and `]`".to_string());
    }

    let (host, port) = input
        .rsplit_once(':')
        .ok_or_else(|| "proxy URI must include a port".to_string())?;

    if host.is_empty() {
        return Err("proxy URI is missing a host".to_string());
    }

    let port = port
        .parse::<u16>()
        .map_err(|_| "proxy URI has an invalid port".to_string())?;

    Ok((host.to_string(), port))
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProxyType {
    Http,
    Socks5,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyScheme {
    Http,
    Https,
    Socks5,
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum OutputView {
    Child,
    Egress,
    WireEgress,
    Both,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    #[default]
    Allow,
    Deny,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ReportFormat {
    #[default]
    Text,
    Markdown,
    Json,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum DoctorFormat {
    #[default]
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn make_cli() -> Cli {
        Cli {
            dump_profile: false,
            output: None,
            output_view: OutputView::Child,
            root: false,
            doctor: false,
            doctor_format: DoctorFormat::Text,
            report: None,
            report_format: ReportFormat::Text,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            hosts_file: None,
            proxy: None,
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            summary: false,
            flow_log: None,
            offline: false,
            block_private: false,
            block_metadata: false,
            default_policy: DefaultPolicy::Allow,
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            proxy_only: false,
            fail_on_leak: false,
            iface: None,
            command: vec!["curl".into()],
        }
    }

    #[test]
    fn parse_proxy_spec_accepts_bracketed_ipv6_hosts() {
        let parsed: ProxySpec = "socks5://[2001:db8::1]:1080".parse().unwrap();

        assert_eq!(parsed.scheme, ProxyScheme::Socks5);
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 1080);
    }

    #[test]
    fn parse_proxy_spec_rejects_ipv6_without_brackets() {
        let err = "http://2001:db8::1:8080".parse::<ProxySpec>().unwrap_err();
        assert!(err.contains("must be enclosed in `[` and `]`"));
    }

    #[test]
    fn parse_proxy_spec_accepts_https_scheme() {
        let parsed: ProxySpec = "https://proxy.example.com:443".parse().unwrap();
        assert_eq!(parsed.scheme, ProxyScheme::Https);
        assert_eq!(parsed.host, "proxy.example.com");
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn validate_requires_complete_proxy_credentials() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            network_backend: NetworkBackend::Rootful,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            proxy_user: Some("alice".into()),
            ..make_cli()
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn validate_rejects_proxy_insecure_for_non_https_proxy() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            network_backend: NetworkBackend::Rootful,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            proxy_insecure: true,
            ..make_cli()
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn validate_rejects_proxy_only_without_proxy() {
        let cli = Cli {
            proxy_only: true,
            ..make_cli()
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn validate_rejects_fail_on_leak_for_rootful_backend() {
        let cli = Cli {
            root: true,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            fail_on_leak: true,
            ..make_cli()
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn validate_rejects_flow_log_for_rootful_backend() {
        let cli = Cli {
            root: true,
            flow_log: Some(PathBuf::from("/tmp/childflow-flow.jsonl")),
            ..make_cli()
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn validate_allows_rootful_backend_without_output() {
        let cli = Cli {
            network_backend: NetworkBackend::Rootful,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_rejects_rootless_internal_iface() {
        let cli = Cli {
            iface: Some("eth0".into()),
            ..make_cli()
        };

        let err = cli.validate().unwrap_err();
        assert!(err.to_string().contains("rootless-internal"));
        assert!(err.to_string().contains("`--iface`"));
    }

    #[test]
    fn validate_allows_rootless_internal_relay_proxy() {
        let cli = Cli {
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootless_internal_proxy_insecure_for_https_proxy() {
        let cli = Cli {
            proxy: Some("https://proxy.example.com:443".parse().unwrap()),
            proxy_insecure: true,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootless_internal_output() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_rejects_missing_hosts_file() {
        let cli = Cli {
            hosts_file: Some(PathBuf::from("/definitely/missing/childflow.hosts")),
            ..make_cli()
        };

        let err = cli.validate().unwrap_err();
        assert!(err.to_string().contains("`--hosts-file`"));
    }

    #[test]
    fn validate_rejects_output_view_without_output_path() {
        let cli = Cli {
            output_view: OutputView::Egress,
            ..make_cli()
        };

        let err = cli.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("`--capture-point` requires `--capture`"));
    }

    #[test]
    fn validate_allows_rootless_egress_output_view() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            output_view: OutputView::Both,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootful_egress_output_view() {
        let cli = Cli {
            root: true,
            output: Some(PathBuf::from("out.pcapng")),
            output_view: OutputView::Egress,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootless_wire_egress_output_view() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            output_view: OutputView::WireEgress,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn selected_backend_uses_root_flag() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            root: true,
            ..make_cli()
        };

        assert_eq!(cli.selected_backend(), NetworkBackend::Rootful);
    }

    #[test]
    fn validate_root_flag_overrides_hidden_backend_and_allows_rootful_without_output() {
        let cli = Cli {
            root: true,
            network_backend: NetworkBackend::RootlessInternal,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_root_flag_allows_iface_without_output() {
        let cli = Cli {
            root: true,
            iface: Some("eth0".into()),
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_hidden_rootful_backend_allows_iface_without_output() {
        let cli = Cli {
            network_backend: NetworkBackend::Rootful,
            iface: Some("eth0".into()),
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_rootful_backend_allows_https_proxy_insecure_when_output_is_present() {
        let cli = Cli {
            network_backend: NetworkBackend::Rootful,
            output: Some(PathBuf::from("out.pcapng")),
            proxy: Some("https://proxy.example.com:443".parse().unwrap()),
            proxy_insecure: true,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn parse_accepts_baseline_sandbox_flags() {
        let cli = Cli::parse_from([
            "childflow",
            "--offline",
            "--summary",
            "--block-private",
            "--block-metadata",
            "--",
            "curl",
            "https://example.com",
        ]);

        assert!(cli.summary);
        assert!(cli.offline);
        assert!(cli.block_private);
        assert!(cli.block_metadata);
        assert_eq!(cli.command, vec!["curl", "https://example.com"]);
    }

    #[test]
    fn parse_accepts_dump_profile_flag() {
        let cli = Cli::parse_from(["childflow", "--dump-profile"]);

        assert!(cli.dump_profile);
        assert!(cli.command.is_empty());
    }

    #[test]
    fn parse_accepts_report_flag() {
        let cli = Cli::parse_from(["childflow", "--report", "/tmp/childflow-flow.jsonl"]);

        assert_eq!(cli.report, Some(PathBuf::from("/tmp/childflow-flow.jsonl")));
        assert_eq!(cli.report_format, ReportFormat::Text);
        assert!(cli.command.is_empty());
    }

    #[test]
    fn parse_accepts_report_format_flag() {
        let cli = Cli::parse_from([
            "childflow",
            "--report",
            "/tmp/childflow-flow.jsonl",
            "--report-format",
            "markdown",
        ]);

        assert_eq!(cli.report, Some(PathBuf::from("/tmp/childflow-flow.jsonl")));
        assert_eq!(cli.report_format, ReportFormat::Markdown);
    }

    #[test]
    fn parse_accepts_report_json_format_flag() {
        let cli = Cli::parse_from([
            "childflow",
            "--report",
            "/tmp/childflow-flow.jsonl",
            "--report-format",
            "json",
        ]);

        assert_eq!(cli.report, Some(PathBuf::from("/tmp/childflow-flow.jsonl")));
        assert_eq!(cli.report_format, ReportFormat::Json);
    }

    #[test]
    fn parse_accepts_cidr_policy_flags() {
        let cli = Cli::parse_from([
            "childflow",
            "--default-policy",
            "deny",
            "--allow-cidr",
            "192.0.2.0/24",
            "--allow-cidr",
            "2001:db8::/32",
            "--deny-cidr",
            "198.51.100.0/24",
            "--",
            "curl",
        ]);

        assert_eq!(cli.default_policy, DefaultPolicy::Deny);
        assert_eq!(cli.allow_cidrs.len(), 2);
        assert_eq!(cli.deny_cidrs.len(), 1);
    }

    #[test]
    fn parse_profile_supplies_command_and_relative_paths() {
        let temp_dir = unique_temp_profile_dir("cli-profile-relative");
        let profile_path = temp_dir.join("sandbox.toml");

        fs::write(
            &profile_path,
            r#"
capture = "captures/run.pcapng"
capture_point = "both"
hosts_file = "fixtures/hosts.override"
flow_log = "logs/flow.jsonl"
command = ["curl", "https://example.com"]
"#,
        )
        .unwrap();

        let cli = Cli::parse_from(["childflow", "--profile", profile_path.to_str().unwrap()]);

        assert_eq!(
            cli.output,
            Some(temp_dir.join("captures").join("run.pcapng"))
        );
        assert_eq!(cli.output_view, OutputView::Both);
        assert_eq!(
            cli.hosts_file,
            Some(temp_dir.join("fixtures").join("hosts.override"))
        );
        assert_eq!(cli.flow_log, Some(temp_dir.join("logs").join("flow.jsonl")));
        assert_eq!(cli.command, vec!["curl", "https://example.com"]);

        let _ = fs::remove_file(&profile_path);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn parse_cli_overrides_profile_values() {
        let temp_dir = unique_temp_profile_dir("cli-profile-override");
        let profile_path = temp_dir.join("sandbox.toml");

        fs::write(
            &profile_path,
            r#"
summary = true
default_policy = "deny"
allow_cidrs = ["203.0.113.10/32"]
command = ["curl", "https://example.com"]
"#,
        )
        .unwrap();

        let cli = Cli::parse_from([
            "childflow",
            "--profile",
            profile_path.to_str().unwrap(),
            "--default-policy",
            "allow",
            "--deny-cidr",
            "198.51.100.0/24",
            "--",
            "ping",
            "-c",
            "1",
            "1.1.1.1",
        ]);

        assert!(cli.summary);
        assert_eq!(cli.default_policy, DefaultPolicy::Allow);
        assert_eq!(cli.allow_cidrs.len(), 1);
        assert_eq!(cli.deny_cidrs.len(), 1);
        assert_eq!(cli.command, vec!["ping", "-c", "1", "1.1.1.1"]);

        let _ = fs::remove_file(&profile_path);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn doctor_flag_allows_empty_command() {
        let cli = Cli {
            doctor: true,
            command: Vec::new(),
            ..make_cli()
        };

        cli.validate().unwrap();
        assert_eq!(cli.selected_backend(), NetworkBackend::RootlessInternal);
    }

    #[test]
    fn report_flag_allows_empty_command() {
        let cli = Cli {
            report: Some(PathBuf::from("/tmp/childflow-flow.jsonl")),
            command: Vec::new(),
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn report_flag_rejects_command() {
        let cli = Cli {
            report: Some(PathBuf::from("/tmp/childflow-flow.jsonl")),
            ..make_cli()
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn parse_accepts_doctor_format_flag() {
        let cli = Cli::parse_from(["childflow", "--doctor", "--doctor-format", "json"]);

        assert!(cli.doctor);
        assert_eq!(cli.doctor_format, DoctorFormat::Json);
        assert!(cli.command.is_empty());
    }

    fn unique_temp_profile_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
