// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod merge;
mod types;
mod validate;

#[cfg(test)]
mod tests;

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use ipnetwork::IpNetwork;

use crate::network::NetworkBackend;
use crate::profile::Profile;

use self::merge::merge_cli;
use self::types::parse_domain_rule;
pub use self::types::{
    DefaultPolicy, DoctorFormat, OutputView, ProxyScheme, ProxySpec, ProxyType, ReportFormat,
    SummaryFormat,
};
use self::validate::validate_cli;

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

    /// Select the output format for `--summary`.
    #[arg(long = "summary-format", value_enum)]
    summary_format: Option<SummaryFormat>,

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

    /// Allow outbound destinations that were resolved from this DNS name or one of its subdomains.
    #[arg(long = "allow-domain", value_parser = parse_domain_rule)]
    allow_domains: Vec<String>,

    /// Allow outbound destinations that were resolved from exactly this DNS name.
    #[arg(long = "allow-domain-exact", value_parser = parse_domain_rule)]
    allow_domains_exact: Vec<String>,

    /// Deny outbound destinations that were resolved from this DNS name or one of its subdomains.
    #[arg(long = "deny-domain", value_parser = parse_domain_rule)]
    deny_domains: Vec<String>,

    /// Deny outbound destinations that were resolved from exactly this DNS name.
    #[arg(long = "deny-domain-exact", value_parser = parse_domain_rule)]
    deny_domains_exact: Vec<String>,

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
    pub summary_format: SummaryFormat,
    pub flow_log: Option<PathBuf>,
    pub offline: bool,
    pub block_private: bool,
    pub block_metadata: bool,
    pub default_policy: DefaultPolicy,
    pub allow_cidrs: Vec<IpNetwork>,
    pub deny_cidrs: Vec<IpNetwork>,
    pub allow_domains_exact: Vec<String>,
    pub allow_domains: Vec<String>,
    pub deny_domains_exact: Vec<String>,
    pub deny_domains: Vec<String>,
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
        validate_cli(self)
    }

    fn from_raw(raw: RawCli) -> Result<Self> {
        let profile = raw.profile.as_deref().map(Profile::load).transpose()?;
        Ok(merge_cli(raw, profile.as_ref()))
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
