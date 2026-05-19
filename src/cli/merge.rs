use crate::network::NetworkBackend;
use crate::profile::Profile;

use super::{Cli, DefaultPolicy, DoctorFormat, OutputView, RawCli, ReportFormat, SummaryFormat};

pub(super) fn merge_cli(raw: RawCli, profile: Option<&Profile>) -> Cli {
    let mut cli = Cli {
        dump_profile: raw.dump_profile,
        output: profile.and_then(|value| value.capture.clone()),
        output_view: profile
            .and_then(|value| value.capture_point)
            .unwrap_or(OutputView::Child),
        root: false,
        doctor: raw.doctor,
        doctor_format: profile
            .and_then(|value| value.doctor_format)
            .unwrap_or(DoctorFormat::Text),
        report: raw.report,
        report_format: profile
            .and_then(|value| value.report_format)
            .unwrap_or(ReportFormat::Text),
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
        summary_format: profile
            .and_then(|value| value.summary_format)
            .unwrap_or(SummaryFormat::Text),
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
        allow_domains_exact: profile
            .and_then(|value| value.allow_domains_exact.clone())
            .unwrap_or_default(),
        allow_domains: profile
            .and_then(|value| value.allow_domains.clone())
            .unwrap_or_default(),
        deny_domains_exact: profile
            .and_then(|value| value.deny_domains_exact.clone())
            .unwrap_or_default(),
        deny_domains: profile
            .and_then(|value| value.deny_domains.clone())
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
    if let Some(value) = raw.summary_format {
        cli.summary_format = value;
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
    if !raw.allow_domains_exact.is_empty() {
        cli.allow_domains_exact = raw.allow_domains_exact;
    }
    if !raw.allow_domains.is_empty() {
        cli.allow_domains = raw.allow_domains;
    }
    if !raw.deny_domains_exact.is_empty() {
        cli.deny_domains_exact = raw.deny_domains_exact;
    }
    if !raw.deny_domains.is_empty() {
        cli.deny_domains = raw.deny_domains;
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
