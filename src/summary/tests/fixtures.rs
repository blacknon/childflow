use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::{Cli, DefaultPolicy, DoctorFormat, OutputView, SummaryFormat};
use crate::network::NetworkBackend;

pub(super) fn make_cli() -> Cli {
    Cli {
        dump_profile: false,
        output: None,
        output_view: OutputView::Child,
        root: false,
        doctor: false,
        doctor_format: DoctorFormat::Text,
        report: None,
        report_format: crate::cli::ReportFormat::Text,
        network_backend: NetworkBackend::RootlessInternal,
        dns: None,
        hosts_file: None,
        proxy: None,
        proxy_user: None,
        proxy_password: None,
        proxy_insecure: false,
        summary: true,
        summary_format: SummaryFormat::Text,
        flow_log: None,
        offline: false,
        block_private: false,
        block_metadata: false,
        default_policy: DefaultPolicy::Allow,
        allow_cidrs: Vec::new(),
        deny_cidrs: Vec::new(),
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
        deny_domains: Vec::new(),
        proxy_only: false,
        fail_on_leak: false,
        iface: None,
        command: vec!["curl".into(), "https://example.com".into()],
    }
}

pub(super) fn unique_temp_flow_log_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "childflow-{prefix}-{}-{nanos}.jsonl",
        std::process::id()
    ))
}
