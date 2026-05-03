// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use crate::capture::{derive_output_paths, effective_view_name, requested_view_name};
use crate::cli::{Cli, OutputView, SummaryFormat};
use crate::observability::summary as observability_summary;
use crate::report::FlowLogReport;
use crate::sandbox::SandboxPolicy;
use crate::util::render_command;
use serde::Serialize;

pub fn print_run_summary(cli: &Cli, exit_code: i32) {
    let rendered = match cli.summary_format {
        SummaryFormat::Text => render_run_summary(cli, exit_code),
        SummaryFormat::Json => render_run_summary_json(cli, exit_code),
    };
    eprint!("{rendered}");
}

fn render_run_summary(cli: &Cli, exit_code: i32) -> String {
    let sandbox_policy = SandboxPolicy::from_cli(cli);
    let command = cli
        .command
        .split_first()
        .map(|(program, args)| render_command(program, args))
        .unwrap_or_else(|| "<none>".to_string());

    format!(
        "childflow summary\nbackend: {}\ncommand: {command}\nsandbox controls: {}\ncapture: {}\nflow-log: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\nexit: {exit_code}\n",
        backend_name(cli),
        format_controls(&sandbox_policy.active_controls()),
        format_capture(cli),
        format_flow_log(cli),
        observability_summary::FLOW_LOG_EVENTS,
        format_flow_log_events(cli),
        observability_summary::FLOW_LOG_DNS_NAMES,
        format_flow_log_dns_names(cli),
        observability_summary::FLOW_LOG_DNS_POLICY_ROWS,
        format_flow_log_dns_policy_rows(cli),
        observability_summary::FLOW_LOG_TOP_DNS_POLICY_CORRELATION,
        format_flow_log_top_dns_policy_correlation(cli),
        observability_summary::FLOW_LOG_TOP_TARGET,
        format_flow_log_top_target(cli),
        observability_summary::FLOW_LOG_POLICY_VIOLATIONS,
        format_flow_log_policy_violations(cli),
        observability_summary::FLOW_LOG_POLICY_MATCHED_DOMAINS,
        format_flow_log_policy_matched_domains(cli),
        observability_summary::FLOW_LOG_CONNECT_ERRORS,
        format_flow_log_connect_errors(cli),
        observability_summary::FLOW_LOG_RUNTIME_FAILURES,
        format_flow_log_runtime_failures(cli),
        observability_summary::FLOW_LOG_RUNTIME_FAILURE_PHASES,
        format_flow_log_runtime_failure_phases(cli)
    )
}

fn backend_name(cli: &Cli) -> &'static str {
    match cli.selected_backend() {
        crate::network::NetworkBackend::Rootful => "rootful",
        crate::network::NetworkBackend::RootlessInternal => "rootless-internal",
    }
}

fn format_controls(controls: &[String]) -> String {
    if controls.is_empty() {
        return "none".to_string();
    }
    controls.join(", ")
}

fn format_capture(cli: &Cli) -> String {
    let Some(output) = cli.output.as_ref() else {
        return "disabled".to_string();
    };

    let requested = requested_view_name(cli.output_view);
    let effective = effective_view_name(cli.output_view);

    match cli.output_view {
        OutputView::Both => match derive_output_paths(output, cli.output_view) {
            Ok((child, egress)) => {
                format!(
                    "requested={requested}, effective={effective}, child={}, egress={}",
                    child.display(),
                    egress.display()
                )
            }
            Err(_) => format!(
                "requested={requested}, effective={effective}, output={}",
                output.display()
            ),
        },
        _ => format!(
            "requested={requested}, effective={effective}, output={}",
            output.display()
        ),
    }
}

fn format_flow_log(cli: &Cli) -> String {
    cli.flow_log
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "disabled".to_string())
}

fn format_flow_log_events(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_event_counts_compact(),
        Err(_) => "unavailable".to_string(),
    }
}

fn format_flow_log_top_target(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_top_target_compact(),
        Err(_) => "unavailable".to_string(),
    }
}

fn format_flow_log_dns_names(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_top_dns_name_compact(),
        Err(_) => "unavailable".to_string(),
    }
}

fn format_flow_log_dns_policy_rows(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_dns_policy_rows_compact(2),
        Err(_) => "unavailable".to_string(),
    }
}

fn format_flow_log_top_dns_policy_correlation(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_top_dns_policy_correlation_compact(),
        Err(_) => "unavailable".to_string(),
    }
}

fn format_flow_log_connect_errors(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_connect_errors_compact(3),
        Err(_) => "unavailable".to_string(),
    }
}

fn format_flow_log_policy_violations(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_policy_violations_compact(3),
        Err(_) => "unavailable".to_string(),
    }
}

fn format_flow_log_policy_matched_domains(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_policy_matched_domains_compact(3),
        Err(_) => "unavailable".to_string(),
    }
}

fn format_flow_log_runtime_failures(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_runtime_failures_compact(3),
        Err(_) => "unavailable".to_string(),
    }
}

fn format_flow_log_runtime_failure_phases(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_runtime_failure_phases_compact(3),
        Err(_) => "unavailable".to_string(),
    }
}

fn render_run_summary_json(cli: &Cli, exit_code: i32) -> String {
    let sandbox_policy = SandboxPolicy::from_cli(cli);
    let command = cli
        .command
        .split_first()
        .map(|(program, args)| render_command(program, args))
        .unwrap_or_else(|| "<none>".to_string());

    let summary = SummaryJsonReport {
        backend: backend_name(cli).to_string(),
        command,
        exit_code,
        sandbox_controls: sandbox_policy.active_controls(),
        capture: build_capture_summary(cli),
        flow_log: build_flow_log_summary(cli),
    };

    serde_json::to_string_pretty(&summary).expect("summary JSON should serialize") + "\n"
}

fn build_capture_summary(cli: &Cli) -> SummaryCaptureReport {
    let Some(output) = cli.output.as_ref() else {
        return SummaryCaptureReport {
            status: "disabled".to_string(),
            requested: None,
            effective: None,
            output: None,
            child_output: None,
            egress_output: None,
        };
    };

    let requested = requested_view_name(cli.output_view).to_string();
    let effective = effective_view_name(cli.output_view).to_string();

    match cli.output_view {
        OutputView::Both => match derive_output_paths(output, cli.output_view) {
            Ok((child, egress)) => SummaryCaptureReport {
                status: "enabled".to_string(),
                requested: Some(requested),
                effective: Some(effective),
                output: None,
                child_output: Some(child.display().to_string()),
                egress_output: Some(egress.display().to_string()),
            },
            Err(_) => SummaryCaptureReport {
                status: "enabled".to_string(),
                requested: Some(requested),
                effective: Some(effective),
                output: Some(output.display().to_string()),
                child_output: None,
                egress_output: None,
            },
        },
        _ => SummaryCaptureReport {
            status: "enabled".to_string(),
            requested: Some(requested),
            effective: Some(effective),
            output: Some(output.display().to_string()),
            child_output: None,
            egress_output: None,
        },
    }
}

fn build_flow_log_summary(cli: &Cli) -> SummaryFlowLogReport {
    let Some(path) = cli.flow_log.as_ref() else {
        return SummaryFlowLogReport {
            status: "disabled".to_string(),
            path: None,
            event_counts: None,
            top_dns_name: None,
            dns_policy_rows: Vec::new(),
            top_dns_policy_correlation: None,
            top_target: None,
            policy_violations: Vec::new(),
            policy_matched_domains: Vec::new(),
            connect_errors: Vec::new(),
            runtime_failures: Vec::new(),
            runtime_failure_phases: Vec::new(),
        };
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => SummaryFlowLogReport {
            status: "available".to_string(),
            path: Some(path.display().to_string()),
            event_counts: Some(SummaryEventCounts {
                total: report.total,
                dns_query: report.dns_query,
                dns_answer: report.dns_answer,
                connect_attempt: report.connect_attempt,
                connect_result: report.connect_result,
                policy_violation: report.policy_violation,
                flow_end: report.flow_end,
                runtime_failure: report.runtime_failure,
                unknown_event: report.unknown_event,
            }),
            top_dns_name: report
                .top_dns_names(1)
                .into_iter()
                .next()
                .map(|(qname, stats)| SummaryTopDnsName {
                    qname: qname.to_string(),
                    queries: stats.queries,
                    answers: stats.answers,
                    answer_ips: stats.answer_ips.iter().cloned().collect(),
                    targets: report.correlated_targets_for_dns_name(qname, 3),
                }),
            top_dns_policy_correlation: report
                .top_dns_policy_correlations(1, 3)
                .into_iter()
                .next()
                .map(|correlation| SummaryTopDnsPolicyCorrelation {
                    qname: correlation.qname,
                    queries: correlation.queries,
                    answers: correlation.answers,
                    answer_ips: correlation.answer_ips,
                    matched_domains: ranked_counts_to_json(correlation.matched_domains),
                    targets: correlation.targets,
                }),
            dns_policy_rows: report
                .top_dns_policy_rows(3, 1)
                .into_iter()
                .map(|row| SummaryDnsPolicyRow {
                    qname: row.qname,
                    queries: row.queries,
                    answers: row.answers,
                    answer_ips: row.answer_ips,
                    target: row.target,
                    target_ip: row.target_ip,
                    connect_attempts: row.connect_attempts,
                    connect_ok: row.connect_ok,
                    connect_error: row.connect_error,
                    flow_end: row.flow_end,
                    matched_domains: ranked_counts_to_json(row.matched_domains),
                })
                .collect(),
            top_target: report.top_connection_targets(1).into_iter().next().map(
                |(target, stats)| SummaryTopTarget {
                    target: target.to_string(),
                    connect_attempts: stats.connect_attempts,
                    connect_ok: stats.connect_ok,
                    connect_error: stats.connect_error,
                    flow_end: stats.flow_end,
                    dns_names: report.dns_names_for_target(target),
                    matched_domains: count_entries_to_json(
                        report.matched_domain_entries_for_target(target, 3),
                    ),
                },
            ),
            policy_violations: count_entries_to_json(report.policy_violation_entries(3)),
            policy_matched_domains: count_entries_to_json(report.policy_matched_domain_entries(3)),
            connect_errors: count_entries_to_json(report.connect_error_entries(3)),
            runtime_failures: count_entries_to_json(report.runtime_failure_entries(3)),
            runtime_failure_phases: count_entries_to_json(report.runtime_failure_phase_entries(3)),
        },
        Err(_) => SummaryFlowLogReport {
            status: "unavailable".to_string(),
            path: Some(path.display().to_string()),
            event_counts: None,
            top_dns_name: None,
            dns_policy_rows: Vec::new(),
            top_dns_policy_correlation: None,
            top_target: None,
            policy_violations: Vec::new(),
            policy_matched_domains: Vec::new(),
            connect_errors: Vec::new(),
            runtime_failures: Vec::new(),
            runtime_failure_phases: Vec::new(),
        },
    }
}

fn count_entries_to_json(entries: Vec<(&str, usize)>) -> Vec<SummaryCountEntry> {
    entries
        .into_iter()
        .map(|(key, count)| SummaryCountEntry {
            key: key.to_string(),
            count,
        })
        .collect()
}

fn ranked_counts_to_json(entries: Vec<crate::report::RankedStringCount>) -> Vec<SummaryCountEntry> {
    entries
        .into_iter()
        .map(|entry| SummaryCountEntry {
            key: entry.key,
            count: entry.count,
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct SummaryJsonReport {
    backend: String,
    command: String,
    exit_code: i32,
    sandbox_controls: Vec<String>,
    capture: SummaryCaptureReport,
    flow_log: SummaryFlowLogReport,
}

#[derive(Debug, Serialize)]
struct SummaryCaptureReport {
    status: String,
    requested: Option<String>,
    effective: Option<String>,
    output: Option<String>,
    child_output: Option<String>,
    egress_output: Option<String>,
}

#[derive(Debug, Serialize)]
struct SummaryFlowLogReport {
    status: String,
    path: Option<String>,
    event_counts: Option<SummaryEventCounts>,
    top_dns_name: Option<SummaryTopDnsName>,
    dns_policy_rows: Vec<SummaryDnsPolicyRow>,
    top_dns_policy_correlation: Option<SummaryTopDnsPolicyCorrelation>,
    top_target: Option<SummaryTopTarget>,
    policy_violations: Vec<SummaryCountEntry>,
    policy_matched_domains: Vec<SummaryCountEntry>,
    connect_errors: Vec<SummaryCountEntry>,
    runtime_failures: Vec<SummaryCountEntry>,
    runtime_failure_phases: Vec<SummaryCountEntry>,
}

#[derive(Debug, Serialize)]
struct SummaryEventCounts {
    total: usize,
    dns_query: usize,
    dns_answer: usize,
    connect_attempt: usize,
    connect_result: usize,
    policy_violation: usize,
    flow_end: usize,
    runtime_failure: usize,
    unknown_event: usize,
}

#[derive(Debug, Serialize)]
struct SummaryTopDnsName {
    qname: String,
    queries: usize,
    answers: usize,
    answer_ips: Vec<String>,
    targets: Vec<crate::report::DnsCorrelatedTarget>,
}

#[derive(Debug, Serialize)]
struct SummaryDnsPolicyRow {
    qname: String,
    queries: usize,
    answers: usize,
    answer_ips: Vec<String>,
    target: Option<String>,
    target_ip: Option<String>,
    connect_attempts: usize,
    connect_ok: usize,
    connect_error: usize,
    flow_end: usize,
    matched_domains: Vec<SummaryCountEntry>,
}

#[derive(Debug, Serialize)]
struct SummaryTopDnsPolicyCorrelation {
    qname: String,
    queries: usize,
    answers: usize,
    answer_ips: Vec<String>,
    matched_domains: Vec<SummaryCountEntry>,
    targets: Vec<crate::report::DnsCorrelatedTarget>,
}

#[derive(Debug, Serialize)]
struct SummaryTopTarget {
    target: String,
    connect_attempts: usize,
    connect_ok: usize,
    connect_error: usize,
    flow_end: usize,
    dns_names: Vec<String>,
    matched_domains: Vec<SummaryCountEntry>,
}

#[derive(Debug, Serialize)]
struct SummaryCountEntry {
    key: String,
    count: usize,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::cli::{DefaultPolicy, DoctorFormat, ProxySpec};
    use crate::network::NetworkBackend;
    use serde_json::Value;

    fn make_cli() -> Cli {
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

    #[test]
    fn render_run_summary_lists_active_sandbox_controls() {
        let mut cli = make_cli();
        cli.offline = true;
        cli.block_metadata = true;

        let rendered = render_run_summary(&cli, 7);

        assert!(rendered.contains("backend: rootless-internal"));
        assert!(rendered.contains("sandbox controls: offline, block-metadata"));
        assert!(rendered.contains("capture: disabled"));
        assert!(rendered.contains("flow-log: disabled"));
        assert!(rendered.contains("flow-log events: disabled"));
        assert!(rendered.contains("flow-log dns names: disabled"));
        assert!(rendered.contains("flow-log dns policy rows: disabled"));
        assert!(rendered.contains("flow-log top dns policy correlation: disabled"));
        assert!(rendered.contains("flow-log top target: disabled"));
        assert!(rendered.contains("flow-log policy violations: disabled"));
        assert!(rendered.contains("flow-log policy matched domains: disabled"));
        assert!(rendered.contains("flow-log connect errors: disabled"));
        assert!(rendered.contains("flow-log runtime failures: disabled"));
        assert!(rendered.contains("flow-log runtime failure phases: disabled"));
        assert!(rendered.contains("exit: 7"));
    }

    #[test]
    fn render_run_summary_expands_both_capture_outputs() {
        let mut cli = make_cli();
        cli.root = true;
        cli.output = Some(PathBuf::from("/tmp/capture.pcapng"));
        cli.flow_log = Some(PathBuf::from("/tmp/flow.jsonl"));
        cli.output_view = OutputView::Both;
        cli.proxy = Some("http://127.0.0.1:8080".parse::<ProxySpec>().unwrap());

        let rendered = render_run_summary(&cli, 0);

        assert!(rendered.contains("backend: rootful"));
        assert!(rendered.contains(
            "capture: requested=both, effective=child+egress, child=/tmp/capture.child.pcapng, egress=/tmp/capture.egress.pcapng"
        ));
        assert!(rendered.contains("flow-log: /tmp/flow.jsonl"));
        assert!(rendered.contains("flow-log events: unavailable"));
        assert!(rendered.contains("flow-log dns names: unavailable"));
        assert!(rendered.contains("flow-log dns policy rows: unavailable"));
        assert!(rendered.contains("flow-log top dns policy correlation: unavailable"));
        assert!(rendered.contains("flow-log top target: unavailable"));
        assert!(rendered.contains("flow-log policy violations: unavailable"));
        assert!(rendered.contains("flow-log policy matched domains: unavailable"));
        assert!(rendered.contains("flow-log connect errors: unavailable"));
        assert!(rendered.contains("flow-log runtime failures: unavailable"));
        assert!(rendered.contains("flow-log runtime failure phases: unavailable"));
        assert!(rendered.contains("command: curl https://example.com"));
    }

    #[test]
    fn render_run_summary_lists_requested_and_effective_capture_views() {
        let mut cli = make_cli();
        cli.output = Some(PathBuf::from("/tmp/capture.pcapng"));
        cli.output_view = OutputView::WireEgress;

        let rendered = render_run_summary(&cli, 0);

        assert!(rendered.contains(
            "capture: requested=wire-egress, effective=wire-egress, output=/tmp/capture.pcapng"
        ));
    }

    #[test]
    fn render_run_summary_counts_flow_log_events() {
        let mut cli = make_cli();
        let flow_log_path = unique_temp_flow_log_path("summary-flow-log");
        fs::write(
            &flow_log_path,
            concat!(
                "{\"event\":\"dns_query\",\"qname\":\"example.com\",\"ts_ms\":0}\n",
                "{\"event\":\"dns_answer\",\"qname\":\"example.com\",\"answer_ips\":[\"93.184.216.34\"],\"ts_ms\":0}\n",
                "{\"event\":\"connect_attempt\",\"ts_ms\":1}\n",
                "{\"event\":\"connect_result\",\"status\":\"error\",\"error\":\"connection refused\",\"remote_addr\":\"93.184.216.34:443\",\"ts_ms\":2}\n",
                "{\"event\":\"policy_violation\",\"reason_code\":\"deny_cidr\",\"matched_domain\":\"blocked.test\",\"ts_ms\":3}\n",
                "{\"event\":\"flow_end\",\"remote_addr\":\"93.184.216.34:443\",\"ts_ms\":4}\n",
                "{\"event\":\"runtime_failure\",\"reason_code\":\"tap_create_blocked\",\"phase\":\"child_bootstrap\",\"detail\":\"tap create failed\",\"ts_ms\":5}\n"
            ),
        )
        .unwrap();
        cli.flow_log = Some(flow_log_path.clone());

        let rendered = render_run_summary(&cli, 0);

        assert!(rendered.contains("flow-log events: total=7"));
        assert!(rendered.contains("connect_attempt=1"));
        assert!(rendered.contains("connect_result=1"));
        assert!(rendered.contains("dns_query=1"));
        assert!(rendered.contains("dns_answer=1"));
        assert!(rendered.contains("policy_violation=1"));
        assert!(rendered.contains("flow_end=1"));
        assert!(rendered.contains("runtime_failure=1"));
        assert!(rendered.contains(
            "flow-log dns names: example.com (queries=1, answers=1, answer_ips=93.184.216.34, targets=93.184.216.34:443 (attempts=0, ok=0, error=1, flow_end=1, matched_domains=none))"
        ));
        assert!(rendered.contains(
            "flow-log dns policy rows: example.com -> 93.184.216.34:443 (answer_ips=93.184.216.34, matched_domains=none, attempts=0, ok=0, error=1, flow_end=1)"
        ));
        assert!(rendered.contains(
            "flow-log top dns policy correlation: example.com (answer_ips=93.184.216.34, matched_domains=none, targets=93.184.216.34:443 (attempts=0, ok=0, error=1, flow_end=1, matched_domains=none))"
        ));
        assert!(rendered.contains(
            "flow-log top target: 93.184.216.34:443 (attempts=0, ok=0, error=1, flow_end=1, dns_names=example.com, matched_domains=none)"
        ));
        assert!(rendered.contains("flow-log policy violations: deny_cidr=1"));
        assert!(rendered.contains("flow-log policy matched domains: blocked.test=1"));
        assert!(rendered.contains("flow-log connect errors: connection refused=1"));
        assert!(rendered.contains("flow-log runtime failures: tap_create_blocked=1"));
        assert!(rendered.contains("flow-log runtime failure phases: child_bootstrap=1"));

        let _ = fs::remove_file(flow_log_path);
    }

    #[test]
    fn render_run_summary_json_emits_machine_readable_summary() {
        let mut cli = make_cli();
        cli.summary_format = SummaryFormat::Json;
        cli.output = Some(PathBuf::from("/tmp/capture.pcapng"));
        cli.output_view = OutputView::WireEgress;

        let rendered = render_run_summary_json(&cli, 3);
        let value: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(value["backend"], "rootless-internal");
        assert_eq!(value["exit_code"], 3);
        assert_eq!(value["capture"]["status"], "enabled");
        assert_eq!(value["capture"]["requested"], "wire-egress");
        assert_eq!(value["capture"]["effective"], "wire-egress");
        assert_eq!(value["capture"]["output"], "/tmp/capture.pcapng");
        assert_eq!(value["flow_log"]["status"], "disabled");
        assert!(value["flow_log"]["top_dns_name"].is_null());
        assert!(value["flow_log"]["top_dns_policy_correlation"].is_null());
        assert_eq!(value["flow_log"]["dns_policy_rows"], serde_json::json!([]));
    }

    #[test]
    fn render_run_summary_json_includes_dns_policy_rows() {
        let mut cli = make_cli();
        cli.summary_format = SummaryFormat::Json;
        let flow_log_path = unique_temp_flow_log_path("summary-dns-policy-rows");
        fs::write(
            &flow_log_path,
            concat!(
                "{\"event\":\"dns_query\",\"qname\":\"example.com\",\"ts_ms\":0}\n",
                "{\"event\":\"dns_answer\",\"qname\":\"example.com\",\"answer_ips\":[\"93.184.216.34\"],\"ts_ms\":0}\n",
                "{\"event\":\"policy_violation\",\"reason_code\":\"deny_domain\",\"matched_domain\":\"blocked.test\",\"remote_ip\":\"93.184.216.34\",\"ts_ms\":1}\n"
            ),
        )
        .unwrap();
        cli.flow_log = Some(flow_log_path.clone());

        let rendered = render_run_summary_json(&cli, 2);
        let value: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(value["flow_log"]["status"], "available");
        assert_eq!(
            value["flow_log"]["dns_policy_rows"][0]["qname"],
            "example.com"
        );
        assert!(value["flow_log"]["dns_policy_rows"][0]["target"].is_null());
        assert_eq!(
            value["flow_log"]["dns_policy_rows"][0]["matched_domains"][0],
            serde_json::json!({"key":"blocked.test","count":1})
        );
        assert_eq!(
            value["flow_log"]["top_dns_policy_correlation"]["qname"],
            "example.com"
        );

        let _ = fs::remove_file(flow_log_path);
    }

    fn unique_temp_flow_log_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "childflow-{prefix}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }
}
