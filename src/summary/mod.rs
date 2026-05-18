// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod json;
mod text;

#[cfg(test)]
mod tests;

use crate::capture::{derive_output_paths, effective_view_name, requested_view_name};
use crate::cli::{Cli, OutputView, SummaryFormat};
use crate::report::{DnsCorrelatedTarget, FlowLogReport, RankedStringCount};
use crate::sandbox::SandboxPolicy;
use crate::util::render_command;
use serde::Serialize;

pub fn print_run_summary(cli: &Cli, exit_code: i32) {
    let rendered = match cli.summary_format {
        SummaryFormat::Text => text::render_run_summary(cli, exit_code),
        SummaryFormat::Json => json::render_run_summary_json(cli, exit_code),
    };
    eprint!("{rendered}");
}

fn backend_name(cli: &Cli) -> &'static str {
    match cli.selected_backend() {
        crate::network::NetworkBackend::Rootful => "rootful",
        crate::network::NetworkBackend::RootlessInternal => "rootless-internal",
    }
}

fn summary_command(cli: &Cli) -> String {
    cli.command
        .split_first()
        .map(|(program, args)| render_command(program, args))
        .unwrap_or_else(|| "<none>".to_string())
}

fn summary_controls(cli: &Cli) -> Vec<String> {
    SandboxPolicy::from_cli(cli).active_controls()
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

fn with_flow_log_report(cli: &Cli, render: impl FnOnce(&FlowLogReport) -> String) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => render(&report),
        Err(_) => "unavailable".to_string(),
    }
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
            policy_controls: Vec::new(),
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
            policy_controls: count_entries_to_json(report.policy_control_entries(3)),
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
            policy_controls: Vec::new(),
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

fn ranked_counts_to_json(entries: Vec<RankedStringCount>) -> Vec<SummaryCountEntry> {
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
    policy_controls: Vec<SummaryCountEntry>,
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
    targets: Vec<DnsCorrelatedTarget>,
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
    targets: Vec<DnsCorrelatedTarget>,
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
