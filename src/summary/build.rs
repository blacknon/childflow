use crate::cli::{Cli, OutputView};
use crate::report::{DnsCorrelatedTarget, FlowLogReport, RankedStringCount};

use super::{
    SummaryCaptureReport, SummaryCountEntry, SummaryDnsPolicyRow, SummaryEventCounts,
    SummaryFlowLogReport, SummaryTopDnsName, SummaryTopDnsPolicyCorrelation, SummaryTopTarget,
};

pub(super) fn build_capture_summary(cli: &Cli) -> SummaryCaptureReport {
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

    let requested = crate::capture::requested_view_name(cli.output_view).to_string();
    let effective = crate::capture::effective_view_name(cli.output_view).to_string();

    match cli.output_view {
        OutputView::Both => match crate::capture::derive_output_paths(output, cli.output_view) {
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

pub(super) fn build_flow_log_summary(cli: &Cli) -> SummaryFlowLogReport {
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

pub(super) fn count_entries_to_json(entries: Vec<(&str, usize)>) -> Vec<SummaryCountEntry> {
    entries
        .into_iter()
        .map(|(key, count)| SummaryCountEntry {
            key: key.to_string(),
            count,
        })
        .collect()
}

pub(super) fn ranked_counts_to_json(entries: Vec<RankedStringCount>) -> Vec<SummaryCountEntry> {
    entries
        .into_iter()
        .map(|entry| SummaryCountEntry {
            key: entry.key,
            count: entry.count,
        })
        .collect()
}

#[allow(dead_code)]
fn _keep_types_visible(_: DnsCorrelatedTarget) {}
