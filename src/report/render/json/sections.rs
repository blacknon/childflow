use serde_json::{Map, Value};

use crate::observability::report as observability_report;

use super::super::super::FlowLogReport;
use super::{json_count_entries, JsonConnectionTarget, JsonCountEntry, JsonDnsName};

pub(super) fn insert_event_counts(report: &FlowLogReport, root: &mut Map<String, Value>) {
    root.insert(
        observability_report::EVENT_COUNTS.to_string(),
        serde_json::json!({
            "total": report.total,
            "dns_query": report.dns_query,
            "dns_answer": report.dns_answer,
            "connect_attempt": report.connect_attempt,
            "connect_result": report.connect_result,
            "policy_violation": report.policy_violation,
            "flow_end": report.flow_end,
            "runtime_failure": report.runtime_failure,
            "unknown_event": report.unknown_event
        }),
    );
}

pub(super) fn insert_protocols(report: &FlowLogReport, root: &mut Map<String, Value>) {
    root.insert(
        observability_report::PROTOCOLS.to_string(),
        serde_json::to_value(&report.protocol_counts).expect("protocol_counts should serialize"),
    );
    root.insert(
        observability_report::SORTED_PROTOCOLS.to_string(),
        serde_json::to_value(json_count_entries(&report.protocol_counts))
            .expect("sorted_protocols should serialize"),
    );
}

pub(super) fn insert_dns_sections(report: &FlowLogReport, root: &mut Map<String, Value>) {
    root.insert(
        observability_report::TOP_DNS_NAMES.to_string(),
        serde_json::to_value(
            report
                .top_dns_names(10)
                .into_iter()
                .map(|(qname, stats)| JsonDnsName {
                    qname,
                    queries: stats.queries,
                    answers: stats.answers,
                    answer_ips: stats.answer_ips.iter().cloned().collect::<Vec<_>>(),
                })
                .collect::<Vec<_>>(),
        )
        .expect("top_dns_names should serialize"),
    );
    root.insert(
        observability_report::DNS_TARGET_CORRELATIONS.to_string(),
        serde_json::to_value(report.top_dns_target_correlations(10, 3))
            .expect("dns_target_correlations should serialize"),
    );
    root.insert(
        observability_report::DNS_POLICY_CORRELATIONS.to_string(),
        serde_json::to_value(report.top_dns_policy_correlations(10, 3))
            .expect("dns_policy_correlations should serialize"),
    );
    root.insert(
        observability_report::DNS_POLICY_ROWS.to_string(),
        serde_json::to_value(report.top_dns_policy_rows(10, 3))
            .expect("dns_policy_rows should serialize"),
    );
}

pub(super) fn insert_proxy_usage(report: &FlowLogReport, root: &mut Map<String, Value>) {
    root.insert(
        observability_report::PROXY_USAGE.to_string(),
        serde_json::json!({
            "proxied_connect_attempts": report.proxied_connect_attempts,
            "direct_connect_attempts": report.direct_connect_attempts
        }),
    );
}

pub(super) fn insert_policy_sections(report: &FlowLogReport, root: &mut Map<String, Value>) {
    root.insert(
        observability_report::POLICY_VIOLATIONS.to_string(),
        serde_json::to_value(&report.policy_reason_counts)
            .expect("policy_violations should serialize"),
    );
    root.insert(
        observability_report::POLICY_CONTROLS.to_string(),
        serde_json::to_value(&report.policy_control_counts)
            .expect("policy_controls should serialize"),
    );
    root.insert(
        observability_report::SORTED_POLICY_VIOLATIONS.to_string(),
        serde_json::to_value(json_count_entries(&report.policy_reason_counts))
            .expect("sorted_policy_violations should serialize"),
    );
    root.insert(
        observability_report::SORTED_POLICY_CONTROLS.to_string(),
        serde_json::to_value(json_count_entries(&report.policy_control_counts))
            .expect("sorted_policy_controls should serialize"),
    );
    root.insert(
        observability_report::POLICY_MATCHED_DOMAINS.to_string(),
        serde_json::to_value(&report.policy_matched_domain_counts)
            .expect("policy_matched_domains should serialize"),
    );
    root.insert(
        observability_report::SORTED_POLICY_MATCHED_DOMAINS.to_string(),
        serde_json::to_value(json_count_entries(&report.policy_matched_domain_counts))
            .expect("sorted_policy_matched_domains should serialize"),
    );
}

pub(super) fn insert_runtime_sections(report: &FlowLogReport, root: &mut Map<String, Value>) {
    root.insert(
        observability_report::CONNECT_ERRORS.to_string(),
        serde_json::to_value(&report.connect_error_counts)
            .expect("connect_errors should serialize"),
    );
    root.insert(
        observability_report::SORTED_CONNECT_ERRORS.to_string(),
        serde_json::to_value(json_count_entries(&report.connect_error_counts))
            .expect("sorted_connect_errors should serialize"),
    );
    root.insert(
        observability_report::RUNTIME_FAILURES.to_string(),
        serde_json::to_value(&report.runtime_failure_reason_counts)
            .expect("runtime_failures should serialize"),
    );
    root.insert(
        observability_report::SORTED_RUNTIME_FAILURES.to_string(),
        serde_json::to_value(json_count_entries(&report.runtime_failure_reason_counts))
            .expect("sorted_runtime_failures should serialize"),
    );
    root.insert(
        observability_report::RUNTIME_FAILURE_PHASES.to_string(),
        serde_json::to_value(&report.runtime_failure_phase_counts)
            .expect("runtime_failure_phases should serialize"),
    );
    root.insert(
        observability_report::SORTED_RUNTIME_FAILURE_PHASES.to_string(),
        serde_json::to_value(json_count_entries(&report.runtime_failure_phase_counts))
            .expect("sorted_runtime_failure_phases should serialize"),
    );
}

pub(super) fn insert_top_connection_targets(report: &FlowLogReport, root: &mut Map<String, Value>) {
    root.insert(
        observability_report::TOP_CONNECTION_TARGETS.to_string(),
        serde_json::to_value(
            report
                .top_connection_targets(10)
                .into_iter()
                .map(|(target, stats)| JsonConnectionTarget {
                    target,
                    connect_attempts: stats.connect_attempts,
                    connect_ok: stats.connect_ok,
                    connect_error: stats.connect_error,
                    flow_end: stats.flow_end,
                    dns_names: report.dns_names_for_target(target),
                    matched_domains: report
                        .matched_domain_entries_for_target(target, usize::MAX)
                        .into_iter()
                        .map(|(key, count)| JsonCountEntry { key, count })
                        .collect(),
                })
                .collect::<Vec<_>>(),
        )
        .expect("top_connection_targets should serialize"),
    );
}
