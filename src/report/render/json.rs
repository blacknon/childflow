use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::observability::report as observability_report;

use super::super::{top_count_entries, FlowLogReport};

#[derive(Debug, Serialize)]
struct JsonConnectionTarget<'a> {
    target: &'a str,
    connect_attempts: usize,
    connect_ok: usize,
    connect_error: usize,
    flow_end: usize,
    dns_names: Vec<String>,
    matched_domains: Vec<JsonCountEntry<'a>>,
}

#[derive(Debug, Serialize)]
struct JsonDnsName<'a> {
    qname: &'a str,
    queries: usize,
    answers: usize,
    answer_ips: Vec<String>,
}

#[derive(Debug, Serialize)]
struct JsonCountEntry<'a> {
    key: &'a str,
    count: usize,
}

fn json_count_entries<'a>(counts: &'a BTreeMap<String, usize>) -> Vec<JsonCountEntry<'a>> {
    top_count_entries(counts, usize::MAX)
        .into_iter()
        .map(|(key, count)| JsonCountEntry { key, count })
        .collect()
}

impl FlowLogReport {
    pub fn render_json(&self, path: &Path) -> Result<String> {
        serde_json::to_string_pretty(&self.json_value(path))
            .context("failed to render flow log report as JSON")
    }

    fn json_value(&self, path: &Path) -> Value {
        let mut root = Map::new();
        root.insert(
            observability_report::FLOW_LOG.to_string(),
            Value::String(path.display().to_string()),
        );
        root.insert(
            observability_report::SCHEMA_VERSIONS.to_string(),
            Value::Array(
                self.schema_versions
                    .iter()
                    .copied()
                    .map(|value| Value::from(value as u64))
                    .collect(),
            ),
        );
        root.insert(
            observability_report::EVENT_COUNTS.to_string(),
            serde_json::json!({
                "total": self.total,
                "dns_query": self.dns_query,
                "dns_answer": self.dns_answer,
                "connect_attempt": self.connect_attempt,
                "connect_result": self.connect_result,
                "policy_violation": self.policy_violation,
                "flow_end": self.flow_end,
                "runtime_failure": self.runtime_failure,
                "unknown_event": self.unknown_event
            }),
        );
        root.insert(
            observability_report::PROTOCOLS.to_string(),
            serde_json::to_value(&self.protocol_counts).expect("protocol_counts should serialize"),
        );
        root.insert(
            observability_report::SORTED_PROTOCOLS.to_string(),
            serde_json::to_value(json_count_entries(&self.protocol_counts))
                .expect("sorted_protocols should serialize"),
        );
        root.insert(
            observability_report::TOP_DNS_NAMES.to_string(),
            serde_json::to_value(
                self.top_dns_names(10)
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
            serde_json::to_value(self.top_dns_target_correlations(10, 3))
                .expect("dns_target_correlations should serialize"),
        );
        root.insert(
            observability_report::DNS_POLICY_CORRELATIONS.to_string(),
            serde_json::to_value(self.top_dns_policy_correlations(10, 3))
                .expect("dns_policy_correlations should serialize"),
        );
        root.insert(
            observability_report::DNS_POLICY_ROWS.to_string(),
            serde_json::to_value(self.top_dns_policy_rows(10, 3))
                .expect("dns_policy_rows should serialize"),
        );
        root.insert(
            observability_report::PROXY_USAGE.to_string(),
            serde_json::json!({
                "proxied_connect_attempts": self.proxied_connect_attempts,
                "direct_connect_attempts": self.direct_connect_attempts
            }),
        );
        root.insert(
            observability_report::POLICY_VIOLATIONS.to_string(),
            serde_json::to_value(&self.policy_reason_counts)
                .expect("policy_violations should serialize"),
        );
        root.insert(
            observability_report::POLICY_CONTROLS.to_string(),
            serde_json::to_value(&self.policy_control_counts)
                .expect("policy_controls should serialize"),
        );
        root.insert(
            observability_report::SORTED_POLICY_VIOLATIONS.to_string(),
            serde_json::to_value(json_count_entries(&self.policy_reason_counts))
                .expect("sorted_policy_violations should serialize"),
        );
        root.insert(
            observability_report::SORTED_POLICY_CONTROLS.to_string(),
            serde_json::to_value(json_count_entries(&self.policy_control_counts))
                .expect("sorted_policy_controls should serialize"),
        );
        root.insert(
            observability_report::POLICY_MATCHED_DOMAINS.to_string(),
            serde_json::to_value(&self.policy_matched_domain_counts)
                .expect("policy_matched_domains should serialize"),
        );
        root.insert(
            observability_report::SORTED_POLICY_MATCHED_DOMAINS.to_string(),
            serde_json::to_value(json_count_entries(&self.policy_matched_domain_counts))
                .expect("sorted_policy_matched_domains should serialize"),
        );
        root.insert(
            observability_report::CONNECT_ERRORS.to_string(),
            serde_json::to_value(&self.connect_error_counts)
                .expect("connect_errors should serialize"),
        );
        root.insert(
            observability_report::SORTED_CONNECT_ERRORS.to_string(),
            serde_json::to_value(json_count_entries(&self.connect_error_counts))
                .expect("sorted_connect_errors should serialize"),
        );
        root.insert(
            observability_report::RUNTIME_FAILURES.to_string(),
            serde_json::to_value(&self.runtime_failure_reason_counts)
                .expect("runtime_failures should serialize"),
        );
        root.insert(
            observability_report::SORTED_RUNTIME_FAILURES.to_string(),
            serde_json::to_value(json_count_entries(&self.runtime_failure_reason_counts))
                .expect("sorted_runtime_failures should serialize"),
        );
        root.insert(
            observability_report::RUNTIME_FAILURE_PHASES.to_string(),
            serde_json::to_value(&self.runtime_failure_phase_counts)
                .expect("runtime_failure_phases should serialize"),
        );
        root.insert(
            observability_report::SORTED_RUNTIME_FAILURE_PHASES.to_string(),
            serde_json::to_value(json_count_entries(&self.runtime_failure_phase_counts))
                .expect("sorted_runtime_failure_phases should serialize"),
        );
        root.insert(
            observability_report::TOP_CONNECTION_TARGETS.to_string(),
            serde_json::to_value(
                self.top_connection_targets(10)
                    .into_iter()
                    .map(|(target, stats)| JsonConnectionTarget {
                        target,
                        connect_attempts: stats.connect_attempts,
                        connect_ok: stats.connect_ok,
                        connect_error: stats.connect_error,
                        flow_end: stats.flow_end,
                        dns_names: self.dns_names_for_target(target),
                        matched_domains: self
                            .matched_domain_entries_for_target(target, usize::MAX)
                            .into_iter()
                            .map(|(key, count)| JsonCountEntry { key, count })
                            .collect(),
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("top_connection_targets should serialize"),
        );

        Value::Object(root)
    }
}
