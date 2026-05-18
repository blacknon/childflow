use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::observability::report as observability_report;

use super::super::{top_count_entries, FlowLogReport};

mod sections;

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

        sections::insert_event_counts(self, &mut root);
        sections::insert_protocols(self, &mut root);
        sections::insert_dns_sections(self, &mut root);
        sections::insert_proxy_usage(self, &mut root);
        sections::insert_policy_sections(self, &mut root);
        sections::insert_runtime_sections(self, &mut root);
        sections::insert_top_connection_targets(self, &mut root);

        Value::Object(root)
    }
}
