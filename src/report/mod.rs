// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod aggregate;
mod render;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::cli::{Cli, ReportFormat};

pub fn run(cli: &Cli) -> Result<i32> {
    let path = cli
        .report
        .as_ref()
        .context("`--report` requires a flow log path")?;
    let report = FlowLogReport::from_path(path)?;
    let rendered = match cli.report_format {
        ReportFormat::Text => report.render_text(path),
        ReportFormat::Markdown => report.render_markdown(path),
        ReportFormat::Json => report.render_json(path)?,
    };
    print!("{rendered}");
    Ok(0)
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize)]
pub struct FlowLogReport {
    pub total: usize,
    pub dns_query: usize,
    pub dns_answer: usize,
    pub connect_attempt: usize,
    pub connect_result: usize,
    pub policy_violation: usize,
    pub flow_end: usize,
    pub runtime_failure: usize,
    pub unknown_event: usize,
    pub schema_versions: BTreeSet<u32>,
    pub protocol_counts: BTreeMap<String, usize>,
    pub dns_name_counts: BTreeMap<String, DnsNameStats>,
    pub policy_reason_counts: BTreeMap<String, usize>,
    pub policy_control_counts: BTreeMap<String, usize>,
    pub policy_matched_domain_counts: BTreeMap<String, usize>,
    pub(crate) policy_matched_domains_by_ip: BTreeMap<String, BTreeMap<String, usize>>,
    pub connect_error_counts: BTreeMap<String, usize>,
    pub runtime_failure_reason_counts: BTreeMap<String, usize>,
    pub runtime_failure_phase_counts: BTreeMap<String, usize>,
    pub connection_targets: BTreeMap<String, ConnectionTargetStats>,
    pub proxied_connect_attempts: usize,
    pub direct_connect_attempts: usize,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize)]
pub struct ConnectionTargetStats {
    pub connect_attempts: usize,
    pub connect_ok: usize,
    pub connect_error: usize,
    pub flow_end: usize,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize)]
pub struct DnsNameStats {
    pub queries: usize,
    pub answers: usize,
    pub answer_ips: BTreeSet<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsTargetCorrelation {
    pub qname: String,
    pub queries: usize,
    pub answers: usize,
    pub answer_ips: Vec<String>,
    pub targets: Vec<DnsCorrelatedTarget>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsPolicyCorrelation {
    pub qname: String,
    pub queries: usize,
    pub answers: usize,
    pub answer_ips: Vec<String>,
    pub matched_domains: Vec<RankedStringCount>,
    pub targets: Vec<DnsCorrelatedTarget>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsPolicyRow {
    pub qname: String,
    pub queries: usize,
    pub answers: usize,
    pub answer_ips: Vec<String>,
    pub target: Option<String>,
    pub target_ip: Option<String>,
    pub connect_attempts: usize,
    pub connect_ok: usize,
    pub connect_error: usize,
    pub flow_end: usize,
    pub matched_domains: Vec<RankedStringCount>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsCorrelatedTarget {
    pub target: String,
    pub connect_attempts: usize,
    pub connect_ok: usize,
    pub connect_error: usize,
    pub flow_end: usize,
    pub matched_domains: Vec<RankedStringCount>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RankedStringCount {
    pub key: String,
    pub count: usize,
}

pub(crate) fn top_count_entries(
    counts: &BTreeMap<String, usize>,
    limit: usize,
) -> Vec<(&str, usize)> {
    let mut entries = counts
        .iter()
        .map(|(name, count)| (name.as_str(), *count))
        .collect::<Vec<_>>();
    entries.sort_by(|(left_name, left_count), (right_name, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_name.cmp(right_name))
    });
    entries.truncate(limit);
    entries
}

pub(crate) fn target_ip_string(target: &str) -> Option<String> {
    SocketAddr::from_str(target)
        .ok()
        .map(|addr| addr.ip().to_string())
}

pub(crate) fn render_ranked_string_counts(entries: &[RankedStringCount]) -> String {
    if entries.is_empty() {
        "none".to_string()
    } else {
        entries
            .iter()
            .map(|entry| format!("{}={}", entry.key, entry.count))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
