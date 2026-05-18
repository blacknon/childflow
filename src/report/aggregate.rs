use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{
    render_ranked_string_counts, target_ip_string, top_count_entries, ConnectionTargetStats,
    DnsCorrelatedTarget, DnsNameStats, DnsPolicyCorrelation, DnsPolicyRow, DnsTargetCorrelation,
    FlowLogReport, RankedStringCount,
};

#[derive(Debug, Deserialize)]
struct FlowLogLine {
    #[serde(default)]
    schema_version: Option<u32>,
    event: String,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    qname: Option<String>,
    #[serde(default)]
    answer_ips: Vec<String>,
    #[serde(default)]
    remote_addr: Option<String>,
    #[serde(default)]
    remote: Option<String>,
    #[serde(default)]
    remote_ip: Option<String>,
    #[serde(default)]
    via_proxy: Option<bool>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    control: Option<String>,
    #[serde(default)]
    matched_domain: Option<String>,
    #[serde(default)]
    phase: Option<String>,
}

impl FlowLogReport {
    pub fn from_path(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open flow log at {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut report = Self::default();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.with_context(|| {
                format!(
                    "failed to read line {} from {}",
                    line_no + 1,
                    path.display()
                )
            })?;
            let event: FlowLogLine = serde_json::from_str(&line).with_context(|| {
                format!(
                    "failed to parse flow log JSON on line {} from {}",
                    line_no + 1,
                    path.display()
                )
            })?;
            report.record(event);
        }

        Ok(report)
    }

    pub fn render_event_counts_compact(&self) -> String {
        format!(
            "total={}, dns_query={}, dns_answer={}, connect_attempt={}, connect_result={}, policy_violation={}, flow_end={}, runtime_failure={}, unknown_event={}",
            self.total,
            self.dns_query,
            self.dns_answer,
            self.connect_attempt,
            self.connect_result,
            self.policy_violation,
            self.flow_end,
            self.runtime_failure,
            self.unknown_event
        )
    }

    pub fn top_connection_targets(&self, limit: usize) -> Vec<(&str, &ConnectionTargetStats)> {
        let mut entries = self
            .connection_targets
            .iter()
            .map(|(target, stats)| (target.as_str(), stats))
            .collect::<Vec<_>>();
        entries.sort_by(|(left_target, left_stats), (right_target, right_stats)| {
            right_stats
                .connect_attempts
                .cmp(&left_stats.connect_attempts)
                .then_with(|| right_stats.connect_error.cmp(&left_stats.connect_error))
                .then_with(|| right_stats.connect_ok.cmp(&left_stats.connect_ok))
                .then_with(|| left_target.cmp(right_target))
        });
        entries.truncate(limit);
        entries
    }

    pub fn top_dns_names(&self, limit: usize) -> Vec<(&str, &DnsNameStats)> {
        let mut entries = self
            .dns_name_counts
            .iter()
            .map(|(qname, stats)| (qname.as_str(), stats))
            .collect::<Vec<_>>();
        entries.sort_by(|(left_name, left_stats), (right_name, right_stats)| {
            right_stats
                .queries
                .cmp(&left_stats.queries)
                .then_with(|| right_stats.answers.cmp(&left_stats.answers))
                .then_with(|| left_name.cmp(right_name))
        });
        entries.truncate(limit);
        entries
    }

    pub fn render_top_dns_name_compact(&self) -> String {
        let Some((qname, stats)) = self.top_dns_names(1).into_iter().next() else {
            return "none".to_string();
        };

        format!(
            "{qname} (queries={}, answers={}, answer_ips={}, targets={})",
            stats.queries,
            stats.answers,
            Self::render_dns_answer_ips(stats),
            self.render_top_targets_for_dns_name(qname, 3)
        )
    }

    pub fn render_top_dns_policy_correlation_compact(&self) -> String {
        let Some(correlation) = self.top_dns_policy_correlations(1, 1).into_iter().next() else {
            return "none".to_string();
        };

        format!(
            "{} (answer_ips={}, matched_domains={}, targets={})",
            correlation.qname,
            if correlation.answer_ips.is_empty() {
                "none".to_string()
            } else {
                correlation.answer_ips.join(", ")
            },
            render_ranked_string_counts(&correlation.matched_domains),
            self.render_dns_target_list(&correlation.targets)
        )
    }

    pub fn render_top_dns_target_correlation_compact(&self) -> String {
        let Some(correlation) = self.top_dns_target_correlations(1, 1).into_iter().next() else {
            return "none".to_string();
        };
        let target = correlation
            .targets
            .first()
            .map(|target| self.render_dns_correlated_target(target))
            .unwrap_or_else(|| "none".to_string());

        format!("{} -> {}", correlation.qname, target)
    }

    pub fn dns_names_for_target(&self, target: &str) -> Vec<String> {
        let Some(ip) = target_ip_string(target) else {
            return Vec::new();
        };
        self.dns_name_counts
            .iter()
            .filter_map(|(qname, stats)| stats.answer_ips.contains(&ip).then_some(qname.clone()))
            .collect()
    }

    pub fn matched_domain_entries_for_target(
        &self,
        target: &str,
        limit: usize,
    ) -> Vec<(&str, usize)> {
        let Some(ip) = target_ip_string(target) else {
            return Vec::new();
        };
        self.policy_matched_domains_by_ip
            .get(&ip)
            .map(|counts| top_count_entries(counts, limit))
            .unwrap_or_default()
    }

    pub fn correlated_targets_for_dns_name(
        &self,
        qname: &str,
        limit: usize,
    ) -> Vec<DnsCorrelatedTarget> {
        let Some(stats) = self.dns_name_counts.get(qname) else {
            return Vec::new();
        };
        let mut targets = self
            .connection_targets
            .iter()
            .filter_map(|(target, target_stats)| {
                let ip = target_ip_string(target)?;
                stats.answer_ips.contains(&ip).then(|| DnsCorrelatedTarget {
                    target: target.clone(),
                    connect_attempts: target_stats.connect_attempts,
                    connect_ok: target_stats.connect_ok,
                    connect_error: target_stats.connect_error,
                    flow_end: target_stats.flow_end,
                    matched_domains: self
                        .matched_domain_entries_for_target(target, usize::MAX)
                        .into_iter()
                        .map(|(key, count)| RankedStringCount {
                            key: key.to_string(),
                            count,
                        })
                        .collect(),
                })
            })
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| {
            right
                .connect_attempts
                .cmp(&left.connect_attempts)
                .then_with(|| right.connect_error.cmp(&left.connect_error))
                .then_with(|| right.connect_ok.cmp(&left.connect_ok))
                .then_with(|| left.target.cmp(&right.target))
        });
        targets.truncate(limit);
        targets
    }

    pub fn top_dns_target_correlations(
        &self,
        dns_limit: usize,
        target_limit: usize,
    ) -> Vec<DnsTargetCorrelation> {
        self.top_dns_names(dns_limit)
            .into_iter()
            .map(|(qname, stats)| DnsTargetCorrelation {
                qname: qname.to_string(),
                queries: stats.queries,
                answers: stats.answers,
                answer_ips: stats.answer_ips.iter().cloned().collect(),
                targets: self.correlated_targets_for_dns_name(qname, target_limit),
            })
            .collect()
    }

    pub fn top_dns_policy_correlations(
        &self,
        dns_limit: usize,
        target_limit: usize,
    ) -> Vec<DnsPolicyCorrelation> {
        self.top_dns_names(dns_limit)
            .into_iter()
            .filter_map(|(qname, stats)| {
                let targets = self.correlated_targets_for_dns_name(qname, target_limit);
                let matched_domains = self.matched_domain_entries_for_dns_name(qname, usize::MAX);
                if targets.is_empty() && matched_domains.is_empty() {
                    return None;
                }
                Some(DnsPolicyCorrelation {
                    qname: qname.to_string(),
                    queries: stats.queries,
                    answers: stats.answers,
                    answer_ips: stats.answer_ips.iter().cloned().collect(),
                    matched_domains,
                    targets,
                })
            })
            .collect()
    }

    pub fn top_dns_policy_rows(&self, dns_limit: usize, target_limit: usize) -> Vec<DnsPolicyRow> {
        let mut rows = Vec::new();
        for correlation in self.top_dns_policy_correlations(dns_limit, target_limit) {
            if correlation.targets.is_empty() {
                rows.push(DnsPolicyRow {
                    qname: correlation.qname,
                    queries: correlation.queries,
                    answers: correlation.answers,
                    answer_ips: correlation.answer_ips,
                    target: None,
                    target_ip: None,
                    connect_attempts: 0,
                    connect_ok: 0,
                    connect_error: 0,
                    flow_end: 0,
                    matched_domains: correlation.matched_domains,
                });
                continue;
            }

            for target in correlation.targets {
                let target_ip = target_ip_string(&target.target);
                rows.push(DnsPolicyRow {
                    qname: correlation.qname.clone(),
                    queries: correlation.queries,
                    answers: correlation.answers,
                    answer_ips: correlation.answer_ips.clone(),
                    target: Some(target.target.clone()),
                    target_ip,
                    connect_attempts: target.connect_attempts,
                    connect_ok: target.connect_ok,
                    connect_error: target.connect_error,
                    flow_end: target.flow_end,
                    matched_domains: target.matched_domains,
                });
            }
        }

        rows.sort_by(|left, right| {
            right
                .connect_attempts
                .cmp(&left.connect_attempts)
                .then_with(|| right.connect_error.cmp(&left.connect_error))
                .then_with(|| right.connect_ok.cmp(&left.connect_ok))
                .then_with(|| left.qname.cmp(&right.qname))
                .then_with(|| left.target.cmp(&right.target))
        });
        rows
    }

    pub fn render_top_target_compact(&self) -> String {
        let Some((target, stats)) = self.top_connection_targets(1).into_iter().next() else {
            return "none".to_string();
        };

        format!(
            "{target} (attempts={}, ok={}, error={}, flow_end={}, dns_names={}, matched_domains={})",
            stats.connect_attempts,
            stats.connect_ok,
            stats.connect_error,
            stats.flow_end,
            self.render_dns_names_for_target(target),
            self.render_matched_domains_for_target(target, 3)
        )
    }

    pub fn render_dns_policy_rows_compact(&self, limit: usize) -> String {
        let rows = self.top_dns_policy_rows(limit, 1);
        if rows.is_empty() {
            return "none".to_string();
        }

        rows.into_iter()
            .map(|row| {
                let answer_ips = if row.answer_ips.is_empty() {
                    "none".to_string()
                } else {
                    row.answer_ips.join(", ")
                };
                let matched_domains = render_ranked_string_counts(&row.matched_domains);
                match row.target {
                    Some(target) => format!(
                        "{} -> {} (answer_ips={}, matched_domains={}, attempts={}, ok={}, error={}, flow_end={})",
                        row.qname,
                        target,
                        answer_ips,
                        matched_domains,
                        row.connect_attempts,
                        row.connect_ok,
                        row.connect_error,
                        row.flow_end
                    ),
                    None => format!(
                        "{} -> no-target (answer_ips={}, matched_domains={})",
                        row.qname, answer_ips, matched_domains
                    ),
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn matched_domain_entries_for_dns_name(
        &self,
        qname: &str,
        limit: usize,
    ) -> Vec<RankedStringCount> {
        let Some(stats) = self.dns_name_counts.get(qname) else {
            return Vec::new();
        };
        let mut counts = BTreeMap::new();
        for ip in &stats.answer_ips {
            if let Some(per_ip) = self.policy_matched_domains_by_ip.get(ip) {
                for (domain, count) in per_ip {
                    *counts.entry(domain.clone()).or_insert(0) += count;
                }
            }
        }
        top_count_entries(&counts, limit)
            .into_iter()
            .map(|(key, count)| RankedStringCount {
                key: key.to_string(),
                count,
            })
            .collect()
    }

    pub fn render_policy_violations_compact(&self, limit: usize) -> String {
        if self.policy_reason_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.policy_reason_counts, limit)
            .into_iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn render_policy_controls_compact(&self, limit: usize) -> String {
        if self.policy_control_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.policy_control_counts, limit)
            .into_iter()
            .map(|(control, count)| format!("{control}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn policy_violation_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.policy_reason_counts, limit)
    }

    pub fn policy_control_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.policy_control_counts, limit)
    }

    pub fn render_policy_matched_domains_compact(&self, limit: usize) -> String {
        if self.policy_matched_domain_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.policy_matched_domain_counts, limit)
            .into_iter()
            .map(|(domain, count)| format!("{domain}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn policy_matched_domain_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.policy_matched_domain_counts, limit)
    }

    pub fn render_connect_errors_compact(&self, limit: usize) -> String {
        if self.connect_error_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.connect_error_counts, limit)
            .into_iter()
            .map(|(error, count)| format!("{error}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn connect_error_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.connect_error_counts, limit)
    }

    pub fn render_runtime_failures_compact(&self, limit: usize) -> String {
        if self.runtime_failure_reason_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.runtime_failure_reason_counts, limit)
            .into_iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn runtime_failure_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.runtime_failure_reason_counts, limit)
    }

    pub fn render_runtime_failure_phases_compact(&self, limit: usize) -> String {
        if self.runtime_failure_phase_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.runtime_failure_phase_counts, limit)
            .into_iter()
            .map(|(phase, count)| format!("{phase}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn runtime_failure_phase_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.runtime_failure_phase_counts, limit)
    }

    pub(crate) fn render_schema_versions(&self) -> String {
        if self.schema_versions.is_empty() {
            return "unknown".to_string();
        }

        self.schema_versions
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn record(&mut self, event: FlowLogLine) {
        self.total += 1;
        if let Some(version) = event.schema_version {
            self.schema_versions.insert(version);
        }
        if let Some(protocol) = event.protocol.as_ref() {
            *self.protocol_counts.entry(protocol.clone()).or_default() += 1;
        }

        match event.event.as_str() {
            "dns_query" => {
                self.dns_query += 1;
                if let Some(qname) = event.qname {
                    self.dns_name_counts.entry(qname).or_default().queries += 1;
                }
            }
            "dns_answer" => {
                self.dns_answer += 1;
                if let Some(qname) = event.qname {
                    let stats = self.dns_name_counts.entry(qname).or_default();
                    stats.answers += 1;
                    for answer_ip in event.answer_ips {
                        stats.answer_ips.insert(answer_ip);
                    }
                }
            }
            "connect_attempt" => {
                self.connect_attempt += 1;
                if event.via_proxy.unwrap_or(false) {
                    self.proxied_connect_attempts += 1;
                } else {
                    self.direct_connect_attempts += 1;
                }
                if let Some(target) = event.remote_addr.or(event.remote) {
                    self.connection_targets
                        .entry(target)
                        .or_default()
                        .connect_attempts += 1;
                }
            }
            "connect_result" => {
                self.connect_result += 1;
                if let Some(target) = event.remote_addr {
                    let stats = self.connection_targets.entry(target).or_default();
                    match event.status.as_deref() {
                        Some("ok") => stats.connect_ok += 1,
                        Some("error") => {
                            stats.connect_error += 1;
                            if let Some(error) = event.error {
                                *self.connect_error_counts.entry(error).or_default() += 1;
                            }
                        }
                        _ => {}
                    }
                }
            }
            "policy_violation" => {
                self.policy_violation += 1;
                if let Some(reason) = event.reason_code {
                    *self.policy_reason_counts.entry(reason).or_default() += 1;
                }
                if let Some(control) = event.control {
                    *self.policy_control_counts.entry(control).or_default() += 1;
                }
                if let Some(domain) = event.matched_domain {
                    *self
                        .policy_matched_domain_counts
                        .entry(domain.clone())
                        .or_default() += 1;
                    if let Some(remote_ip) = event.remote_ip {
                        *self
                            .policy_matched_domains_by_ip
                            .entry(remote_ip)
                            .or_default()
                            .entry(domain)
                            .or_default() += 1;
                    }
                }
            }
            "runtime_failure" => {
                self.runtime_failure += 1;
                if let Some(reason) = event.reason_code {
                    *self
                        .runtime_failure_reason_counts
                        .entry(reason)
                        .or_default() += 1;
                }
                if let Some(phase) = event.phase {
                    *self.runtime_failure_phase_counts.entry(phase).or_default() += 1;
                }
            }
            "flow_end" => {
                self.flow_end += 1;
                if let Some(target) = event.remote_addr {
                    self.connection_targets.entry(target).or_default().flow_end += 1;
                }
            }
            _ => self.unknown_event += 1,
        }
    }

    pub(crate) fn render_dns_names_for_target(&self, target: &str) -> String {
        let dns_names = self.dns_names_for_target(target);
        if dns_names.is_empty() {
            "none".to_string()
        } else {
            dns_names.join(", ")
        }
    }

    pub(crate) fn render_top_targets_for_dns_name(&self, qname: &str, limit: usize) -> String {
        self.render_dns_target_list(&self.correlated_targets_for_dns_name(qname, limit))
    }

    pub(crate) fn render_dns_target_list(&self, targets: &[DnsCorrelatedTarget]) -> String {
        if targets.is_empty() {
            return "none".to_string();
        }
        targets
            .iter()
            .map(|target| self.render_dns_correlated_target(target))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(crate) fn render_dns_correlated_target(&self, target: &DnsCorrelatedTarget) -> String {
        let matched_domains = render_ranked_string_counts(&target.matched_domains);
        format!(
            "{} (attempts={}, ok={}, error={}, flow_end={}, matched_domains={})",
            target.target,
            target.connect_attempts,
            target.connect_ok,
            target.connect_error,
            target.flow_end,
            matched_domains
        )
    }

    pub(crate) fn render_matched_domains_for_target(&self, target: &str, limit: usize) -> String {
        let counts = self
            .matched_domain_entries_for_target(target, limit)
            .into_iter()
            .map(|(key, count)| RankedStringCount {
                key: key.to_string(),
                count,
            })
            .collect::<Vec<_>>();
        render_ranked_string_counts(&counts)
    }

    pub(crate) fn render_dns_answer_ips(stats: &DnsNameStats) -> String {
        if stats.answer_ips.is_empty() {
            "none".to_string()
        } else {
            stats
                .answer_ips
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        }
    }
}
