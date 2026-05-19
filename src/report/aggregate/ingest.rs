use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::FlowLogReport;

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
}
