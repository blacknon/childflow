// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

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
    };
    print!("{rendered}");
    Ok(0)
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
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
    pub policy_reason_counts: BTreeMap<String, usize>,
    pub connect_error_counts: BTreeMap<String, usize>,
    pub runtime_failure_reason_counts: BTreeMap<String, usize>,
    pub connection_targets: BTreeMap<String, ConnectionTargetStats>,
    pub proxied_connect_attempts: usize,
    pub direct_connect_attempts: usize,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ConnectionTargetStats {
    pub connect_attempts: usize,
    pub connect_ok: usize,
    pub connect_error: usize,
    pub flow_end: usize,
}

impl FlowLogReport {
    pub fn from_path(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open flow log at {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut report = Self::default();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.with_context(|| {
                format!("failed to read line {} from {}", line_no + 1, path.display())
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

    pub fn render_text(&self, path: &Path) -> String {
        let mut rendered = format!(
            "childflow report\nflow-log: {}\nschema-version: {}\nevents:\n  total: {}\n  dns_query: {}\n  dns_answer: {}\n  connect_attempt: {}\n  connect_result: {}\n  policy_violation: {}\n  flow_end: {}\n  runtime_failure: {}\n  unknown_event: {}\n",
            path.display(),
            self.render_schema_versions(),
            self.total,
            self.dns_query,
            self.dns_answer,
            self.connect_attempt,
            self.connect_result,
            self.policy_violation,
            self.flow_end,
            self.runtime_failure,
            self.unknown_event
        );

        rendered.push_str("protocols:\n");
        if self.protocol_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (protocol, count) in &self.protocol_counts {
                rendered.push_str(&format!("  {protocol}: {count}\n"));
            }
        }

        rendered.push_str("proxy-usage:\n");
        rendered.push_str(&format!(
            "  proxied_connect_attempts: {}\n  direct_connect_attempts: {}\n",
            self.proxied_connect_attempts, self.direct_connect_attempts
        ));

        rendered.push_str("policy-violations:\n");
        if self.policy_reason_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (reason, count) in &self.policy_reason_counts {
                rendered.push_str(&format!("  {reason}: {count}\n"));
            }
        }

        rendered.push_str("connect-errors:\n");
        if self.connect_error_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (error, count) in &self.connect_error_counts {
                rendered.push_str(&format!("  {error}: {count}\n"));
            }
        }

        rendered.push_str("runtime-failures:\n");
        if self.runtime_failure_reason_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (reason, count) in &self.runtime_failure_reason_counts {
                rendered.push_str(&format!("  {reason}: {count}\n"));
            }
        }

        rendered.push_str("top-connection-targets:\n");
        if self.connection_targets.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (target, stats) in self.top_connection_targets(10) {
                rendered.push_str(&format!(
                    "  {target}: attempts={}, ok={}, error={}, flow_end={}\n",
                    stats.connect_attempts, stats.connect_ok, stats.connect_error, stats.flow_end
                ));
            }
        }

        rendered
    }

    pub fn render_markdown(&self, path: &Path) -> String {
        let mut rendered = format!(
            "# childflow report\n\n- flow-log: `{}`\n- schema-version: `{}`\n\n## Event counts\n\n| Metric | Count |\n| --- | ---: |\n| total | {} |\n| dns_query | {} |\n| dns_answer | {} |\n| connect_attempt | {} |\n| connect_result | {} |\n| policy_violation | {} |\n| flow_end | {} |\n| runtime_failure | {} |\n| unknown_event | {} |\n",
            path.display(),
            self.render_schema_versions(),
            self.total,
            self.dns_query,
            self.dns_answer,
            self.connect_attempt,
            self.connect_result,
            self.policy_violation,
            self.flow_end,
            self.runtime_failure,
            self.unknown_event
        );

        rendered.push_str("\n## Protocols\n\n");
        if self.protocol_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Protocol | Count |\n| --- | ---: |\n");
            for (protocol, count) in &self.protocol_counts {
                rendered.push_str(&format!("| {protocol} | {count} |\n"));
            }
        }

        rendered.push_str("\n## Proxy usage\n\n");
        rendered.push_str("| Metric | Count |\n| --- | ---: |\n");
        rendered.push_str(&format!(
            "| proxied_connect_attempts | {} |\n| direct_connect_attempts | {} |\n",
            self.proxied_connect_attempts, self.direct_connect_attempts
        ));

        rendered.push_str("\n## Policy violations\n\n");
        if self.policy_reason_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Reason code | Count |\n| --- | ---: |\n");
            for (reason, count) in &self.policy_reason_counts {
                rendered.push_str(&format!("| {reason} | {count} |\n"));
            }
        }

        rendered.push_str("\n## Connect errors\n\n");
        if self.connect_error_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Error | Count |\n| --- | ---: |\n");
            for (error, count) in &self.connect_error_counts {
                rendered.push_str(&format!("| {error} | {count} |\n"));
            }
        }

        rendered.push_str("\n## Runtime failures\n\n");
        if self.runtime_failure_reason_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Reason code | Count |\n| --- | ---: |\n");
            for (reason, count) in &self.runtime_failure_reason_counts {
                rendered.push_str(&format!("| {reason} | {count} |\n"));
            }
        }

        rendered.push_str("\n## Top connection targets\n\n");
        if self.connection_targets.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Target | Attempts | OK | Error | Flow end |\n| --- | ---: | ---: | ---: | ---: |\n");
            for (target, stats) in self.top_connection_targets(10) {
                rendered.push_str(&format!(
                    "| `{target}` | {} | {} | {} | {} |\n",
                    stats.connect_attempts, stats.connect_ok, stats.connect_error, stats.flow_end
                ));
            }
        }

        rendered
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

    fn record(&mut self, event: FlowLogLine) {
        self.total += 1;
        if let Some(version) = event.schema_version {
            self.schema_versions.insert(version);
        }
        if let Some(protocol) = event.protocol.as_ref() {
            *self.protocol_counts.entry(protocol.clone()).or_default() += 1;
        }

        match event.event.as_str() {
            "dns_query" => self.dns_query += 1,
            "dns_answer" => self.dns_answer += 1,
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
            }
            "runtime_failure" => {
                self.runtime_failure += 1;
                if let Some(reason) = event.reason_code {
                    *self.runtime_failure_reason_counts.entry(reason).or_default() += 1;
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

    fn render_schema_versions(&self) -> String {
        if self.schema_versions.is_empty() {
            return "unknown".to_string();
        }

        self.schema_versions
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
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

    pub fn render_top_target_compact(&self) -> String {
        let Some((target, stats)) = self.top_connection_targets(1).into_iter().next() else {
            return "none".to_string();
        };

        format!(
            "{target} (attempts={}, ok={}, error={}, flow_end={})",
            stats.connect_attempts, stats.connect_ok, stats.connect_error, stats.flow_end
        )
    }

    pub fn render_connect_errors_compact(&self, limit: usize) -> String {
        if self.connect_error_counts.is_empty() {
            return "none".to_string();
        }

        self.connect_error_counts
            .iter()
            .take(limit)
            .map(|(error, count)| format!("{error}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug, Deserialize)]
struct FlowLogLine {
    #[serde(default)]
    schema_version: Option<u32>,
    event: String,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    remote_addr: Option<String>,
    #[serde(default)]
    remote: Option<String>,
    #[serde(default)]
    via_proxy: Option<bool>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    reason_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn flow_log_report_counts_known_and_unknown_events() -> Result<()> {
        let path = unique_temp_flow_log_path("report-counts");
        fs::write(
            &path,
            concat!(
                "{\"schema_version\":1,\"event\":\"dns_query\",\"protocol\":\"udp\"}\n",
                "{\"schema_version\":1,\"event\":\"connect_attempt\",\"protocol\":\"tcp\"}\n",
                "{\"schema_version\":1,\"event\":\"connect_result\",\"protocol\":\"tcp\"}\n",
                "{\"schema_version\":1,\"event\":\"policy_violation\",\"protocol\":\"tcp\"}\n",
                "{\"schema_version\":1,\"event\":\"flow_end\",\"protocol\":\"tcp\"}\n",
                "{\"schema_version\":2,\"event\":\"future_event\"}\n"
            ),
        )?;

        let report = FlowLogReport::from_path(&path)?;
        assert_eq!(report.total, 6);
        assert_eq!(report.dns_query, 1);
        assert_eq!(report.connect_attempt, 1);
        assert_eq!(report.connect_result, 1);
        assert_eq!(report.policy_violation, 1);
        assert_eq!(report.flow_end, 1);
        assert_eq!(report.unknown_event, 1);
        assert_eq!(report.render_schema_versions(), "1, 2");
        assert_eq!(report.protocol_counts.get("tcp"), Some(&4));
        assert_eq!(report.policy_reason_counts.get("proxy_only"), None);

        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn flow_log_report_renders_text_output() -> Result<()> {
        let report = FlowLogReport {
            total: 4,
            dns_query: 1,
            dns_answer: 1,
            connect_attempt: 1,
            connect_result: 1,
            policy_violation: 0,
            flow_end: 0,
            runtime_failure: 0,
            unknown_event: 0,
            schema_versions: BTreeSet::from([1]),
            protocol_counts: BTreeMap::from([
                ("tcp".into(), 2),
                ("udp".into(), 2),
            ]),
            policy_reason_counts: BTreeMap::new(),
            connect_error_counts: BTreeMap::new(),
            runtime_failure_reason_counts: BTreeMap::new(),
            connection_targets: BTreeMap::from([(
                "93.184.216.34:443".into(),
                ConnectionTargetStats {
                    connect_attempts: 1,
                    connect_ok: 1,
                    connect_error: 0,
                    flow_end: 0,
                },
            )]),
            proxied_connect_attempts: 1,
            direct_connect_attempts: 0,
        };

        let rendered = report.render_text(Path::new("/tmp/flow.jsonl"));
        assert!(rendered.contains("childflow report"));
        assert!(rendered.contains("flow-log: /tmp/flow.jsonl"));
        assert!(rendered.contains("schema-version: 1"));
        assert!(rendered.contains("total: 4"));
        assert!(rendered.contains("dns_query: 1"));
        assert!(rendered.contains("runtime_failure: 0"));
        assert!(rendered.contains("unknown_event: 0"));
        assert!(rendered.contains("protocols:"));
        assert!(rendered.contains("tcp: 2"));
        assert!(rendered.contains("proxy-usage:"));
        assert!(rendered.contains("proxied_connect_attempts: 1"));
        assert!(rendered.contains("connect-errors:\n  <none>"));
        assert!(rendered.contains("runtime-failures:\n  <none>"));
        assert!(rendered.contains("top-connection-targets:"));
        assert!(rendered.contains("93.184.216.34:443: attempts=1, ok=1"));
        Ok(())
    }

    #[test]
    fn flow_log_report_renders_markdown_output() -> Result<()> {
        let report = FlowLogReport {
            total: 3,
            dns_query: 0,
            dns_answer: 0,
            connect_attempt: 1,
            connect_result: 1,
            policy_violation: 1,
            flow_end: 0,
            runtime_failure: 1,
            unknown_event: 0,
            schema_versions: BTreeSet::from([1]),
            protocol_counts: BTreeMap::from([("tcp".into(), 3)]),
            policy_reason_counts: BTreeMap::from([("proxy_only".into(), 1)]),
            connect_error_counts: BTreeMap::from([("connection refused".into(), 2)]),
            runtime_failure_reason_counts: BTreeMap::from([("tap_create_blocked".into(), 1)]),
            connection_targets: BTreeMap::from([(
                "93.184.216.34:443".into(),
                ConnectionTargetStats {
                    connect_attempts: 1,
                    connect_ok: 1,
                    connect_error: 0,
                    flow_end: 0,
                },
            )]),
            proxied_connect_attempts: 1,
            direct_connect_attempts: 0,
        };

        let rendered = report.render_markdown(Path::new("/tmp/flow.jsonl"));
        assert!(rendered.contains("# childflow report"));
        assert!(rendered.contains("| total | 3 |"));
        assert!(rendered.contains("| runtime_failure | 1 |"));
        assert!(rendered.contains("| tcp | 3 |"));
        assert!(rendered.contains("| proxy_only | 1 |"));
        assert!(rendered.contains("| connection refused | 2 |"));
        assert!(rendered.contains("| tap_create_blocked | 1 |"));
        assert!(rendered.contains("| `93.184.216.34:443` | 1 | 1 | 0 | 0 |"));
        Ok(())
    }

    #[test]
    fn flow_log_report_aggregates_connection_targets_and_policy_reasons() -> Result<()> {
        let path = unique_temp_flow_log_path("report-aggregation");
        fs::write(
            &path,
            concat!(
                "{\"schema_version\":1,\"event\":\"connect_attempt\",\"protocol\":\"tcp\",\"remote_addr\":\"93.184.216.34:443\",\"via_proxy\":true}\n",
                "{\"schema_version\":1,\"event\":\"connect_result\",\"protocol\":\"tcp\",\"remote_addr\":\"93.184.216.34:443\",\"via_proxy\":true,\"status\":\"ok\"}\n",
                "{\"schema_version\":1,\"event\":\"flow_end\",\"protocol\":\"tcp\",\"remote_addr\":\"93.184.216.34:443\"}\n",
                "{\"schema_version\":1,\"event\":\"connect_attempt\",\"protocol\":\"tcp\",\"remote_addr\":\"198.51.100.7:8443\",\"via_proxy\":false}\n",
                "{\"schema_version\":1,\"event\":\"connect_result\",\"protocol\":\"tcp\",\"remote_addr\":\"198.51.100.7:8443\",\"via_proxy\":false,\"status\":\"error\",\"error\":\"connection refused\"}\n",
                "{\"schema_version\":1,\"event\":\"policy_violation\",\"protocol\":\"tcp\",\"remote\":\"10.0.0.1:443\",\"reason_code\":\"deny_cidr\"}\n"
            ),
        )?;

        let report = FlowLogReport::from_path(&path)?;
        assert_eq!(report.proxied_connect_attempts, 1);
        assert_eq!(report.direct_connect_attempts, 1);
        assert_eq!(report.policy_reason_counts.get("deny_cidr"), Some(&1));
        assert_eq!(report.runtime_failure, 0);
        assert_eq!(
            report.connect_error_counts.get("connection refused"),
            Some(&1)
        );
        assert_eq!(
            report.connection_targets.get("93.184.216.34:443"),
            Some(&ConnectionTargetStats {
                connect_attempts: 1,
                connect_ok: 1,
                connect_error: 0,
                flow_end: 1,
            })
        );
        assert_eq!(
            report.connection_targets.get("198.51.100.7:8443"),
            Some(&ConnectionTargetStats {
                connect_attempts: 1,
                connect_ok: 0,
                connect_error: 1,
                flow_end: 0,
            })
        );

        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn flow_log_report_sorts_top_targets_by_activity() {
        let report = FlowLogReport {
            connection_targets: BTreeMap::from([
                (
                    "b.example:443".into(),
                    ConnectionTargetStats {
                        connect_attempts: 1,
                        connect_ok: 1,
                        connect_error: 0,
                        flow_end: 1,
                    },
                ),
                (
                    "a.example:443".into(),
                    ConnectionTargetStats {
                        connect_attempts: 3,
                        connect_ok: 2,
                        connect_error: 1,
                        flow_end: 2,
                    },
                ),
                (
                    "c.example:443".into(),
                    ConnectionTargetStats {
                        connect_attempts: 2,
                        connect_ok: 0,
                        connect_error: 2,
                        flow_end: 0,
                    },
                ),
            ]),
            ..Default::default()
        };

        let top = report.top_connection_targets(3);
        assert_eq!(top[0].0, "a.example:443");
        assert_eq!(top[1].0, "c.example:443");
        assert_eq!(top[2].0, "b.example:443");
    }

    #[test]
    fn flow_log_report_renders_compact_target_and_errors() {
        let report = FlowLogReport {
            connect_error_counts: BTreeMap::from([
                ("connection refused".into(), 2),
                ("timed out".into(), 1),
            ]),
            connection_targets: BTreeMap::from([(
                "a.example:443".into(),
                ConnectionTargetStats {
                    connect_attempts: 3,
                    connect_ok: 1,
                    connect_error: 2,
                    flow_end: 1,
                },
            )]),
            ..Default::default()
        };

        assert_eq!(
            report.render_top_target_compact(),
            "a.example:443 (attempts=3, ok=1, error=2, flow_end=1)"
        );
        assert_eq!(
            report.render_connect_errors_compact(2),
            "connection refused=2, timed out=1"
        );
    }

    #[test]
    fn flow_log_report_counts_runtime_failures() -> Result<()> {
        let path = unique_temp_flow_log_path("report-runtime-failures");
        fs::write(
            &path,
            concat!(
                "{\"schema_version\":1,\"event\":\"runtime_failure\",\"phase\":\"child_bootstrap\",\"reason_code\":\"tap_create_blocked\",\"detail\":\"tap create failed\"}\n",
                "{\"schema_version\":1,\"event\":\"runtime_failure\",\"phase\":\"run\",\"reason_code\":\"runtime_shutdown_failed\",\"detail\":\"shutdown failed\"}\n"
            ),
        )?;

        let report = FlowLogReport::from_path(&path)?;
        assert_eq!(report.runtime_failure, 2);
        assert_eq!(
            report.runtime_failure_reason_counts.get("tap_create_blocked"),
            Some(&1)
        );
        assert_eq!(
            report.runtime_failure_reason_counts.get("runtime_shutdown_failed"),
            Some(&1)
        );

        let _ = fs::remove_file(path);
        Ok(())
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
