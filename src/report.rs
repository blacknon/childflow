// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::cli::Cli;

pub fn run(cli: &Cli) -> Result<i32> {
    let path = cli
        .report
        .as_ref()
        .context("`--report` requires a flow log path")?;
    let report = FlowLogReport::from_path(path)?;
    print!("{}", report.render(path));
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
    pub unknown_event: usize,
    pub schema_versions: BTreeSet<u32>,
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

    pub fn render(&self, path: &Path) -> String {
        format!(
            "childflow report\nflow-log: {}\nschema-version: {}\nevents:\n  total: {}\n  dns_query: {}\n  dns_answer: {}\n  connect_attempt: {}\n  connect_result: {}\n  policy_violation: {}\n  flow_end: {}\n  unknown_event: {}\n",
            path.display(),
            self.render_schema_versions(),
            self.total,
            self.dns_query,
            self.dns_answer,
            self.connect_attempt,
            self.connect_result,
            self.policy_violation,
            self.flow_end,
            self.unknown_event
        )
    }

    pub fn render_event_counts_compact(&self) -> String {
        format!(
            "total={}, dns_query={}, dns_answer={}, connect_attempt={}, connect_result={}, policy_violation={}, flow_end={}, unknown_event={}",
            self.total,
            self.dns_query,
            self.dns_answer,
            self.connect_attempt,
            self.connect_result,
            self.policy_violation,
            self.flow_end,
            self.unknown_event
        )
    }

    fn record(&mut self, event: FlowLogLine) {
        self.total += 1;
        if let Some(version) = event.schema_version {
            self.schema_versions.insert(version);
        }

        match event.event.as_str() {
            "dns_query" => self.dns_query += 1,
            "dns_answer" => self.dns_answer += 1,
            "connect_attempt" => self.connect_attempt += 1,
            "connect_result" => self.connect_result += 1,
            "policy_violation" => self.policy_violation += 1,
            "flow_end" => self.flow_end += 1,
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
}

#[derive(Debug, Deserialize)]
struct FlowLogLine {
    #[serde(default)]
    schema_version: Option<u32>,
    event: String,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn flow_log_report_counts_known_and_unknown_events() -> Result<()> {
        let path = unique_temp_flow_log_path("report-counts");
        fs::write(
            &path,
            concat!(
                "{\"schema_version\":1,\"event\":\"dns_query\"}\n",
                "{\"schema_version\":1,\"event\":\"connect_attempt\"}\n",
                "{\"schema_version\":1,\"event\":\"connect_result\"}\n",
                "{\"schema_version\":1,\"event\":\"policy_violation\"}\n",
                "{\"schema_version\":1,\"event\":\"flow_end\"}\n",
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
            unknown_event: 0,
            schema_versions: BTreeSet::from([1]),
        };

        let rendered = report.render(Path::new("/tmp/flow.jsonl"));
        assert!(rendered.contains("childflow report"));
        assert!(rendered.contains("flow-log: /tmp/flow.jsonl"));
        assert!(rendered.contains("schema-version: 1"));
        assert!(rendered.contains("total: 4"));
        assert!(rendered.contains("dns_query: 1"));
        assert!(rendered.contains("unknown_event: 0"));
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
