// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{json, Value};

pub const FLOW_LOG_SCHEMA_VERSION: u32 = 1;

pub struct FlowLogger {
    writer: BufWriter<File>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsAnswerMode {
    Relayed,
    SyntheticEmpty,
}

impl DnsAnswerMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Relayed => "relayed",
            Self::SyntheticEmpty => "synthetic_empty",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectResultStatus {
    Ok,
    Error,
}

impl ConnectResultStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

pub struct PolicyViolationEvent<'a> {
    pub protocol: &'static str,
    pub remote: &'a str,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub reason_code: &'static str,
    pub control: &'static str,
    pub matched_cidr: Option<&'a str>,
    pub matched_domain: Option<&'a str>,
    pub reason: &'a str,
}

pub struct RuntimeFailureEvent<'a> {
    pub phase: &'a str,
    pub reason_code: &'a str,
    pub detail: &'a str,
}

impl FlowLogger {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("failed to create flow log at {}", path.display()))?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    pub fn log_dns_query(
        &mut self,
        server: SocketAddr,
        qname: Option<&str>,
        qtype: Option<&'static str>,
    ) -> Result<()> {
        self.write_event(json!({
            "event": "dns_query",
            "protocol": "udp",
            "server": server.to_string(),
            "server_ip": server.ip().to_string(),
            "server_port": server.port(),
            "qname": qname,
            "qtype": qtype.unwrap_or("unknown"),
        }))
    }

    pub fn log_dns_answer(
        &mut self,
        server: SocketAddr,
        qname: Option<&str>,
        qtype: Option<&'static str>,
        mode: DnsAnswerMode,
        bytes: usize,
        answer_ips: &[IpAddr],
    ) -> Result<()> {
        self.write_event(json!({
            "event": "dns_answer",
            "protocol": "udp",
            "server": server.to_string(),
            "server_ip": server.ip().to_string(),
            "server_port": server.port(),
            "qname": qname,
            "qtype": qtype.unwrap_or("unknown"),
            "mode": mode.as_str(),
            "bytes": bytes,
            "answer_ips": answer_ips.iter().map(IpAddr::to_string).collect::<Vec<_>>(),
        }))
    }

    pub fn log_connect_attempt(&mut self, remote_addr: SocketAddr, via_proxy: bool) -> Result<()> {
        self.write_event(json!({
            "event": "connect_attempt",
            "protocol": "tcp",
            "remote_addr": remote_addr.to_string(),
            "remote_ip": remote_addr.ip().to_string(),
            "remote_port": remote_addr.port(),
            "via_proxy": via_proxy,
        }))
    }

    pub fn log_connect_result(
        &mut self,
        remote_addr: SocketAddr,
        via_proxy: bool,
        status: ConnectResultStatus,
        error: Option<&str>,
    ) -> Result<()> {
        self.write_event(json!({
            "event": "connect_result",
            "protocol": "tcp",
            "remote_addr": remote_addr.to_string(),
            "remote_ip": remote_addr.ip().to_string(),
            "remote_port": remote_addr.port(),
            "via_proxy": via_proxy,
            "status": status.as_str(),
            "error": error,
        }))
    }

    pub fn log_policy_violation(&mut self, violation: PolicyViolationEvent<'_>) -> Result<()> {
        self.write_event(json!({
            "event": "policy_violation",
            "protocol": violation.protocol,
            "remote": violation.remote,
            "remote_ip": violation.remote_ip.map(|value| value.to_string()),
            "remote_port": violation.remote_port,
            "action": "deny",
            "reason_code": violation.reason_code,
            "control": violation.control,
            "matched_cidr": violation.matched_cidr,
            "matched_domain": violation.matched_domain,
            "reason": violation.reason,
        }))
    }

    pub fn log_flow_end(&mut self, protocol: &'static str, remote_addr: SocketAddr) -> Result<()> {
        self.write_event(json!({
            "event": "flow_end",
            "protocol": protocol,
            "remote_addr": remote_addr.to_string(),
            "remote_ip": remote_addr.ip().to_string(),
            "remote_port": remote_addr.port(),
        }))
    }

    fn write_event(&mut self, mut value: Value) -> Result<()> {
        write_event_line(&mut self.writer, &mut value)
    }
}

pub fn append_runtime_failure(path: &Path, failure: RuntimeFailureEvent<'_>) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open flow log for append at {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let mut value = json!({
        "event": "runtime_failure",
        "phase": failure.phase,
        "reason_code": failure.reason_code,
        "detail": failure.detail,
    });
    write_event_line(&mut writer, &mut value)
}

fn write_event_line(writer: &mut BufWriter<File>, value: &mut Value) -> Result<()> {
    if let Value::Object(map) = value {
        map.insert("schema_version".into(), json!(FLOW_LOG_SCHEMA_VERSION));
        map.insert("ts_ms".into(), json!(timestamp_millis()));
    }
    serde_json::to_writer(&mut *writer, value).context("failed to serialize flow log event")?;
    writer
        .write_all(b"\n")
        .context("failed to write flow log newline")?;
    writer.flush().context("failed to flush flow log")?;
    Ok(())
}

fn timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};

    use super::{
        append_runtime_failure, ConnectResultStatus, DnsAnswerMode, FlowLogger,
        PolicyViolationEvent, RuntimeFailureEvent, FLOW_LOG_SCHEMA_VERSION,
    };

    #[test]
    fn flow_logger_writes_connect_and_end_events_as_json_lines() -> Result<()> {
        let path = unique_temp_flow_log_path("flow-log-connect");
        let mut logger = FlowLogger::open(&path)?;
        logger.log_connect_attempt("127.0.0.1:8080".parse()?, false)?;
        logger.log_connect_result(
            "127.0.0.1:8080".parse()?,
            false,
            ConnectResultStatus::Ok,
            None,
        )?;
        logger.log_flow_end("tcp", "127.0.0.1:8080".parse()?)?;
        drop(logger);

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"event\":\"connect_attempt\""));
        assert!(lines[0].contains(&format!("\"schema_version\":{FLOW_LOG_SCHEMA_VERSION}")));
        assert!(lines[0].contains("\"protocol\":\"tcp\""));
        assert!(lines[0].contains("\"remote_ip\":\"127.0.0.1\""));
        assert!(lines[0].contains("\"remote_port\":8080"));
        assert!(lines[1].contains("\"event\":\"connect_result\""));
        assert!(lines[1].contains("\"status\":\"ok\""));
        assert!(lines[2].contains("\"event\":\"flow_end\""));
        assert!(lines[2].contains("\"remote_addr\":\"127.0.0.1:8080\""));
        assert!(lines.iter().all(|line| line.contains("\"ts_ms\":")));

        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn flow_logger_writes_policy_violation_reason() -> Result<()> {
        let path = unique_temp_flow_log_path("flow-log-policy");
        let mut logger = FlowLogger::open(&path)?;
        logger.log_policy_violation(PolicyViolationEvent {
            protocol: "tcp",
            remote: "10.0.0.1:443",
            remote_ip: Some("10.0.0.1".parse()?),
            remote_port: Some(443),
            reason_code: "deny_cidr",
            control: "--deny-cidr",
            matched_cidr: Some("10.0.0.0/8"),
            matched_domain: None,
            reason: "--deny-cidr matched",
        })?;
        drop(logger);

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        assert!(contents.contains("\"event\":\"policy_violation\""));
        assert!(contents.contains("\"protocol\":\"tcp\""));
        assert!(contents.contains("\"remote_ip\":\"10.0.0.1\""));
        assert!(contents.contains("\"remote_port\":443"));
        assert!(contents.contains("\"action\":\"deny\""));
        assert!(contents.contains("\"reason_code\":\"deny_cidr\""));
        assert!(contents.contains("\"control\":\"--deny-cidr\""));
        assert!(contents.contains("\"matched_cidr\":\"10.0.0.0/8\""));
        assert!(contents.contains("\"matched_domain\":null"));
        assert!(contents.contains("\"reason\":\"--deny-cidr matched\""));

        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn flow_logger_writes_dns_events_with_structured_server_fields() -> Result<()> {
        let path = unique_temp_flow_log_path("flow-log-dns");
        let mut logger = FlowLogger::open(&path)?;
        logger.log_dns_query("1.1.1.1:53".parse()?, Some("example.com"), Some("A"))?;
        logger.log_dns_answer(
            "1.1.1.1:53".parse()?,
            Some("example.com"),
            Some("A"),
            DnsAnswerMode::Relayed,
            128,
            &["93.184.216.34".parse()?],
        )?;
        drop(logger);

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        assert!(contents.contains("\"event\":\"dns_query\""));
        assert!(contents.contains("\"protocol\":\"udp\""));
        assert!(contents.contains("\"server_ip\":\"1.1.1.1\""));
        assert!(contents.contains("\"server_port\":53"));
        assert!(contents.contains("\"qname\":\"example.com\""));
        assert!(contents.contains("\"event\":\"dns_answer\""));
        assert!(contents.contains("\"answer_ips\":[\"93.184.216.34\"]"));
        assert!(contents.contains("\"mode\":\"relayed\""));
        assert!(contents.contains("\"bytes\":128"));

        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn flow_logger_uses_stable_status_and_mode_values() -> Result<()> {
        let path = unique_temp_flow_log_path("flow-log-values");
        let mut logger = FlowLogger::open(&path)?;
        logger.log_connect_result(
            "127.0.0.1:8080".parse()?,
            true,
            ConnectResultStatus::Error,
            Some("boom"),
        )?;
        logger.log_dns_answer(
            "1.1.1.1:53".parse()?,
            Some("example.com"),
            Some("AAAA"),
            DnsAnswerMode::SyntheticEmpty,
            0,
            &[],
        )?;
        drop(logger);

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        assert!(contents.contains("\"status\":\"error\""));
        assert!(contents.contains("\"mode\":\"synthetic_empty\""));

        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn append_runtime_failure_writes_structured_event() -> Result<()> {
        let path = unique_temp_flow_log_path("flow-log-runtime-failure");
        append_runtime_failure(
            &path,
            RuntimeFailureEvent {
                phase: "child_bootstrap",
                reason_code: "tap_create_blocked",
                detail: "failed to create tap device `tap0`",
            },
        )?;

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        assert!(contents.contains("\"event\":\"runtime_failure\""));
        assert!(contents.contains("\"phase\":\"child_bootstrap\""));
        assert!(contents.contains("\"reason_code\":\"tap_create_blocked\""));
        assert!(contents.contains("\"detail\":\"failed to create tap device `tap0`\""));

        let _ = fs::remove_file(&path);
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
