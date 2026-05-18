// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

#[cfg(test)]
mod tests;
mod values;

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{json, Value};

pub use self::values::{
    ConnectResultStatus, DnsAnswerMode, PolicyViolationEvent, RuntimeFailureEvent,
};

pub const FLOW_LOG_SCHEMA_VERSION: u32 = 1;

pub struct FlowLogger {
    writer: BufWriter<File>,
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
        server: std::net::SocketAddr,
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
        server: std::net::SocketAddr,
        qname: Option<&str>,
        qtype: Option<&'static str>,
        mode: DnsAnswerMode,
        bytes: usize,
        answer_ips: &[std::net::IpAddr],
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
            "answer_ips": answer_ips.iter().map(std::net::IpAddr::to_string).collect::<Vec<_>>(),
        }))
    }

    pub fn log_connect_attempt(
        &mut self,
        remote_addr: std::net::SocketAddr,
        via_proxy: bool,
    ) -> Result<()> {
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
        remote_addr: std::net::SocketAddr,
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

    pub fn log_flow_end(
        &mut self,
        protocol: &'static str,
        remote_addr: std::net::SocketAddr,
    ) -> Result<()> {
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
