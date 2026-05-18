use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use super::{
    append_runtime_failure, ConnectResultStatus, DnsAnswerMode, FlowLogger, PolicyViolationEvent,
    RuntimeFailureEvent, FLOW_LOG_SCHEMA_VERSION,
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

    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
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

    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
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

    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
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

    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
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

    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
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
