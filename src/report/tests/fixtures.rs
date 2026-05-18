use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::report::{ConnectionTargetStats, DnsNameStats, FlowLogReport};

pub(super) fn unique_temp_flow_log_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "childflow-{prefix}-{}-{nanos}.jsonl",
        std::process::id()
    ))
}

pub(super) fn write_temp_flow_log(prefix: &str, contents: &str) -> Result<PathBuf> {
    let path = unique_temp_flow_log_path(prefix);
    fs::write(&path, contents)?;
    Ok(path)
}

pub(super) fn remove_temp_flow_log(path: &Path) {
    let _ = fs::remove_file(path);
}

pub(super) fn minimal_render_report() -> FlowLogReport {
    FlowLogReport {
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
        protocol_counts: BTreeMap::from([("tcp".into(), 2), ("udp".into(), 2)]),
        dns_name_counts: BTreeMap::from([(
            "example.com".into(),
            DnsNameStats {
                queries: 1,
                answers: 1,
                answer_ips: BTreeSet::from(["93.184.216.34".into()]),
            },
        )]),
        policy_reason_counts: BTreeMap::new(),
        policy_control_counts: BTreeMap::new(),
        policy_matched_domain_counts: BTreeMap::new(),
        policy_matched_domains_by_ip: BTreeMap::new(),
        connect_error_counts: BTreeMap::new(),
        runtime_failure_reason_counts: BTreeMap::new(),
        runtime_failure_phase_counts: BTreeMap::new(),
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
    }
}
