use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Result;
use serde_json::Value;

use crate::report::{ConnectionTargetStats, DnsNameStats, FlowLogReport};

use super::fixtures::minimal_render_report;

#[test]
fn flow_log_report_renders_text_output() -> Result<()> {
    let report = minimal_render_report();

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
    assert!(rendered.contains("top-dns-names:"));
    assert!(rendered.contains("example.com: queries=1, answers=1, answer_ips=93.184.216.34"));
    assert!(rendered.contains("dns-target-correlations:"));
    assert!(rendered.contains(
        "example.com: answer_ips=93.184.216.34, targets=93.184.216.34:443 (attempts=1, ok=1, error=0, flow_end=0, matched_domains=none)"
    ));
    assert!(rendered.contains(
        "dns-policy-correlations:\n  example.com: answer_ips=93.184.216.34, matched_domains=none, targets=93.184.216.34:443 (attempts=1, ok=1, error=0, flow_end=0, matched_domains=none)"
    ));
    assert!(rendered.contains("proxy-usage:"));
    assert!(rendered.contains("proxied_connect_attempts: 1"));
    assert!(rendered.contains("policy-matched-domains:\n  <none>"));
    assert!(rendered.contains("connect-errors:\n  <none>"));
    assert!(rendered.contains("runtime-failures:\n  <none>"));
    assert!(rendered.contains("runtime-failure-phases:\n  <none>"));
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
        dns_name_counts: BTreeMap::from([(
            "example.com".into(),
            DnsNameStats {
                queries: 2,
                answers: 1,
                answer_ips: BTreeSet::from(["93.184.216.34".into()]),
            },
        )]),
        policy_reason_counts: BTreeMap::from([("proxy_only".into(), 1)]),
        policy_control_counts: BTreeMap::from([("--proxy-only".into(), 1)]),
        policy_matched_domain_counts: BTreeMap::from([("blocked.test".into(), 1)]),
        policy_matched_domains_by_ip: BTreeMap::from([(
            "93.184.216.34".into(),
            BTreeMap::from([("blocked.test".into(), 1)]),
        )]),
        connect_error_counts: BTreeMap::from([("connection refused".into(), 2)]),
        runtime_failure_reason_counts: BTreeMap::from([("tap_create_blocked".into(), 1)]),
        runtime_failure_phase_counts: BTreeMap::from([("child_bootstrap".into(), 1)]),
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
    assert!(rendered.contains("## Highlights"));
    assert!(rendered.contains(
        "- top connection target: `93.184.216.34:443` (attempts=1, ok=1, error=0, flow_end=0, dns_names=example.com, matched_domains=blocked.test=1)"
    ));
    assert!(rendered.contains(
        "- top DNS name: `example.com` (queries=2, answers=1, answer_ips=93.184.216.34, targets=93.184.216.34:443 (attempts=1, ok=1, error=0, flow_end=0, matched_domains=blocked.test=1))"
    ));
    assert!(rendered.contains(
        "- top DNS target correlation: `example.com` -> 93.184.216.34:443 (attempts=1, ok=1, error=0, flow_end=0, matched_domains=blocked.test=1)"
    ));
    assert!(rendered.contains(
        "- top DNS policy correlation: `example.com` (answer_ips=93.184.216.34, matched_domains=blocked.test=1, targets=93.184.216.34:443 (attempts=1, ok=1, error=0, flow_end=0, matched_domains=blocked.test=1))"
    ));
    assert!(rendered.contains("- most common policy violation: `proxy_only` (1)"));
    assert!(rendered.contains("- most common policy control: `--proxy-only` (1)"));
    assert!(rendered.contains("- most common matched domain: `blocked.test` (1)"));
    assert!(rendered.contains("- most common connect error: `connection refused` (2)"));
    assert!(rendered.contains("- most common runtime failure: `tap_create_blocked` (1)"));
    assert!(rendered.contains("- most common runtime failure phase: `child_bootstrap` (1)"));
    assert!(rendered.contains("## DNS overview"));
    assert!(rendered.contains(
        "- top DNS target correlation: example.com -> 93.184.216.34:443 (attempts=1, ok=1, error=0, flow_end=0, matched_domains=blocked.test=1)"
    ));
    assert!(rendered.contains("## Policy overview"));
    assert!(rendered.contains("- policy violations: proxy_only=1"));
    assert!(rendered.contains("- policy controls: --proxy-only=1"));
    assert!(rendered.contains("- matched domains: blocked.test=1"));
    assert!(rendered.contains("## Runtime overview"));
    assert!(rendered.contains("- connect errors: connection refused=2"));
    assert!(rendered.contains("- runtime failures: tap_create_blocked=1"));
    assert!(rendered.contains("- runtime failure phases: child_bootstrap=1"));
    assert!(rendered.contains("| total | 3 |"));
    assert!(rendered.contains("| runtime_failure | 1 |"));
    assert!(rendered.contains("| tcp | 3 |"));
    assert!(rendered.contains("| `example.com` | 2 | 1 | 93.184.216.34 |"));
    assert!(rendered.contains(
        "| `example.com` | 93.184.216.34 | 93.184.216.34:443 (attempts=1, ok=1, error=0, flow_end=0, matched_domains=blocked.test=1) |"
    ));
    assert!(rendered.contains(
        "| `example.com` | 93.184.216.34 | blocked.test=1 | 93.184.216.34:443 (attempts=1, ok=1, error=0, flow_end=0, matched_domains=blocked.test=1) |"
    ));
    assert!(rendered.contains("| proxy_only | 1 |"));
    assert!(rendered.contains("| `--proxy-only` | 1 |"));
    assert!(rendered.contains("| `blocked.test` | 1 |"));
    assert!(rendered.contains("| connection refused | 2 |"));
    assert!(rendered.contains("| tap_create_blocked | 1 |"));
    assert!(rendered.contains("| child_bootstrap | 1 |"));
    assert!(
        rendered.contains("| `93.184.216.34:443` | 1 | 1 | 0 | 0 | example.com | blocked.test=1 |")
    );
    Ok(())
}

#[test]
fn flow_log_report_renders_json_output() -> Result<()> {
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
        dns_name_counts: BTreeMap::from([(
            "example.com".into(),
            DnsNameStats {
                queries: 2,
                answers: 1,
                answer_ips: BTreeSet::from(["93.184.216.34".into()]),
            },
        )]),
        policy_reason_counts: BTreeMap::from([("proxy_only".into(), 1)]),
        policy_control_counts: BTreeMap::from([("--proxy-only".into(), 1)]),
        policy_matched_domain_counts: BTreeMap::from([("blocked.test".into(), 1)]),
        policy_matched_domains_by_ip: BTreeMap::from([(
            "93.184.216.34".into(),
            BTreeMap::from([("blocked.test".into(), 1)]),
        )]),
        connect_error_counts: BTreeMap::from([("connection refused".into(), 2)]),
        runtime_failure_reason_counts: BTreeMap::from([("tap_create_blocked".into(), 1)]),
        runtime_failure_phase_counts: BTreeMap::from([("child_bootstrap".into(), 1)]),
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

    let rendered = report.render_json(Path::new("/tmp/flow.jsonl"))?;
    let json: Value = serde_json::from_str(&rendered)?;
    assert_eq!(json["flow_log"], "/tmp/flow.jsonl");
    assert_eq!(json["schema_versions"], serde_json::json!([1]));
    assert_eq!(json["event_counts"]["total"], 3);
    assert_eq!(json["protocols"]["tcp"], 3);
    assert_eq!(
        json["sorted_protocols"][0],
        serde_json::json!({"key":"tcp","count":3})
    );
    assert_eq!(
        json["top_dns_names"][0],
        serde_json::json!({"qname":"example.com","queries":2,"answers":1,"answer_ips":["93.184.216.34"]})
    );
    assert_eq!(
        json["dns_target_correlations"][0]["targets"][0]["target"],
        "93.184.216.34:443"
    );
    assert_eq!(
        json["dns_policy_correlations"][0]["matched_domains"][0],
        serde_json::json!({"key":"blocked.test","count":1})
    );
    assert_eq!(json["dns_policy_rows"][0]["qname"], "example.com");
    assert_eq!(json["dns_policy_rows"][0]["target"], "93.184.216.34:443");
    assert_eq!(json["dns_policy_rows"][0]["target_ip"], "93.184.216.34");
    assert_eq!(
        json["dns_policy_rows"][0]["matched_domains"][0],
        serde_json::json!({"key":"blocked.test","count":1})
    );
    assert_eq!(
        json["top_connection_targets"][0]["dns_names"],
        serde_json::json!(["example.com"])
    );
    assert_eq!(
        json["top_connection_targets"][0]["matched_domains"][0],
        serde_json::json!({"key":"blocked.test","count":1})
    );
    assert_eq!(json["proxy_usage"]["proxied_connect_attempts"], 1);
    assert_eq!(json["policy_violations"]["proxy_only"], 1);
    assert_eq!(json["policy_controls"]["--proxy-only"], 1);
    assert_eq!(
        json["sorted_policy_violations"][0],
        serde_json::json!({"key":"proxy_only","count":1})
    );
    assert_eq!(
        json["sorted_policy_controls"][0],
        serde_json::json!({"key":"--proxy-only","count":1})
    );
    assert_eq!(json["policy_matched_domains"]["blocked.test"], 1);
    assert_eq!(
        json["sorted_policy_matched_domains"][0],
        serde_json::json!({"key":"blocked.test","count":1})
    );
    assert_eq!(json["connect_errors"]["connection refused"], 2);
    assert_eq!(
        json["sorted_connect_errors"][0],
        serde_json::json!({"key":"connection refused","count":2})
    );
    assert_eq!(json["runtime_failures"]["tap_create_blocked"], 1);
    assert_eq!(
        json["sorted_runtime_failures"][0],
        serde_json::json!({"key":"tap_create_blocked","count":1})
    );
    assert_eq!(json["runtime_failure_phases"]["child_bootstrap"], 1);
    assert_eq!(
        json["sorted_runtime_failure_phases"][0],
        serde_json::json!({"key":"child_bootstrap","count":1})
    );
    assert_eq!(
        json["top_connection_targets"][0]["target"],
        "93.184.216.34:443"
    );
    Ok(())
}
