use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::report::{
    ConnectionTargetStats, DnsCorrelatedTarget, DnsNameStats, DnsPolicyRow, FlowLogReport,
    RankedStringCount,
};

use super::fixtures::{remove_temp_flow_log, write_temp_flow_log};

#[test]
fn flow_log_report_counts_known_and_unknown_events() -> Result<()> {
    let path = write_temp_flow_log(
        "report-counts",
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

    remove_temp_flow_log(&path);
    Ok(())
}

#[test]
fn flow_log_report_aggregates_connection_targets_and_policy_reasons() -> Result<()> {
    let path = write_temp_flow_log(
        "report-aggregation",
        concat!(
            "{\"schema_version\":1,\"event\":\"connect_attempt\",\"protocol\":\"tcp\",\"remote_addr\":\"93.184.216.34:443\",\"via_proxy\":true}\n",
            "{\"schema_version\":1,\"event\":\"connect_result\",\"protocol\":\"tcp\",\"remote_addr\":\"93.184.216.34:443\",\"via_proxy\":true,\"status\":\"ok\"}\n",
            "{\"schema_version\":1,\"event\":\"flow_end\",\"protocol\":\"tcp\",\"remote_addr\":\"93.184.216.34:443\"}\n",
            "{\"schema_version\":1,\"event\":\"connect_attempt\",\"protocol\":\"tcp\",\"remote_addr\":\"198.51.100.7:8443\",\"via_proxy\":false}\n",
            "{\"schema_version\":1,\"event\":\"connect_result\",\"protocol\":\"tcp\",\"remote_addr\":\"198.51.100.7:8443\",\"via_proxy\":false,\"status\":\"error\",\"error\":\"connection refused\"}\n",
            "{\"schema_version\":1,\"event\":\"policy_violation\",\"protocol\":\"tcp\",\"remote\":\"10.0.0.1:443\",\"reason_code\":\"deny_cidr\",\"control\":\"--deny-cidr\",\"matched_domain\":\"blocked.test\"}\n"
        ),
    )?;

    let report = FlowLogReport::from_path(&path)?;
    assert_eq!(report.proxied_connect_attempts, 1);
    assert_eq!(report.direct_connect_attempts, 1);
    assert_eq!(report.policy_reason_counts.get("deny_cidr"), Some(&1));
    assert_eq!(report.policy_control_counts.get("--deny-cidr"), Some(&1));
    assert_eq!(
        report.policy_matched_domain_counts.get("blocked.test"),
        Some(&1)
    );
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

    remove_temp_flow_log(&path);
    Ok(())
}

#[test]
fn flow_log_report_aggregates_dns_names() -> Result<()> {
    let path = write_temp_flow_log(
        "report-dns-names",
        concat!(
            "{\"schema_version\":1,\"event\":\"dns_query\",\"protocol\":\"udp\",\"qname\":\"example.com\"}\n",
            "{\"schema_version\":1,\"event\":\"dns_answer\",\"protocol\":\"udp\",\"qname\":\"example.com\",\"answer_ips\":[\"93.184.216.34\"]}\n",
            "{\"schema_version\":1,\"event\":\"connect_result\",\"protocol\":\"tcp\",\"remote_addr\":\"93.184.216.34:443\",\"remote_ip\":\"93.184.216.34\",\"remote_port\":443,\"status\":\"ok\"}\n",
            "{\"schema_version\":1,\"event\":\"flow_end\",\"protocol\":\"tcp\",\"remote_addr\":\"93.184.216.34:443\",\"remote_ip\":\"93.184.216.34\",\"remote_port\":443}\n",
            "{\"schema_version\":1,\"event\":\"dns_query\",\"protocol\":\"udp\",\"qname\":\"api.example.com\"}\n",
            "{\"schema_version\":1,\"event\":\"dns_query\",\"protocol\":\"udp\",\"qname\":\"example.com\"}\n"
        ),
    )?;

    let report = FlowLogReport::from_path(&path)?;
    assert_eq!(
        report.dns_name_counts.get("example.com"),
        Some(&DnsNameStats {
            queries: 2,
            answers: 1,
            answer_ips: BTreeSet::from(["93.184.216.34".into()]),
        })
    );
    assert_eq!(
        report
            .top_dns_names(2)
            .into_iter()
            .map(|(qname, _)| qname)
            .collect::<Vec<_>>(),
        vec!["example.com", "api.example.com"]
    );
    assert_eq!(
        report.render_top_dns_name_compact(),
        "example.com (queries=2, answers=1, answer_ips=93.184.216.34, targets=93.184.216.34:443 (attempts=0, ok=1, error=0, flow_end=1, matched_domains=none))"
    );
    assert_eq!(
        report.dns_names_for_target("93.184.216.34:443"),
        vec!["example.com".to_string()]
    );
    assert_eq!(
        report.correlated_targets_for_dns_name("example.com", 2),
        vec![DnsCorrelatedTarget {
            target: "93.184.216.34:443".to_string(),
            connect_attempts: 0,
            connect_ok: 1,
            connect_error: 0,
            flow_end: 1,
            matched_domains: Vec::new(),
        }]
    );

    remove_temp_flow_log(&path);
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
        dns_name_counts: BTreeMap::from([(
            "example.com".into(),
            DnsNameStats {
                queries: 1,
                answers: 1,
                answer_ips: BTreeSet::from(["93.184.216.34".into()]),
            },
        )]),
        policy_reason_counts: BTreeMap::from([("deny_cidr".into(), 2), ("proxy_only".into(), 1)]),
        policy_matched_domain_counts: BTreeMap::from([
            ("blocked.test".into(), 2),
            ("example.com".into(), 1),
        ]),
        policy_matched_domains_by_ip: BTreeMap::from([(
            "93.184.216.34".into(),
            BTreeMap::from([("blocked.test".into(), 2), ("example.com".into(), 1)]),
        )]),
        connect_error_counts: BTreeMap::from([
            ("connection refused".into(), 2),
            ("timed out".into(), 1),
        ]),
        runtime_failure_reason_counts: BTreeMap::from([
            ("tap_create_blocked".into(), 1),
            ("runtime_shutdown_failed".into(), 1),
        ]),
        runtime_failure_phase_counts: BTreeMap::from([
            ("child_bootstrap".into(), 1),
            ("run".into(), 1),
        ]),
        connection_targets: BTreeMap::from([(
            "93.184.216.34:443".into(),
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
        "93.184.216.34:443 (attempts=3, ok=1, error=2, flow_end=1, dns_names=example.com, matched_domains=blocked.test=2, example.com=1)"
    );
    assert_eq!(
        report.render_top_dns_name_compact(),
        "example.com (queries=1, answers=1, answer_ips=93.184.216.34, targets=93.184.216.34:443 (attempts=3, ok=1, error=2, flow_end=1, matched_domains=blocked.test=2, example.com=1))"
    );
    assert_eq!(
        report
            .matched_domain_entries_for_dns_name("example.com", 3)
            .into_iter()
            .map(|entry| (entry.key, entry.count))
            .collect::<Vec<_>>(),
        vec![
            ("blocked.test".to_string(), 2),
            ("example.com".to_string(), 1),
        ]
    );
    assert_eq!(
        report.render_policy_violations_compact(2),
        "deny_cidr=2, proxy_only=1"
    );
    assert_eq!(
        report.render_policy_matched_domains_compact(2),
        "blocked.test=2, example.com=1"
    );
    assert_eq!(
        report.render_connect_errors_compact(2),
        "connection refused=2, timed out=1"
    );
    assert_eq!(
        report.render_runtime_failures_compact(2),
        "runtime_shutdown_failed=1, tap_create_blocked=1"
    );
    assert_eq!(
        report.render_runtime_failure_phases_compact(2),
        "child_bootstrap=1, run=1"
    );
}

#[test]
fn flow_log_report_flattens_dns_policy_rows_without_target() {
    let report = FlowLogReport {
        dns_name_counts: BTreeMap::from([(
            "example.com".into(),
            DnsNameStats {
                queries: 1,
                answers: 1,
                answer_ips: BTreeSet::from(["93.184.216.34".into()]),
            },
        )]),
        policy_matched_domain_counts: BTreeMap::from([("blocked.test".into(), 1)]),
        policy_matched_domains_by_ip: BTreeMap::from([(
            "93.184.216.34".into(),
            BTreeMap::from([("blocked.test".into(), 1)]),
        )]),
        ..Default::default()
    };

    assert_eq!(
        report.top_dns_policy_rows(10, 3),
        vec![DnsPolicyRow {
            qname: "example.com".to_string(),
            queries: 1,
            answers: 1,
            answer_ips: vec!["93.184.216.34".to_string()],
            target: None,
            target_ip: None,
            connect_attempts: 0,
            connect_ok: 0,
            connect_error: 0,
            flow_end: 0,
            matched_domains: vec![RankedStringCount {
                key: "blocked.test".to_string(),
                count: 1,
            }],
        }]
    );
}

#[test]
fn flow_log_report_counts_runtime_failures() -> Result<()> {
    let path = write_temp_flow_log(
        "report-runtime-failures",
        concat!(
            "{\"schema_version\":1,\"event\":\"runtime_failure\",\"phase\":\"child_bootstrap\",\"reason_code\":\"tap_create_blocked\",\"detail\":\"tap create failed\"}\n",
            "{\"schema_version\":1,\"event\":\"runtime_failure\",\"phase\":\"run\",\"reason_code\":\"runtime_shutdown_failed\",\"detail\":\"shutdown failed\"}\n"
        ),
    )?;

    let report = FlowLogReport::from_path(&path)?;
    assert_eq!(report.runtime_failure, 2);
    assert_eq!(
        report
            .runtime_failure_reason_counts
            .get("tap_create_blocked"),
        Some(&1)
    );
    assert_eq!(
        report
            .runtime_failure_reason_counts
            .get("runtime_shutdown_failed"),
        Some(&1)
    );
    assert_eq!(
        report.runtime_failure_phase_counts.get("child_bootstrap"),
        Some(&1)
    );
    assert_eq!(report.runtime_failure_phase_counts.get("run"), Some(&1));

    remove_temp_flow_log(&path);
    Ok(())
}
