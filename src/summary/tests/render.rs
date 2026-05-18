use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use crate::cli::{OutputView, ProxySpec, SummaryFormat};

use super::super::{json, text};
use super::fixtures::{make_cli, unique_temp_flow_log_path};

#[test]
fn render_run_summary_lists_active_sandbox_controls() {
    let mut cli = make_cli();
    cli.offline = true;
    cli.block_metadata = true;

    let rendered = text::render_run_summary(&cli, 7);

    assert!(rendered.contains("backend: rootless-internal"));
    assert!(rendered.contains("sandbox controls: offline, block-metadata"));
    assert!(rendered.contains("capture: disabled"));
    assert!(rendered.contains("flow-log: disabled"));
    assert!(rendered.contains("flow-log events: disabled"));
    assert!(rendered.contains("flow-log dns names: disabled"));
    assert!(rendered.contains("flow-log dns policy rows: disabled"));
    assert!(rendered.contains("flow-log top dns policy correlation: disabled"));
    assert!(rendered.contains("flow-log top target: disabled"));
    assert!(rendered.contains("flow-log policy violations: disabled"));
    assert!(rendered.contains("flow-log policy controls: disabled"));
    assert!(rendered.contains("flow-log policy matched domains: disabled"));
    assert!(rendered.contains("flow-log connect errors: disabled"));
    assert!(rendered.contains("flow-log runtime failures: disabled"));
    assert!(rendered.contains("flow-log runtime failure phases: disabled"));
    assert!(rendered.contains("exit: 7"));
}

#[test]
fn render_run_summary_expands_both_capture_outputs() {
    let mut cli = make_cli();
    cli.root = true;
    cli.output = Some(PathBuf::from("/tmp/capture.pcapng"));
    cli.flow_log = Some(PathBuf::from("/tmp/flow.jsonl"));
    cli.output_view = OutputView::Both;
    cli.proxy = Some("http://127.0.0.1:8080".parse::<ProxySpec>().unwrap());

    let rendered = text::render_run_summary(&cli, 0);

    assert!(rendered.contains("backend: rootful"));
    assert!(rendered.contains(
        "capture: requested=both, effective=child+egress, child=/tmp/capture.child.pcapng, egress=/tmp/capture.egress.pcapng"
    ));
    assert!(rendered.contains("flow-log: /tmp/flow.jsonl"));
    assert!(rendered.contains("flow-log events: unavailable"));
    assert!(rendered.contains("flow-log dns names: unavailable"));
    assert!(rendered.contains("flow-log dns policy rows: unavailable"));
    assert!(rendered.contains("flow-log top dns policy correlation: unavailable"));
    assert!(rendered.contains("flow-log top target: unavailable"));
    assert!(rendered.contains("flow-log policy violations: unavailable"));
    assert!(rendered.contains("flow-log policy controls: unavailable"));
    assert!(rendered.contains("flow-log policy matched domains: unavailable"));
    assert!(rendered.contains("flow-log connect errors: unavailable"));
    assert!(rendered.contains("flow-log runtime failures: unavailable"));
    assert!(rendered.contains("flow-log runtime failure phases: unavailable"));
    assert!(rendered.contains("command: curl https://example.com"));
}

#[test]
fn render_run_summary_lists_requested_and_effective_capture_views() {
    let mut cli = make_cli();
    cli.output = Some(PathBuf::from("/tmp/capture.pcapng"));
    cli.output_view = OutputView::WireEgress;

    let rendered = text::render_run_summary(&cli, 0);

    assert!(rendered.contains(
        "capture: requested=wire-egress, effective=wire-egress, output=/tmp/capture.pcapng"
    ));
}

#[test]
fn render_run_summary_counts_flow_log_events() {
    let mut cli = make_cli();
    let flow_log_path = unique_temp_flow_log_path("summary-flow-log");
    fs::write(
        &flow_log_path,
        concat!(
            "{\"event\":\"dns_query\",\"qname\":\"example.com\",\"ts_ms\":0}\n",
            "{\"event\":\"dns_answer\",\"qname\":\"example.com\",\"answer_ips\":[\"93.184.216.34\"],\"ts_ms\":0}\n",
            "{\"event\":\"connect_attempt\",\"ts_ms\":1}\n",
            "{\"event\":\"connect_result\",\"status\":\"error\",\"error\":\"connection refused\",\"remote_addr\":\"93.184.216.34:443\",\"ts_ms\":2}\n",
            "{\"event\":\"policy_violation\",\"reason_code\":\"deny_cidr\",\"control\":\"--deny-cidr\",\"matched_domain\":\"blocked.test\",\"ts_ms\":3}\n",
            "{\"event\":\"flow_end\",\"remote_addr\":\"93.184.216.34:443\",\"ts_ms\":4}\n",
            "{\"event\":\"runtime_failure\",\"reason_code\":\"tap_create_blocked\",\"phase\":\"child_bootstrap\",\"detail\":\"tap create failed\",\"ts_ms\":5}\n"
        ),
    )
    .unwrap();
    cli.flow_log = Some(flow_log_path.clone());

    let rendered = text::render_run_summary(&cli, 0);

    assert!(rendered.contains("flow-log events: total=7"));
    assert!(rendered.contains("connect_attempt=1"));
    assert!(rendered.contains("connect_result=1"));
    assert!(rendered.contains("dns_query=1"));
    assert!(rendered.contains("dns_answer=1"));
    assert!(rendered.contains("policy_violation=1"));
    assert!(rendered.contains("flow_end=1"));
    assert!(rendered.contains("runtime_failure=1"));
    assert!(rendered.contains(
        "flow-log dns names: example.com (queries=1, answers=1, answer_ips=93.184.216.34, targets=93.184.216.34:443 (attempts=0, ok=0, error=1, flow_end=1, matched_domains=none))"
    ));
    assert!(rendered.contains(
        "flow-log dns policy rows: example.com -> 93.184.216.34:443 (answer_ips=93.184.216.34, matched_domains=none, attempts=0, ok=0, error=1, flow_end=1)"
    ));
    assert!(rendered.contains(
        "flow-log top dns policy correlation: example.com (answer_ips=93.184.216.34, matched_domains=none, targets=93.184.216.34:443 (attempts=0, ok=0, error=1, flow_end=1, matched_domains=none))"
    ));
    assert!(rendered.contains(
        "flow-log top target: 93.184.216.34:443 (attempts=0, ok=0, error=1, flow_end=1, dns_names=example.com, matched_domains=none)"
    ));
    assert!(rendered.contains("flow-log policy violations: deny_cidr=1"));
    assert!(rendered.contains("flow-log policy controls: --deny-cidr=1"));
    assert!(rendered.contains("flow-log policy matched domains: blocked.test=1"));
    assert!(rendered.contains("flow-log connect errors: connection refused=1"));
    assert!(rendered.contains("flow-log runtime failures: tap_create_blocked=1"));
    assert!(rendered.contains("flow-log runtime failure phases: child_bootstrap=1"));

    let _ = fs::remove_file(flow_log_path);
}

#[test]
fn render_run_summary_json_emits_machine_readable_summary() {
    let mut cli = make_cli();
    cli.summary_format = SummaryFormat::Json;
    cli.output = Some(PathBuf::from("/tmp/capture.pcapng"));
    cli.output_view = OutputView::WireEgress;

    let rendered = json::render_run_summary_json(&cli, 3);
    let value: Value = serde_json::from_str(&rendered).unwrap();

    assert_eq!(value["backend"], "rootless-internal");
    assert_eq!(value["exit_code"], 3);
    assert_eq!(value["capture"]["status"], "enabled");
    assert_eq!(value["capture"]["requested"], "wire-egress");
    assert_eq!(value["capture"]["effective"], "wire-egress");
    assert_eq!(value["capture"]["output"], "/tmp/capture.pcapng");
    assert_eq!(value["flow_log"]["status"], "disabled");
    assert!(value["flow_log"]["top_dns_name"].is_null());
    assert!(value["flow_log"]["top_dns_policy_correlation"].is_null());
    assert_eq!(value["flow_log"]["dns_policy_rows"], serde_json::json!([]));
    assert_eq!(value["flow_log"]["policy_controls"], serde_json::json!([]));
}

#[test]
fn render_run_summary_json_includes_dns_policy_rows() {
    let mut cli = make_cli();
    cli.summary_format = SummaryFormat::Json;
    let flow_log_path = unique_temp_flow_log_path("summary-dns-policy-rows");
    fs::write(
        &flow_log_path,
        concat!(
            "{\"event\":\"dns_query\",\"qname\":\"example.com\",\"ts_ms\":0}\n",
            "{\"event\":\"dns_answer\",\"qname\":\"example.com\",\"answer_ips\":[\"93.184.216.34\"],\"ts_ms\":0}\n",
            "{\"event\":\"policy_violation\",\"reason_code\":\"deny_domain\",\"control\":\"--deny-domain\",\"matched_domain\":\"blocked.test\",\"remote_ip\":\"93.184.216.34\",\"ts_ms\":1}\n"
        ),
    )
    .unwrap();
    cli.flow_log = Some(flow_log_path.clone());

    let rendered = json::render_run_summary_json(&cli, 2);
    let value: Value = serde_json::from_str(&rendered).unwrap();

    assert_eq!(value["flow_log"]["status"], "available");
    assert_eq!(
        value["flow_log"]["dns_policy_rows"][0]["qname"],
        "example.com"
    );
    assert!(value["flow_log"]["dns_policy_rows"][0]["target"].is_null());
    assert_eq!(
        value["flow_log"]["dns_policy_rows"][0]["matched_domains"][0],
        serde_json::json!({"key":"blocked.test","count":1})
    );
    assert_eq!(
        value["flow_log"]["top_dns_policy_correlation"]["qname"],
        "example.com"
    );
    assert_eq!(
        value["flow_log"]["policy_controls"][0],
        serde_json::json!({"key":"--deny-domain","count":1})
    );

    let _ = fs::remove_file(flow_log_path);
}
