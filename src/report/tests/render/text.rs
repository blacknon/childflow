use std::path::Path;

use anyhow::Result;

use crate::report::FlowLogReport;

use super::super::fixtures::minimal_render_report;

#[test]
fn flow_log_report_renders_text_output() -> Result<()> {
    let report: FlowLogReport = minimal_render_report();

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
