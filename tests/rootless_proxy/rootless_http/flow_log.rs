use std::time::Duration;

use anyhow::{Context, Result};

use crate::support::{
    discover_reachable_host_ipv4, run_childflow_command, spawn_local_http_server,
    unique_temp_flow_log_path,
};

#[test]
fn rootless_internal_writes_flow_log_for_local_http() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-flow-log-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let flow_log_path = unique_temp_flow_log_path("rootless-local-http-flow");

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal flow-log smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-flow-log-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(Duration::from_secs(5))
            .context("local HTTP server did not receive a request from the flow-log run")?,
        "GET /hello HTTP/1.1"
    );

    let flow_log = std::fs::read_to_string(&flow_log_path)
        .with_context(|| format!("failed to read {}", flow_log_path.display()))?;
    assert!(flow_log.contains("\"schema_version\":1"));
    assert!(flow_log.contains("\"event\":\"connect_attempt\""));
    assert!(flow_log.contains("\"protocol\":\"tcp\""));
    assert!(flow_log.contains(&format!("\"remote_ip\":\"{host_ip}\"")));
    assert!(flow_log.contains(&format!("\"remote_port\":{}", server_addr.port())));
    assert!(flow_log.contains("\"event\":\"connect_result\""));
    assert!(flow_log.contains("\"event\":\"flow_end\""));

    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_writes_policy_violation_to_flow_log() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-flow-log-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let host_cidr = format!("{host_ip}/32");
    let flow_log_path = unique_temp_flow_log_path("rootless-policy-violation");

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--deny-cidr",
        &host_cidr,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal policy-violation flow-log test")?;

    assert!(
        !output.status.success(),
        "expected deny-cidr childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        requests.recv_timeout(Duration::from_millis(500)).is_err(),
        "deny-cidr sandbox unexpectedly reached the local HTTP server"
    );

    let flow_log = std::fs::read_to_string(&flow_log_path)
        .with_context(|| format!("failed to read {}", flow_log_path.display()))?;
    assert!(flow_log.contains("\"event\":\"policy_violation\""));
    assert!(flow_log.contains("\"schema_version\":1"));
    assert!(flow_log.contains("\"protocol\":\"tcp\""));
    assert!(flow_log.contains("\"action\":\"deny\""));
    assert!(flow_log.contains("\"reason_code\":\"deny_cidr\""));
    assert!(flow_log.contains("\"control\":\"--deny-cidr\""));
    assert!(flow_log.contains(&format!("\"matched_cidr\":\"{host_cidr}\"")));

    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}
