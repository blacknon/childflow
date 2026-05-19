use std::time::Duration;

use anyhow::Result;

use crate::support::{
    run_childflow_command, spawn_local_http_server, unique_loopback_dns_ip,
    unique_temp_flow_log_path,
};

#[test]
fn rootless_internal_deny_domain_blocks_subdomain_via_dns_resolution() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-deny-domain-subdomain-should-not-connect")?;
    let flow_log_path = unique_temp_flow_log_path("rootless-deny-domain-subdomain");
    let dns_bind_ip = unique_loopback_dns_ip();

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--deny-domain",
        "blocked.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://api.blocked.test:{}/hello", server_addr.port()),
    ])?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());

    let flow_log = std::fs::read_to_string(&flow_log_path)?;
    assert!(flow_log.contains("\"reason_code\":\"deny_domain\""));
    assert!(flow_log.contains("\"matched_domain\":\"blocked.test\""));
    assert!(flow_log.contains("\"remote\":\"api.blocked.test\""));
    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_deny_domain_blocks_local_http_via_dns_resolution() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-deny-domain-should-not-connect")?;
    let flow_log_path = unique_temp_flow_log_path("rootless-deny-domain");
    let dns_bind_ip = unique_loopback_dns_ip();

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--deny-domain",
        "blocked.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://blocked.test:{}/hello", server_addr.port()),
    ])?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());

    let flow_log = std::fs::read_to_string(&flow_log_path)?;
    assert!(flow_log.contains("\"reason_code\":\"deny_domain\""));
    assert!(flow_log.contains("\"matched_domain\":\"blocked.test\""));
    assert!(flow_log.contains("\"remote\":\"blocked.test\""));
    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_deny_domain_exact_blocks_local_http_via_dns_resolution() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-deny-domain-exact-should-not-connect")?;
    let flow_log_path = unique_temp_flow_log_path("rootless-deny-domain-exact");
    let dns_bind_ip = unique_loopback_dns_ip();

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--deny-domain-exact",
        "blocked.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://blocked.test:{}/hello", server_addr.port()),
    ])?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());

    let flow_log = std::fs::read_to_string(&flow_log_path)?;
    assert!(flow_log.contains("\"reason_code\":\"deny_domain_exact\""));
    assert!(flow_log.contains("\"matched_domain\":\"blocked.test\""));
    assert!(flow_log.contains("\"remote\":\"blocked.test\""));
    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}
