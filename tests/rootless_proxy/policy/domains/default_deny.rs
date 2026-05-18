use std::time::Duration;

use anyhow::Result;

use crate::support::{
    discover_reachable_host_ipv4, run_childflow_command, spawn_local_http_server,
    unique_loopback_dns_ip, unique_temp_flow_log_path, LocalDnsServer,
};

#[test]
fn rootless_internal_default_deny_blocks_subdomain_when_only_exact_domain_allowed() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-allow-domain-exact-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "api.allowed.test", host_ip)?;
    let flow_log_path = unique_temp_flow_log_path("rootless-allow-domain-exact-subdomain");

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--default-policy",
        "deny",
        "--allow-domain-exact",
        "allowed.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://api.allowed.test:{}/hello", server_addr.port()),
    ])?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());

    let flow_log = std::fs::read_to_string(&flow_log_path)?;
    assert!(flow_log.contains("\"event\":\"policy_violation\""));
    assert!(flow_log.contains("\"protocol\":\"dns\""));
    assert!(flow_log.contains("\"reason_code\":\"default_deny\""));
    assert!(flow_log.contains("\"control\":\"--default-policy\""));
    assert!(flow_log.contains("\"remote\":\"api.allowed.test\""));
    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_default_deny_blocks_unmatched_domain_query() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-default-deny-domain-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "blocked.test", host_ip)?;
    let flow_log_path = unique_temp_flow_log_path("rootless-default-deny-domain");

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--default-policy",
        "deny",
        "--allow-domain",
        "allowed.test",
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
    assert!(flow_log.contains("\"reason_code\":\"default_deny\""));
    assert!(flow_log.contains("\"remote\":\"blocked.test\""));
    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}
