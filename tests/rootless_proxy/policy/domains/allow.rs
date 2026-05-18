use std::time::Duration;

use anyhow::Result;

use crate::support::{
    discover_reachable_host_ipv4, run_childflow_command, spawn_local_http_server,
    unique_loopback_dns_ip, LocalDnsServer,
};

#[test]
fn rootless_internal_default_deny_allows_explicit_domain() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-allow-domain-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "allowed.test", host_ip)?;

    let output = run_childflow_command(&[
        "--default-policy",
        "deny",
        "--allow-domain",
        "allowed.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://allowed.test:{}/hello", server_addr.port()),
    ])?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-allow-domain-ok"
    );
    assert_eq!(
        requests.recv_timeout(Duration::from_secs(5))?,
        "GET /hello HTTP/1.1"
    );
    Ok(())
}

#[test]
fn rootless_internal_default_deny_allows_subdomain_of_explicit_domain() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-allow-domain-subdomain-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "api.allowed.test", host_ip)?;

    let output = run_childflow_command(&[
        "--default-policy",
        "deny",
        "--allow-domain",
        "allowed.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://api.allowed.test:{}/hello", server_addr.port()),
    ])?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-allow-domain-subdomain-ok"
    );
    assert_eq!(
        requests.recv_timeout(Duration::from_secs(5))?,
        "GET /hello HTTP/1.1"
    );
    Ok(())
}

#[test]
fn rootless_internal_default_deny_allows_explicit_exact_domain() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-allow-domain-exact-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "allowed.test", host_ip)?;

    let output = run_childflow_command(&[
        "--default-policy",
        "deny",
        "--allow-domain-exact",
        "allowed.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://allowed.test:{}/hello", server_addr.port()),
    ])?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-allow-domain-exact-ok"
    );
    assert_eq!(
        requests.recv_timeout(Duration::from_secs(5))?,
        "GET /hello HTTP/1.1"
    );
    Ok(())
}
