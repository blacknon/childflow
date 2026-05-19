use std::time::Duration;

use anyhow::Result;

use super::super::support::{
    discover_reachable_host_ipv4, run_childflow_command, spawn_local_http_server,
};

#[test]
fn rootless_internal_offline_blocks_local_http() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-offline-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--offline",
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootless_internal_block_private_blocks_local_http() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-private-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--block-private",
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootless_internal_default_deny_blocks_local_http() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-default-deny-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--default-policy",
        "deny",
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootless_internal_default_deny_allows_explicit_cidr() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-allow-cidr-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let host_cidr = format!("{host_ip}/32");

    let output = run_childflow_command(&[
        "--default-policy",
        "deny",
        "--allow-cidr",
        &host_cidr,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-allow-cidr-ok"
    );
    assert_eq!(
        requests.recv_timeout(Duration::from_secs(5))?,
        "GET /hello HTTP/1.1"
    );
    Ok(())
}

#[test]
fn rootless_internal_deny_cidr_blocks_local_http() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-deny-cidr-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let host_cidr = format!("{host_ip}/32");

    let output = run_childflow_command(&[
        "--deny-cidr",
        &host_cidr,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}
