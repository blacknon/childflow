use std::time::Duration;

use anyhow::{Context, Result};

use super::super::support::{
    discover_reachable_host_ipv4, run_childflow_command, spawn_http_connect_proxy,
    spawn_local_udp_server,
};

#[test]
fn rootless_internal_proxy_only_blocks_udp_leak() -> Result<()> {
    let (server_addr, requests) = spawn_local_udp_server()?;
    let (proxy_addr, _proxy_requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--proxy-only",
        "-p",
        &format!("http://{host_ip}:{}", proxy_addr.port()),
        "--",
        "python3",
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'childflow-proxy-only', (sys.argv[1], int(sys.argv[2]))); s.close()",
        &host_ip.to_string(),
        &server_addr.port().to_string(),
    ])?;

    assert!(output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootless_internal_fail_on_leak_returns_nonzero_for_blocked_udp() -> Result<()> {
    let (server_addr, requests) = spawn_local_udp_server()?;
    let (proxy_addr, _proxy_requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--proxy-only",
        "--fail-on-leak",
        "-p",
        &format!("http://{host_ip}:{}", proxy_addr.port()),
        "--",
        "python3",
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'childflow-fail-on-leak', (sys.argv[1], int(sys.argv[2]))); s.close()",
        &host_ip.to_string(),
        &server_addr.port().to_string(),
    ])
    .context("failed to run childflow rootless-internal fail-on-leak UDP test")?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--fail-on-leak"));
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}
