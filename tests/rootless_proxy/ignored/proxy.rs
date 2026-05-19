use std::process::Command;

use anyhow::{Context, Result};

use crate::support::{
    assert_connects_to_https_target, discover_reachable_host_ipv4, spawn_http_connect_proxy,
};

#[test]
#[ignore = "requires privileged linux namespaces, outbound network access, curl, and a local proxy listener"]
fn rootless_internal_routes_https_through_relay_http_proxy() -> Result<()> {
    let (proxy_addr, requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = Command::new(env!("CARGO_BIN_EXE_childflow"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--network-backend",
            "rootless-internal",
            "-p",
            &format!("http://{host_ip}:{}", proxy_addr.port()),
            "--",
            "curl",
            "-fsSL",
            "--max-time",
            "30",
            "https://example.com",
        ])
        .output()
        .context("failed to run childflow rootless-internal proxy smoke test")?;

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Example Domain"));
    assert_connects_to_https_target(&requests.recv_timeout(std::time::Duration::from_secs(5))?);
    Ok(())
}

#[test]
#[ignore = "requires privileged linux namespaces, outbound network access, curl, and a local proxy listener"]
fn rootless_internal_proxy_works_with_dns_override() -> Result<()> {
    let (proxy_addr, requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = Command::new(env!("CARGO_BIN_EXE_childflow"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--network-backend",
            "rootless-internal",
            "-d",
            "1.1.1.1",
            "-p",
            &format!("http://{host_ip}:{}", proxy_addr.port()),
            "--",
            "curl",
            "-fsSL",
            "--max-time",
            "30",
            "https://example.com",
        ])
        .output()
        .context("failed to run childflow rootless-internal proxy + DNS override smoke test")?;

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Example Domain"));
    assert_connects_to_https_target(&requests.recv_timeout(std::time::Duration::from_secs(5))?);
    Ok(())
}

#[test]
#[ignore = "requires privileged linux namespaces, outbound network access, busybox, and a local proxy listener"]
fn rootless_internal_routes_single_binary_client_through_relay_proxy() -> Result<()> {
    let (proxy_addr, requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = Command::new(env!("CARGO_BIN_EXE_childflow"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--network-backend",
            "rootless-internal",
            "-p",
            &format!("http://{host_ip}:{}", proxy_addr.port()),
            "--",
            "/bin/busybox",
            "wget",
            "-O",
            "/dev/stdout",
            "http://example.com",
        ])
        .output()
        .context("failed to run childflow rootless-internal single-binary proxy smoke test")?;

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Example Domain"));
    let request_line = requests.recv_timeout(std::time::Duration::from_secs(5))?;
    assert!(request_line.starts_with("CONNECT ") && request_line.ends_with(":80 HTTP/1.1"));
    Ok(())
}
