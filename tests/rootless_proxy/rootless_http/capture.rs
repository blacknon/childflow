use std::time::Duration;

use anyhow::{Context, Result};

use crate::support::{
    assert_capture_file_written, assert_capture_has_enhanced_packets, discover_reachable_host_ipv4,
    run_childflow_command, spawn_http_connect_proxy, spawn_local_http_server,
    unique_temp_capture_path,
};

#[test]
fn rootless_internal_reaches_local_http_server_and_writes_capture() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-local-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let output_path = unique_temp_capture_path("rootless-local-http");

    let output = run_childflow_command(&[
        "-c",
        output_path.to_str().unwrap(),
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal local HTTP smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-local-ok"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("childflow summary"));
    assert_eq!(
        requests
            .recv_timeout(Duration::from_secs(5))
            .context("local HTTP server did not receive a request from the childflow run")?,
        "GET /hello HTTP/1.1"
    );

    assert_capture_file_written(&output_path)?;
    assert_capture_has_enhanced_packets(&output_path, 4)?;
    let _ = std::fs::remove_file(&output_path);
    Ok(())
}

#[test]
fn rootless_internal_proxy_and_dns_override_write_capture_for_local_http() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-proxy-dns-ok")?;
    let (proxy_addr, proxy_requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;
    let output_path = unique_temp_capture_path("rootless-local-proxy-dns");

    let output = run_childflow_command(&[
        "-c",
        output_path.to_str().unwrap(),
        "-d",
        "1.1.1.1",
        "-p",
        &format!("http://{host_ip}:{}", proxy_addr.port()),
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal local relay proxy + DNS override smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-proxy-dns-ok"
    );
    assert_eq!(
        proxy_requests
            .recv_timeout(Duration::from_secs(5))
            .context("proxy did not receive a CONNECT request from the proxy + DNS override run")?,
        format!("CONNECT {host_ip}:{} HTTP/1.1", server_addr.port())
    );
    assert_eq!(
        requests.recv_timeout(Duration::from_secs(5)).context(
            "local HTTP server did not receive a request from the proxy + DNS override run"
        )?,
        "GET /hello HTTP/1.1"
    );

    assert_capture_file_written(&output_path)?;
    assert_capture_has_enhanced_packets(&output_path, 4)?;
    let _ = std::fs::remove_file(&output_path);
    Ok(())
}
