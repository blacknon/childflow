use std::time::Duration;

use anyhow::{Context, Result};

use crate::support::{
    discover_reachable_host_ipv4, run_childflow_command, spawn_http_connect_proxy,
    spawn_local_http_server,
};

#[test]
fn rootless_internal_routes_local_http_through_relay_proxy() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-proxy-ok")?;
    let (proxy_addr, proxy_requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "-p",
        &format!("http://{host_ip}:{}", proxy_addr.port()),
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal local relay proxy smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-proxy-ok"
    );
    assert_eq!(
        proxy_requests
            .recv_timeout(Duration::from_secs(5))
            .context("proxy did not receive a CONNECT request from the childflow run")?,
        format!("CONNECT {host_ip}:{} HTTP/1.1", server_addr.port())
    );
    assert_eq!(
        requests
            .recv_timeout(Duration::from_secs(5))
            .context("local HTTP server did not receive a request from the proxied run")?,
        "GET /hello HTTP/1.1"
    );

    Ok(())
}

#[test]
fn rootless_internal_proxy_only_allows_local_http_through_relay_proxy() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-proxy-only-ok")?;
    let (proxy_addr, proxy_requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--proxy-only",
        "-p",
        &format!("http://{host_ip}:{}", proxy_addr.port()),
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal proxy-only relay proxy smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-proxy-only-ok"
    );
    assert_eq!(
        proxy_requests
            .recv_timeout(Duration::from_secs(5))
            .context("proxy did not receive a CONNECT request from the proxy-only childflow run")?,
        format!("CONNECT {host_ip}:{} HTTP/1.1", server_addr.port())
    );
    assert_eq!(
        requests.recv_timeout(Duration::from_secs(5)).context(
            "local HTTP server did not receive a request from the proxy-only proxied run"
        )?,
        "GET /hello HTTP/1.1"
    );

    Ok(())
}
