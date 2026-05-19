use std::time::Duration;

use anyhow::{Context, Result};

use super::support::{
    assert_capture_file_written, discover_reachable_host_ipv4, list_childflow_transient_links,
    run_childflow_command, spawn_http_connect_proxy, spawn_local_http_server,
    spawn_local_tcp_server, spawn_local_udp_server, unique_loopback_dns_ip,
    unique_temp_capture_path, LocalDnsServer,
};

#[test]
fn rootful_default_deny_blocks_local_http() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-rootful-default-deny-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--root",
        "--default-policy",
        "deny",
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootful default-deny smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootful_default_deny_blocks_local_udp() -> Result<()> {
    let (server_addr, requests) = spawn_local_udp_server()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--root",
        "--default-policy",
        "deny",
        "--",
        "python3",
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'childflow-rootful-default-deny-udp', (sys.argv[1], int(sys.argv[2]))); s.close()",
        &host_ip.to_string(),
        &server_addr.port().to_string(),
    ])
    .context("failed to run childflow rootful default-deny UDP smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootful_default_deny_blocks_local_https_connect() -> Result<()> {
    let (server_addr, accepts) = spawn_local_tcp_server()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--root",
        "--default-policy",
        "deny",
        "--",
        "python3",
        "-c",
        "import socket,sys; s=socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5); s.sendall(b'childflow-rootful-deny-tcp'); s.close()",
        &host_ip.to_string(),
        &server_addr.port().to_string(),
    ])
    .context("failed to run childflow rootful default-deny TCP smoke test")?;

    assert!(!output.status.success());
    assert!(accepts.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootful_doctor_json_reports_rootful_backend() -> Result<()> {
    let output = run_childflow_command(&["--root", "--doctor", "--doctor-format", "json"])
        .context("failed to run childflow rootful doctor json smoke test")?;

    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("failed to parse rootful doctor json output")?;
    assert_eq!(report["backend"], "rootful");
    assert!(report["status"].is_string());
    assert!(report["capabilities"].is_array());
    assert!(report["preflight"].is_array());
    Ok(())
}

#[test]
fn rootful_doctor_text_reports_rootful_backend() -> Result<()> {
    let output = run_childflow_command(&["--root", "--doctor"])
        .context("failed to run childflow rootful doctor text smoke test")?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("childflow doctor"));
    assert!(stdout.contains("backend: rootful"));
    assert!(stdout.contains("status:"));
    assert!(stdout.contains("capabilities"));
    assert!(stdout.contains("preflight"));
    Ok(())
}

#[test]
fn rootful_cleanup_removes_transient_links_after_run() -> Result<()> {
    let before = list_childflow_transient_links()?;
    let (server_addr, requests) =
        spawn_local_http_server("childflow-rootful-cleanup-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--root",
        "--default-policy",
        "deny",
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootful cleanup smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    let after = list_childflow_transient_links()?;
    assert_eq!(after, before, "rootful run leaked transient links");
    Ok(())
}

#[test]
fn rootful_failed_setup_rolls_back_transient_links() -> Result<()> {
    let before = list_childflow_transient_links()?;

    let output = run_childflow_command(&[
        "--root",
        "--iface",
        "childflow-definitely-missing0",
        "--",
        "python3",
        "-c",
        "print('unreachable')",
    ])
    .context("failed to run childflow rootful rollback smoke test")?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to prepare the selected network backend")
            || stderr.contains("failed to determine")
            || stderr.contains("failed to inspect default route"),
        "unexpected stderr for rootful rollback smoke test:\n{}",
        stderr
    );
    let after = list_childflow_transient_links()?;
    assert_eq!(after, before, "failed rootful setup leaked transient links");
    Ok(())
}

#[test]
#[ignore = "known rootful allow-cidr behavior needs follow-up"]
fn rootful_default_deny_allows_explicit_cidr() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-rootful-allow-cidr-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let host_cidr = format!("{host_ip}/32");

    let output = run_childflow_command(&[
        "--root",
        "--default-policy",
        "deny",
        "--allow-cidr",
        &host_cidr,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootful allow-cidr smoke test")?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-rootful-allow-cidr-ok"
    );
    assert_eq!(
        requests.recv_timeout(Duration::from_secs(5))?,
        "GET /hello HTTP/1.1"
    );
    Ok(())
}

#[test]
fn rootful_block_private_blocks_local_http() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-rootful-private-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--root",
        "--block-private",
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootful block-private smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootful_block_private_blocks_local_udp() -> Result<()> {
    let (server_addr, requests) = spawn_local_udp_server()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--root",
        "--block-private",
        "--",
        "python3",
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'childflow-rootful-private-udp', (sys.argv[1], int(sys.argv[2]))); s.close()",
        &host_ip.to_string(),
        &server_addr.port().to_string(),
    ])
    .context("failed to run childflow rootful block-private UDP smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootful_default_deny_blocks_unmatched_domain_query() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-rootful-default-deny-domain-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let dns_server = LocalDnsServer::spawn(&dns_bind_ip, "blocked.test", host_ip)?;

    let output = run_childflow_command(&[
        "--root",
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
    ])
    .context("failed to run childflow rootful default-deny DNS smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    assert!(dns_server
        .recv_query_timeout(Duration::from_millis(500))
        .is_err());
    Ok(())
}

#[test]
fn rootful_offline_blocks_dns_query() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-rootful-offline-domain-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let dns_server = LocalDnsServer::spawn(&dns_bind_ip, "offline.test", host_ip)?;

    let output = run_childflow_command(&[
        "--root",
        "--offline",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://offline.test:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootful offline DNS smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    assert!(dns_server
        .recv_query_timeout(Duration::from_millis(500))
        .is_err());
    Ok(())
}

#[test]
fn rootful_deny_cidr_blocks_local_http() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-rootful-deny-cidr-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let host_cidr = format!("{host_ip}/32");

    let output = run_childflow_command(&[
        "--root",
        "--deny-cidr",
        &host_cidr,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootful deny-cidr smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootful_deny_cidr_blocks_local_udp() -> Result<()> {
    let (server_addr, requests) = spawn_local_udp_server()?;
    let host_ip = discover_reachable_host_ipv4()?;
    let host_cidr = format!("{host_ip}/32");

    let output = run_childflow_command(&[
        "--root",
        "--deny-cidr",
        &host_cidr,
        "--",
        "python3",
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'childflow-rootful-deny-cidr-udp', (sys.argv[1], int(sys.argv[2]))); s.close()",
        &host_ip.to_string(),
        &server_addr.port().to_string(),
    ])
    .context("failed to run childflow rootful deny-cidr UDP smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
#[ignore = "rootful proxy-only bootstrap is not stable in the docker/dev environment yet"]
fn rootful_proxy_only_routes_local_http_through_relay_proxy() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-rootful-proxy-only-ok")?;
    let (proxy_addr, proxy_requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--root",
        "--proxy-only",
        "-p",
        &format!("http://{host_ip}:{}", proxy_addr.port()),
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootful proxy-only relay proxy smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-rootful-proxy-only-ok"
    );
    assert_eq!(
        proxy_requests.recv_timeout(Duration::from_secs(5))?,
        format!("CONNECT {host_ip}:{} HTTP/1.1", server_addr.port())
    );
    assert_eq!(
        requests.recv_timeout(Duration::from_secs(5))?,
        "GET /hello HTTP/1.1"
    );
    Ok(())
}

#[test]
#[ignore = "rootful proxy-only bootstrap is not stable in the docker/dev environment yet"]
fn rootful_proxy_only_blocks_direct_udp() -> Result<()> {
    let (server_addr, requests) = spawn_local_udp_server()?;
    let (proxy_addr, _proxy_requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--root",
        "--proxy-only",
        "-p",
        &format!("http://{host_ip}:{}", proxy_addr.port()),
        "--",
        "python3",
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'childflow-rootful-proxy-only-udp', (sys.argv[1], int(sys.argv[2]))); s.close()",
        &host_ip.to_string(),
        &server_addr.port().to_string(),
    ])
    .context("failed to run childflow rootful proxy-only UDP leak test")?;

    assert!(output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
#[ignore = "blocked-flow capture expectations need a dedicated pcap assertion strategy"]
fn rootful_capture_omits_blocked_udp_payload() -> Result<()> {
    let (server_addr, requests) = spawn_local_udp_server()?;
    let host_ip = discover_reachable_host_ipv4()?;
    let output_path = unique_temp_capture_path("rootful-default-deny-udp");
    let marker = b"childflow-rootful-capture-blocked-udp";

    let output = run_childflow_command(&[
        "--root",
        "-c",
        output_path.to_str().unwrap(),
        "--default-policy",
        "deny",
        "--",
        "python3",
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'childflow-rootful-capture-blocked-udp', (sys.argv[1], int(sys.argv[2]))); s.close()",
        &host_ip.to_string(),
        &server_addr.port().to_string(),
    ])
    .context("failed to run childflow rootful blocked UDP capture smoke test")?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    assert_capture_file_written(&output_path)?;
    let capture = std::fs::read(&output_path)?;
    assert!(
        !capture.windows(marker.len()).any(|window| window == marker),
        "blocked UDP payload unexpectedly appeared in capture {}",
        output_path.display()
    );
    let _ = std::fs::remove_file(&output_path);
    Ok(())
}
