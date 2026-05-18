use std::time::Duration;

use anyhow::{Context, Result};

use super::support::{
    discover_reachable_host_ipv4, run_childflow_command, spawn_local_http_server,
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
