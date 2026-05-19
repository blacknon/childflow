use std::process::Command;

use anyhow::{Context, Result};

use crate::support::{
    assert_capture_file_written, assert_capture_has_enhanced_packets,
    assert_connects_to_https_target, discover_reachable_host_ipv4, spawn_http_connect_proxy,
    unique_temp_capture_path,
};

#[test]
#[ignore = "requires privileged linux namespaces, outbound network access, and curl"]
fn rootless_internal_writes_capture_for_https_request() -> Result<()> {
    let output_path = unique_temp_capture_path("rootless-output");

    let output = Command::new(env!("CARGO_BIN_EXE_childflow"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--network-backend",
            "rootless-internal",
            "-c",
            output_path.to_str().unwrap(),
            "--",
            "curl",
            "-fsSL",
            "--max-time",
            "30",
            "https://example.com",
        ])
        .output()
        .context("failed to run childflow rootless-internal capture smoke test")?;

    assert!(output.status.success());
    assert_capture_file_written(&output_path)?;
    let _ = std::fs::remove_file(&output_path);
    Ok(())
}

#[test]
#[ignore = "requires privileged linux namespaces, outbound network access, curl, and a local proxy listener"]
fn rootless_internal_writes_capture_for_proxy_flow() -> Result<()> {
    let (proxy_addr, requests) = spawn_http_connect_proxy()?;
    let host_ip = discover_reachable_host_ipv4()?;
    let output_path = unique_temp_capture_path("rootless-proxy-output");

    let output = Command::new(env!("CARGO_BIN_EXE_childflow"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--network-backend",
            "rootless-internal",
            "-c",
            output_path.to_str().unwrap(),
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
        .context("failed to run childflow rootless-internal capture + proxy smoke test")?;

    assert!(output.status.success());
    assert_connects_to_https_target(&requests.recv_timeout(std::time::Duration::from_secs(5))?);
    assert_capture_file_written(&output_path)?;
    let _ = std::fs::remove_file(&output_path);
    Ok(())
}

#[test]
#[ignore = "requires privileged linux namespaces, outbound network access, curl, and CAP_NET_RAW-equivalent privileges on the host egress interface"]
fn rootless_internal_writes_wire_egress_capture_for_https_request() -> Result<()> {
    let output_path = unique_temp_capture_path("rootless-wire-egress-output");

    let output = Command::new(env!("CARGO_BIN_EXE_childflow"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--network-backend",
            "rootless-internal",
            "-C",
            "wire-egress",
            "-c",
            output_path.to_str().unwrap(),
            "--",
            "curl",
            "-fsSL",
            "--max-time",
            "30",
            "https://example.com",
        ])
        .output()
        .context("failed to run childflow rootless-internal wire-egress capture smoke test")?;

    assert!(output.status.success());
    assert_capture_file_written(&output_path)?;
    assert_capture_has_enhanced_packets(&output_path, 1)?;
    let _ = std::fs::remove_file(&output_path);
    Ok(())
}
