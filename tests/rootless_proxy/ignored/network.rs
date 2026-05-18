use std::process::Command;

use anyhow::Result;

#[test]
#[ignore = "requires privileged linux namespaces, outbound network access, and ping"]
fn rootless_internal_relays_ipv4_ping() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_childflow"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--network-backend",
            "rootless-internal",
            "--",
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            "3",
            "8.8.8.8",
        ])
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1 received") || stdout.contains("1 packets received"));
    Ok(())
}

#[test]
#[ignore = "requires privileged linux namespaces, outbound network access, and traceroute"]
fn rootless_internal_relays_udp_traceroute_hops() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_childflow"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--network-backend",
            "rootless-internal",
            "--",
            "traceroute",
            "-n",
            "-q",
            "1",
            "-w",
            "2",
            "-m",
            "2",
            "8.8.8.8",
        ])
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.lines().any(|line| {
        let trimmed = line.trim_start();
        (trimmed.starts_with("1 ") || trimmed.starts_with("2 ")) && !trimmed.contains(" *")
    }));
    Ok(())
}

#[test]
#[ignore = "requires privileged linux namespaces, outbound network access, and traceroute"]
fn rootless_internal_relays_icmp_traceroute_hops() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_childflow"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--network-backend",
            "rootless-internal",
            "--",
            "traceroute",
            "-I",
            "-n",
            "-q",
            "1",
            "-w",
            "2",
            "-m",
            "2",
            "8.8.8.8",
        ])
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.lines().any(|line| {
        let trimmed = line.trim_start();
        (trimmed.starts_with("1 ") || trimmed.starts_with("2 ")) && !trimmed.contains(" *")
    }));
    Ok(())
}
