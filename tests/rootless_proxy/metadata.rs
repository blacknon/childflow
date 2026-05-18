use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result};

use super::support::{
    discover_reachable_host_ipv4, run_childflow_command, spawn_bound_http_server,
    spawn_local_http_server, LoopbackAliasGuard,
};

#[test]
fn rootless_internal_reaches_metadata_alias_without_block() -> Result<()> {
    let _guard = LoopbackAliasGuard::add(Ipv4Addr::new(169, 254, 169, 254))?;
    let (server_addr, requests) =
        spawn_bound_http_server(Ipv4Addr::new(169, 254, 169, 254), "childflow-metadata-ok")?;

    let output = run_childflow_command(&[
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=5).read().decode())",
        &format!("http://169.254.169.254:{}/latest/meta-data/", server_addr.port()),
    ])?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-metadata-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(Duration::from_secs(5))
            .context("metadata alias server did not receive a request")?,
        "GET /latest/meta-data/ HTTP/1.1"
    );
    Ok(())
}

#[test]
fn rootless_internal_block_metadata_blocks_metadata_alias() -> Result<()> {
    let _guard = LoopbackAliasGuard::add(Ipv4Addr::new(169, 254, 169, 254))?;
    let (server_addr, requests) = spawn_bound_http_server(
        Ipv4Addr::new(169, 254, 169, 254),
        "childflow-metadata-should-not-connect",
    )?;

    let output = run_childflow_command(&[
        "--block-metadata",
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!(
            "http://169.254.169.254:{}/latest/meta-data/",
            server_addr.port()
        ),
    ])?;

    assert!(!output.status.success());
    assert!(requests.recv_timeout(Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn rootless_internal_summary_is_printed_only_when_requested() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-summary-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;

    let output = run_childflow_command(&[
        "--summary",
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-summary-ok"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("childflow summary"));
    assert!(stderr.contains("backend: rootless-internal"));
    assert!(stderr.contains("sandbox controls: none"));
    assert!(stderr.contains("capture: disabled"));
    assert!(stderr.contains("exit: 0"));
    assert_eq!(
        requests
            .recv_timeout(Duration::from_secs(5))
            .context("summary-enabled local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );
    Ok(())
}
