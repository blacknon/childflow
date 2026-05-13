// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};

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

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, "childflow-local-ok");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("childflow summary"));

    let request_line = requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("local HTTP server did not receive a request from the childflow run")?;
    assert_eq!(request_line, "GET /hello HTTP/1.1");

    assert_capture_file_written(&output_path)?;
    assert_capture_has_enhanced_packets(&output_path, 4)?;
    let _ = std::fs::remove_file(&output_path);
    Ok(())
}

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

    let proxy_request_line = proxy_requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("proxy did not receive a CONNECT request from the childflow run")?;
    assert_eq!(
        proxy_request_line,
        format!("CONNECT {host_ip}:{} HTTP/1.1", server_addr.port())
    );

    let request_line = requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("local HTTP server did not receive a request from the proxied run")?;
    assert_eq!(request_line, "GET /hello HTTP/1.1");

    Ok(())
}

#[test]
fn rootless_internal_runs_from_profile_toml() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-profile-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let profile_dir = unique_temp_profile_dir("rootless-profile");
    let profile_path = profile_dir.join("sandbox.toml");

    fs::write(
        &profile_path,
        format!(
            concat!(
                "default_policy = \"deny\"\n",
                "allow_cidrs = [\"{host_ip}/32\"]\n",
                "command = [\n",
                "  \"python3\",\n",
                "  \"-c\",\n",
                "  \"import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())\",\n",
                "  \"http://{host_ip}:{port}/hello\",\n",
                "]\n"
            ),
            host_ip = host_ip,
            port = server_addr.port()
        ),
    )
    .context("failed to write childflow profile")?;

    let output = run_childflow_command(&["--profile", profile_path.to_str().unwrap()])
        .context("failed to run childflow from a profile")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-profile-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("profile-driven local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    let _ = fs::remove_file(&profile_path);
    let _ = fs::remove_dir_all(&profile_dir);
    Ok(())
}

#[test]
fn rootless_internal_runs_from_extended_profile_toml() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-profile-extends-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let profile_root = unique_temp_profile_dir("rootless-profile-extends");
    let child_dir = profile_root.join("child");
    fs::create_dir_all(&child_dir).context("failed to create child profile directory")?;
    let base_profile_path = profile_root.join("base.toml");
    let child_profile_path = child_dir.join("sandbox.toml");

    fs::write(
        &base_profile_path,
        format!(
            concat!(
                "default_policy = \"deny\"\n",
                "allow_cidrs = [\"{host_ip}/32\"]\n"
            ),
            host_ip = host_ip
        ),
    )
    .context("failed to write base childflow profile")?;
    fs::write(
        &child_profile_path,
        format!(
            concat!(
                "extends = \"../base.toml\"\n",
                "command = [\n",
                "  \"python3\",\n",
                "  \"-c\",\n",
                "  \"import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())\",\n",
                "  \"http://{host_ip}:{port}/hello\",\n",
                "]\n"
            ),
            host_ip = host_ip,
            port = server_addr.port()
        ),
    )
    .context("failed to write child childflow profile")?;

    let output = run_childflow_command(&["--profile", child_profile_path.to_str().unwrap()])
        .context("failed to run childflow from an extended profile")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-profile-extends-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("extended-profile local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    let _ = fs::remove_file(&base_profile_path);
    let _ = fs::remove_file(&child_profile_path);
    let _ = fs::remove_dir_all(&profile_root);
    Ok(())
}

#[test]
fn rootless_internal_extended_profile_supports_cli_command_override() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-profile-cli-override-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let profile_root = unique_temp_profile_dir("rootless-profile-cli-override");
    let child_dir = profile_root.join("child");
    fs::create_dir_all(&child_dir).context("failed to create child profile directory")?;
    let base_profile_path = profile_root.join("base.toml");
    let child_profile_path = child_dir.join("sandbox.toml");

    fs::write(
        &base_profile_path,
        format!(
            concat!(
                "default_policy = \"deny\"\n",
                "allow_cidrs = [\"{host_ip}/32\"]\n",
                "command = [\"curl\", \"https://example.com\"]\n"
            ),
            host_ip = host_ip
        ),
    )
    .context("failed to write base childflow profile for CLI override test")?;
    fs::write(
        &child_profile_path,
        "extends = \"../base.toml\"\nsummary = true\n",
    )
    .context("failed to write child childflow profile for CLI override test")?;

    let output = run_childflow_command(&[
        "--profile",
        child_profile_path.to_str().unwrap(),
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow from an extended profile with CLI command override")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-profile-cli-override-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("CLI-overridden profile local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    let _ = fs::remove_file(&base_profile_path);
    let _ = fs::remove_file(&child_profile_path);
    let _ = fs::remove_dir_all(&profile_root);
    Ok(())
}

#[test]
fn dump_profile_prints_effective_merged_toml_without_running_command() -> Result<()> {
    let profile_dir = unique_temp_profile_dir("rootless-profile-dump");
    let profile_path = profile_dir.join("sandbox.toml");

    fs::write(
        &profile_path,
        r#"
summary = true
default_policy = "deny"
allow_cidrs = ["203.0.113.10/32"]
command = ["curl", "https://example.com"]
"#,
    )
    .context("failed to write childflow profile for dump-profile")?;

    let output = run_childflow_command(&[
        "--profile",
        profile_path.to_str().unwrap(),
        "--deny-cidr",
        "198.51.100.0/24",
        "--dump-profile",
    ])
    .context("failed to run childflow dump-profile command")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("summary = true"));
    assert!(stdout.contains("default_policy = \"deny\""));
    assert!(stdout.contains("deny_cidrs = [\"198.51.100.0/24\"]"));
    assert!(stdout.contains("command = ["));
    assert!(stdout.contains("\"curl\""));
    assert!(stdout.contains("\"https://example.com\""));
    assert!(String::from_utf8_lossy(&output.stderr).is_empty());

    let _ = fs::remove_file(&profile_path);
    let _ = fs::remove_dir_all(&profile_dir);
    Ok(())
}

#[test]
fn dump_profile_resolves_extended_paths_and_replaces_inherited_lists() -> Result<()> {
    let profile_root = unique_temp_profile_dir("rootless-profile-dump-extends");
    let child_dir = profile_root.join("child");
    fs::create_dir_all(child_dir.join("captures"))
        .context("failed to create child capture directory")?;
    fs::create_dir_all(child_dir.join("logs")).context("failed to create child log directory")?;
    let base_profile_path = profile_root.join("base.toml");
    let child_profile_path = child_dir.join("sandbox.toml");
    let expected_capture = child_dir.join("captures").join("run.pcapng");
    let expected_flow_log = child_dir.join("logs").join("flow.jsonl");

    fs::write(
        &base_profile_path,
        r#"
default_policy = "deny"
allow_cidrs = ["10.0.0.0/8"]
deny_cidrs = ["192.168.0.0/16"]
command = ["curl", "https://example.com"]
"#,
    )
    .context("failed to write base childflow profile for dump-profile extends test")?;
    fs::write(
        &child_profile_path,
        r#"
extends = "../base.toml"
capture = "./captures/run.pcapng"
flow_log = "./logs/flow.jsonl"
summary = true
"#,
    )
    .context("failed to write child childflow profile for dump-profile extends test")?;

    let output = run_childflow_command(&[
        "--profile",
        child_profile_path.to_str().unwrap(),
        "--allow-cidr",
        "198.51.100.0/24",
        "--deny-cidr",
        "203.0.113.0/24",
        "--dump-profile",
    ])
    .context("failed to run childflow dump-profile command for extended profile")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let dumped: toml::Value =
        toml::from_str(&stdout).context("failed to parse dumped extended profile TOML")?;
    let dumped_table = dumped
        .as_table()
        .context("dumped extended profile was not a TOML table")?;

    assert_eq!(
        dumped_table
            .get("summary")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dumped_table
            .get("default_policy")
            .and_then(|value| value.as_str()),
        Some("deny")
    );
    assert_eq!(
        dumped_table.get("capture").and_then(|value| value.as_str()),
        Some(expected_capture.to_string_lossy().as_ref())
    );
    assert_eq!(
        dumped_table
            .get("flow_log")
            .and_then(|value| value.as_str()),
        Some(expected_flow_log.to_string_lossy().as_ref())
    );
    assert_eq!(
        dumped_table
            .get("allow_cidrs")
            .and_then(|value| value.as_array()),
        Some(&vec![toml::Value::String("198.51.100.0/24".to_string())])
    );
    assert_eq!(
        dumped_table
            .get("deny_cidrs")
            .and_then(|value| value.as_array()),
        Some(&vec![toml::Value::String("203.0.113.0/24".to_string())])
    );
    assert_eq!(
        dumped_table
            .get("command")
            .and_then(|value| value.as_array()),
        Some(&vec![
            toml::Value::String("curl".to_string()),
            toml::Value::String("https://example.com".to_string()),
        ])
    );
    assert!(String::from_utf8_lossy(&output.stderr).is_empty());

    let _ = fs::remove_file(&base_profile_path);
    let _ = fs::remove_file(&child_profile_path);
    let _ = fs::remove_dir_all(&profile_root);
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

    let proxy_request_line = proxy_requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("proxy did not receive a CONNECT request from the proxy-only childflow run")?;
    assert_eq!(
        proxy_request_line,
        format!("CONNECT {host_ip}:{} HTTP/1.1", server_addr.port())
    );

    let request_line = requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("local HTTP server did not receive a request from the proxy-only proxied run")?;
    assert_eq!(request_line, "GET /hello HTTP/1.1");

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
    .context(
        "failed to run childflow rootless-internal local relay proxy + DNS override smoke test",
    )?;

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

    let proxy_request_line = proxy_requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("proxy did not receive a CONNECT request from the proxy + DNS override run")?;
    assert_eq!(
        proxy_request_line,
        format!("CONNECT {host_ip}:{} HTTP/1.1", server_addr.port())
    );

    let request_line = requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("local HTTP server did not receive a request from the proxy + DNS override run")?;
    assert_eq!(request_line, "GET /hello HTTP/1.1");

    assert_capture_file_written(&output_path)?;
    assert_capture_has_enhanced_packets(&output_path, 4)?;
    let _ = std::fs::remove_file(&output_path);
    Ok(())
}

#[test]
fn rootless_internal_writes_flow_log_for_local_http() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-flow-log-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let flow_log_path = unique_temp_flow_log_path("rootless-local-http-flow");

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal flow-log smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-flow-log-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("local HTTP server did not receive a request from the flow-log run")?,
        "GET /hello HTTP/1.1"
    );

    let flow_log = std::fs::read_to_string(&flow_log_path)
        .with_context(|| format!("failed to read {}", flow_log_path.display()))?;
    assert!(flow_log.contains("\"schema_version\":1"));
    assert!(flow_log.contains("\"event\":\"connect_attempt\""));
    assert!(flow_log.contains("\"protocol\":\"tcp\""));
    assert!(flow_log.contains(&format!("\"remote_ip\":\"{host_ip}\"")));
    assert!(flow_log.contains(&format!("\"remote_port\":{}", server_addr.port())));
    assert!(flow_log.contains("\"event\":\"connect_result\""));
    assert!(flow_log.contains("\"event\":\"flow_end\""));

    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_writes_policy_violation_to_flow_log() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-flow-log-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let host_cidr = format!("{host_ip}/32");
    let flow_log_path = unique_temp_flow_log_path("rootless-policy-violation");

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--deny-cidr",
        &host_cidr,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal policy-violation flow-log test")?;

    assert!(
        !output.status.success(),
        "expected deny-cidr childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "deny-cidr sandbox unexpectedly reached the local HTTP server"
    );

    let flow_log = std::fs::read_to_string(&flow_log_path)
        .with_context(|| format!("failed to read {}", flow_log_path.display()))?;
    assert!(flow_log.contains("\"event\":\"policy_violation\""));
    assert!(flow_log.contains("\"schema_version\":1"));
    assert!(flow_log.contains("\"protocol\":\"tcp\""));
    assert!(flow_log.contains("\"action\":\"deny\""));
    assert!(flow_log.contains("\"reason_code\":\"deny_cidr\""));
    assert!(flow_log.contains("\"control\":\"--deny-cidr\""));
    assert!(flow_log.contains(&format!("\"matched_cidr\":\"{host_cidr}\"")));

    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

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
    ])
    .context("failed to run childflow rootless-internal offline smoke test")?;

    assert!(
        !output.status.success(),
        "expected offline childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "offline sandbox unexpectedly reached the local HTTP server"
    );

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
    ])
    .context("failed to run childflow rootless-internal block-private smoke test")?;

    assert!(
        !output.status.success(),
        "expected block-private childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "block-private sandbox unexpectedly reached the local HTTP server"
    );

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
    ])
    .context("failed to run childflow rootless-internal default-deny smoke test")?;

    assert!(
        !output.status.success(),
        "expected default-deny childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "default-deny sandbox unexpectedly reached the local HTTP server"
    );

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
    ])
    .context("failed to run childflow rootless-internal allow-cidr smoke test")?;

    assert!(
        output.status.success(),
        "expected allow-cidr childflow run to succeed, but it failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-allow-cidr-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("allow-cidr local HTTP server did not receive a request")?,
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
    ])
    .context("failed to run childflow rootless-internal deny-cidr smoke test")?;

    assert!(
        !output.status.success(),
        "expected deny-cidr childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "deny-cidr sandbox unexpectedly reached the local HTTP server"
    );

    Ok(())
}

#[test]
fn rootless_internal_default_deny_allows_explicit_domain() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-allow-domain-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "allowed.test", host_ip)?;

    let output = run_childflow_command(&[
        "--default-policy",
        "deny",
        "--allow-domain",
        "allowed.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://allowed.test:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal allow-domain smoke test")?;

    assert!(
        output.status.success(),
        "expected allow-domain childflow run to succeed, but it failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-allow-domain-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("allow-domain local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    Ok(())
}

#[test]
fn rootless_internal_default_deny_allows_subdomain_of_explicit_domain() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-allow-domain-subdomain-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "api.allowed.test", host_ip)?;

    let output = run_childflow_command(&[
        "--default-policy",
        "deny",
        "--allow-domain",
        "allowed.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://api.allowed.test:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal allow-domain subdomain smoke test")?;

    assert!(
        output.status.success(),
        "expected allow-domain subdomain childflow run to succeed, but it failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-allow-domain-subdomain-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("allow-domain subdomain local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    Ok(())
}

#[test]
fn rootless_internal_default_deny_allows_explicit_exact_domain() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-allow-domain-exact-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "allowed.test", host_ip)?;

    let output = run_childflow_command(&[
        "--default-policy",
        "deny",
        "--allow-domain-exact",
        "allowed.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://allowed.test:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal allow-domain-exact smoke test")?;

    assert!(
        output.status.success(),
        "expected allow-domain-exact childflow run to succeed, but it failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-allow-domain-exact-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("allow-domain-exact local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    Ok(())
}

#[test]
fn rootless_internal_default_deny_blocks_subdomain_when_only_exact_domain_allowed() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-allow-domain-exact-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "api.allowed.test", host_ip)?;
    let flow_log_path = unique_temp_flow_log_path("rootless-allow-domain-exact-subdomain");

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--default-policy",
        "deny",
        "--allow-domain-exact",
        "allowed.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://api.allowed.test:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal allow-domain-exact mismatch smoke test")?;

    assert!(
        !output.status.success(),
        "expected unmatched allow-domain-exact childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "allow-domain-exact sandbox unexpectedly reached the local HTTP server"
    );

    let flow_log = std::fs::read_to_string(&flow_log_path)
        .with_context(|| format!("failed to read {}", flow_log_path.display()))?;
    assert!(flow_log.contains("\"event\":\"policy_violation\""));
    assert!(flow_log.contains("\"protocol\":\"dns\""));
    assert!(flow_log.contains("\"reason_code\":\"default_deny\""));
    assert!(flow_log.contains("\"control\":\"--default-policy\""));
    assert!(flow_log.contains("\"remote\":\"api.allowed.test\""));

    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_deny_domain_blocks_subdomain_via_dns_resolution() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-deny-domain-subdomain-should-not-connect")?;
    let flow_log_path = unique_temp_flow_log_path("rootless-deny-domain-subdomain");
    let dns_bind_ip = unique_loopback_dns_ip();

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--deny-domain",
        "blocked.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://api.blocked.test:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal deny-domain subdomain smoke test")?;

    assert!(
        !output.status.success(),
        "expected deny-domain childflow run to fail for subdomain, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "deny-domain sandbox unexpectedly reached the local HTTP server through a subdomain"
    );

    let flow_log = std::fs::read_to_string(&flow_log_path)
        .with_context(|| format!("failed to read {}", flow_log_path.display()))?;
    assert!(flow_log.contains("\"event\":\"policy_violation\""));
    assert!(flow_log.contains("\"protocol\":\"dns\""));
    assert!(flow_log.contains("\"reason_code\":\"deny_domain\""));
    assert!(flow_log.contains("\"control\":\"--deny-domain\""));
    assert!(flow_log.contains("\"matched_domain\":\"blocked.test\""));
    assert!(flow_log.contains("\"remote\":\"api.blocked.test\""));

    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_deny_domain_blocks_local_http_via_dns_resolution() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-deny-domain-should-not-connect")?;
    let flow_log_path = unique_temp_flow_log_path("rootless-deny-domain");
    let dns_bind_ip = unique_loopback_dns_ip();

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--deny-domain",
        "blocked.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://blocked.test:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal deny-domain smoke test")?;

    assert!(
        !output.status.success(),
        "expected deny-domain childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "deny-domain sandbox unexpectedly reached the local HTTP server"
    );

    let flow_log = std::fs::read_to_string(&flow_log_path)
        .with_context(|| format!("failed to read {}", flow_log_path.display()))?;
    assert!(flow_log.contains("\"event\":\"policy_violation\""));
    assert!(flow_log.contains("\"protocol\":\"dns\""));
    assert!(flow_log.contains("\"reason_code\":\"deny_domain\""));
    assert!(flow_log.contains("\"control\":\"--deny-domain\""));
    assert!(flow_log.contains("\"matched_domain\":\"blocked.test\""));
    assert!(flow_log.contains("\"remote\":\"blocked.test\""));

    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_deny_domain_exact_blocks_local_http_via_dns_resolution() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-deny-domain-exact-should-not-connect")?;
    let flow_log_path = unique_temp_flow_log_path("rootless-deny-domain-exact");
    let dns_bind_ip = unique_loopback_dns_ip();

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
        "--deny-domain-exact",
        "blocked.test",
        "-d",
        &dns_bind_ip,
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()",
        &format!("http://blocked.test:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow rootless-internal deny-domain-exact smoke test")?;

    assert!(
        !output.status.success(),
        "expected deny-domain-exact childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "deny-domain-exact sandbox unexpectedly reached the local HTTP server"
    );

    let flow_log = std::fs::read_to_string(&flow_log_path)
        .with_context(|| format!("failed to read {}", flow_log_path.display()))?;
    assert!(flow_log.contains("\"event\":\"policy_violation\""));
    assert!(flow_log.contains("\"protocol\":\"dns\""));
    assert!(flow_log.contains("\"reason_code\":\"deny_domain_exact\""));
    assert!(flow_log.contains("\"control\":\"--deny-domain-exact\""));
    assert!(flow_log.contains("\"matched_domain\":\"blocked.test\""));
    assert!(flow_log.contains("\"remote\":\"blocked.test\""));

    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_default_deny_blocks_unmatched_domain_query() -> Result<()> {
    let (server_addr, requests) =
        spawn_local_http_server("childflow-default-deny-domain-should-not-connect")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let dns_bind_ip = unique_loopback_dns_ip();
    let _dns_server = LocalDnsServer::spawn(&dns_bind_ip, "blocked.test", host_ip)?;
    let flow_log_path = unique_temp_flow_log_path("rootless-default-deny-domain");

    let output = run_childflow_command(&[
        "--flow-log",
        flow_log_path.to_str().unwrap(),
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
    .context("failed to run childflow rootless-internal default-deny allow-domain DNS test")?;

    assert!(
        !output.status.success(),
        "expected unmatched allow-domain childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "default-deny allow-domain sandbox unexpectedly reached the local HTTP server"
    );

    let flow_log = std::fs::read_to_string(&flow_log_path)
        .with_context(|| format!("failed to read {}", flow_log_path.display()))?;
    assert!(flow_log.contains("\"event\":\"policy_violation\""));
    assert!(flow_log.contains("\"protocol\":\"dns\""));
    assert!(flow_log.contains("\"reason_code\":\"default_deny\""));
    assert!(flow_log.contains("\"control\":\"--default-policy\""));
    assert!(flow_log.contains("\"remote\":\"blocked.test\""));

    let _ = std::fs::remove_file(&flow_log_path);
    Ok(())
}

#[test]
fn rootless_internal_proxy_only_blocks_udp_leak() -> Result<()> {
    let (_server_addr, requests) = spawn_local_udp_server()?;
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
        &_server_addr.port().to_string(),
    ])
    .context("failed to run childflow rootless-internal proxy-only UDP leak test")?;

    assert!(
        output.status.success(),
        "expected proxy-only UDP leak probe to exit cleanly, but it failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "proxy-only sandbox unexpectedly delivered a UDP packet directly"
    );

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

    assert!(
        !output.status.success(),
        "expected fail-on-leak UDP probe to return non-zero, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--fail-on-leak"),
        "expected fail-on-leak warning in stderr, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "fail-on-leak sandbox unexpectedly delivered a UDP packet directly"
    );

    Ok(())
}

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

    assert!(
        !output.status.success(),
        "expected rootful default-deny childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "rootful default-deny sandbox unexpectedly reached the local HTTP server"
    );

    Ok(())
}

#[test]
fn rootful_doctor_json_reports_rootful_backend() -> Result<()> {
    let output = run_childflow_command(&[
        "--root",
        "--doctor",
        "--doctor-format",
        "json",
    ])
    .context("failed to run childflow rootful doctor json smoke test")?;

    assert!(
        output.status.success(),
        "expected rootful doctor childflow run to succeed, but it failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

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

    assert!(
        output.status.success(),
        "expected rootful doctor text childflow run to succeed, but it failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

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
    assert!(
        !output.status.success(),
        "expected rootful block-private childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "rootful block-private sandbox unexpectedly reached the local HTTP server"
    );

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

    assert!(
        !output.status.success(),
        "expected rootful deny-cidr childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "rootful deny-cidr sandbox unexpectedly reached the local HTTP server"
    );

    Ok(())
}

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
    ])
    .context("failed to run childflow rootless-internal metadata-alias reachability test")?;

    assert!(
        output.status.success(),
        "expected metadata-alias childflow run to succeed, but it failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-metadata-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(std::time::Duration::from_secs(5))
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
    ])
    .context("failed to run childflow rootless-internal block-metadata smoke test")?;

    assert!(
        !output.status.success(),
        "expected block-metadata childflow run to fail, but it succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        requests
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err(),
        "block-metadata sandbox unexpectedly reached the metadata alias server"
    );

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
    ])
    .context("failed to run childflow rootless-internal summary smoke test")?;

    assert!(
        output.status.success(),
        "expected summary-enabled childflow run to succeed, but it failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("summary-enabled local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    Ok(())
}

fn run_childflow_command(args: &[&str]) -> Result<std::process::Output> {
    let binary = env!("CARGO_BIN_EXE_childflow");
    let mut command = if unsafe { nix::libc::geteuid() } == 0 {
        let mut command = Command::new(binary);
        command.args(args);
        command
    } else {
        let mut command = Command::new("sudo");
        command.arg("-n").arg(binary).args(args);
        command
    };

    command.current_dir(env!("CARGO_MANIFEST_DIR"));
    command
        .output()
        .with_context(|| format!("failed to execute childflow command `{binary}`"))
}

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

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Example Domain"),
        "expected Example Domain in stdout, got:\n{stdout}"
    );

    let request_line = requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("proxy did not receive a CONNECT request from the childflow run")?;
    assert_connects_to_https_target(&request_line);

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

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Example Domain"),
        "expected Example Domain in stdout, got:\n{stdout}"
    );

    let request_line = requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context(
            "proxy did not receive a CONNECT request from the childflow run with DNS override",
        )?;
    assert_connects_to_https_target(&request_line);

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

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Example Domain"),
        "expected Example Domain in stdout, got:\n{stdout}"
    );

    let request_line = requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("proxy did not receive a CONNECT request from the single-binary childflow run")?;
    assert!(
        request_line.starts_with("CONNECT ") && request_line.ends_with(":80 HTTP/1.1"),
        "unexpected proxy request line: {request_line}"
    );

    Ok(())
}

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

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

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

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let request_line = requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("proxy did not receive a CONNECT request from the rootless capture + proxy run")?;
    assert_connects_to_https_target(&request_line);
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

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_capture_file_written(&output_path)?;
    assert_capture_has_enhanced_packets(&output_path, 1)?;
    let _ = std::fs::remove_file(&output_path);
    Ok(())
}

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
        .output()
        .context("failed to run childflow rootless-internal ping smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 received") || stdout.contains("1 packets received"),
        "expected ping success output, got:\n{stdout}"
    );

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
        .output()
        .context("failed to run childflow rootless-internal traceroute smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.lines().any(|line| {
            let trimmed = line.trim_start();
            (trimmed.starts_with("1 ") || trimmed.starts_with("2 ")) && !trimmed.contains(" *")
        }),
        "expected traceroute to report at least one concrete hop, got:\n{stdout}"
    );

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
        .output()
        .context("failed to run childflow rootless-internal ICMP traceroute smoke test")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.lines().any(|line| {
            let trimmed = line.trim_start();
            (trimmed.starts_with("1 ") || trimmed.starts_with("2 ")) && !trimmed.contains(" *")
        }),
        "expected ICMP traceroute to report at least one concrete hop, got:\n{stdout}"
    );

    Ok(())
}

fn spawn_http_connect_proxy() -> Result<(SocketAddr, Receiver<String>)> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .context("failed to bind local HTTP CONNECT proxy test listener")?;
    let addr = listener
        .local_addr()
        .context("failed to query test proxy local address")?;
    let (request_tx, request_rx) = mpsc::channel();

    thread::spawn(move || {
        let result: Result<()> = (|| {
            let (mut inbound, _) = listener.accept().context("proxy accept failed")?;
            let request =
                read_http_headers(&mut inbound).context("failed to read proxy request")?;
            let request_line = request
                .lines()
                .next()
                .ok_or_else(|| anyhow!("proxy request was empty"))?
                .to_string();
            request_tx
                .send(request_line.clone())
                .context("failed to publish proxy request line to test thread")?;

            let target = parse_connect_target(&request_line)?;
            let mut outbound = TcpStream::connect(&target)
                .with_context(|| format!("proxy failed to connect to upstream target {target}"))?;
            inbound
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .context("failed to acknowledge CONNECT tunnel")?;
            relay_bidirectional(inbound, &mut outbound)?;
            Ok(())
        })();

        if let Err(err) = result {
            let _ = request_tx.send(format!("proxy-error: {err:#}"));
        }
    });

    Ok((addr, request_rx))
}

fn spawn_local_http_server(body: &'static str) -> Result<(SocketAddr, Receiver<String>)> {
    spawn_bound_http_server(Ipv4Addr::UNSPECIFIED, body)
}

fn spawn_bound_http_server(
    bind_ip: Ipv4Addr,
    body: &'static str,
) -> Result<(SocketAddr, Receiver<String>)> {
    let listener = TcpListener::bind((bind_ip, 0)).context("failed to bind local HTTP server")?;
    let addr = listener
        .local_addr()
        .context("failed to query local HTTP server address")?;
    let (request_tx, request_rx) = mpsc::channel();

    thread::spawn(move || {
        let result: Result<()> = (|| {
            let (mut stream, _) = listener
                .accept()
                .context("local HTTP server accept failed")?;
            let request = read_http_headers(&mut stream)
                .context("failed to read local HTTP server request")?;
            let request_line = request
                .lines()
                .next()
                .ok_or_else(|| anyhow!("local HTTP server request was empty"))?
                .to_string();
            request_tx
                .send(request_line)
                .context("failed to publish local HTTP request line to test thread")?;

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .context("failed to write local HTTP server response")?;
            Ok(())
        })();

        if let Err(err) = result {
            let _ = request_tx.send(format!("server-error: {err:#}"));
        }
    });

    Ok((addr, request_rx))
}

fn spawn_local_udp_server() -> Result<(SocketAddr, Receiver<Vec<u8>>)> {
    let listener =
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("failed to bind local UDP server")?;
    let addr = listener
        .local_addr()
        .context("failed to query local UDP server address")?;
    let (payload_tx, payload_rx) = mpsc::channel();

    thread::spawn(move || {
        let result: Result<()> = (|| {
            let mut buf = [0_u8; 2048];
            let (n, _) = listener
                .recv_from(&mut buf)
                .context("failed to receive local UDP payload")?;
            payload_tx
                .send(buf[..n].to_vec())
                .context("failed to publish local UDP payload to test thread")?;
            Ok(())
        })();

        if let Err(err) = result {
            let _ = payload_tx.send(format!("server-error: {err:#}").into_bytes());
        }
    });

    Ok((addr, payload_rx))
}

struct LoopbackAliasGuard {
    _ip: Ipv4Addr,
}

impl LoopbackAliasGuard {
    fn add(ip: Ipv4Addr) -> Result<Self> {
        let output = privileged_ip_command(["addr", "add", &format!("{ip}/32"), "dev", "lo"])
            .output()
            .context("failed to add loopback alias for metadata test")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") && !stderr.contains("Address already assigned") {
                bail!("failed to add loopback alias {ip}: {}", stderr.trim());
            }
            return Ok(Self { _ip: ip });
        }
        Ok(Self { _ip: ip })
    }
}

impl Drop for LoopbackAliasGuard {
    fn drop(&mut self) {}
}

fn privileged_ip_command<const N: usize>(args: [&str; N]) -> Command {
    if unsafe { nix::libc::geteuid() } == 0 {
        let mut command = Command::new("ip");
        command.args(args);
        command
    } else {
        let mut command = Command::new("sudo");
        command.arg("-n").arg("ip").args(args);
        command
    }
}

struct LocalDnsServer {
    child: Child,
}

impl LocalDnsServer {
    fn spawn(bind_ip: &str, expected_qname: &str, answer_ip: Ipv4Addr) -> Result<Self> {
        let script_path = unique_temp_profile_dir("rootless-local-dns").join("dns_server.py");
        fs::write(&script_path, LOCAL_DNS_SERVER_PY)
            .with_context(|| format!("failed to write {}", script_path.display()))?;

        let mut command = if unsafe { nix::libc::geteuid() } == 0 {
            Command::new("python3")
        } else {
            let mut command = Command::new("sudo");
            command.arg("-n").arg("python3");
            command
        };

        let mut child = command
            .arg(script_path.to_str().unwrap())
            .arg(bind_ip)
            .arg(expected_qname)
            .arg(answer_ip.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to start local DNS server helper")?;

        let mut stdout = String::new();
        let stdout_pipe = child
            .stdout
            .as_mut()
            .context("local DNS server did not expose stdout")?;
        let mut buf = [0_u8; 1];
        loop {
            let n = stdout_pipe
                .read(&mut buf)
                .context("failed to read local DNS server readiness signal")?;
            if n == 0 {
                let mut stderr = String::new();
                if let Some(stderr_pipe) = child.stderr.as_mut() {
                    let _ = stderr_pipe.read_to_string(&mut stderr);
                }
                bail!(
                    "local DNS server exited before readiness; stderr: {}",
                    stderr.trim()
                );
            }
            stdout.push(buf[0] as char);
            if stdout.ends_with('\n') {
                break;
            }
        }

        if stdout.trim() != "READY" {
            bail!(
                "unexpected local DNS server readiness line: {}",
                stdout.trim()
            );
        }

        Ok(Self { child })
    }
}

impl Drop for LocalDnsServer {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
            Err(_) => {}
        }
    }
}

const LOCAL_DNS_SERVER_PY: &str = r#"#!/usr/bin/env python3
import ipaddress
import socket
import struct
import sys

bind_ip, expected_qname, answer_ip = sys.argv[1], sys.argv[2].rstrip(".").lower(), sys.argv[3]
answer_bytes = ipaddress.IPv4Address(answer_ip).packed

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((bind_ip, 53))
print("READY", flush=True)

data, addr = sock.recvfrom(2048)
if len(data) < 12:
    sys.exit(1)

qid = data[:2]
qdcount = struct.unpack("!H", data[4:6])[0]
if qdcount != 1:
    sys.exit(1)

offset = 12
labels = []
while True:
    if offset >= len(data):
        sys.exit(1)
    length = data[offset]
    offset += 1
    if length == 0:
        break
    labels.append(data[offset:offset + length].decode("ascii"))
    offset += length

question_end = offset + 4
question = data[12:question_end]
qname = ".".join(labels).rstrip(".").lower()
qtype = struct.unpack("!H", data[offset:offset + 2])[0]

flags = 0x8180
answers = b""
ancount = 0
if qname == expected_qname and qtype == 1:
    answers = struct.pack("!HHHLH4s", 0xC00C, 1, 1, 30, 4, answer_bytes)
    ancount = 1

header = qid + struct.pack("!HHHHH", flags, qdcount, ancount, 0, 0)
sock.sendto(header + question + answers, addr)
"#;

fn read_http_headers(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        let n = stream
            .read(&mut chunk)
            .context("failed to read from inbound proxy client stream")?;
        if n == 0 {
            bail!("proxy client closed before finishing HTTP headers");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            bail!("proxy request headers exceeded 16 KiB");
        }
    }

    String::from_utf8(buf).context("proxy request headers were not valid UTF-8")
}

fn parse_connect_target(request_line: &str) -> Result<String> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if method != "CONNECT" {
        bail!("expected CONNECT request, got `{request_line}`");
    }
    if target.is_empty() {
        bail!("CONNECT request did not include a target authority");
    }
    Ok(target.to_string())
}

fn assert_connects_to_https_target(request_line: &str) {
    assert!(
        request_line.starts_with("CONNECT ") && request_line.ends_with(":443 HTTP/1.1"),
        "unexpected proxy request line: {request_line}"
    );
}

fn assert_capture_file_written(path: &PathBuf) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat capture output {}", path.display()))?;
    assert!(
        metadata.len() > 0,
        "expected a non-empty capture output at {}",
        path.display()
    );
    Ok(())
}

fn assert_capture_has_enhanced_packets(path: &PathBuf, minimum_packets: usize) -> Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read capture output {}", path.display()))?;
    let packet_count = count_pcapng_enhanced_packets(&bytes).with_context(|| {
        format!(
            "failed to parse pcapng blocks while checking {}",
            path.display()
        )
    })?;

    assert!(
        packet_count >= minimum_packets,
        "expected at least {minimum_packets} enhanced packet blocks in {}, found {packet_count}",
        path.display()
    );
    Ok(())
}

fn count_pcapng_enhanced_packets(bytes: &[u8]) -> Result<usize> {
    const SECTION_HEADER_BLOCK: u32 = 0x0A0D0D0A;
    const ENHANCED_PACKET_BLOCK: u32 = 0x00000006;
    const BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D;
    const SWAPPED_BYTE_ORDER_MAGIC: u32 = 0x4D3C2B1A;

    if bytes.len() < 12 {
        bail!("pcapng file is too short to contain a section header");
    }

    let mut offset = 0usize;
    let mut little_endian = true;
    let mut saw_section_header = false;
    let mut packet_count = 0usize;

    while offset + 12 <= bytes.len() {
        let block_type = read_u32_le(bytes, offset)?;
        let total_length_le = read_u32_le(bytes, offset + 4)?;

        if block_type == SECTION_HEADER_BLOCK {
            let magic = read_u32_le(bytes, offset + 8)?;
            little_endian = match magic {
                BYTE_ORDER_MAGIC => true,
                SWAPPED_BYTE_ORDER_MAGIC => false,
                other => bail!("unexpected pcapng byte-order magic: 0x{other:08x}"),
            };
            saw_section_header = true;
        }

        let total_length = if little_endian {
            total_length_le
        } else {
            read_u32_be(bytes, offset + 4)?
        } as usize;

        if total_length < 12 {
            bail!("pcapng block at offset {offset} has an invalid length of {total_length}");
        }

        let block_end = offset
            .checked_add(total_length)
            .ok_or_else(|| anyhow!("pcapng block length overflowed at offset {offset}"))?;
        if block_end > bytes.len() {
            bail!(
                "pcapng block at offset {offset} extends past the end of the file (len {total_length})"
            );
        }

        let trailing_length = if little_endian {
            read_u32_le(bytes, block_end - 4)?
        } else {
            read_u32_be(bytes, block_end - 4)?
        } as usize;
        if trailing_length != total_length {
            bail!(
                "pcapng block at offset {offset} has mismatched lengths: {total_length} vs {trailing_length}"
            );
        }

        let normalized_block_type = if little_endian {
            block_type
        } else {
            read_u32_be(bytes, offset)?
        };
        if normalized_block_type == ENHANCED_PACKET_BLOCK {
            packet_count += 1;
        }

        offset = block_end;
    }

    if !saw_section_header {
        bail!("pcapng file did not contain a section header block");
    }
    if offset != bytes.len() {
        bail!(
            "pcapng file has {} trailing bytes after the last full block",
            bytes.len() - offset
        );
    }

    Ok(packet_count)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow!("offset overflow while reading little-endian u32"))?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        anyhow!("unexpected EOF while reading little-endian u32 at offset {offset}")
    })?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow!("offset overflow while reading big-endian u32"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| anyhow!("unexpected EOF while reading big-endian u32 at offset {offset}"))?;
    Ok(u32::from_be_bytes(slice.try_into().unwrap()))
}

fn unique_temp_capture_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}.pcapng"))
}

fn unique_temp_flow_log_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}.jsonl"))
}

fn unique_temp_profile_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{nanos}"));
    let _ = fs::create_dir_all(&path);
    path
}

fn unique_loopback_dns_ip() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let a = 20 + ((nanos & 0x7f) as u8);
    let b = 1 + (((nanos >> 8) & 0xfe) as u8);
    let c = 1 + (((nanos >> 16) & 0xfe) as u8);
    format!("127.{a}.{b}.{c}")
}

fn relay_bidirectional(mut inbound: TcpStream, outbound: &mut TcpStream) -> Result<()> {
    let mut inbound_reader = inbound
        .try_clone()
        .context("failed to clone inbound proxy stream")?;
    let mut outbound_reader = outbound
        .try_clone()
        .context("failed to clone outbound proxy stream")?;
    let mut outbound_writer = outbound
        .try_clone()
        .context("failed to clone outbound proxy writer")?;

    let left_to_right = thread::spawn(move || -> std::io::Result<u64> {
        let copied = std::io::copy(&mut inbound_reader, &mut outbound_writer)?;
        let _ = outbound_writer.shutdown(Shutdown::Write);
        Ok(copied)
    });

    let right_to_left = thread::spawn(move || -> std::io::Result<u64> {
        let copied = std::io::copy(&mut outbound_reader, &mut inbound)?;
        let _ = inbound.shutdown(Shutdown::Write);
        Ok(copied)
    });

    let _ = left_to_right
        .join()
        .map_err(|_| anyhow!("proxy relay client->upstream thread panicked"))?
        .context("proxy relay client->upstream failed")?;
    let _ = right_to_left
        .join()
        .map_err(|_| anyhow!("proxy relay upstream->client thread panicked"))?
        .context("proxy relay upstream->client failed")?;
    Ok(())
}

fn discover_reachable_host_ipv4() -> Result<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .context("failed to bind UDP socket while discovering host IPv4")?;
    socket
        .connect((Ipv4Addr::new(1, 1, 1, 1), 80))
        .context("failed to connect UDP socket while discovering host IPv4")?;
    match socket
        .local_addr()
        .context("failed to query local UDP socket address")?
        .ip()
    {
        IpAddr::V4(ip) if !ip.is_loopback() => Ok(ip),
        other => bail!("expected a non-loopback IPv4 address for proxy reachability, got {other}"),
    }
}
