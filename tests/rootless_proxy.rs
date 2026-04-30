// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
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
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .context("failed to bind local HTTP server")?;
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
