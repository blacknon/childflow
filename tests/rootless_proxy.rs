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
            "-o",
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
            "-o",
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
