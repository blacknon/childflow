use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use anyhow::{anyhow, bail, Context, Result};

pub(crate) fn spawn_http_connect_proxy() -> Result<(SocketAddr, Receiver<String>)> {
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

pub(crate) fn spawn_local_http_server(
    body: &'static str,
) -> Result<(SocketAddr, Receiver<String>)> {
    spawn_bound_http_server(Ipv4Addr::UNSPECIFIED, body)
}

pub(crate) fn spawn_bound_http_server(
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

pub(crate) fn spawn_local_udp_server() -> Result<(SocketAddr, Receiver<Vec<u8>>)> {
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

pub(crate) fn assert_connects_to_https_target(request_line: &str) {
    assert!(
        request_line.starts_with("CONNECT ") && request_line.ends_with(":443 HTTP/1.1"),
        "unexpected proxy request line: {request_line}"
    );
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
