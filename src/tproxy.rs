use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

use crate::cli::ProxyType;

#[derive(Clone)]
pub struct ProxyServer {
    pub host: String,
    pub port: u16,
}

#[derive(Clone)]
pub struct ProxyUpstreamConfig {
    pub server: ProxyServer,
    pub kind: ProxyType,
    pub bind_interface: Option<String>,
}

pub struct TproxyHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<()>>>,
    listen_port: u16,
}

impl TproxyHandle {
    pub fn start(upstream: ProxyUpstreamConfig) -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .context("failed to create transparent listener socket")?;
        socket.set_reuse_address(true).ok();
        socket.set_reuse_port(true).ok();
        socket
            .set_ip_transparent_v4(true)
            .context("failed to enable IP_TRANSPARENT on listener socket")?;
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        socket
            .bind(&bind_addr.into())
            .context("failed to bind transparent listener")?;
        socket
            .listen(1024)
            .context("failed to listen on transparent socket")?;

        let listener: TcpListener = socket.into();
        listener
            .set_nonblocking(true)
            .context("failed to set transparent listener nonblocking")?;
        let listen_port = listener
            .local_addr()
            .context("failed to query transparent listener local address")?
            .port();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let join = thread::spawn(move || accept_loop(listener, upstream, stop_for_thread));

        Ok(Self {
            stop,
            join: Some(join),
            listen_port,
        })
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for TproxyHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn accept_loop(
    listener: TcpListener,
    upstream: ProxyUpstreamConfig,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let upstream = upstream.clone();
                thread::spawn(move || {
                    let _ = handle_connection(stream, &upstream);
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => {
                return Err(err).context("transparent listener accept failed");
            }
        }
    }

    Ok(())
}

fn handle_connection(mut inbound: TcpStream, upstream: &ProxyUpstreamConfig) -> Result<()> {
    let original_dst = inbound
        .local_addr()
        .context("failed to query original destination from transparent socket")?;

    let target = match original_dst {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => bail!("IPv6 interception is not implemented in this PoC"),
    };

    let mut outbound = connect_upstream_proxy(upstream, target)?;
    relay_bidirectional(&mut inbound, &mut outbound)?;
    Ok(())
}

fn connect_upstream_proxy(
    upstream: &ProxyUpstreamConfig,
    target: SocketAddrV4,
) -> Result<TcpStream> {
    let upstream_addr = resolve_proxy_server(&upstream.server)?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create outbound proxy socket")?;

    if let Some(iface) = &upstream.bind_interface {
        socket
            .bind_device(Some(iface.as_bytes()))
            .with_context(|| {
                format!("failed to bind outbound proxy socket to interface {iface}")
            })?;
    }

    socket
        .connect(&SocketAddr::V4(upstream_addr).into())
        .with_context(|| {
            format!(
                "failed to connect to upstream proxy {}",
                render_proxy_server(&upstream.server)
            )
        })?;

    let mut stream: TcpStream = socket.into();
    stream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY on outbound proxy socket")?;

    match upstream.kind {
        ProxyType::Http => negotiate_http_connect(&mut stream, target)?,
        ProxyType::Socks5 => negotiate_socks5_connect(&mut stream, target)?,
    }

    Ok(stream)
}

fn resolve_proxy_server(server: &ProxyServer) -> Result<SocketAddrV4> {
    let addrs = (server.host.as_str(), server.port)
        .to_socket_addrs()
        .with_context(|| {
            format!(
                "failed to resolve upstream proxy {}",
                render_proxy_server(server)
            )
        })?;

    for addr in addrs {
        if let SocketAddr::V4(v4) = addr {
            return Ok(v4);
        }
    }

    bail!(
        "upstream proxy {} did not resolve to an IPv4 address",
        render_proxy_server(server)
    );
}

fn render_proxy_server(server: &ProxyServer) -> String {
    format!("{}:{}", server.host, server.port)
}

fn negotiate_http_connect(stream: &mut TcpStream, target: SocketAddrV4) -> Result<()> {
    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        target.ip(),
        target.port(),
        target.ip(),
        target.port()
    );
    stream
        .write_all(request.as_bytes())
        .context("failed to write HTTP CONNECT request")?;
    stream
        .flush()
        .context("failed to flush HTTP CONNECT request")?;

    let response = read_headers(stream)?;
    let first_line = response.lines().next().unwrap_or_default();
    if !(first_line.starts_with("HTTP/1.1 200") || first_line.starts_with("HTTP/1.0 200")) {
        bail!("upstream HTTP proxy rejected CONNECT: {first_line}");
    }

    Ok(())
}

fn negotiate_socks5_connect(stream: &mut TcpStream, target: SocketAddrV4) -> Result<()> {
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .context("failed to write SOCKS5 greeting")?;
    let mut method_reply = [0_u8; 2];
    stream
        .read_exact(&mut method_reply)
        .context("failed to read SOCKS5 method reply")?;
    if method_reply != [0x05, 0x00] {
        bail!("SOCKS5 proxy does not allow unauthenticated CONNECT");
    }

    let ip = target.ip().octets();
    let port = target.port().to_be_bytes();
    let request = [vec![0x05, 0x01, 0x00, 0x01], ip.to_vec(), port.to_vec()].concat();
    stream
        .write_all(&request)
        .context("failed to write SOCKS5 CONNECT request")?;

    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read SOCKS5 CONNECT reply header")?;
    if header[1] != 0x00 {
        bail!("SOCKS5 CONNECT failed with reply code 0x{:02x}", header[1]);
    }

    match header[3] {
        0x01 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .context("failed to read SOCKS5 IPv4 reply tail")?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .context("failed to read SOCKS5 domain length")?;
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .context("failed to read SOCKS5 domain reply tail")?;
        }
        0x04 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .context("failed to read SOCKS5 IPv6 reply tail")?;
        }
        other => bail!("unsupported SOCKS5 ATYP in reply: 0x{other:02x}"),
    }

    Ok(())
}

fn read_headers(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut chunk)
            .context("failed to read proxy response")?;
        if n == 0 {
            bail!("proxy closed connection while reading response headers");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            bail!("proxy response headers are too large");
        }
    }

    String::from_utf8(buf).map_err(|err| anyhow!("proxy response is not valid UTF-8: {err}"))
}

fn relay_bidirectional(left: &mut TcpStream, right: &mut TcpStream) -> Result<()> {
    let mut left_reader = left.try_clone().context("failed to clone inbound stream")?;
    let mut left_writer = left
        .try_clone()
        .context("failed to clone inbound stream writer")?;
    let mut right_reader = right
        .try_clone()
        .context("failed to clone outbound stream")?;
    let mut right_writer = right
        .try_clone()
        .context("failed to clone outbound stream writer")?;

    let client_to_proxy = thread::spawn(move || -> std::io::Result<u64> {
        let copied = std::io::copy(&mut left_reader, &mut right_writer)?;
        let _ = right_writer.shutdown(Shutdown::Write);
        Ok(copied)
    });
    let proxy_to_client = thread::spawn(move || -> std::io::Result<u64> {
        let copied = std::io::copy(&mut right_reader, &mut left_writer)?;
        let _ = left_writer.shutdown(Shutdown::Write);
        Ok(copied)
    });

    client_to_proxy
        .join()
        .map_err(|_| anyhow!("client->proxy relay thread panicked"))?
        .context("client->proxy relay failed")?;
    proxy_to_client
        .join()
        .map_err(|_| anyhow!("proxy->client relay thread panicked"))?
        .context("proxy->client relay failed")?;

    Ok(())
}
