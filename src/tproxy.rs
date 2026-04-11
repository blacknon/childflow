use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslStream, SslVerifyMode};
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
    pub tls: bool,
    pub auth: Option<ProxyAuth>,
    pub insecure: bool,
    pub bind_interface: Option<String>,
}

#[derive(Clone)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

enum ProxyStream {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

pub struct TproxyHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<()>>>,
    listen_port: u16,
}

impl TproxyHandle {
    pub fn start(upstream: ProxyUpstreamConfig) -> Result<Self> {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
            .context("failed to create transparent listener socket")?;
        socket.set_reuse_address(true).ok();
        socket.set_reuse_port(true).ok();
        socket
            .set_only_v6(false)
            .context("failed to configure dual-stack transparent listener")?;
        socket
            .set_ip_transparent(true)
            .context("failed to enable IP_TRANSPARENT on listener socket")?;
        let bind_addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0));
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
    let target = inbound
        .local_addr()
        .context("failed to query original destination from transparent socket")?;
    let target = normalize_socket_addr(target);

    let mut outbound = connect_upstream_proxy(upstream, target)?;
    relay_bidirectional(&mut inbound, &mut outbound)?;
    Ok(())
}

fn connect_upstream_proxy(
    upstream: &ProxyUpstreamConfig,
    target: SocketAddr,
) -> Result<ProxyStream> {
    let upstream_addrs = resolve_proxy_server(&upstream.server)?;
    let mut stream = connect_tcp_proxy_socket(upstream, &upstream_addrs)?;
    stream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY on outbound proxy socket")?;

    if upstream.tls {
        let mut tls_stream = connect_tls_proxy(stream, &upstream.server, upstream.insecure)?;
        match upstream.kind {
            ProxyType::Http => {
                negotiate_http_connect(&mut tls_stream, target, upstream.auth.as_ref())?
            }
            ProxyType::Socks5 => {
                negotiate_socks5_connect(&mut tls_stream, target, upstream.auth.as_ref())?
            }
        }
        return Ok(ProxyStream::Tls(Box::new(tls_stream)));
    }

    match upstream.kind {
        ProxyType::Http => negotiate_http_connect(&mut stream, target, upstream.auth.as_ref())?,
        ProxyType::Socks5 => negotiate_socks5_connect(&mut stream, target, upstream.auth.as_ref())?,
    }

    Ok(ProxyStream::Tcp(stream))
}

fn resolve_proxy_server(server: &ProxyServer) -> Result<Vec<SocketAddr>> {
    let addrs = (server.host.as_str(), server.port)
        .to_socket_addrs()
        .with_context(|| {
            format!(
                "failed to resolve upstream proxy {}",
                render_proxy_server(server)
            )
        })?;

    let addrs: Vec<_> = addrs.collect();
    if addrs.is_empty() {
        bail!(
            "upstream proxy {} did not resolve to an IP address",
            render_proxy_server(server)
        );
    }
    Ok(addrs)
}

fn render_proxy_server(server: &ProxyServer) -> String {
    format!("{}:{}", server.host, server.port)
}

fn connect_tls_proxy(
    stream: TcpStream,
    server: &ProxyServer,
    insecure: bool,
) -> Result<SslStream<TcpStream>> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).context("failed to build TLS connector")?;
    if insecure {
        builder.set_verify_callback(SslVerifyMode::PEER, |_preverify_ok, _ctx| true);
    }
    let connector = builder.build();
    connector
        .connect(server.host.as_str(), stream)
        .map_err(|err| {
            anyhow!(
                "failed to establish TLS to upstream proxy {}: {}",
                render_proxy_server(server),
                render_handshake_error(err)
            )
        })
}

fn connect_tcp_proxy_socket(
    upstream: &ProxyUpstreamConfig,
    addrs: &[SocketAddr],
) -> Result<TcpStream> {
    let mut errors = Vec::new();

    for addr in addrs {
        match connect_single_proxy_addr(upstream, *addr) {
            Ok(stream) => return Ok(stream),
            Err(err) => errors.push(format!("{addr}: {err:#}")),
        }
    }

    bail!(
        "failed to connect to upstream proxy {} via any resolved address:\n{}",
        render_proxy_server(&upstream.server),
        errors.join("\n")
    );
}

fn connect_single_proxy_addr(
    upstream: &ProxyUpstreamConfig,
    addr: SocketAddr,
) -> Result<TcpStream> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create outbound proxy socket")?;

    if let Some(iface) = &upstream.bind_interface {
        socket
            .bind_device(Some(iface.as_bytes()))
            .with_context(|| {
                format!("failed to bind outbound proxy socket to interface {iface}")
            })?;
    }

    socket
        .connect(&addr.into())
        .with_context(|| format!("failed to connect to upstream proxy address {addr}"))?;

    Ok(socket.into())
}

fn render_handshake_error(err: HandshakeError<TcpStream>) -> String {
    match err {
        HandshakeError::SetupFailure(err) => err.to_string(),
        HandshakeError::Failure(mid) => mid.error().to_string(),
        HandshakeError::WouldBlock(mid) => mid.error().to_string(),
    }
}

fn negotiate_http_connect<S: Read + Write>(
    stream: &mut S,
    target: SocketAddr,
    auth: Option<&ProxyAuth>,
) -> Result<()> {
    let authority = render_target_authority(target);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n",
    );
    if let Some(auth) = auth {
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&render_basic_proxy_auth(auth));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
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

fn negotiate_socks5_connect<S: Read + Write>(
    stream: &mut S,
    target: SocketAddr,
    auth: Option<&ProxyAuth>,
) -> Result<()> {
    let methods = if auth.is_some() {
        vec![0x00, 0x02]
    } else {
        vec![0x00]
    };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(&methods);
    stream
        .write_all(&greeting)
        .context("failed to write SOCKS5 greeting")?;
    let mut method_reply = [0_u8; 2];
    stream
        .read_exact(&mut method_reply)
        .context("failed to read SOCKS5 method reply")?;
    if method_reply[0] != 0x05 {
        bail!(
            "unexpected SOCKS5 greeting reply version 0x{:02x}",
            method_reply[0]
        );
    }
    match method_reply[1] {
        0x00 => {}
        0x02 => authenticate_socks5(stream, auth)?,
        0xff => bail!("SOCKS5 proxy did not accept any offered authentication method"),
        other => bail!("SOCKS5 proxy selected unsupported authentication method 0x{other:02x}"),
    }

    let request = match target.ip() {
        IpAddr::V4(ip) => [
            vec![0x05, 0x01, 0x00, 0x01],
            ip.octets().to_vec(),
            target.port().to_be_bytes().to_vec(),
        ]
        .concat(),
        IpAddr::V6(ip) => [
            vec![0x05, 0x01, 0x00, 0x04],
            ip.octets().to_vec(),
            target.port().to_be_bytes().to_vec(),
        ]
        .concat(),
    };
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

fn authenticate_socks5<S: Read + Write>(stream: &mut S, auth: Option<&ProxyAuth>) -> Result<()> {
    let auth =
        auth.ok_or_else(|| anyhow!("SOCKS5 proxy requested username/password authentication"))?;
    let username = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        bail!("SOCKS5 proxy credentials must be at most 255 bytes each");
    }

    let mut request = vec![0x01, username.len() as u8];
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream
        .write_all(&request)
        .context("failed to write SOCKS5 username/password authentication request")?;

    let mut reply = [0_u8; 2];
    stream
        .read_exact(&mut reply)
        .context("failed to read SOCKS5 authentication reply")?;
    if reply != [0x01, 0x00] {
        bail!("SOCKS5 authentication failed");
    }

    Ok(())
}

fn render_basic_proxy_auth(auth: &ProxyAuth) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", auth.username, auth.password))
}

fn render_target_authority(target: SocketAddr) -> String {
    match target {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), v6.port()),
            None => SocketAddr::V6(v6),
        },
        SocketAddr::V4(_) => addr,
    }
}

fn read_headers<S: Read>(stream: &mut S) -> Result<String> {
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

fn relay_bidirectional<S: Read + Write>(left: &mut TcpStream, right: &mut S) -> Result<()> {
    std::io::copy_bidirectional(left, right).context("proxy relay failed")?;
    let _ = left.shutdown(Shutdown::Both);
    Ok(())
}

impl Read for ProxyStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for ProxyStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

    struct ScriptedStream {
        reader: Cursor<Vec<u8>>,
        writes: Vec<u8>,
        flushes: usize,
    }

    impl ScriptedStream {
        fn new(chunks: &[&[u8]]) -> Self {
            let mut bytes = Vec::new();
            for chunk in chunks {
                bytes.extend_from_slice(chunk);
            }
            Self {
                reader: Cursor::new(bytes),
                writes: Vec::new(),
                flushes: 0,
            }
        }
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reader.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn render_target_authority_brackets_ipv6() {
        let target = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::10".parse::<Ipv6Addr>().unwrap(),
            443,
            0,
            0,
        ));
        assert_eq!(render_target_authority(target), "[2001:db8::10]:443");
    }

    #[test]
    fn normalize_socket_addr_converts_ipv4_mapped_ipv6() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 0, 2, 45).to_ipv6_mapped(),
            8443,
            0,
            0,
        ));

        assert_eq!(
            normalize_socket_addr(mapped),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45)), 8443)
        );
    }

    #[test]
    fn render_basic_proxy_auth_encodes_user_and_password() {
        let auth = ProxyAuth {
            username: "alice".into(),
            password: "s3cret".into(),
        };

        assert_eq!(render_basic_proxy_auth(&auth), "YWxpY2U6czNjcmV0");
    }

    #[test]
    fn http_connect_includes_proxy_authorization_header() {
        let mut stream = ScriptedStream::new(&[b"HTTP/1.1 200 Connection Established\r\n\r\n"]);
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);
        let auth = ProxyAuth {
            username: "demo".into(),
            password: "pass".into(),
        };

        negotiate_http_connect(&mut stream, target, Some(&auth)).unwrap();

        let written = String::from_utf8(stream.writes).unwrap();
        assert!(written.contains("CONNECT 198.51.100.10:443 HTTP/1.1"));
        assert!(written.contains("Proxy-Authorization: Basic ZGVtbzpwYXNz\r\n"));
        assert_eq!(stream.flushes, 1);
    }

    #[test]
    fn socks5_connect_performs_username_password_authentication() {
        let mut stream = ScriptedStream::new(&[
            &[0x05, 0x02],
            &[0x01, 0x00],
            &[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90],
        ]);
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 8080);
        let auth = ProxyAuth {
            username: "demo".into(),
            password: "pass".into(),
        };

        negotiate_socks5_connect(&mut stream, target, Some(&auth)).unwrap();

        assert!(stream.writes.starts_with(&[0x05, 0x02, 0x00, 0x02]));
        assert!(stream.writes.windows(2).any(|w| w == [0x01, 0x04]));
        assert!(stream.writes.windows(b"demo".len()).any(|w| w == b"demo"));
        assert!(stream.writes.windows(b"pass".len()).any(|w| w == b"pass"));
        assert!(stream
            .writes
            .ends_with(&[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x1f, 0x90]));
    }
}
