// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslStream, SslVerifyMode};
use socket2::{Domain, Protocol, Socket, Type};

use crate::cli::{Cli, ProxyScheme, ProxyType};

#[derive(Clone, Debug)]
pub struct RootlessRelayProxyPlan {
    upstream: ProxyUpstreamConfig,
}

impl RootlessRelayProxyPlan {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let proxy = cli
            .proxy
            .as_ref()
            .context("rootless relay proxy planning requires `--proxy`")?;

        Ok(Self {
            upstream: ProxyUpstreamConfig {
                server: ProxyServer {
                    host: proxy.host.clone(),
                    port: proxy.port,
                },
                kind: match proxy.scheme {
                    ProxyScheme::Http | ProxyScheme::Https => ProxyType::Http,
                    ProxyScheme::Socks5 => ProxyType::Socks5,
                },
                tls: matches!(proxy.scheme, ProxyScheme::Https),
                auth: match (&cli.proxy_user, &cli.proxy_password) {
                    (Some(username), Some(password)) => Some(ProxyAuth {
                        username: username.clone(),
                        password: password.clone(),
                    }),
                    (None, None) => None,
                    _ => bail!("`--proxy-user` and `--proxy-password` must be provided together"),
                },
                insecure: cli.proxy_insecure,
            },
        })
    }

    pub fn upstream(&self) -> &ProxyUpstreamConfig {
        &self.upstream
    }
}

#[derive(Clone, Debug)]
pub struct ProxyServer {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct ProxyUpstreamConfig {
    pub server: ProxyServer,
    pub kind: ProxyType,
    pub tls: bool,
    pub auth: Option<ProxyAuth>,
    pub insecure: bool,
}

pub enum OutboundStream {
    Tcp(TcpStream),
    Tls(SslStream<TcpStream>),
}

impl OutboundStream {
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(buf),
            Self::Tls(stream) => stream.write_all(buf),
        }
    }

    pub fn shutdown_write(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(std::net::Shutdown::Write),
            Self::Tls(stream) => stream.get_ref().shutdown(std::net::Shutdown::Write),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(timeout),
            Self::Tls(stream) => stream.get_ref().set_read_timeout(timeout),
        }
    }
}

pub fn connect_via_proxy(
    upstream: &ProxyUpstreamConfig,
    target: SocketAddr,
) -> Result<OutboundStream> {
    let upstream_addrs = resolve_proxy_server(&upstream.server)?;
    let mut stream = connect_tcp_proxy_socket(&upstream_addrs)?;
    stream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY on the rootless upstream proxy socket")?;

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
        return Ok(OutboundStream::Tls(tls_stream));
    }

    match upstream.kind {
        ProxyType::Http => negotiate_http_connect(&mut stream, target, upstream.auth.as_ref())?,
        ProxyType::Socks5 => negotiate_socks5_connect(&mut stream, target, upstream.auth.as_ref())?,
    }

    Ok(OutboundStream::Tcp(stream))
}

fn resolve_proxy_server(server: &ProxyServer) -> Result<Vec<SocketAddr>> {
    let addrs = (server.host.as_str(), server.port)
        .to_socket_addrs()
        .with_context(|| {
            format!(
                "failed to resolve rootless upstream proxy {}",
                render_proxy_server(server)
            )
        })?;
    let addrs: Vec<_> = addrs.collect();
    if addrs.is_empty() {
        bail!(
            "rootless upstream proxy {} did not resolve to an IP address",
            render_proxy_server(server)
        );
    }
    Ok(addrs)
}

fn render_proxy_server(server: &ProxyServer) -> String {
    format!("{}:{}", server.host, server.port)
}

fn connect_tcp_proxy_socket(addrs: &[SocketAddr]) -> Result<TcpStream> {
    let mut errors = Vec::new();

    for addr in addrs {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .context("failed to create rootless upstream proxy socket")?;
        match socket.connect(&(*addr).into()) {
            Ok(()) => return Ok(socket.into()),
            Err(err) => errors.push(format!("{addr}: {err}")),
        }
    }

    bail!(
        "failed to connect to the rootless upstream proxy via any resolved address:\n{}",
        errors.join("\n")
    );
}

fn connect_tls_proxy(
    stream: TcpStream,
    server: &ProxyServer,
    insecure: bool,
) -> Result<SslStream<TcpStream>> {
    let mut builder = SslConnector::builder(SslMethod::tls())
        .context("failed to build TLS connector for the rootless upstream proxy")?;
    if insecure {
        builder.set_verify_callback(SslVerifyMode::PEER, |_preverify_ok, _ctx| true);
    }
    let connector = builder.build();
    connector
        .connect(server.host.as_str(), stream)
        .map_err(|err| {
            anyhow!(
                "failed to establish TLS to the rootless upstream proxy {}: {}",
                render_proxy_server(server),
                render_handshake_error(err)
            )
        })
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
        .context("failed to write rootless HTTP CONNECT request")?;
    stream
        .flush()
        .context("failed to flush rootless HTTP CONNECT request")?;

    let response = read_headers(stream)?;
    let first_line = response.lines().next().unwrap_or_default();
    if !(first_line.starts_with("HTTP/1.1 200") || first_line.starts_with("HTTP/1.0 200")) {
        bail!("rootless upstream HTTP proxy rejected CONNECT: {first_line}");
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
        .context("failed to write rootless SOCKS5 greeting")?;
    let mut method_reply = [0_u8; 2];
    stream
        .read_exact(&mut method_reply)
        .context("failed to read rootless SOCKS5 method reply")?;
    if method_reply[0] != 0x05 {
        bail!(
            "unexpected rootless SOCKS5 greeting reply version 0x{:02x}",
            method_reply[0]
        );
    }
    match method_reply[1] {
        0x00 => {}
        0x02 => authenticate_socks5(stream, auth)?,
        0xff => bail!("rootless SOCKS5 proxy did not accept any offered authentication method"),
        other => {
            bail!("rootless SOCKS5 proxy selected unsupported authentication method 0x{other:02x}")
        }
    }

    let request = match target.ip() {
        std::net::IpAddr::V4(ip) => [
            vec![0x05, 0x01, 0x00, 0x01],
            ip.octets().to_vec(),
            target.port().to_be_bytes().to_vec(),
        ]
        .concat(),
        std::net::IpAddr::V6(ip) => [
            vec![0x05, 0x01, 0x00, 0x04],
            ip.octets().to_vec(),
            target.port().to_be_bytes().to_vec(),
        ]
        .concat(),
    };
    stream
        .write_all(&request)
        .context("failed to write rootless SOCKS5 CONNECT request")?;

    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read rootless SOCKS5 CONNECT reply header")?;
    if header[1] != 0x00 {
        bail!(
            "rootless SOCKS5 CONNECT failed with reply code 0x{:02x}",
            header[1]
        );
    }

    match header[3] {
        0x01 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .context("failed to read rootless SOCKS5 IPv4 reply tail")?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .context("failed to read rootless SOCKS5 domain length")?;
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .context("failed to read rootless SOCKS5 domain reply tail")?;
        }
        0x04 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .context("failed to read rootless SOCKS5 IPv6 reply tail")?;
        }
        other => bail!("unsupported rootless SOCKS5 ATYP in reply: 0x{other:02x}"),
    }

    Ok(())
}

fn authenticate_socks5<S: Read + Write>(stream: &mut S, auth: Option<&ProxyAuth>) -> Result<()> {
    let auth = auth.ok_or_else(|| {
        anyhow!("rootless SOCKS5 proxy requested username/password authentication")
    })?;
    let username = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        bail!("rootless SOCKS5 proxy credentials must be at most 255 bytes each");
    }

    let mut request = vec![0x01, username.len() as u8];
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream
        .write_all(&request)
        .context("failed to write rootless SOCKS5 username/password authentication request")?;

    let mut reply = [0_u8; 2];
    stream
        .read_exact(&mut reply)
        .context("failed to read rootless SOCKS5 authentication reply")?;
    if reply != [0x01, 0x00] {
        bail!("rootless SOCKS5 authentication failed");
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

fn read_headers<S: Read>(stream: &mut S) -> Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut chunk)
            .context("failed to read rootless proxy response")?;
        if n == 0 {
            bail!("rootless proxy closed connection while reading response headers");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            bail!("rootless proxy response headers are too large");
        }
    }

    String::from_utf8(buf)
        .map_err(|err| anyhow!("rootless proxy response is not valid UTF-8: {err}"))
}