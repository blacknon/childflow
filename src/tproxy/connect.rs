use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

use anyhow::{anyhow, bail, Context, Result};
use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslStream, SslVerifyMode};
use socket2::{Domain, Protocol, Socket, Type};

use crate::cli::ProxyType;

use super::{protocol, ProxyServer, ProxyStream, ProxyUpstreamConfig};

pub(super) fn connect_upstream_proxy(
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
                protocol::negotiate_http_connect(&mut tls_stream, target, upstream.auth.as_ref())?
            }
            ProxyType::Socks5 => {
                protocol::negotiate_socks5_connect(&mut tls_stream, target, upstream.auth.as_ref())?
            }
        }
        return Ok(ProxyStream::Tls(Box::new(tls_stream)));
    }

    match upstream.kind {
        ProxyType::Http => {
            protocol::negotiate_http_connect(&mut stream, target, upstream.auth.as_ref())?
        }
        ProxyType::Socks5 => {
            protocol::negotiate_socks5_connect(&mut stream, target, upstream.auth.as_ref())?
        }
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
