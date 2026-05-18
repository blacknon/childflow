use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

use anyhow::{anyhow, bail, Context, Result};
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use socket2::{Domain, Protocol, Socket, Type};

use super::{render_handshake_error, ProxyServer};

pub(super) fn resolve_proxy_server(server: &ProxyServer) -> Result<Vec<SocketAddr>> {
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

pub(super) fn connect_tcp_proxy_socket(addrs: &[SocketAddr]) -> Result<TcpStream> {
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

pub(super) fn connect_tls_proxy(
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

fn render_proxy_server(server: &ProxyServer) -> String {
    format!("{}:{}", server.host, server.port)
}
