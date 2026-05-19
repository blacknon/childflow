// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod connect;
mod protocol;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use openssl::ssl::SslStream;

use crate::cli::{Cli, ProxyScheme, ProxyType};

use self::connect::{connect_tcp_proxy_socket, connect_tls_proxy, resolve_proxy_server};
use self::protocol::{negotiate_http_connect, negotiate_socks5_connect, render_handshake_error};

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
