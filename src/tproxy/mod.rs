// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod connect;
mod lifecycle;
mod listener;
mod protocol;
mod relay;

#[cfg(test)]
mod tests;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Result;
use openssl::ssl::SslStream;

use crate::cli::{Cli, ProxyScheme, ProxyType};

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
    Tls(Box<SslStream<TcpStream>>),
}

pub struct TproxyHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<()>>>,
    listen_port: u16,
}

pub struct TransparentProxyPlan {
    upstream: Arc<ProxyUpstreamConfig>,
}

impl TransparentProxyPlan {
    pub fn from_cli(cli: &Cli) -> Option<Self> {
        let proxy_spec = cli.proxy.clone()?;

        Some(Self {
            upstream: Arc::new(ProxyUpstreamConfig {
                server: ProxyServer {
                    host: proxy_spec.host,
                    port: proxy_spec.port,
                },
                kind: match proxy_spec.scheme {
                    ProxyScheme::Http | ProxyScheme::Https => ProxyType::Http,
                    ProxyScheme::Socks5 => ProxyType::Socks5,
                },
                tls: matches!(proxy_spec.scheme, ProxyScheme::Https),
                auth: match (cli.proxy_user.clone(), cli.proxy_password.clone()) {
                    (Some(username), Some(password)) => Some(ProxyAuth { username, password }),
                    _ => None,
                },
                insecure: cli.proxy_insecure,
                bind_interface: cli.iface.clone(),
            }),
        })
    }

    pub fn start(&self) -> Result<TproxyHandle> {
        TproxyHandle::start(Arc::clone(&self.upstream))
    }
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

impl ProxyStream {
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_nonblocking(nonblocking),
            Self::Tls(stream) => stream.get_ref().set_nonblocking(nonblocking),
        }
    }

    fn shutdown_write(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Write),
            Self::Tls(stream) => stream.get_ref().shutdown(Shutdown::Write),
        }
    }
}
