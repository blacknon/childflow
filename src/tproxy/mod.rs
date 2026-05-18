// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod connect;
mod protocol;
mod relay;

#[cfg(test)]
mod tests;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::libc;
use openssl::ssl::SslStream;
use socket2::{Domain, Protocol, Socket, Type};

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

impl TproxyHandle {
    pub fn start(upstream: Arc<ProxyUpstreamConfig>) -> Result<Self> {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
            .context("failed to create transparent listener socket")?;
        socket.set_reuse_address(true).ok();
        socket.set_reuse_port(true).ok();
        socket
            .set_only_v6(false)
            .context("failed to configure dual-stack transparent listener")?;
        enable_transparent(&socket)
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

    fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(err).context("transparent proxy stopped with an error");
                }
                Err(_) => bail!("transparent proxy thread panicked"),
            }
        }
        Ok(())
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }
}

impl Drop for TproxyHandle {
    fn drop(&mut self) {
        if let Err(err) = self.stop_and_join() {
            crate::util::warn(format!("{err:#}"));
        }
    }
}

fn accept_loop(
    listener: TcpListener,
    upstream: Arc<ProxyUpstreamConfig>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let upstream = Arc::clone(&upstream);
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
    let target = protocol::normalize_socket_addr(target);

    let mut outbound = connect::connect_upstream_proxy(upstream, target)?;
    relay::relay_bidirectional(&mut inbound, &mut outbound)?;
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

fn enable_transparent(socket: &Socket) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();
    let value: libc::c_int = 1;

    unsafe {
        // SAFETY: `fd` is a live socket descriptor, `value` points to a valid `c_int`,
        // and the kernel only reads the provided option bytes during this call.
        if libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TRANSPARENT,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }

        #[cfg(target_os = "linux")]
        {
            // SAFETY: same justification as the IPv4 call above, but for the IPv6 socket option.
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_TRANSPARENT,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    Ok(())
}
