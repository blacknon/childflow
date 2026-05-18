use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::libc;
use socket2::{Domain, Protocol, Socket, Type};

use super::{connect, relay, ProxyUpstreamConfig, TproxyHandle};

impl TproxyHandle {
    pub fn start(upstream: Arc<ProxyUpstreamConfig>) -> Result<Self> {
        let listener = build_listener()?;
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
}

fn build_listener() -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create transparent listener socket")?;
    socket.set_reuse_address(true).ok();
    socket.set_reuse_port(true).ok();
    socket
        .set_only_v6(false)
        .context("failed to configure dual-stack transparent listener")?;
    enable_transparent(&socket).context("failed to enable IP_TRANSPARENT on listener socket")?;
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
    Ok(listener)
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
    let target = super::protocol::normalize_socket_addr(target);

    let mut outbound = connect::connect_upstream_proxy(upstream, target)?;
    relay::relay_bidirectional(&mut inbound, &mut outbound)?;
    Ok(())
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
