use std::mem::{size_of, MaybeUninit};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::super::IcmpRelayOutcome;

pub(super) fn relay_icmpv4_message(
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    message: &[u8],
) -> Result<IcmpRelayOutcome> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(nix::libc::IPPROTO_ICMP)),
    )
    .context("failed to create an ICMPv4 raw socket")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to configure the ICMPv4 raw-socket timeout")?;

    let ttl = i32::from(hop_limit);
    // SAFETY: `setsockopt` is invoked with a valid fd, correct buffer pointer, and matching length.
    let rc = unsafe {
        nix::libc::setsockopt(
            socket.as_raw_fd(),
            nix::libc::IPPROTO_IP,
            nix::libc::IP_TTL,
            (&ttl as *const i32).cast(),
            size_of::<i32>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to configure the ICMPv4 raw-socket TTL");
    }

    let remote = SockAddr::from(std::net::SocketAddr::new(IpAddr::V4(remote_ip), 0));
    socket
        .send_to(message, &remote)
        .with_context(|| format!("failed to send an ICMPv4 request toward {remote_ip}"))?;

    let mut buf = [MaybeUninit::<u8>::uninit(); 65535];
    loop {
        let (size, addr) = socket
            .recv_from(&mut buf)
            .with_context(|| format!("failed to receive an ICMPv4 reply for {remote_ip}"))?;
        let source_ip = match addr.as_socket() {
            Some(std::net::SocketAddr::V4(addr)) => *addr.ip(),
            _ => continue,
        };
        // SAFETY: `recv_from` initialized the first `size` bytes in `buf`.
        let packet = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), size) };
        if packet.len() < 20 {
            continue;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if packet.len() < header_len + 8 {
            continue;
        }
        let message = packet[header_len..].to_vec();
        if (3..=12).contains(&message[0]) {
            return Ok(IcmpRelayOutcome::Error {
                source_ip: IpAddr::V4(source_ip),
                icmp_type: message[0],
                code: message[1],
            });
        }
        return Ok(IcmpRelayOutcome::Message(message));
    }
}

pub(super) fn relay_icmpv6_message(
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    message: &[u8],
) -> Result<IcmpRelayOutcome> {
    let socket = Socket::new(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::from(nix::libc::IPPROTO_ICMPV6)),
    )
    .context("failed to create an ICMPv6 raw socket")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to configure the ICMPv6 raw-socket timeout")?;

    let hop_limit = i32::from(hop_limit);
    // SAFETY: `setsockopt` is invoked with a valid fd, correct buffer pointer, and matching length.
    let rc = unsafe {
        nix::libc::setsockopt(
            socket.as_raw_fd(),
            nix::libc::IPPROTO_IPV6,
            nix::libc::IPV6_UNICAST_HOPS,
            (&hop_limit as *const i32).cast(),
            size_of::<i32>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to configure the ICMPv6 raw-socket hop limit");
    }

    let checksum_offset = 2_i32;
    // SAFETY: `setsockopt` is invoked with a valid fd, correct buffer pointer, and matching length.
    let rc = unsafe {
        nix::libc::setsockopt(
            socket.as_raw_fd(),
            nix::libc::IPPROTO_IPV6,
            nix::libc::IPV6_CHECKSUM,
            (&checksum_offset as *const i32).cast(),
            size_of::<i32>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to configure the ICMPv6 checksum offset");
    }

    let remote = SockAddr::from(std::net::SocketAddr::new(IpAddr::V6(remote_ip), 0));
    socket
        .send_to(message, &remote)
        .with_context(|| format!("failed to send an ICMPv6 request toward {remote_ip}"))?;

    let mut buf = [MaybeUninit::<u8>::uninit(); 65535];
    loop {
        let (size, addr) = socket
            .recv_from(&mut buf)
            .with_context(|| format!("failed to receive an ICMPv6 reply for {remote_ip}"))?;
        let source_ip = match addr.as_socket() {
            Some(std::net::SocketAddr::V6(addr)) => *addr.ip(),
            _ => continue,
        };
        // SAFETY: `recv_from` initialized the first `size` bytes in `buf`.
        let message =
            unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), size) }.to_vec();
        if message.len() < 8 {
            continue;
        }
        if (1..=4).contains(&message[0]) {
            return Ok(IcmpRelayOutcome::Error {
                source_ip: IpAddr::V6(source_ip),
                icmp_type: message[0],
                code: message[1],
            });
        }
        return Ok(IcmpRelayOutcome::Message(message));
    }
}
