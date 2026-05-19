// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::mem::size_of;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};

pub(super) fn configure_udp_probe_socket(
    socket: &UdpSocket,
    remote_addr: SocketAddr,
    hop_limit: u8,
) -> Result<()> {
    if hop_limit > 0 {
        match remote_addr {
            SocketAddr::V4(_) => socket
                .set_ttl(u32::from(hop_limit))
                .context("failed to set the IPv4 UDP probe TTL")?,
            SocketAddr::V6(_) => set_udp_ipv6_hops(socket, hop_limit)?,
        }
    }

    enable_udp_error_queue(socket, remote_addr)?;
    Ok(())
}

fn set_udp_ipv6_hops(socket: &UdpSocket, hop_limit: u8) -> Result<()> {
    let fd = socket.as_raw_fd();
    let value: std::ffi::c_int = i32::from(hop_limit);
    // SAFETY: `fd` is a valid UDP socket, `value` is initialized, and the kernel only reads
    // the option bytes during the syscall.
    let rc = unsafe {
        nix::libc::setsockopt(
            fd,
            nix::libc::IPPROTO_IPV6,
            nix::libc::IPV6_UNICAST_HOPS,
            (&value as *const std::ffi::c_int).cast(),
            size_of::<std::ffi::c_int>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to set the IPv6 UDP probe hop limit");
    }
    Ok(())
}

fn enable_udp_error_queue(socket: &UdpSocket, remote_addr: SocketAddr) -> Result<()> {
    let fd = socket.as_raw_fd();
    let enabled: std::ffi::c_int = 1;
    let (level, optname) = match remote_addr {
        SocketAddr::V4(_) => (nix::libc::SOL_IP, nix::libc::IP_RECVERR),
        SocketAddr::V6(_) => (nix::libc::SOL_IPV6, nix::libc::IPV6_RECVERR),
    };
    // SAFETY: `fd` is a valid UDP socket and `enabled` stays alive for the duration of the
    // syscall while the kernel reads the option bytes.
    let rc = unsafe {
        nix::libc::setsockopt(
            fd,
            level,
            optname,
            (&enabled as *const std::ffi::c_int).cast(),
            size_of::<std::ffi::c_int>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to enable UDP error-queue delivery for rootless traceroute support");
    }
    Ok(())
}
