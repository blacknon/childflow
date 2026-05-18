// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::io::ErrorKind;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};

pub(super) struct ReceivedUdpError {
    pub(super) source_ip: IpAddr,
    pub(super) icmp_type: u8,
    pub(super) code: u8,
}

pub(super) fn recv_udp_error(socket: &UdpSocket) -> Result<Option<ReceivedUdpError>> {
    let fd = socket.as_raw_fd();
    let mut data = [0_u8; 512];
    let mut control = [0_u8; 512];
    // SAFETY: zero-initialized storage is valid scratch space for the kernel to fill in.
    let mut name: nix::libc::sockaddr_storage = unsafe { zeroed() };
    let mut iov = nix::libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    // SAFETY: `msghdr` is plain old data and we populate all fields we rely on before use.
    let mut msg: nix::libc::msghdr = unsafe { zeroed() };
    msg.msg_name = (&mut name as *mut nix::libc::sockaddr_storage).cast();
    msg.msg_namelen = size_of::<nix::libc::sockaddr_storage>() as nix::libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    // SAFETY: the buffers referenced by `msg` remain valid and writable for the duration
    // of this syscall, which fills them from the socket error queue.
    let rc = unsafe { nix::libc::recvmsg(fd, &mut msg, nix::libc::MSG_ERRQUEUE) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
            return Ok(None);
        }
        return Err(err).context("failed to read the UDP error queue");
    }

    parse_udp_error_message(&msg)
}

fn parse_udp_error_message(msg: &nix::libc::msghdr) -> Result<Option<ReceivedUdpError>> {
    // SAFETY: `msg` was filled by `recvmsg`, so ancillary iteration may examine its headers.
    let mut cmsg = unsafe { nix::libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is non-null and points into the control buffer owned by `msg`.
        let level = unsafe { (*cmsg).cmsg_level };
        // SAFETY: same reasoning as for `cmsg_level` above.
        let ty = unsafe { (*cmsg).cmsg_type };
        if (level == nix::libc::SOL_IP && ty == nix::libc::IP_RECVERR)
            || (level == nix::libc::SOL_IPV6 && ty == nix::libc::IPV6_RECVERR)
        {
            // SAFETY: Linux documents the `IP*_RECVERR` payload as `sock_extended_err`.
            let err_ptr =
                unsafe { nix::libc::CMSG_DATA(cmsg).cast::<nix::libc::sock_extended_err>() };
            // SAFETY: `err_ptr` points at ancillary data with the documented layout above.
            let err = unsafe { &*err_ptr };
            // SAFETY: the offender sockaddr is stored immediately after `sock_extended_err`
            // in this ancillary payload layout.
            let offender_ptr = unsafe {
                (err_ptr.cast::<u8>())
                    .add(size_of::<nix::libc::sock_extended_err>())
                    .cast::<nix::libc::sockaddr>()
            };
            let source_ip =
                sockaddr_to_ip(offender_ptr).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            return Ok(Some(ReceivedUdpError {
                source_ip,
                icmp_type: err.ee_type,
                code: err.ee_code,
            }));
        }
        // SAFETY: advances within the validated control buffer described by `msg`.
        cmsg = unsafe { nix::libc::CMSG_NXTHDR(msg, cmsg) };
    }

    Ok(None)
}

fn sockaddr_to_ip(sockaddr: *const nix::libc::sockaddr) -> Option<IpAddr> {
    if sockaddr.is_null() {
        return None;
    }

    // SAFETY: `sockaddr` is non-null and points to a sockaddr produced by the kernel.
    let family = unsafe { (*sockaddr).sa_family as i32 };
    match family {
        nix::libc::AF_INET => {
            // SAFETY: `sa_family` confirmed the pointer layout is `sockaddr_in`.
            let addr = unsafe { &*(sockaddr as *const nix::libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                addr.sin_addr.s_addr,
            ))))
        }
        nix::libc::AF_INET6 => {
            // SAFETY: `sa_family` confirmed the pointer layout is `sockaddr_in6`.
            let addr = unsafe { &*(sockaddr as *const nix::libc::sockaddr_in6) };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}
