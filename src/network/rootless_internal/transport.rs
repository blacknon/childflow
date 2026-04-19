// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::io::ErrorKind;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::proxy::rootless_relay::{self, OutboundStream, ProxyUpstreamConfig};

use super::engine::{ConnectionCommand, RemoteEvent};
use super::state::FlowKey;

pub(super) const DNS_TYPE_AAAA: u16 = 28;
const DNS_HEADER_LEN: usize = 12;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum UdpRelayOutcome {
    Payload(Vec<u8>),
    IcmpError {
        source_ip: IpAddr,
        icmp_type: u8,
        code: u8,
    },
}

pub(super) fn connect_remote(
    remote_addr: SocketAddr,
    proxy_upstream: Option<&ProxyUpstreamConfig>,
    event_tx: Sender<RemoteEvent>,
    key: FlowKey,
) -> Result<Sender<ConnectionCommand>> {
    let stream = if let Some(proxy_upstream) = proxy_upstream {
        rootless_relay::connect_via_proxy(proxy_upstream, remote_addr).with_context(|| {
            format!(
                "failed to connect to remote TCP destination {remote_addr} through the configured rootless upstream proxy"
            )
        })?
    } else {
        let stream = match remote_addr {
            SocketAddr::V4(addr) => {
                TcpStream::connect_timeout(&SocketAddr::V4(addr), Duration::from_secs(5))
            }
            SocketAddr::V6(addr) => {
                TcpStream::connect_timeout(&SocketAddr::V6(addr), Duration::from_secs(5))
            }
        }
        .with_context(|| format!("failed to connect to remote TCP destination {remote_addr}"))?;
        stream
            .set_nodelay(true)
            .context("failed to enable TCP_NODELAY for remote TCP socket")?;
        OutboundStream::Tcp(stream)
    };

    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("failed to configure the rootless outbound stream read timeout")?;

    let (command_tx, command_rx) = mpsc::channel();
    spawn_remote_worker(event_tx, key, stream, command_rx);
    Ok(command_tx)
}

fn spawn_remote_worker(
    event_tx: Sender<RemoteEvent>,
    key: FlowKey,
    mut stream: OutboundStream,
    command_rx: Receiver<ConnectionCommand>,
) {
    thread::spawn(move || {
        let mut buf = [0_u8; 8192];
        let mut write_closed = false;
        loop {
            match command_rx.recv_timeout(Duration::from_millis(10)) {
                Ok(ConnectionCommand::Write(payload)) => {
                    if stream.write_all(&payload).is_err() {
                        let _ = event_tx.send(RemoteEvent::TcpClosed { key: key.clone() });
                        break;
                    }
                }
                Ok(ConnectionCommand::ShutdownWrite) => {
                    write_closed = true;
                    let _ = stream.shutdown_write();
                }
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }

            match stream.read(&mut buf) {
                Ok(0) => {
                    let _ = event_tx.send(RemoteEvent::TcpClosed { key: key.clone() });
                    break;
                }
                Ok(n) => {
                    let _ = event_tx.send(RemoteEvent::TcpData {
                        key: key.clone(),
                        payload: buf[..n].to_vec(),
                    });
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                    ) =>
                {
                    if write_closed {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                Err(_) => {
                    let _ = event_tx.send(RemoteEvent::TcpClosed { key: key.clone() });
                    break;
                }
            }
        }
    });
}

pub(super) fn relay_dns_udp(upstream_ip: IpAddr, payload: &[u8]) -> Result<Vec<u8>> {
    relay_dns_udp_to(SocketAddr::new(upstream_ip, 53), payload)
}

fn relay_dns_udp_to(upstream_addr: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    match relay_udp_payload(upstream_addr, 64, payload)? {
        UdpRelayOutcome::Payload(response) => Ok(response),
        UdpRelayOutcome::IcmpError {
            source_ip,
            icmp_type,
            code,
        } => anyhow::bail!(
            "received ICMP type {icmp_type} code {code} from {source_ip} while waiting for a DNS UDP response from {upstream_addr}"
        ),
    }
}

pub(super) fn relay_udp_payload(
    remote_addr: SocketAddr,
    hop_limit: u8,
    payload: &[u8],
) -> Result<UdpRelayOutcome> {
    let bind_addr = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)
        .context("failed to bind UDP socket for the rootless-internal relay")?;
    configure_udp_probe_socket(&socket, remote_addr, hop_limit)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to set rootless UDP relay timeout")?;
    socket
        .connect(remote_addr)
        .with_context(|| format!("failed to connect the rootless UDP relay to {remote_addr}"))?;
    socket
        .send(payload)
        .with_context(|| format!("failed to send rootless UDP payload to {remote_addr}"))?;
    let mut buf = [0_u8; 4096];
    match socket.recv(&mut buf) {
        Ok(n) => Ok(UdpRelayOutcome::Payload(buf[..n].to_vec())),
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::TimedOut
                    | ErrorKind::WouldBlock
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::HostUnreachable
                    | ErrorKind::NetworkUnreachable
            ) =>
        {
            if let Some(error) = recv_udp_error(&socket)? {
                Ok(UdpRelayOutcome::IcmpError {
                    source_ip: error.source_ip,
                    icmp_type: error.icmp_type,
                    code: error.code,
                })
            } else {
                Err(err).with_context(|| {
                    format!("failed to receive a rootless UDP response from {remote_addr}")
                })
            }
        }
        Err(err) => Err(err).with_context(|| {
            format!("failed to receive a rootless UDP response from {remote_addr}")
        }),
    }
}

struct ReceivedUdpError {
    source_ip: IpAddr,
    icmp_type: u8,
    code: u8,
}

fn configure_udp_probe_socket(
    socket: &UdpSocket,
    remote_addr: SocketAddr,
    hop_limit: u8,
) -> Result<()> {
    if hop_limit > 0 {
        match remote_addr {
            SocketAddr::V4(_) => socket
                .set_ttl(u32::from(hop_limit))
                .context("failed to set the IPv4 UDP probe TTL")?,
            SocketAddr::V6(_) => {
                let fd = socket.as_raw_fd();
                let value: std::ffi::c_int = i32::from(hop_limit);
                let rc = unsafe {
                    nix::libc::setsockopt(
                        fd,
                        nix::libc::IPPROTO_IPV6,
                        nix::libc::IPV6_UNICAST_HOPS,
                        &value as *const _ as *const _,
                        size_of::<std::ffi::c_int>() as nix::libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to set the IPv6 UDP probe hop limit");
                }
            }
        }
    }

    let fd = socket.as_raw_fd();
    let enabled: std::ffi::c_int = 1;
    let (level, optname) = match remote_addr {
        SocketAddr::V4(_) => (nix::libc::SOL_IP, nix::libc::IP_RECVERR),
        SocketAddr::V6(_) => (nix::libc::SOL_IPV6, nix::libc::IPV6_RECVERR),
    };
    let rc = unsafe {
        nix::libc::setsockopt(
            fd,
            level,
            optname,
            &enabled as *const _ as *const _,
            size_of::<std::ffi::c_int>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to enable UDP error-queue delivery for rootless traceroute support");
    }

    Ok(())
}

fn recv_udp_error(socket: &UdpSocket) -> Result<Option<ReceivedUdpError>> {
    let fd = socket.as_raw_fd();
    let mut data = [0_u8; 512];
    let mut control = [0_u8; 512];
    let mut name: nix::libc::sockaddr_storage = unsafe { zeroed() };
    let mut iov = nix::libc::iovec {
        iov_base: data.as_mut_ptr() as *mut _,
        iov_len: data.len(),
    };
    let mut msg: nix::libc::msghdr = unsafe { zeroed() };
    msg.msg_name = &mut name as *mut _ as *mut _;
    msg.msg_namelen = size_of::<nix::libc::sockaddr_storage>() as nix::libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut _;
    msg.msg_controllen = control.len();

    let rc = unsafe { nix::libc::recvmsg(fd, &mut msg, nix::libc::MSG_ERRQUEUE) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
            return Ok(None);
        }
        return Err(err).context("failed to read the UDP error queue");
    }

    let mut cmsg = unsafe { nix::libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let level = unsafe { (*cmsg).cmsg_level };
        let ty = unsafe { (*cmsg).cmsg_type };
        if (level == nix::libc::SOL_IP && ty == nix::libc::IP_RECVERR)
            || (level == nix::libc::SOL_IPV6 && ty == nix::libc::IPV6_RECVERR)
        {
            let err_ptr =
                unsafe { nix::libc::CMSG_DATA(cmsg) as *const nix::libc::sock_extended_err };
            let err = unsafe { &*err_ptr };
            let offender_ptr = unsafe {
                (err_ptr as *const u8).add(size_of::<nix::libc::sock_extended_err>())
                    as *const nix::libc::sockaddr
            };
            let source_ip =
                sockaddr_to_ip(offender_ptr).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            return Ok(Some(ReceivedUdpError {
                source_ip,
                icmp_type: err.ee_type,
                code: err.ee_code,
            }));
        }
        cmsg = unsafe { nix::libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    Ok(None)
}

fn sockaddr_to_ip(sockaddr: *const nix::libc::sockaddr) -> Option<IpAddr> {
    if sockaddr.is_null() {
        return None;
    }

    let family = unsafe { (*sockaddr).sa_family as i32 };
    match family {
        nix::libc::AF_INET => {
            let addr = unsafe { &*(sockaddr as *const nix::libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                addr.sin_addr.s_addr,
            ))))
        }
        nix::libc::AF_INET6 => {
            let addr = unsafe { &*(sockaddr as *const nix::libc::sockaddr_in6) };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

pub(super) fn dns_query_type(payload: &[u8]) -> Option<u16> {
    if payload.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount != 1 {
        return None;
    }
    let question_end = dns_question_end(payload)?;
    let qtype_offset = question_end.checked_sub(4)?;
    Some(u16::from_be_bytes([
        payload[qtype_offset],
        payload[qtype_offset + 1],
    ]))
}

fn dns_question_end(payload: &[u8]) -> Option<usize> {
    let mut offset = DNS_HEADER_LEN;
    while offset < payload.len() {
        let label_len = payload[offset] as usize;
        offset += 1;
        if label_len == 0 {
            return offset.checked_add(4).filter(|end| *end <= payload.len());
        }
        offset = offset.checked_add(label_len)?;
    }
    None
}

pub(super) fn synthesize_empty_dns_response(query: &[u8]) -> Result<Vec<u8>> {
    let question_end = dns_question_end(query).context("failed to parse DNS question")?;
    let mut response = query[..question_end].to_vec();
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let response_flags = (flags | 0x8000 | 0x0080) & !0x0200;
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[6..8].copy_from_slice(&0_u16.to_be_bytes());
    response[8..10].copy_from_slice(&0_u16.to_be_bytes());
    response[10..12].copy_from_slice(&0_u16.to_be_bytes());
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn relay_dns_udp_forwards_payload_and_response() {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let request = b"query".to_vec();
        let response = b"reply".to_vec();

        let join = thread::spawn({
            let request = request.clone();
            let response = response.clone();
            move || {
                let mut buf = [0_u8; 64];
                let (n, peer) = upstream.recv_from(&mut buf).unwrap();
                assert_eq!(&buf[..n], request.as_slice());
                upstream.send_to(&response, peer).unwrap();
            }
        });

        let actual = relay_dns_udp_to(upstream_addr, &request).unwrap();
        join.join().unwrap();
        assert_eq!(actual, response);
    }

    #[test]
    fn relay_udp_payload_forwards_payload_and_response() {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let request = b"udp-request".to_vec();
        let response = b"udp-response".to_vec();

        let join = thread::spawn({
            let request = request.clone();
            let response = response.clone();
            move || {
                let mut buf = [0_u8; 64];
                let (n, peer) = upstream.recv_from(&mut buf).unwrap();
                assert_eq!(&buf[..n], request.as_slice());
                upstream.send_to(&response, peer).unwrap();
            }
        });

        let actual = relay_udp_payload(upstream_addr, 64, &request).unwrap();
        join.join().unwrap();
        assert_eq!(actual, UdpRelayOutcome::Payload(response));
    }

    #[test]
    fn connect_remote_reaches_tcp_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            let _ = listener.accept().unwrap();
            accepted_tx.send(()).unwrap();
        });

        let (event_tx, _event_rx) = mpsc::channel();
        let key = FlowKey {
            child_ip: IpAddr::V4(Ipv4Addr::new(10, 240, 0, 2)),
            child_port: 40000,
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote_port: addr.port(),
        };
        let command_tx = connect_remote(addr, None, event_tx, key).unwrap();
        accepted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        drop(command_tx);
        join.join().unwrap();
    }

    #[test]
    fn dns_query_type_detects_aaaa_question() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00,
            0x01,
        ];
        assert_eq!(dns_query_type(&query), Some(DNS_TYPE_AAAA));
    }

    #[test]
    fn synthesize_empty_dns_response_preserves_question() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00,
            0x01,
        ];
        let response = synthesize_empty_dns_response(&query).unwrap();
        assert_eq!(&response[..2], &query[..2]);
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(&response[12..], &query[12..]);
        assert_ne!(response[2] & 0x80, 0);
    }
}
