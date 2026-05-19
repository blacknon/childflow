// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result};

mod error_queue;
mod probe;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum UdpRelayOutcome {
    Payload(Vec<u8>),
    IcmpError {
        source_ip: IpAddr,
        icmp_type: u8,
        code: u8,
    },
}

pub(crate) fn relay_dns_udp(upstream_ip: IpAddr, payload: &[u8]) -> Result<Vec<u8>> {
    relay_dns_udp_to(SocketAddr::new(upstream_ip, 53), payload)
}

pub(crate) fn relay_udp_payload(
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
    probe::configure_udp_probe_socket(&socket, remote_addr, hop_limit)?;
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
            if let Some(error) = error_queue::recv_udp_error(&socket)? {
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

pub(super) fn relay_dns_udp_to(upstream_addr: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
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
