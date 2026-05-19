use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use etherparse::{IpNumber, TcpHeader, UdpHeader};

use super::ip::{build_ip_frame, build_ip_packet};
use super::{IpKind, TcpReply};

pub fn build_tcp_frame(reply: TcpReply<'_>) -> Result<Vec<u8>> {
    let mut tcp = TcpHeader::new(reply.src_port, reply.dst_port, reply.seq, 64240);
    tcp.acknowledgment_number = reply.ack;
    tcp.syn = reply.syn;
    tcp.ack = reply.ack_flag;
    tcp.fin = reply.fin;
    tcp.rst = reply.rst;
    tcp.psh = reply.psh;

    build_ip_frame(
        reply.src_mac,
        reply.dst_mac,
        reply.src_ip,
        reply.dst_ip,
        IpNumber::TCP,
        |ip_kind, bytes| {
            tcp.checksum = match ip_kind {
                IpKind::V4(ip) => tcp.calc_checksum_ipv4(ip, reply.payload),
                IpKind::V6(ip) => tcp.calc_checksum_ipv6(ip, reply.payload),
            }
            .context("failed to calculate TCP checksum")?;
            tcp.write(bytes).context("failed to serialize TCP header")?;
            bytes.extend_from_slice(reply.payload);
            Ok(())
        },
    )
}

pub fn build_udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    build_ip_frame(
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        IpNumber::UDP,
        |ip_kind, bytes| {
            let udp = match ip_kind {
                IpKind::V4(ip) => UdpHeader::with_ipv4_checksum(src_port, dst_port, ip, payload)
                    .context("failed to build IPv4 UDP header")?,
                IpKind::V6(ip) => UdpHeader::with_ipv6_checksum(src_port, dst_port, ip, payload)
                    .context("failed to build IPv6 UDP header")?,
            };
            udp.write(bytes).context("failed to serialize UDP header")?;
            bytes.extend_from_slice(payload);
            Ok(())
        },
    )
}

pub fn build_udp_ip_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    hop_limit: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    build_ip_packet(
        src_ip,
        dst_ip,
        UdpHeader::LEN
            .checked_add(payload.len())
            .ok_or_else(|| anyhow!("UDP payload too large"))?,
        hop_limit,
        IpNumber::UDP,
        |ip_kind, bytes| {
            let udp = match ip_kind {
                IpKind::V4(ip) => UdpHeader::with_ipv4_checksum(src_port, dst_port, ip, payload)
                    .context("failed to build IPv4 UDP header")?,
                IpKind::V6(ip) => UdpHeader::with_ipv6_checksum(src_port, dst_port, ip, payload)
                    .context("failed to build IPv6 UDP header")?,
            };
            udp.write(bytes).context("failed to serialize UDP header")?;
            bytes.extend_from_slice(payload);
            Ok(())
        },
    )
}
