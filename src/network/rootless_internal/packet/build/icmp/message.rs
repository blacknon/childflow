use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use etherparse::IpNumber;

use super::{
    build_ip_packet, icmpv6_checksum, internet_checksum, normalize_icmpv4_message,
    normalize_icmpv6_message, wrap_ipv4_packet_with_ethernet, wrap_ipv6_packet_with_ethernet,
    ParsedIcmpv4Packet, ParsedIcmpv6Packet,
};

pub fn build_icmpv4_frame_from_message(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    message: &[u8],
) -> Result<Vec<u8>> {
    let icmp = normalize_icmpv4_message(message)?;
    build_ip_packet(
        IpAddr::V4(src_ip),
        IpAddr::V4(dst_ip),
        icmp.len(),
        64,
        IpNumber::ICMP,
        |_ip_kind, bytes| {
            bytes.extend_from_slice(&icmp);
            Ok(())
        },
    )
    .and_then(|ip_packet| wrap_ipv4_packet_with_ethernet(src_mac, dst_mac, &ip_packet))
}

pub fn build_icmpv6_frame_from_message(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    message: &[u8],
) -> Result<Vec<u8>> {
    let icmp = normalize_icmpv6_message(src_ip, dst_ip, message)?;
    build_ip_packet(
        IpAddr::V6(src_ip),
        IpAddr::V6(dst_ip),
        icmp.len(),
        64,
        IpNumber::IPV6_ICMP,
        |_ip_kind, bytes| {
            bytes.extend_from_slice(&icmp);
            Ok(())
        },
    )
    .and_then(|ip_packet| wrap_ipv6_packet_with_ethernet(src_mac, dst_mac, &ip_packet))
}

pub fn build_icmpv4_ip_packet_from_message(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ttl: u8,
    message: &[u8],
) -> Result<Vec<u8>> {
    let icmp = normalize_icmpv4_message(message)?;
    build_ip_packet(
        IpAddr::V4(src_ip),
        IpAddr::V4(dst_ip),
        icmp.len(),
        ttl,
        IpNumber::ICMP,
        |_ip_kind, bytes| {
            bytes.extend_from_slice(&icmp);
            Ok(())
        },
    )
}

pub fn build_icmpv6_ip_packet_from_message(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    hop_limit: u8,
    message: &[u8],
) -> Result<Vec<u8>> {
    let icmp = normalize_icmpv6_message(src_ip, dst_ip, message)?;
    build_ip_packet(
        IpAddr::V6(src_ip),
        IpAddr::V6(dst_ip),
        icmp.len(),
        hop_limit,
        IpNumber::IPV6_ICMP,
        |_ip_kind, bytes| {
            bytes.extend_from_slice(&icmp);
            Ok(())
        },
    )
}

pub fn build_icmpv4_message_from_parsed(packet: &ParsedIcmpv4Packet) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + packet.payload.len());
    icmp.push(packet.icmp_type);
    icmp.push(packet.code);
    icmp.extend_from_slice(&[0, 0]);
    icmp.extend_from_slice(&packet.identifier.to_be_bytes());
    icmp.extend_from_slice(&packet.sequence.to_be_bytes());
    icmp.extend_from_slice(&packet.payload);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    icmp
}

pub fn build_icmpv6_message_from_parsed(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    packet: &ParsedIcmpv6Packet,
) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + packet.payload.len());
    icmp.push(packet.icmp_type);
    icmp.push(packet.code);
    icmp.extend_from_slice(&[0, 0]);
    icmp.extend_from_slice(&packet.identifier.to_be_bytes());
    icmp.extend_from_slice(&packet.sequence.to_be_bytes());
    icmp.extend_from_slice(&packet.payload);
    let checksum = icmpv6_checksum(src_ip, dst_ip, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    icmp
}
