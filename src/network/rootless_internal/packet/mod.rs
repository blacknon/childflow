// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod build;
mod parse;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

pub use self::build::{
    build_icmpv4_echo_frame, build_icmpv4_echo_ip_packet, build_icmpv4_error_frame,
    build_icmpv4_frame_from_message, build_icmpv4_ip_packet_from_message,
    build_icmpv4_message_from_parsed, build_icmpv6_echo_frame, build_icmpv6_echo_ip_packet,
    build_icmpv6_error_frame, build_icmpv6_frame_from_message, build_icmpv6_ip_packet_from_message,
    build_icmpv6_message_from_parsed, build_tcp_frame, build_udp_frame, build_udp_ip_packet,
};
pub use self::parse::parse_frame;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketMeta {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub hop_limit: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedTcpPacket {
    pub meta: PacketMeta,
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub ack: bool,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedUdpPacket {
    pub meta: PacketMeta,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedIcmpv4Packet {
    pub meta: PacketMeta,
    pub icmp_type: u8,
    pub code: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedIcmpv6Packet {
    pub meta: PacketMeta,
    pub icmp_type: u8,
    pub code: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

pub struct Icmpv4EchoFrame<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub icmp_type: u8,
    pub code: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}

pub struct Icmpv6EchoFrame<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub icmp_type: u8,
    pub code: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}

pub struct Icmpv4ErrorFrame<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub icmp_type: u8,
    pub code: u8,
    pub quote: &'a [u8],
}

pub struct Icmpv6ErrorFrame<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub icmp_type: u8,
    pub code: u8,
    pub quote: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedPacket {
    Tcp(ParsedTcpPacket),
    Udp(ParsedUdpPacket),
    Icmpv4(ParsedIcmpv4Packet),
    Icmpv6(ParsedIcmpv6Packet),
    Unsupported,
}

pub struct TcpReply<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub payload: &'a [u8],
}

enum IpKind<'a> {
    V4(&'a etherparse::Ipv4Header),
    V6(&'a etherparse::Ipv6Header),
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    finalize_checksum(checksum_sum(bytes))
}

fn normalize_icmpv4_message(message: &[u8]) -> Result<Vec<u8>> {
    if message.len() < 8 {
        bail!("ICMPv4 message too short");
    }
    let mut icmp = message.to_vec();
    icmp[2] = 0;
    icmp[3] = 0;
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(icmp)
}

fn normalize_icmpv6_message(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, message: &[u8]) -> Result<Vec<u8>> {
    if message.len() < 8 {
        bail!("ICMPv6 message too short");
    }
    let mut icmp = message.to_vec();
    icmp[2] = 0;
    icmp[3] = 0;
    let checksum = icmpv6_checksum(src_ip, dst_ip, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(icmp)
}

fn checksum_sum(bytes: &[u8]) -> u32 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let [last] = chunks.remainder() {
        sum = sum.wrapping_add(u16::from_be_bytes([*last, 0]) as u32);
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv6_checksum(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut sum = 0_u32;
    sum = sum.wrapping_add(checksum_sum(&src_ip.octets()));
    sum = sum.wrapping_add(checksum_sum(&dst_ip.octets()));
    sum = sum.wrapping_add(checksum_sum(&(payload.len() as u32).to_be_bytes()));
    sum = sum.wrapping_add(checksum_sum(&[0, 0, 0, etherparse::IpNumber::IPV6_ICMP.0]));
    sum = sum.wrapping_add(checksum_sum(payload));
    finalize_checksum(sum)
}
