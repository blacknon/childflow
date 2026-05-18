use std::net::{IpAddr, Ipv4Addr};

use anyhow::{bail, Context, Result};
use etherparse::{
    Ethernet2Header, Ethernet2HeaderSlice, IpNumber, Ipv4Slice, Ipv6Slice, TcpSlice, UdpSlice,
};

use super::{
    PacketMeta, ParsedIcmpv4Packet, ParsedIcmpv6Packet, ParsedPacket, ParsedTcpPacket,
    ParsedUdpPacket,
};

pub fn parse_frame(frame: &[u8]) -> Result<ParsedPacket> {
    let eth = Ethernet2HeaderSlice::from_slice(frame).context("failed to parse Ethernet header")?;
    let payload = &frame[Ethernet2Header::LEN..];
    let base_meta = PacketMeta {
        src_mac: eth.source(),
        dst_mac: eth.destination(),
        src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        hop_limit: 0,
    };

    match eth.ether_type() {
        etherparse::EtherType::IPV4 => parse_ipv4_packet(payload, base_meta),
        etherparse::EtherType::IPV6 => parse_ipv6_packet(payload, base_meta),
        _ => Ok(ParsedPacket::Unsupported),
    }
}

fn parse_ipv4_packet(payload: &[u8], mut meta: PacketMeta) -> Result<ParsedPacket> {
    let ip = Ipv4Slice::from_slice(payload).context("failed to parse IPv4 packet")?;
    meta.src_ip = IpAddr::V4(ip.header().source_addr());
    meta.dst_ip = IpAddr::V4(ip.header().destination_addr());
    meta.hop_limit = ip.header().ttl();

    let payload = ip.payload();
    if payload.fragmented {
        return Ok(ParsedPacket::Unsupported);
    }

    match payload.ip_number {
        IpNumber::TCP => {
            let tcp =
                TcpSlice::from_slice(payload.payload).context("failed to parse TCP header")?;
            Ok(ParsedPacket::Tcp(ParsedTcpPacket {
                meta,
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                sequence_number: tcp.sequence_number(),
                acknowledgment_number: tcp.acknowledgment_number(),
                ack: tcp.ack(),
                syn: tcp.syn(),
                fin: tcp.fin(),
                rst: tcp.rst(),
                psh: tcp.psh(),
                payload: tcp.payload().to_vec(),
            }))
        }
        IpNumber::UDP => {
            let udp =
                UdpSlice::from_slice(payload.payload).context("failed to parse UDP header")?;
            Ok(ParsedPacket::Udp(ParsedUdpPacket {
                meta,
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                payload: udp.payload().to_vec(),
            }))
        }
        IpNumber::ICMP => parse_icmpv4_packet(payload.payload, meta),
        _ => Ok(ParsedPacket::Unsupported),
    }
}

fn parse_ipv6_packet(payload: &[u8], mut meta: PacketMeta) -> Result<ParsedPacket> {
    let ip = Ipv6Slice::from_slice(payload).context("failed to parse IPv6 packet")?;
    meta.src_ip = IpAddr::V6(ip.header().source_addr());
    meta.dst_ip = IpAddr::V6(ip.header().destination_addr());
    meta.hop_limit = ip.header().hop_limit();

    let payload = ip.payload();
    if payload.fragmented {
        return Ok(ParsedPacket::Unsupported);
    }

    match payload.ip_number {
        IpNumber::TCP => {
            let tcp =
                TcpSlice::from_slice(payload.payload).context("failed to parse TCPv6 header")?;
            Ok(ParsedPacket::Tcp(ParsedTcpPacket {
                meta,
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                sequence_number: tcp.sequence_number(),
                acknowledgment_number: tcp.acknowledgment_number(),
                ack: tcp.ack(),
                syn: tcp.syn(),
                fin: tcp.fin(),
                rst: tcp.rst(),
                psh: tcp.psh(),
                payload: tcp.payload().to_vec(),
            }))
        }
        IpNumber::UDP => {
            let udp =
                UdpSlice::from_slice(payload.payload).context("failed to parse UDPv6 header")?;
            Ok(ParsedPacket::Udp(ParsedUdpPacket {
                meta,
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                payload: udp.payload().to_vec(),
            }))
        }
        IpNumber::IPV6_ICMP => parse_icmpv6_packet(payload.payload, meta),
        _ => Ok(ParsedPacket::Unsupported),
    }
}

fn parse_icmpv4_packet(payload: &[u8], meta: PacketMeta) -> Result<ParsedPacket> {
    if payload.len() < 8 {
        bail!("failed to parse ICMPv4 packet: payload too short");
    }

    Ok(ParsedPacket::Icmpv4(ParsedIcmpv4Packet {
        meta,
        icmp_type: payload[0],
        code: payload[1],
        identifier: u16::from_be_bytes([payload[4], payload[5]]),
        sequence: u16::from_be_bytes([payload[6], payload[7]]),
        payload: payload[8..].to_vec(),
    }))
}

fn parse_icmpv6_packet(payload: &[u8], meta: PacketMeta) -> Result<ParsedPacket> {
    if payload.len() < 8 {
        bail!("failed to parse ICMPv6 packet: payload too short");
    }

    Ok(ParsedPacket::Icmpv6(ParsedIcmpv6Packet {
        meta,
        icmp_type: payload[0],
        code: payload[1],
        identifier: u16::from_be_bytes([payload[4], payload[5]]),
        sequence: u16::from_be_bytes([payload[6], payload[7]]),
        payload: payload[8..].to_vec(),
    }))
}
