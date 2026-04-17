use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Context, Result};
use etherparse::{
    Ethernet2Header, Ethernet2HeaderSlice, IpNumber, Ipv4Header, Ipv4Slice, Ipv6Header, Ipv6Slice,
    TcpHeader, TcpSlice, UdpHeader, UdpSlice,
};

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

pub fn build_icmpv4_echo_frame(frame: Icmpv4EchoFrame<'_>) -> Result<Vec<u8>> {
    let icmp = build_icmpv4_echo_payload(&frame);
    build_icmpv4_frame_from_message(
        frame.src_mac,
        frame.dst_mac,
        frame.src_ip,
        frame.dst_ip,
        &icmp,
    )
}

pub fn build_icmpv6_echo_frame(frame: Icmpv6EchoFrame<'_>) -> Result<Vec<u8>> {
    let icmp = build_icmpv6_echo_payload(&frame);
    build_icmpv6_frame_from_message(
        frame.src_mac,
        frame.dst_mac,
        frame.src_ip,
        frame.dst_ip,
        &icmp,
    )
}

pub fn build_icmpv4_echo_ip_packet(frame: Icmpv4EchoFrame<'_>, ttl: u8) -> Result<Vec<u8>> {
    let icmp = build_icmpv4_echo_payload(&frame);
    build_icmpv4_ip_packet_from_message(frame.src_ip, frame.dst_ip, ttl, &icmp)
}

pub fn build_icmpv6_echo_ip_packet(frame: Icmpv6EchoFrame<'_>, hop_limit: u8) -> Result<Vec<u8>> {
    let icmp = build_icmpv6_echo_payload(&frame);
    build_icmpv6_ip_packet_from_message(frame.src_ip, frame.dst_ip, hop_limit, &icmp)
}

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

pub fn build_icmpv4_error_frame(frame: Icmpv4ErrorFrame<'_>) -> Result<Vec<u8>> {
    let quote = &frame.quote[..frame.quote.len().min(548)];
    let mut icmp = Vec::with_capacity(8 + quote.len());
    icmp.push(frame.icmp_type);
    icmp.push(frame.code);
    icmp.extend_from_slice(&[0, 0]);
    icmp.extend_from_slice(&[0, 0, 0, 0]);
    icmp.extend_from_slice(quote);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    build_ip_frame(
        frame.src_mac,
        frame.dst_mac,
        IpAddr::V4(frame.src_ip),
        IpAddr::V4(frame.dst_ip),
        IpNumber::ICMP,
        |_ip_kind, bytes| {
            bytes.extend_from_slice(&icmp);
            Ok(())
        },
    )
}

pub fn build_icmpv6_error_frame(frame: Icmpv6ErrorFrame<'_>) -> Result<Vec<u8>> {
    let quote = &frame.quote[..frame.quote.len().min(1232)];
    let mut icmp = Vec::with_capacity(8 + quote.len());
    icmp.push(frame.icmp_type);
    icmp.push(frame.code);
    icmp.extend_from_slice(&[0, 0]);
    icmp.extend_from_slice(&[0, 0, 0, 0]);
    icmp.extend_from_slice(quote);
    let checksum = icmpv6_checksum(frame.src_ip, frame.dst_ip, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    build_ip_frame(
        frame.src_mac,
        frame.dst_mac,
        IpAddr::V6(frame.src_ip),
        IpAddr::V6(frame.dst_ip),
        IpNumber::IPV6_ICMP,
        |_ip_kind, bytes| {
            bytes.extend_from_slice(&icmp);
            Ok(())
        },
    )
}

enum IpKind<'a> {
    V4(&'a Ipv4Header),
    V6(&'a Ipv6Header),
}

fn build_ip_frame<F>(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    transport_proto: IpNumber,
    write_transport: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(IpKind<'_>, &mut Vec<u8>) -> Result<()>,
{
    let eth = Ethernet2Header {
        source: src_mac,
        destination: dst_mac,
        ether_type: match (src_ip, dst_ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) => etherparse::EtherType::IPV4,
            (IpAddr::V6(_), IpAddr::V6(_)) => etherparse::EtherType::IPV6,
            _ => bail!("source and destination IP versions must match"),
        },
    };

    let mut payload = Vec::new();
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ip = Ipv4Header::new(0, 64, transport_proto, src.octets(), dst.octets())
                .context("failed to create IPv4 header")?;
            write_transport(IpKind::V4(&ip), &mut payload)?;
            let ip = Ipv4Header::new(
                payload
                    .len()
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv4 header"))?,
                64,
                transport_proto,
                src.octets(),
                dst.octets(),
            )
            .context("failed to create IPv4 header")?;

            let mut bytes =
                Vec::with_capacity(Ethernet2Header::LEN + ip.header_len() + payload.len());
            eth.write(&mut bytes)
                .context("failed to serialize Ethernet header")?;
            ip.write(&mut bytes)
                .context("failed to serialize IPv4 header")?;
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: Default::default(),
                payload_length: 0,
                next_header: transport_proto,
                hop_limit: 64,
                source: src.octets(),
                destination: dst.octets(),
            };
            write_transport(IpKind::V6(&ip), &mut payload)?;
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: Default::default(),
                payload_length: payload
                    .len()
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv6 header"))?,
                next_header: transport_proto,
                hop_limit: 64,
                source: src.octets(),
                destination: dst.octets(),
            };

            let mut bytes =
                Vec::with_capacity(Ethernet2Header::LEN + Ipv6Header::LEN + payload.len());
            eth.write(&mut bytes)
                .context("failed to serialize Ethernet header")?;
            ip.write(&mut bytes)
                .context("failed to serialize IPv6 header")?;
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }
        _ => bail!("source and destination IP versions must match"),
    }
}

fn build_ip_packet<F>(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    payload_len: usize,
    hop_limit: u8,
    transport_proto: IpNumber,
    write_transport: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(IpKind<'_>, &mut Vec<u8>) -> Result<()>,
{
    let mut payload = Vec::with_capacity(payload_len);
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ip = Ipv4Header::new(
                payload_len
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv4 header"))?,
                hop_limit,
                transport_proto,
                src.octets(),
                dst.octets(),
            )
            .context("failed to create IPv4 header")?;
            write_transport(IpKind::V4(&ip), &mut payload)?;
            let ip = Ipv4Header::new(
                payload
                    .len()
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv4 header"))?,
                hop_limit,
                transport_proto,
                src.octets(),
                dst.octets(),
            )
            .context("failed to create IPv4 header")?;
            let mut bytes = Vec::with_capacity(ip.header_len() + payload.len());
            ip.write(&mut bytes)
                .context("failed to serialize IPv4 header")?;
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: Default::default(),
                payload_length: payload_len
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv6 header"))?,
                next_header: transport_proto,
                hop_limit,
                source: src.octets(),
                destination: dst.octets(),
            };
            write_transport(IpKind::V6(&ip), &mut payload)?;
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: Default::default(),
                payload_length: payload
                    .len()
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv6 header"))?,
                next_header: transport_proto,
                hop_limit,
                source: src.octets(),
                destination: dst.octets(),
            };
            let mut bytes = Vec::with_capacity(Ipv6Header::LEN + payload.len());
            ip.write(&mut bytes)
                .context("failed to serialize IPv6 header")?;
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }
        _ => bail!("source and destination IP versions must match"),
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    finalize_checksum(checksum_sum(bytes))
}

fn build_icmpv4_echo_payload(frame: &Icmpv4EchoFrame<'_>) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + frame.payload.len());
    icmp.push(frame.icmp_type);
    icmp.push(frame.code);
    icmp.extend_from_slice(&[0, 0]);
    icmp.extend_from_slice(&frame.identifier.to_be_bytes());
    icmp.extend_from_slice(&frame.sequence.to_be_bytes());
    icmp.extend_from_slice(frame.payload);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    icmp
}

fn build_icmpv6_echo_payload(frame: &Icmpv6EchoFrame<'_>) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + frame.payload.len());
    icmp.push(frame.icmp_type);
    icmp.push(frame.code);
    icmp.extend_from_slice(&[0, 0]);
    icmp.extend_from_slice(&frame.identifier.to_be_bytes());
    icmp.extend_from_slice(&frame.sequence.to_be_bytes());
    icmp.extend_from_slice(frame.payload);
    let checksum = icmpv6_checksum(frame.src_ip, frame.dst_ip, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    icmp
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

fn wrap_ipv4_packet_with_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ip_packet: &[u8],
) -> Result<Vec<u8>> {
    let eth = Ethernet2Header {
        source: src_mac,
        destination: dst_mac,
        ether_type: etherparse::EtherType::IPV4,
    };
    let mut bytes = Vec::with_capacity(Ethernet2Header::LEN + ip_packet.len());
    eth.write(&mut bytes)
        .context("failed to serialize Ethernet header")?;
    bytes.extend_from_slice(ip_packet);
    Ok(bytes)
}

fn wrap_ipv6_packet_with_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ip_packet: &[u8],
) -> Result<Vec<u8>> {
    let eth = Ethernet2Header {
        source: src_mac,
        destination: dst_mac,
        ether_type: etherparse::EtherType::IPV6,
    };
    let mut bytes = Vec::with_capacity(Ethernet2Header::LEN + ip_packet.len());
    eth.write(&mut bytes)
        .context("failed to serialize Ethernet header")?;
    bytes.extend_from_slice(ip_packet);
    Ok(bytes)
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
    sum = sum.wrapping_add(checksum_sum(&[0, 0, 0, IpNumber::IPV6_ICMP.0]));
    sum = sum.wrapping_add(checksum_sum(payload));
    finalize_checksum(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_tcp_frame_emits_ipv4_ethernet_packet() {
        let frame = build_tcp_frame(TcpReply {
            src_mac: [0x02, 0xcf, 0, 0, 0, 1],
            dst_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 443,
            dst_port: 40000,
            seq: 1,
            ack: 2,
            syn: true,
            ack_flag: true,
            fin: false,
            rst: false,
            psh: false,
            payload: &[],
        })
        .unwrap();

        match parse_frame(&frame).unwrap() {
            ParsedPacket::Tcp(packet) => {
                assert_eq!(packet.src_port, 443);
                assert_eq!(packet.dst_port, 40000);
                assert!(packet.syn);
                assert!(packet.ack);
                assert_eq!(packet.meta.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                assert_eq!(packet.meta.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn build_udp_frame_round_trips_ipv6_payload() {
        let payload = b"dns".to_vec();
        let frame = build_udp_frame(
            [0x02, 0xcf, 0, 0, 0, 1],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            IpAddr::V6("fd42::1".parse().unwrap()),
            IpAddr::V6("fd42::2".parse().unwrap()),
            53,
            40000,
            &payload,
        )
        .unwrap();

        match parse_frame(&frame).unwrap() {
            ParsedPacket::Udp(packet) => {
                assert_eq!(packet.src_port, 53);
                assert_eq!(packet.dst_port, 40000);
                assert_eq!(packet.payload, payload);
                assert_eq!(packet.meta.src_ip, IpAddr::V6("fd42::1".parse().unwrap()));
                assert_eq!(packet.meta.dst_ip, IpAddr::V6("fd42::2".parse().unwrap()));
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn build_icmpv4_echo_frame_round_trips_payload() {
        let payload = b"ping-data".to_vec();
        let frame = build_icmpv4_echo_frame(Icmpv4EchoFrame {
            src_mac: [0x02, 0xcf, 0, 0, 0, 1],
            dst_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            src_ip: Ipv4Addr::new(1, 1, 1, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            icmp_type: 0,
            code: 0,
            identifier: 0x1234,
            sequence: 7,
            payload: &payload,
        })
        .unwrap();

        match parse_frame(&frame).unwrap() {
            ParsedPacket::Icmpv4(packet) => {
                assert_eq!(packet.icmp_type, 0);
                assert_eq!(packet.code, 0);
                assert_eq!(packet.identifier, 0x1234);
                assert_eq!(packet.sequence, 7);
                assert_eq!(packet.payload, payload);
                assert_eq!(packet.meta.src_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
                assert_eq!(packet.meta.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn build_icmpv6_echo_frame_round_trips_payload() {
        let payload = b"ping6-data".to_vec();
        let src_ip = "2001:db8::1".parse().unwrap();
        let dst_ip = "fd42::2".parse().unwrap();
        let frame = build_icmpv6_echo_frame(Icmpv6EchoFrame {
            src_mac: [0x02, 0xcf, 0, 0, 0, 1],
            dst_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            src_ip,
            dst_ip,
            icmp_type: 129,
            code: 0,
            identifier: 0x4321,
            sequence: 9,
            payload: &payload,
        })
        .unwrap();

        match parse_frame(&frame).unwrap() {
            ParsedPacket::Icmpv6(packet) => {
                assert_eq!(packet.icmp_type, 129);
                assert_eq!(packet.code, 0);
                assert_eq!(packet.identifier, 0x4321);
                assert_eq!(packet.sequence, 9);
                assert_eq!(packet.payload, payload);
                assert_eq!(packet.meta.src_ip, IpAddr::V6(src_ip));
                assert_eq!(packet.meta.dst_ip, IpAddr::V6(dst_ip));
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }
}
