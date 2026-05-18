use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Context, Result};
use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader};

use super::{
    icmpv6_checksum, internet_checksum, normalize_icmpv4_message, normalize_icmpv6_message,
    Icmpv4EchoFrame, Icmpv4ErrorFrame, Icmpv6EchoFrame, Icmpv6ErrorFrame, IpKind,
    ParsedIcmpv4Packet, ParsedIcmpv6Packet, TcpReply,
};

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
