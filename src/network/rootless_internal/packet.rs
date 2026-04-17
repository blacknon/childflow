use std::net::{IpAddr, Ipv4Addr};

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
pub enum ParsedPacket {
    Tcp(ParsedTcpPacket),
    Udp(ParsedUdpPacket),
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
        _ => Ok(ParsedPacket::Unsupported),
    }
}

fn parse_ipv6_packet(payload: &[u8], mut meta: PacketMeta) -> Result<ParsedPacket> {
    let ip = Ipv6Slice::from_slice(payload).context("failed to parse IPv6 packet")?;
    meta.src_ip = IpAddr::V6(ip.header().source_addr());
    meta.dst_ip = IpAddr::V6(ip.header().destination_addr());

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
        _ => Ok(ParsedPacket::Unsupported),
    }
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
}
