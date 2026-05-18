use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

pub enum IpKind<'a> {
    V4(&'a etherparse::Ipv4Header),
    V6(&'a etherparse::Ipv6Header),
}
