use std::net::IpAddr;

pub(super) struct Icmpv4EchoRequest {
    pub(super) gateway_mac: [u8; 6],
    pub(super) child_mac: [u8; 6],
    pub(super) child_ip: std::net::Ipv4Addr,
    pub(super) remote_ip: std::net::Ipv4Addr,
    pub(super) hop_limit: u8,
    pub(super) identifier: u16,
    pub(super) sequence: u16,
    pub(super) payload: Vec<u8>,
}

pub(super) struct Icmpv4RawRequest {
    pub(super) gateway_mac: [u8; 6],
    pub(super) child_mac: [u8; 6],
    pub(super) child_ip: std::net::Ipv4Addr,
    pub(super) remote_ip: std::net::Ipv4Addr,
    pub(super) hop_limit: u8,
    pub(super) message: Vec<u8>,
}

pub(super) struct Icmpv6EchoRequest {
    pub(super) gateway_mac: [u8; 6],
    pub(super) child_mac: [u8; 6],
    pub(super) child_ip: std::net::Ipv6Addr,
    pub(super) remote_ip: std::net::Ipv6Addr,
    pub(super) hop_limit: u8,
    pub(super) identifier: u16,
    pub(super) sequence: u16,
    pub(super) payload: Vec<u8>,
}

pub(super) struct Icmpv6RawRequest {
    pub(super) gateway_mac: [u8; 6],
    pub(super) child_mac: [u8; 6],
    pub(super) child_ip: std::net::Ipv6Addr,
    pub(super) remote_ip: std::net::Ipv6Addr,
    pub(super) hop_limit: u8,
    pub(super) message: Vec<u8>,
}

pub(super) enum IcmpRelayOutcome {
    Message(Vec<u8>),
    Error {
        source_ip: IpAddr,
        icmp_type: u8,
        code: u8,
    },
}
