use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{BLOCK_METADATA_IPV4, BLOCK_METADATA_IPV6};

pub fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value == BLOCK_METADATA_IPV4,
        IpAddr::V6(value) => value == BLOCK_METADATA_IPV6,
    }
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => is_private_ipv4(value),
        IpAddr::V6(value) => is_private_ipv6(value),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
}
