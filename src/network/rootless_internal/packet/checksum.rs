use std::net::Ipv6Addr;

use anyhow::{bail, Result};

pub fn internet_checksum(bytes: &[u8]) -> u16 {
    finalize_checksum(checksum_sum(bytes))
}

pub fn normalize_icmpv4_message(message: &[u8]) -> Result<Vec<u8>> {
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

pub fn normalize_icmpv6_message(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    message: &[u8],
) -> Result<Vec<u8>> {
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

pub fn icmpv6_checksum(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut sum = 0_u32;
    sum = sum.wrapping_add(checksum_sum(&src_ip.octets()));
    sum = sum.wrapping_add(checksum_sum(&dst_ip.octets()));
    sum = sum.wrapping_add(checksum_sum(&(payload.len() as u32).to_be_bytes()));
    sum = sum.wrapping_add(checksum_sum(&[0, 0, 0, etherparse::IpNumber::IPV6_ICMP.0]));
    sum = sum.wrapping_add(checksum_sum(payload));
    finalize_checksum(sum)
}
