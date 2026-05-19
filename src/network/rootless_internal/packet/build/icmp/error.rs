use anyhow::Result;
use etherparse::IpNumber;
use std::net::IpAddr;

use super::{
    build_ip_frame, icmpv6_checksum, internet_checksum, Icmpv4ErrorFrame, Icmpv6ErrorFrame,
};

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
