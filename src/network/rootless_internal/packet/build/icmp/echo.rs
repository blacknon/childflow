use anyhow::Result;

use super::{
    build_icmpv4_frame_from_message, build_icmpv4_ip_packet_from_message,
    build_icmpv6_frame_from_message, build_icmpv6_ip_packet_from_message, icmpv6_checksum,
    internet_checksum, Icmpv4EchoFrame, Icmpv6EchoFrame,
};

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
