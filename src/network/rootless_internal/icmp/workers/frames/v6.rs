use anyhow::Result;

use crate::network::rootless_internal::packet::{self, Icmpv6EchoFrame, Icmpv6ErrorFrame};

use super::super::super::types::{Icmpv6EchoRequest, Icmpv6RawRequest};

pub(in crate::network::rootless_internal::icmp::workers) fn build_child_icmpv6_echo_probe(
    request: &Icmpv6EchoRequest,
) -> Result<Vec<u8>> {
    packet::build_icmpv6_echo_ip_packet(
        Icmpv6EchoFrame {
            src_mac: request.child_mac,
            dst_mac: request.gateway_mac,
            src_ip: request.child_ip,
            dst_ip: request.remote_ip,
            icmp_type: 128,
            code: 0,
            identifier: request.identifier,
            sequence: request.sequence,
            payload: &request.payload,
        },
        request.hop_limit,
    )
}

pub(in crate::network::rootless_internal::icmp::workers) fn build_icmpv6_echo_reply_frame(
    request: &Icmpv6EchoRequest,
    reply: &[u8],
) -> Result<Vec<u8>> {
    if reply.is_empty() {
        packet::build_icmpv6_echo_frame(Icmpv6EchoFrame {
            src_mac: request.gateway_mac,
            dst_mac: request.child_mac,
            src_ip: request.remote_ip,
            dst_ip: request.child_ip,
            icmp_type: 129,
            code: 0,
            identifier: request.identifier,
            sequence: request.sequence,
            payload: request.payload.as_slice(),
        })
    } else {
        packet::build_icmpv6_frame_from_message(
            request.gateway_mac,
            request.child_mac,
            request.remote_ip,
            request.child_ip,
            reply,
        )
    }
}

pub(in crate::network::rootless_internal::icmp::workers) fn build_icmpv6_error_reply_frame(
    request: &impl Icmpv6RequestView,
    source_ip: std::net::Ipv6Addr,
    icmp_type: u8,
    code: u8,
    probe: &[u8],
) -> Result<Vec<u8>> {
    packet::build_icmpv6_error_frame(Icmpv6ErrorFrame {
        src_mac: request.gateway_mac(),
        dst_mac: request.child_mac(),
        src_ip: source_ip,
        dst_ip: request.child_ip(),
        icmp_type,
        code,
        quote: probe,
    })
}

pub(in crate::network::rootless_internal::icmp::workers) fn build_child_icmpv6_raw_probe(
    request: &Icmpv6RawRequest,
) -> Result<Vec<u8>> {
    packet::build_icmpv6_ip_packet_from_message(
        request.child_ip,
        request.remote_ip,
        request.hop_limit,
        &request.message,
    )
}

pub(in crate::network::rootless_internal::icmp::workers) fn build_icmpv6_raw_reply_frame(
    request: &Icmpv6RawRequest,
    reply: &[u8],
) -> Result<Vec<u8>> {
    packet::build_icmpv6_frame_from_message(
        request.gateway_mac,
        request.child_mac,
        request.remote_ip,
        request.child_ip,
        reply,
    )
}

pub(in crate::network::rootless_internal::icmp::workers) trait Icmpv6RequestView {
    fn gateway_mac(&self) -> [u8; 6];
    fn child_mac(&self) -> [u8; 6];
    fn child_ip(&self) -> std::net::Ipv6Addr;
}

impl Icmpv6RequestView for Icmpv6EchoRequest {
    fn gateway_mac(&self) -> [u8; 6] {
        self.gateway_mac
    }

    fn child_mac(&self) -> [u8; 6] {
        self.child_mac
    }

    fn child_ip(&self) -> std::net::Ipv6Addr {
        self.child_ip
    }
}

impl Icmpv6RequestView for Icmpv6RawRequest {
    fn gateway_mac(&self) -> [u8; 6] {
        self.gateway_mac
    }

    fn child_mac(&self) -> [u8; 6] {
        self.child_mac
    }

    fn child_ip(&self) -> std::net::Ipv6Addr {
        self.child_ip
    }
}
