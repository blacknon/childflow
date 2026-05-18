use anyhow::Result;

use crate::network::rootless_internal::packet::{self, Icmpv4EchoFrame, Icmpv4ErrorFrame};

use super::super::super::types::{Icmpv4EchoRequest, Icmpv4RawRequest};

pub(in crate::network::rootless_internal::icmp::workers) fn build_child_icmpv4_echo_probe(
    request: &Icmpv4EchoRequest,
) -> Result<Vec<u8>> {
    packet::build_icmpv4_echo_ip_packet(
        Icmpv4EchoFrame {
            src_mac: request.child_mac,
            dst_mac: request.gateway_mac,
            src_ip: request.child_ip,
            dst_ip: request.remote_ip,
            icmp_type: 8,
            code: 0,
            identifier: request.identifier,
            sequence: request.sequence,
            payload: &request.payload,
        },
        request.hop_limit,
    )
}

pub(in crate::network::rootless_internal::icmp::workers) fn build_icmpv4_echo_reply_frame(
    request: &Icmpv4EchoRequest,
    reply: &[u8],
) -> Result<Vec<u8>> {
    if reply.is_empty() {
        packet::build_icmpv4_echo_frame(Icmpv4EchoFrame {
            src_mac: request.gateway_mac,
            dst_mac: request.child_mac,
            src_ip: request.remote_ip,
            dst_ip: request.child_ip,
            icmp_type: 0,
            code: 0,
            identifier: request.identifier,
            sequence: request.sequence,
            payload: request.payload.as_slice(),
        })
    } else {
        packet::build_icmpv4_frame_from_message(
            request.gateway_mac,
            request.child_mac,
            request.remote_ip,
            request.child_ip,
            reply,
        )
    }
}

pub(in crate::network::rootless_internal::icmp::workers) fn build_icmpv4_error_reply_frame(
    request: &impl Icmpv4RequestView,
    source_ip: std::net::Ipv4Addr,
    icmp_type: u8,
    code: u8,
    probe: &[u8],
) -> Result<Vec<u8>> {
    packet::build_icmpv4_error_frame(Icmpv4ErrorFrame {
        src_mac: request.gateway_mac(),
        dst_mac: request.child_mac(),
        src_ip: source_ip,
        dst_ip: request.child_ip(),
        icmp_type,
        code,
        quote: probe,
    })
}

pub(in crate::network::rootless_internal::icmp::workers) fn build_child_icmpv4_raw_probe(
    request: &Icmpv4RawRequest,
) -> Result<Vec<u8>> {
    packet::build_icmpv4_ip_packet_from_message(
        request.child_ip,
        request.remote_ip,
        request.hop_limit,
        &request.message,
    )
}

pub(in crate::network::rootless_internal::icmp::workers) fn build_icmpv4_raw_reply_frame(
    request: &Icmpv4RawRequest,
    reply: &[u8],
) -> Result<Vec<u8>> {
    packet::build_icmpv4_frame_from_message(
        request.gateway_mac,
        request.child_mac,
        request.remote_ip,
        request.child_ip,
        reply,
    )
}

pub(in crate::network::rootless_internal::icmp::workers) trait Icmpv4RequestView {
    fn gateway_mac(&self) -> [u8; 6];
    fn child_mac(&self) -> [u8; 6];
    fn child_ip(&self) -> std::net::Ipv4Addr;
}

impl Icmpv4RequestView for Icmpv4EchoRequest {
    fn gateway_mac(&self) -> [u8; 6] {
        self.gateway_mac
    }

    fn child_mac(&self) -> [u8; 6] {
        self.child_mac
    }

    fn child_ip(&self) -> std::net::Ipv4Addr {
        self.child_ip
    }
}

impl Icmpv4RequestView for Icmpv4RawRequest {
    fn gateway_mac(&self) -> [u8; 6] {
        self.gateway_mac
    }

    fn child_mac(&self) -> [u8; 6] {
        self.child_mac
    }

    fn child_ip(&self) -> std::net::Ipv4Addr {
        self.child_ip
    }
}
