use std::net::IpAddr;

use anyhow::Result;

use crate::sandbox::BlockReason;
use crate::util;

use super::super::super::addr::AddressPlan;
use super::super::super::packet::ParsedUdpPacket;
use super::super::super::transport::{dns_query_name, dns_query_type, DNS_TYPE_AAAA};
use super::super::{note_policy_violation, PolicyViolationTarget, UdpPacketContext};

mod relay;
mod synthetic;

pub(super) fn is_dns_request(addr_plan: &AddressPlan, udp: &ParsedUdpPacket) -> bool {
    udp.dst_port == 53
        && (udp.meta.dst_ip == IpAddr::V4(addr_plan.gateway_ipv4)
            || udp.meta.dst_ip == IpAddr::V6(addr_plan.gateway_ipv6))
}

pub(super) fn handle_dns_packet(ctx: UdpPacketContext<'_>, udp: &ParsedUdpPacket) -> Result<()> {
    let dns_qtype = dns_query_type_name(&udp.payload);
    let dns_qname = dns_query_name(&udp.payload);

    if let Some(qname) = dns_qname.as_deref() {
        if let Some(reason) = ctx.sandbox_policy.block_reason_for_dns_name(qname) {
            return synthetic::deny_blocked_domain(
                ctx,
                udp,
                dns_qname.as_deref(),
                dns_qtype,
                &reason,
            );
        }
    }

    if ctx.sandbox_policy.proxy_only {
        note_policy_violation(
            ctx.flow_log,
            ctx.leak_detected,
            ctx.sandbox_policy,
            PolicyViolationTarget {
                protocol: "dns",
                remote: &format!("{}:53", udp.meta.dst_ip),
                remote_ip: Some(udp.meta.dst_ip),
                remote_port: Some(53),
            },
            &BlockReason::ProxyOnly,
        );
        return synthetic::reply_with_empty_dns_response(
            ctx,
            udp,
            dns_qname.as_deref(),
            dns_qtype,
            "failed to write synthetic proxy-only DNS response to tap",
            "failed to capture a synthetic rootless proxy-only DNS response frame",
        );
    }

    if !ctx.allow_ipv6_outbound && dns_query_type(&udp.payload) == Some(DNS_TYPE_AAAA) {
        return synthetic::reply_with_empty_dns_response(
            ctx,
            udp,
            dns_qname.as_deref(),
            dns_qtype,
            "failed to write synthetic DNS AAAA response to tap",
            "failed to capture a synthetic rootless DNS AAAA response frame",
        );
    }

    if ctx.sandbox_policy.offline {
        return synthetic::reply_with_empty_dns_response(
            ctx,
            udp,
            dns_qname.as_deref(),
            dns_qtype,
            "failed to write synthetic offline DNS response to tap",
            "failed to capture a synthetic rootless offline DNS response frame",
        );
    }

    let Some(upstream_ip) = ctx.dns_upstream else {
        util::warn(
            "rootless-internal DNS relay received a query, but no upstream resolver is configured",
        );
        return Ok(());
    };

    relay::relay_dns_query(ctx, udp, dns_qname.as_deref(), dns_qtype, upstream_ip)
}

fn dns_query_type_name(payload: &[u8]) -> Option<&'static str> {
    match dns_query_type(payload) {
        Some(1) => Some("A"),
        Some(28) => Some("AAAA"),
        Some(_) => Some("other"),
        None => None,
    }
}
