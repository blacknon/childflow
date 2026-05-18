use std::io::Write;
use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};

use crate::flow_log::DnsAnswerMode;
use crate::sandbox::BlockReason;
use crate::util;

use super::super::super::packet::{self, ParsedUdpPacket};
use super::super::super::transport::{
    dns_answer_ips, dns_query_name, dns_query_type, relay_dns_udp, synthesize_empty_dns_response,
    DNS_TYPE_AAAA,
};
use super::super::events::{capture_frame, note_dns_answer, note_dns_query};
use super::super::{note_policy_violation, PolicyViolationTarget, UdpPacketContext};

pub(super) fn is_dns_request(
    addr_plan: &super::super::super::addr::AddressPlan,
    udp: &ParsedUdpPacket,
) -> bool {
    udp.dst_port == 53
        && (udp.meta.dst_ip == IpAddr::V4(addr_plan.gateway_ipv4)
            || udp.meta.dst_ip == IpAddr::V6(addr_plan.gateway_ipv6))
}

pub(super) fn handle_dns_packet(ctx: UdpPacketContext<'_>, udp: &ParsedUdpPacket) -> Result<()> {
    let dns_qtype = dns_query_type_name(&udp.payload);
    let dns_qname = dns_query_name(&udp.payload);

    if let Some(qname) = dns_qname.as_deref() {
        if let Some(reason) = ctx.sandbox_policy.block_reason_for_dns_name(qname) {
            note_dns_query(
                ctx.flow_log,
                SocketAddr::new(udp.meta.dst_ip, 53),
                dns_qname.as_deref(),
                dns_qtype,
            )?;
            note_policy_violation(
                ctx.flow_log,
                ctx.leak_detected,
                ctx.sandbox_policy,
                PolicyViolationTarget {
                    protocol: "dns",
                    remote: qname,
                    remote_ip: None,
                    remote_port: None,
                },
                &reason,
            );
            return write_synthetic_dns_response(
                ctx,
                udp,
                dns_qname.as_deref(),
                dns_qtype,
                synthesize_empty_dns_response(&udp.payload)?,
                "failed to write synthetic denied-domain DNS response to tap",
                "failed to capture a synthetic rootless denied-domain DNS response frame",
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
        return write_synthetic_dns_response(
            ctx,
            udp,
            dns_qname.as_deref(),
            dns_qtype,
            synthesize_empty_dns_response(&udp.payload)?,
            "failed to write synthetic proxy-only DNS response to tap",
            "failed to capture a synthetic rootless proxy-only DNS response frame",
        );
    }

    if !ctx.allow_ipv6_outbound && dns_query_type(&udp.payload) == Some(DNS_TYPE_AAAA) {
        note_dns_query(
            ctx.flow_log,
            SocketAddr::new(udp.meta.dst_ip, 53),
            dns_qname.as_deref(),
            dns_qtype,
        )?;
        return write_synthetic_dns_response(
            ctx,
            udp,
            dns_qname.as_deref(),
            dns_qtype,
            synthesize_empty_dns_response(&udp.payload)?,
            "failed to write synthetic DNS AAAA response to tap",
            "failed to capture a synthetic rootless DNS AAAA response frame",
        );
    }

    if ctx.sandbox_policy.offline {
        note_dns_query(
            ctx.flow_log,
            SocketAddr::new(udp.meta.dst_ip, 53),
            dns_qname.as_deref(),
            dns_qtype,
        )?;
        return write_synthetic_dns_response(
            ctx,
            udp,
            dns_qname.as_deref(),
            dns_qtype,
            synthesize_empty_dns_response(&udp.payload)?,
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

    let server = SocketAddr::new(upstream_ip, 53);
    note_dns_query(ctx.flow_log, server, dns_qname.as_deref(), dns_qtype)?;
    let response = relay_dns_udp(upstream_ip, &udp.payload)?;
    let resolved_ips = dns_answer_ips(&response);
    if let Some(qname) = dns_qname.as_deref() {
        ctx.resolved_domains.note_resolution(qname, &resolved_ips);
    }
    let frame = packet::build_udp_frame(
        ctx.addr_plan.gateway_mac,
        udp.meta.src_mac,
        udp.meta.dst_ip,
        udp.meta.src_ip,
        53,
        udp.src_port,
        &response,
    )?;
    ctx.tap
        .write_all(&frame)
        .context("failed to write DNS UDP response to tap")?;
    capture_frame(
        ctx.capture,
        &frame,
        "failed to capture a rootless DNS UDP response frame",
    );
    note_dns_answer(
        ctx.flow_log,
        server,
        dns_qname.as_deref(),
        dns_qtype,
        DnsAnswerMode::Relayed,
        response.len(),
        &resolved_ips,
    )?;
    Ok(())
}

fn write_synthetic_dns_response(
    ctx: UdpPacketContext<'_>,
    udp: &ParsedUdpPacket,
    qname: Option<&str>,
    qtype: Option<&'static str>,
    response: Vec<u8>,
    write_context: &str,
    capture_context: &str,
) -> Result<()> {
    let frame = packet::build_udp_frame(
        ctx.addr_plan.gateway_mac,
        udp.meta.src_mac,
        udp.meta.dst_ip,
        udp.meta.src_ip,
        53,
        udp.src_port,
        &response,
    )?;
    ctx.tap
        .write_all(&frame)
        .with_context(|| write_context.to_string())?;
    capture_frame(ctx.capture, &frame, capture_context);
    note_dns_answer(
        ctx.flow_log,
        SocketAddr::new(udp.meta.dst_ip, 53),
        qname,
        qtype,
        DnsAnswerMode::SyntheticEmpty,
        response.len(),
        &[],
    )?;
    Ok(())
}

fn dns_query_type_name(payload: &[u8]) -> Option<&'static str> {
    match dns_query_type(payload) {
        Some(1) => Some("A"),
        Some(28) => Some("AAAA"),
        Some(_) => Some("other"),
        None => None,
    }
}
