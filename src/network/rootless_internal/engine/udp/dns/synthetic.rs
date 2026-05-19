use std::io::Write;

use anyhow::{Context, Result};

use crate::flow_log::DnsAnswerMode;
use crate::sandbox::BlockReason;

use super::super::super::super::packet::{self, ParsedUdpPacket};
use super::super::super::super::transport::synthesize_empty_dns_response;
use super::super::super::events::{capture_frame, note_dns_answer, note_dns_query};
use super::super::super::{note_policy_violation, PolicyViolationTarget, UdpPacketContext};

pub(super) fn deny_blocked_domain(
    ctx: UdpPacketContext<'_>,
    udp: &ParsedUdpPacket,
    qname: Option<&str>,
    qtype: Option<&'static str>,
    reason: &BlockReason,
) -> Result<()> {
    note_dns_query(
        ctx.flow_log,
        std::net::SocketAddr::new(udp.meta.dst_ip, 53),
        qname,
        qtype,
    )?;
    note_policy_violation(
        ctx.flow_log,
        ctx.leak_detected,
        ctx.sandbox_policy,
        PolicyViolationTarget {
            protocol: "dns",
            remote: qname.unwrap_or("<unknown>"),
            remote_ip: None,
            remote_port: None,
        },
        reason,
    );
    reply_with_synthetic_dns_response(
        ctx,
        udp,
        qname,
        qtype,
        synthesize_empty_dns_response(&udp.payload)?,
        "failed to write synthetic denied-domain DNS response to tap",
        "failed to capture a synthetic rootless denied-domain DNS response frame",
    )
}

pub(super) fn reply_with_empty_dns_response(
    ctx: UdpPacketContext<'_>,
    udp: &ParsedUdpPacket,
    qname: Option<&str>,
    qtype: Option<&'static str>,
    write_context: &str,
    capture_context: &str,
) -> Result<()> {
    note_dns_query(
        ctx.flow_log,
        std::net::SocketAddr::new(udp.meta.dst_ip, 53),
        qname,
        qtype,
    )?;
    reply_with_synthetic_dns_response(
        ctx,
        udp,
        qname,
        qtype,
        synthesize_empty_dns_response(&udp.payload)?,
        write_context,
        capture_context,
    )
}

fn reply_with_synthetic_dns_response(
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
        std::net::SocketAddr::new(udp.meta.dst_ip, 53),
        qname,
        qtype,
        DnsAnswerMode::SyntheticEmpty,
        response.len(),
        &[],
    )?;
    Ok(())
}
