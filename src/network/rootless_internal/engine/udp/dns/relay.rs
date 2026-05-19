use std::io::Write;
use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};

use crate::flow_log::DnsAnswerMode;

use super::super::super::super::packet::{self, ParsedUdpPacket};
use super::super::super::super::transport::{dns_answer_ips, relay_dns_udp};
use super::super::super::events::{capture_frame, note_dns_answer, note_dns_query};
use super::super::super::UdpPacketContext;

pub(super) fn relay_dns_query(
    ctx: UdpPacketContext<'_>,
    udp: &ParsedUdpPacket,
    qname: Option<&str>,
    qtype: Option<&'static str>,
    upstream_ip: IpAddr,
) -> Result<()> {
    let server = SocketAddr::new(upstream_ip, 53);
    note_dns_query(ctx.flow_log, server, qname, qtype)?;
    let response = relay_dns_udp(upstream_ip, &udp.payload)?;
    let resolved_ips = dns_answer_ips(&response);
    if let Some(qname) = qname {
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
        qname,
        qtype,
        DnsAnswerMode::Relayed,
        response.len(),
        &resolved_ips,
    )?;
    Ok(())
}
