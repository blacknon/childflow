use anyhow::Result;

mod dns;
mod relay;

use crate::util;

use super::super::packet::ParsedUdpPacket;
use super::{note_policy_violation, PolicyViolationTarget, UdpPacketContext};

pub(super) fn handle_udp_packet(ctx: UdpPacketContext<'_>, udp: &ParsedUdpPacket) -> Result<()> {
    if dns::is_dns_request(ctx.addr_plan, udp) {
        return dns::handle_dns_packet(ctx, udp);
    }

    if let Some(reason) = ctx.sandbox_policy.block_reason_for_remote_ip_with_domains(
        udp.meta.dst_ip,
        ctx.resolved_domains.domains_for_ip(udp.meta.dst_ip),
    ) {
        note_policy_violation(
            ctx.flow_log,
            ctx.leak_detected,
            ctx.sandbox_policy,
            PolicyViolationTarget {
                protocol: "udp",
                remote: &format!("{}:{}", udp.meta.dst_ip, udp.dst_port),
                remote_ip: Some(udp.meta.dst_ip),
                remote_port: Some(udp.dst_port),
            },
            &reason,
        );
        util::debug(format!(
            "rootless-internal dropped UDP flow to {}:{} ({})",
            udp.meta.dst_ip,
            udp.dst_port,
            reason.describe()
        ));
        return Ok(());
    }

    relay::spawn_udp_worker(
        ctx.event_tx.clone(),
        relay::UdpRelayRequest {
            gateway_mac: ctx.addr_plan.gateway_mac,
            child_mac: udp.meta.src_mac,
            child_ip: udp.meta.src_ip,
            child_port: udp.src_port,
            remote_ip: udp.meta.dst_ip,
            remote_port: udp.dst_port,
            hop_limit: udp.meta.hop_limit,
            payload: udp.payload.clone(),
        },
    );

    Ok(())
}
