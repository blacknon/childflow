use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use anyhow::Result;

use crate::flow_log::{FlowLogger, PolicyViolationEvent};
use crate::sandbox::SandboxPolicy;
use crate::util;

use super::super::addr::AddressPlan;
use super::super::engine::{RemoteEvent, ResolvedDomainIndex};
use super::super::packet::{self, ParsedIcmpv4Packet, ParsedIcmpv6Packet};
use super::types::{Icmpv4EchoRequest, Icmpv4RawRequest, Icmpv6EchoRequest, Icmpv6RawRequest};
use super::workers::{
    should_relay_icmpv4_request, should_relay_icmpv6_request, spawn_icmpv4_echo_worker,
    spawn_icmpv4_raw_worker, spawn_icmpv6_echo_worker, spawn_icmpv6_raw_worker,
};

pub(super) fn handle_icmpv4_packet(
    event_tx: &Sender<RemoteEvent>,
    addr_plan: &AddressPlan,
    sandbox_policy: &SandboxPolicy,
    flow_log: &mut Option<FlowLogger>,
    leak_detected: &Arc<AtomicBool>,
    resolved_domains: &ResolvedDomainIndex,
    icmp: &ParsedIcmpv4Packet,
) -> Result<()> {
    let (src_ip, dst_ip) = match (icmp.meta.src_ip, icmp.meta.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
        _ => return Ok(()),
    };

    let is_gateway_target = dst_ip == addr_plan.gateway_ipv4;
    if let Some(reason) = sandbox_policy.block_reason_for_remote_ip_with_domains(
        IpAddr::V4(dst_ip),
        resolved_domains.domains_for_ip(IpAddr::V4(dst_ip)),
    ) {
        if let Some(logger) = flow_log.as_mut() {
            let matched_cidr = reason.matched_cidr().map(|cidr| cidr.to_string());
            logger.log_policy_violation(PolicyViolationEvent {
                protocol: "icmpv4",
                remote: &dst_ip.to_string(),
                remote_ip: Some(IpAddr::V4(dst_ip)),
                remote_port: None,
                reason_code: reason.code(),
                control: reason.control(),
                matched_cidr: matched_cidr.as_deref(),
                matched_domain: reason.matched_domain(),
                reason: &reason.describe(),
            })?;
        }
        if sandbox_policy.fail_on_leak {
            leak_detected.store(true, Ordering::Relaxed);
        }
        util::debug(format!(
            "rootless-internal dropped ICMPv4 flow to {} ({})",
            dst_ip,
            reason.describe()
        ));
        return Ok(());
    }

    if icmp.icmp_type == 8 && icmp.code == 0 && !is_gateway_target {
        spawn_icmpv4_echo_worker(
            event_tx.clone(),
            Icmpv4EchoRequest {
                gateway_mac: addr_plan.gateway_mac,
                child_mac: icmp.meta.src_mac,
                child_ip: src_ip,
                remote_ip: dst_ip,
                hop_limit: icmp.meta.hop_limit,
                identifier: icmp.identifier,
                sequence: icmp.sequence,
                payload: icmp.payload.clone(),
            },
        );
        return Ok(());
    }

    if should_relay_icmpv4_request(icmp.icmp_type) && !is_gateway_target {
        spawn_icmpv4_raw_worker(
            event_tx.clone(),
            Icmpv4RawRequest {
                gateway_mac: addr_plan.gateway_mac,
                child_mac: icmp.meta.src_mac,
                child_ip: src_ip,
                remote_ip: dst_ip,
                hop_limit: icmp.meta.hop_limit,
                message: packet::build_icmpv4_message_from_parsed(icmp),
            },
        );
        return Ok(());
    }

    util::debug(format!(
        "ignoring unsupported outbound ICMPv4 type {} code {} toward {}",
        icmp.icmp_type, icmp.code, dst_ip
    ));

    Ok(())
}

pub(super) fn handle_icmpv6_packet(
    event_tx: &Sender<RemoteEvent>,
    addr_plan: &AddressPlan,
    sandbox_policy: &SandboxPolicy,
    flow_log: &mut Option<FlowLogger>,
    leak_detected: &Arc<AtomicBool>,
    resolved_domains: &ResolvedDomainIndex,
    icmp: &ParsedIcmpv6Packet,
) -> Result<()> {
    let (src_ip, dst_ip) = match (icmp.meta.src_ip, icmp.meta.dst_ip) {
        (IpAddr::V6(src), IpAddr::V6(dst)) => (src, dst),
        _ => return Ok(()),
    };

    let is_gateway_target = dst_ip == addr_plan.gateway_ipv6;
    if let Some(reason) = sandbox_policy.block_reason_for_remote_ip_with_domains(
        IpAddr::V6(dst_ip),
        resolved_domains.domains_for_ip(IpAddr::V6(dst_ip)),
    ) {
        if let Some(logger) = flow_log.as_mut() {
            let matched_cidr = reason.matched_cidr().map(|cidr| cidr.to_string());
            logger.log_policy_violation(PolicyViolationEvent {
                protocol: "icmpv6",
                remote: &dst_ip.to_string(),
                remote_ip: Some(IpAddr::V6(dst_ip)),
                remote_port: None,
                reason_code: reason.code(),
                control: reason.control(),
                matched_cidr: matched_cidr.as_deref(),
                matched_domain: reason.matched_domain(),
                reason: &reason.describe(),
            })?;
        }
        if sandbox_policy.fail_on_leak {
            leak_detected.store(true, Ordering::Relaxed);
        }
        util::debug(format!(
            "rootless-internal dropped ICMPv6 flow to {} ({})",
            dst_ip,
            reason.describe()
        ));
        return Ok(());
    }

    if icmp.icmp_type == 128 && icmp.code == 0 && !is_gateway_target {
        spawn_icmpv6_echo_worker(
            event_tx.clone(),
            Icmpv6EchoRequest {
                gateway_mac: addr_plan.gateway_mac,
                child_mac: icmp.meta.src_mac,
                child_ip: src_ip,
                remote_ip: dst_ip,
                hop_limit: icmp.meta.hop_limit,
                identifier: icmp.identifier,
                sequence: icmp.sequence,
                payload: icmp.payload.clone(),
            },
        );
        return Ok(());
    }

    if should_relay_icmpv6_request(icmp.icmp_type, dst_ip) && !is_gateway_target {
        spawn_icmpv6_raw_worker(
            event_tx.clone(),
            Icmpv6RawRequest {
                gateway_mac: addr_plan.gateway_mac,
                child_mac: icmp.meta.src_mac,
                child_ip: src_ip,
                remote_ip: dst_ip,
                hop_limit: icmp.meta.hop_limit,
                message: packet::build_icmpv6_message_from_parsed(src_ip, dst_ip, icmp),
            },
        );
        return Ok(());
    }

    util::debug(format!(
        "ignoring unsupported outbound ICMPv6 type {} code {} toward {}",
        icmp.icmp_type, icmp.code, dst_ip
    ));

    Ok(())
}
