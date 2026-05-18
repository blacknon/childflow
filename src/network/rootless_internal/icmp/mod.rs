// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod relay;

#[cfg(test)]
mod tests;

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;

use anyhow::Result;

use crate::flow_log::{FlowLogger, PolicyViolationEvent};
use crate::sandbox::SandboxPolicy;
use crate::util;

use super::addr::AddressPlan;
use super::engine::{RemoteEvent, ResolvedDomainIndex};
use super::packet::{
    self, Icmpv4EchoFrame, Icmpv4ErrorFrame, Icmpv6EchoFrame, Icmpv6ErrorFrame, ParsedIcmpv4Packet,
    ParsedIcmpv6Packet,
};

struct Icmpv4EchoRequest {
    gateway_mac: [u8; 6],
    child_mac: [u8; 6],
    child_ip: std::net::Ipv4Addr,
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

struct Icmpv4RawRequest {
    gateway_mac: [u8; 6],
    child_mac: [u8; 6],
    child_ip: std::net::Ipv4Addr,
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    message: Vec<u8>,
}

struct Icmpv6EchoRequest {
    gateway_mac: [u8; 6],
    child_mac: [u8; 6],
    child_ip: std::net::Ipv6Addr,
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

struct Icmpv6RawRequest {
    gateway_mac: [u8; 6],
    child_mac: [u8; 6],
    child_ip: std::net::Ipv6Addr,
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    message: Vec<u8>,
}

enum IcmpRelayOutcome {
    Message(Vec<u8>),
    Error {
        source_ip: IpAddr,
        icmp_type: u8,
        code: u8,
    },
}

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

fn spawn_icmpv4_echo_worker(event_tx: Sender<RemoteEvent>, request: Icmpv4EchoRequest) {
    thread::spawn(move || {
        let child_probe = packet::build_icmpv4_echo_ip_packet(
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
        );

        let result = relay::relay_icmpv4_echo(request.remote_ip, request.hop_limit, &request.payload)
            .and_then(|outcome| match outcome {
                IcmpRelayOutcome::Message(reply) => {
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
                            &reply,
                        )
                    }
                }
                IcmpRelayOutcome::Error {
                    source_ip,
                    icmp_type,
                    code,
                } => {
                    let probe = child_probe.as_ref().map_err(|err| {
                        anyhow::anyhow!(
                            "failed to preserve the child ICMPv4 probe for ICMP synthesis toward {}: {err:#}",
                            request.remote_ip
                        )
                    })?;
                    let source_ip = match source_ip {
                        IpAddr::V4(ip) => ip,
                        _ => anyhow::bail!(
                            "ICMPv4 relay received a non-IPv4 error source for {}",
                            request.remote_ip
                        ),
                    };
                    packet::build_icmpv4_error_frame(Icmpv4ErrorFrame {
                        src_mac: request.gateway_mac,
                        dst_mac: request.child_mac,
                        src_ip: source_ip,
                        dst_ip: request.child_ip,
                        icmp_type,
                        code,
                        quote: probe,
                    })
                }
            });

        match result {
            Ok(frame) => {
                let _ = event_tx.send(RemoteEvent::Frame(frame));
            }
            Err(err) => {
                util::debug(format!(
                    "rootless-internal could not complete an outbound ICMP echo exchange for {}: {err:#}",
                    request.remote_ip
                ));
            }
        }
    });
}

fn spawn_icmpv4_raw_worker(event_tx: Sender<RemoteEvent>, request: Icmpv4RawRequest) {
    thread::spawn(move || {
        let child_probe = packet::build_icmpv4_ip_packet_from_message(
            request.child_ip,
            request.remote_ip,
            request.hop_limit,
            &request.message,
        );

        let result = relay::relay_icmpv4_message(request.remote_ip, request.hop_limit, &request.message)
            .and_then(|outcome| match outcome {
                IcmpRelayOutcome::Message(reply) => packet::build_icmpv4_frame_from_message(
                    request.gateway_mac,
                    request.child_mac,
                    request.remote_ip,
                    request.child_ip,
                    &reply,
                ),
                IcmpRelayOutcome::Error {
                    source_ip,
                    icmp_type,
                    code,
                } => {
                    let probe = child_probe.as_ref().map_err(|err| {
                        anyhow::anyhow!(
                            "failed to preserve the child ICMPv4 probe for ICMP synthesis toward {}: {err:#}",
                            request.remote_ip
                        )
                    })?;
                    let source_ip = match source_ip {
                        IpAddr::V4(ip) => ip,
                        _ => anyhow::bail!(
                            "ICMPv4 relay received a non-IPv4 error source for {}",
                            request.remote_ip
                        ),
                    };
                    packet::build_icmpv4_error_frame(Icmpv4ErrorFrame {
                        src_mac: request.gateway_mac,
                        dst_mac: request.child_mac,
                        src_ip: source_ip,
                        dst_ip: request.child_ip,
                        icmp_type,
                        code,
                        quote: probe,
                    })
                }
            });

        match result {
            Ok(frame) => {
                let _ = event_tx.send(RemoteEvent::Frame(frame));
            }
            Err(err) => {
                util::warn(format!(
                    "rootless-internal could not complete a generic outbound ICMPv4 exchange for {}: {err:#}. This path depends on raw ICMP socket access on the host",
                    request.remote_ip
                ));
            }
        }
    });
}

fn spawn_icmpv6_echo_worker(event_tx: Sender<RemoteEvent>, request: Icmpv6EchoRequest) {
    thread::spawn(move || {
        let child_probe = packet::build_icmpv6_echo_ip_packet(
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
        );

        let result = relay::relay_icmpv6_echo(request.remote_ip, request.hop_limit, &request.payload)
            .and_then(|outcome| match outcome {
                IcmpRelayOutcome::Message(reply) => {
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
                            &reply,
                        )
                    }
                }
                IcmpRelayOutcome::Error {
                    source_ip,
                    icmp_type,
                    code,
                } => {
                    let probe = child_probe.as_ref().map_err(|err| {
                        anyhow::anyhow!(
                            "failed to preserve the child ICMPv6 probe for ICMP synthesis toward {}: {err:#}",
                            request.remote_ip
                        )
                    })?;
                    let source_ip = match source_ip {
                        IpAddr::V6(ip) => ip,
                        _ => anyhow::bail!(
                            "ICMPv6 relay received a non-IPv6 error source for {}",
                            request.remote_ip
                        ),
                    };
                    packet::build_icmpv6_error_frame(Icmpv6ErrorFrame {
                        src_mac: request.gateway_mac,
                        dst_mac: request.child_mac,
                        src_ip: source_ip,
                        dst_ip: request.child_ip,
                        icmp_type,
                        code,
                        quote: probe,
                    })
                }
            });

        match result {
            Ok(frame) => {
                let _ = event_tx.send(RemoteEvent::Frame(frame));
            }
            Err(err) => {
                util::debug(format!(
                    "rootless-internal could not complete an outbound ICMPv6 echo exchange for {}: {err:#}",
                    request.remote_ip
                ));
            }
        }
    });
}

fn spawn_icmpv6_raw_worker(event_tx: Sender<RemoteEvent>, request: Icmpv6RawRequest) {
    thread::spawn(move || {
        let child_probe = packet::build_icmpv6_ip_packet_from_message(
            request.child_ip,
            request.remote_ip,
            request.hop_limit,
            &request.message,
        );

        let result = relay::relay_icmpv6_message(request.remote_ip, request.hop_limit, &request.message)
            .and_then(|outcome| match outcome {
                IcmpRelayOutcome::Message(reply) => packet::build_icmpv6_frame_from_message(
                    request.gateway_mac,
                    request.child_mac,
                    request.remote_ip,
                    request.child_ip,
                    &reply,
                ),
                IcmpRelayOutcome::Error {
                    source_ip,
                    icmp_type,
                    code,
                } => {
                    let probe = child_probe.as_ref().map_err(|err| {
                        anyhow::anyhow!(
                            "failed to preserve the child ICMPv6 probe for ICMP synthesis toward {}: {err:#}",
                            request.remote_ip
                        )
                    })?;
                    let source_ip = match source_ip {
                        IpAddr::V6(ip) => ip,
                        _ => anyhow::bail!(
                            "ICMPv6 relay received a non-IPv6 error source for {}",
                            request.remote_ip
                        ),
                    };
                    packet::build_icmpv6_error_frame(Icmpv6ErrorFrame {
                        src_mac: request.gateway_mac,
                        dst_mac: request.child_mac,
                        src_ip: source_ip,
                        dst_ip: request.child_ip,
                        icmp_type,
                        code,
                        quote: probe,
                    })
                }
            });

        match result {
            Ok(frame) => {
                let _ = event_tx.send(RemoteEvent::Frame(frame));
            }
            Err(err) => {
                util::warn(format!(
                    "rootless-internal could not complete a generic outbound ICMPv6 exchange for {}: {err:#}. This path depends on raw ICMP socket access on the host",
                    request.remote_ip
                ));
            }
        }
    });
}

fn should_relay_icmpv4_request(icmp_type: u8) -> bool {
    !matches!(icmp_type, 0 | 3 | 4 | 5 | 11 | 12)
}

fn should_relay_icmpv6_request(icmp_type: u8, dst_ip: std::net::Ipv6Addr) -> bool {
    !dst_ip.is_multicast() && icmp_type >= 128 && !matches!(icmp_type, 128 | 129 | 130..=137 | 143)
}
