// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod events;
mod runtime;
mod tcp;
mod udp;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use anyhow::Result;

use crate::capture::CaptureWriters;
use crate::domain::normalize_domain_name;
use crate::flow_log::{FlowLogger, PolicyViolationEvent};
use crate::proxy::rootless_relay::ProxyUpstreamConfig;
use crate::sandbox::{BlockReason, SandboxPolicy};
use crate::util;

use super::addr::AddressPlan;
use super::icmp::{handle_icmpv4_packet, handle_icmpv6_packet};
use super::packet::{self, ParsedPacket};
use super::state::{FlowKey, TcpSession};
use super::tap::TapHandle;

pub struct EngineConfig {
    pub dns_upstream: Option<IpAddr>,
    pub allow_ipv6_outbound: bool,
    pub sandbox_policy: SandboxPolicy,
    pub proxy_upstream: Option<ProxyUpstreamConfig>,
    pub capture: Option<CaptureWriters>,
    pub flow_log: Option<FlowLogger>,
}

pub struct EngineHandle {
    pub(super) stop: Arc<AtomicBool>,
    pub(super) leak_detected: Arc<AtomicBool>,
    pub(super) join: Option<std::thread::JoinHandle<Result<()>>>,
}

#[derive(Debug)]
pub(super) enum RemoteEvent {
    TcpData { key: FlowKey, payload: Vec<u8> },
    TcpClosed { key: FlowKey },
    Frame(Vec<u8>),
}

struct ConnectionState {
    session: TcpSession,
    command_tx: Sender<ConnectionCommand>,
    flow_end_logged: bool,
}

#[derive(Debug, Default)]
pub(super) struct ResolvedDomainIndex {
    ip_to_domains: BTreeMap<IpAddr, BTreeSet<String>>,
}

impl ResolvedDomainIndex {
    fn note_resolution(&mut self, qname: &str, answer_ips: &[IpAddr]) {
        let Some(qname) = normalize_domain_name(qname) else {
            return;
        };
        for ip in answer_ips {
            self.ip_to_domains
                .entry(*ip)
                .or_default()
                .insert(qname.clone());
        }
    }

    pub(super) fn domains_for_ip(&self, ip: IpAddr) -> Option<&BTreeSet<String>> {
        self.ip_to_domains.get(&ip)
    }
}

pub(super) enum ConnectionCommand {
    Write(Vec<u8>),
    ShutdownWrite,
}

struct TcpPacketContext<'a> {
    tap: &'a mut TapHandle,
    addr_plan: &'a AddressPlan,
    event_tx: &'a Sender<RemoteEvent>,
    connections: &'a mut HashMap<FlowKey, ConnectionState>,
    sandbox_policy: &'a SandboxPolicy,
    proxy_upstream: Option<&'a ProxyUpstreamConfig>,
    capture: &'a mut Option<CaptureWriters>,
    flow_log: &'a mut Option<FlowLogger>,
    leak_detected: &'a Arc<AtomicBool>,
    resolved_domains: &'a ResolvedDomainIndex,
}

struct UdpPacketContext<'a> {
    tap: &'a mut TapHandle,
    addr_plan: &'a AddressPlan,
    dns_upstream: Option<IpAddr>,
    allow_ipv6_outbound: bool,
    sandbox_policy: &'a SandboxPolicy,
    capture: &'a mut Option<CaptureWriters>,
    event_tx: &'a Sender<RemoteEvent>,
    flow_log: &'a mut Option<FlowLogger>,
    leak_detected: &'a Arc<AtomicBool>,
    resolved_domains: &'a mut ResolvedDomainIndex,
}

struct PolicyViolationTarget<'a> {
    protocol: &'static str,
    remote: &'a str,
    remote_ip: Option<IpAddr>,
    remote_port: Option<u16>,
}

fn note_leak_if_requested(
    leak_detected: &Arc<AtomicBool>,
    sandbox_policy: &SandboxPolicy,
    _reason: &BlockReason,
) {
    if sandbox_policy.fail_on_leak {
        leak_detected.store(true, Ordering::Relaxed);
    }
}

fn note_policy_violation(
    flow_log: &mut Option<FlowLogger>,
    leak_detected: &Arc<AtomicBool>,
    sandbox_policy: &SandboxPolicy,
    target: PolicyViolationTarget<'_>,
    reason: &BlockReason,
) {
    if let Some(logger) = flow_log.as_mut() {
        let matched_cidr = reason.matched_cidr().map(|cidr| cidr.to_string());
        if let Err(err) = logger.log_policy_violation(PolicyViolationEvent {
            protocol: target.protocol,
            remote: target.remote,
            remote_ip: target.remote_ip,
            remote_port: target.remote_port,
            reason_code: reason.code(),
            control: reason.control(),
            matched_cidr: matched_cidr.as_deref(),
            matched_domain: reason.matched_domain(),
            reason: &reason.describe(),
        }) {
            util::warn(format!("{err:#}"));
        }
    }
    note_leak_if_requested(leak_detected, sandbox_policy, reason);
}

pub fn detect_ipv6_outbound() -> bool {
    runtime::detect_ipv6_outbound()
}
