// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod events;
mod tcp;
mod udp;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{ErrorKind, Read};
use std::net::IpAddr;
use std::os::fd::{BorrowedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::fcntl::{fcntl, FcntlArg, OFlag};

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
    stop: Arc<AtomicBool>,
    leak_detected: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<()>>>,
}

impl EngineHandle {
    pub fn start(tap: TapHandle, addr_plan: AddressPlan, config: EngineConfig) -> Result<Self> {
        set_nonblocking(tap.raw_fd())?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let leak_detected = Arc::new(AtomicBool::new(false));
        let leak_detected_for_thread = Arc::clone(&leak_detected);
        let join = thread::spawn(move || {
            run_engine(
                tap,
                addr_plan,
                config,
                stop_for_thread,
                leak_detected_for_thread,
            )
        });

        Ok(Self {
            stop,
            leak_detected,
            join: Some(join),
        })
    }

    fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(err).context("rootless-internal engine stopped with an error");
                }
                Err(_) => anyhow::bail!("rootless-internal engine thread panicked"),
            }
        }
        Ok(())
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }

    pub fn leak_detected(&self) -> bool {
        self.leak_detected.load(Ordering::Relaxed)
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if let Err(err) = self.stop_and_join() {
            util::warn(format!("{err:#}"));
        }
    }
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

fn run_engine(
    mut tap: TapHandle,
    addr_plan: AddressPlan,
    mut config: EngineConfig,
    stop: Arc<AtomicBool>,
    leak_detected: Arc<AtomicBool>,
) -> Result<()> {
    let (event_tx, event_rx) = mpsc::channel();
    let mut child_mac = None;
    let mut connections: HashMap<FlowKey, ConnectionState> = HashMap::new();
    let mut resolved_domains = ResolvedDomainIndex::default();
    let mut buf = [0_u8; 65535];

    while !stop.load(Ordering::Relaxed) {
        events::drain_remote_events(
            &mut tap,
            &addr_plan,
            &mut child_mac,
            &event_rx,
            &mut connections,
            &mut config.capture,
            &mut config.flow_log,
        )?;

        match tap.read(&mut buf) {
            Ok(0) => thread::sleep(Duration::from_millis(10)),
            Ok(n) => {
                events::capture_frame(
                    &mut config.capture,
                    &buf[..n],
                    "failed to capture a child->engine frame from the rootless tap",
                );
                match packet::parse_frame(&buf[..n]) {
                    Ok(ParsedPacket::Tcp(tcp)) => {
                        child_mac.get_or_insert(tcp.meta.src_mac);
                        tcp::handle_tcp_packet(
                            TcpPacketContext {
                                tap: &mut tap,
                                addr_plan: &addr_plan,
                                event_tx: &event_tx,
                                connections: &mut connections,
                                sandbox_policy: &config.sandbox_policy,
                                proxy_upstream: config.proxy_upstream.as_ref(),
                                capture: &mut config.capture,
                                flow_log: &mut config.flow_log,
                                leak_detected: &leak_detected,
                                resolved_domains: &resolved_domains,
                            },
                            &tcp,
                        )?;
                    }
                    Ok(ParsedPacket::Udp(udp)) => {
                        child_mac.get_or_insert(udp.meta.src_mac);
                        udp::handle_udp_packet(
                            UdpPacketContext {
                                tap: &mut tap,
                                addr_plan: &addr_plan,
                                dns_upstream: config.dns_upstream,
                                allow_ipv6_outbound: config.allow_ipv6_outbound,
                                sandbox_policy: &config.sandbox_policy,
                                capture: &mut config.capture,
                                event_tx: &event_tx,
                                flow_log: &mut config.flow_log,
                                leak_detected: &leak_detected,
                                resolved_domains: &mut resolved_domains,
                            },
                            &udp,
                        )?;
                    }
                    Ok(ParsedPacket::Icmpv4(icmp)) => {
                        child_mac.get_or_insert(icmp.meta.src_mac);
                        handle_icmpv4_packet(
                            &event_tx,
                            &addr_plan,
                            &config.sandbox_policy,
                            &mut config.flow_log,
                            &leak_detected,
                            &resolved_domains,
                            &icmp,
                        )?;
                    }
                    Ok(ParsedPacket::Icmpv6(icmp)) => {
                        child_mac.get_or_insert(icmp.meta.src_mac);
                        handle_icmpv6_packet(
                            &event_tx,
                            &addr_plan,
                            &config.sandbox_policy,
                            &mut config.flow_log,
                            &leak_detected,
                            &resolved_domains,
                            &icmp,
                        )?;
                    }
                    Ok(ParsedPacket::Unsupported) => {}
                    Err(err) => util::debug(format!(
                        "rootless-internal engine ignored an unsupported frame: {err:#}"
                    )),
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err).context("failed to read a frame from the rootless tap"),
        }
    }

    events::drain_remote_events(
        &mut tap,
        &addr_plan,
        &mut child_mac,
        &event_rx,
        &mut connections,
        &mut config.capture,
        &mut config.flow_log,
    )?;
    events::flush_remaining_flow_end_events(&mut connections, &mut config.flow_log)?;

    Ok(())
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
    let Ok(routes) = std::fs::read_to_string("/proc/net/ipv6_route") else {
        return false;
    };
    routes.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.len() > 9
            && fields[0] == "00000000000000000000000000000000"
            && fields[1] == "00000000"
            && fields[9] != "lo"
    })
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY: `fd` comes from `TapHandle` and stays open for the duration of this call.
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let flags = OFlag::from_bits_truncate(
        fcntl(fd, FcntlArg::F_GETFL).context("failed to read tap fd flags")?,
    );
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .context("failed to set tap fd nonblocking")?;
    Ok(())
}
