// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{BorrowedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::fcntl::{fcntl, FcntlArg, OFlag};

use crate::capture::CaptureWriters;
use crate::domain::normalize_domain_name;
use crate::flow_log::{ConnectResultStatus, DnsAnswerMode, FlowLogger, PolicyViolationEvent};
use crate::proxy::rootless_relay::ProxyUpstreamConfig;
use crate::sandbox::{BlockReason, SandboxPolicy};
use crate::util;

use super::addr::AddressPlan;
use super::icmp::{handle_icmpv4_packet, handle_icmpv6_packet};
use super::packet::{
    self, Icmpv4ErrorFrame, Icmpv6ErrorFrame, ParsedPacket, ParsedTcpPacket, ParsedUdpPacket,
    TcpReply,
};
use super::state::{FlowKey, TcpSession};
use super::tap::TapHandle;
use super::transport::{
    connect_remote, dns_answer_ips, dns_query_name, dns_query_type, relay_dns_udp,
    relay_udp_payload, synthesize_empty_dns_response, UdpRelayOutcome, DNS_TYPE_AAAA,
};

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

struct UdpRelayRequest {
    gateway_mac: [u8; 6],
    child_mac: [u8; 6],
    child_ip: IpAddr,
    child_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    hop_limit: u8,
    payload: Vec<u8>,
}

struct PolicyViolationTarget<'a> {
    protocol: &'static str,
    remote: &'a str,
    remote_ip: Option<IpAddr>,
    remote_port: Option<u16>,
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
    sandbox_policy: SandboxPolicy,
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
    sandbox_policy: SandboxPolicy,
    capture: &'a mut Option<CaptureWriters>,
    event_tx: &'a Sender<RemoteEvent>,
    flow_log: &'a mut Option<FlowLogger>,
    leak_detected: &'a Arc<AtomicBool>,
    resolved_domains: &'a mut ResolvedDomainIndex,
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
        drain_remote_events(
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
                capture_frame(
                    &mut config.capture,
                    &buf[..n],
                    "failed to capture a child->engine frame from the rootless tap",
                );
                match packet::parse_frame(&buf[..n]) {
                    Ok(ParsedPacket::Tcp(tcp)) => {
                        child_mac.get_or_insert(tcp.meta.src_mac);
                        handle_tcp_packet(
                            TcpPacketContext {
                                tap: &mut tap,
                                addr_plan: &addr_plan,
                                event_tx: &event_tx,
                                connections: &mut connections,
                                sandbox_policy: config.sandbox_policy.clone(),
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
                        handle_udp_packet(
                            UdpPacketContext {
                                tap: &mut tap,
                                addr_plan: &addr_plan,
                                dns_upstream: config.dns_upstream,
                                allow_ipv6_outbound: config.allow_ipv6_outbound,
                                sandbox_policy: config.sandbox_policy.clone(),
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

    drain_remote_events(
        &mut tap,
        &addr_plan,
        &mut child_mac,
        &event_rx,
        &mut connections,
        &mut config.capture,
        &mut config.flow_log,
    )?;
    flush_remaining_flow_end_events(&mut connections, &mut config.flow_log)?;

    Ok(())
}

fn handle_tcp_packet(ctx: TcpPacketContext<'_>, tcp: &ParsedTcpPacket) -> Result<()> {
    let TcpPacketContext {
        tap,
        addr_plan,
        event_tx,
        connections,
        sandbox_policy,
        proxy_upstream,
        capture,
        flow_log,
        leak_detected,
        resolved_domains,
    } = ctx;
    let key = FlowKey {
        child_ip: tcp.meta.src_ip,
        child_port: tcp.src_port,
        remote_ip: tcp.meta.dst_ip,
        remote_port: tcp.dst_port,
    };

    if tcp.rst {
        connections.remove(&key);
        return Ok(());
    }

    if tcp.syn && !tcp.ack {
        if let Some(reason) = sandbox_policy.block_reason_for_tcp_remote_ip_with_domains(
            key.remote_ip,
            proxy_upstream.is_some(),
            resolved_domains.domains_for_ip(key.remote_ip),
        ) {
            note_policy_violation(
                flow_log,
                leak_detected,
                &sandbox_policy,
                PolicyViolationTarget {
                    protocol: "tcp",
                    remote: &format!("{}:{}", key.remote_ip, key.remote_port),
                    remote_ip: Some(key.remote_ip),
                    remote_port: Some(key.remote_port),
                },
                &reason,
            );
            deny_tcp_connect(tap, addr_plan, capture, tcp, reason)?;
            return Ok(());
        }

        let remote_addr = key.remote_addr();
        log_connect_attempt(flow_log, remote_addr, proxy_upstream.is_some())?;
        let command_tx = match connect_remote(
            remote_addr,
            proxy_upstream,
            event_tx.clone(),
            key.clone(),
        ) {
            Ok(command_tx) => {
                log_connect_result(
                    flow_log,
                    remote_addr,
                    proxy_upstream.is_some(),
                    ConnectResultStatus::Ok,
                    None,
                )?;
                command_tx
            }
            Err(err) => {
                log_connect_result(
                    flow_log,
                    remote_addr,
                    proxy_upstream.is_some(),
                    ConnectResultStatus::Error,
                    Some(&format!("{err:#}")),
                )?;
                util::warn(format!(
                    "rootless-internal could not open outbound TCP connection for {remote_addr}: {err:#}. Returning RST to the child flow"
                ));
                let rst = packet::build_tcp_frame(TcpReply {
                    src_mac: addr_plan.gateway_mac,
                    dst_mac: tcp.meta.src_mac,
                    src_ip: tcp.meta.dst_ip,
                    dst_ip: tcp.meta.src_ip,
                    src_port: tcp.dst_port,
                    dst_port: tcp.src_port,
                    seq: 0,
                    ack: tcp.sequence_number.wrapping_add(1),
                    syn: false,
                    ack_flag: true,
                    fin: false,
                    rst: true,
                    psh: false,
                    payload: &[],
                })?;
                tap.write_all(&rst)
                    .context("failed to write TCP RST after outbound connect failure")?;
                capture_frame(
                    capture,
                    &rst,
                    "failed to capture a rootless TCP RST frame after outbound connect failure",
                );
                return Ok(());
            }
        };
        let engine_isn = util::run_entropy();
        let session = TcpSession::new(tcp.sequence_number, engine_isn);
        let syn_ack = packet::build_tcp_frame(TcpReply {
            src_mac: addr_plan.gateway_mac,
            dst_mac: tcp.meta.src_mac,
            src_ip: tcp.meta.dst_ip,
            dst_ip: tcp.meta.src_ip,
            src_port: tcp.dst_port,
            dst_port: tcp.src_port,
            seq: engine_isn,
            ack: session.child_next_seq,
            syn: true,
            ack_flag: true,
            fin: false,
            rst: false,
            psh: false,
            payload: &[],
        })?;
        tap.write_all(&syn_ack)
            .context("failed to write SYN-ACK to tap")?;
        capture_frame(
            capture,
            &syn_ack,
            "failed to capture a rootless TCP SYN-ACK frame",
        );
        connections.insert(
            key,
            ConnectionState {
                session,
                command_tx,
                flow_end_logged: false,
            },
        );
        return Ok(());
    }

    let Some(connection) = connections.get_mut(&key) else {
        let rst = packet::build_tcp_frame(TcpReply {
            src_mac: addr_plan.gateway_mac,
            dst_mac: tcp.meta.src_mac,
            src_ip: tcp.meta.dst_ip,
            dst_ip: tcp.meta.src_ip,
            src_port: tcp.dst_port,
            dst_port: tcp.src_port,
            seq: 0,
            ack: tcp
                .sequence_number
                .wrapping_add(tcp.payload.len() as u32 + if tcp.syn { 1 } else { 0 }),
            syn: false,
            ack_flag: true,
            fin: false,
            rst: true,
            psh: false,
            payload: &[],
        })?;
        tap.write_all(&rst)
            .context("failed to write TCP RST to tap")?;
        capture_frame(capture, &rst, "failed to capture a rootless TCP RST frame");
        return Ok(());
    };

    if tcp.ack && tcp.payload.is_empty() && !tcp.fin {
        if connection.session.fin_from_child
            && connection.session.fin_from_remote
            && tcp.acknowledgment_number == connection.session.engine_next_seq
        {
            connections.remove(&key);
        }
        return Ok(());
    }

    if !tcp.payload.is_empty() {
        if !connection
            .session
            .accept_child_payload(tcp.sequence_number, tcp.payload.len())
        {
            return Ok(());
        }
        connection
            .command_tx
            .send(ConnectionCommand::Write(tcp.payload.clone()))
            .context("failed to forward child TCP payload to the remote socket worker")?;
        let ack = packet::build_tcp_frame(TcpReply {
            src_mac: addr_plan.gateway_mac,
            dst_mac: tcp.meta.src_mac,
            src_ip: tcp.meta.dst_ip,
            dst_ip: tcp.meta.src_ip,
            src_port: tcp.dst_port,
            dst_port: tcp.src_port,
            seq: connection.session.engine_next_seq,
            ack: connection.session.child_next_seq,
            syn: false,
            ack_flag: true,
            fin: false,
            rst: false,
            psh: false,
            payload: &[],
        })?;
        tap.write_all(&ack)
            .context("failed to write TCP ACK to tap")?;
        capture_frame(capture, &ack, "failed to capture a rootless TCP ACK frame");
    }

    if tcp.fin && connection.session.accept_child_fin(tcp.sequence_number) {
        let _ = connection.command_tx.send(ConnectionCommand::ShutdownWrite);
        let ack = packet::build_tcp_frame(TcpReply {
            src_mac: addr_plan.gateway_mac,
            dst_mac: tcp.meta.src_mac,
            src_ip: tcp.meta.dst_ip,
            dst_ip: tcp.meta.src_ip,
            src_port: tcp.dst_port,
            dst_port: tcp.src_port,
            seq: connection.session.engine_next_seq,
            ack: connection.session.child_next_seq,
            syn: false,
            ack_flag: true,
            fin: false,
            rst: false,
            psh: false,
            payload: &[],
        })?;
        tap.write_all(&ack)
            .context("failed to write FIN ACK to tap")?;
        capture_frame(
            capture,
            &ack,
            "failed to capture a rootless TCP FIN-ACK frame",
        );
    }

    Ok(())
}

fn handle_udp_packet(ctx: UdpPacketContext<'_>, udp: &ParsedUdpPacket) -> Result<()> {
    let UdpPacketContext {
        tap,
        addr_plan,
        dns_upstream,
        allow_ipv6_outbound,
        sandbox_policy,
        capture,
        event_tx,
        flow_log,
        leak_detected,
        resolved_domains,
    } = ctx;
    let dns_qtype = dns_query_type_name(&udp.payload);
    let dns_qname = dns_query_name(&udp.payload);
    if udp.dst_port == 53
        && (udp.meta.dst_ip == IpAddr::V4(addr_plan.gateway_ipv4)
            || udp.meta.dst_ip == IpAddr::V6(addr_plan.gateway_ipv6))
    {
        if let Some(qname) = dns_qname.as_deref() {
            if let Some(reason) = sandbox_policy.block_reason_for_dns_name(qname) {
                log_dns_query(
                    flow_log,
                    SocketAddr::new(udp.meta.dst_ip, 53),
                    dns_qname.as_deref(),
                    dns_qtype,
                )?;
                note_policy_violation(
                    flow_log,
                    leak_detected,
                    &sandbox_policy,
                    PolicyViolationTarget {
                        protocol: "dns",
                        remote: qname,
                        remote_ip: None,
                        remote_port: None,
                    },
                    &reason,
                );
                let response = synthesize_empty_dns_response(&udp.payload)?;
                let frame = packet::build_udp_frame(
                    addr_plan.gateway_mac,
                    udp.meta.src_mac,
                    udp.meta.dst_ip,
                    udp.meta.src_ip,
                    53,
                    udp.src_port,
                    &response,
                )?;
                tap.write_all(&frame)
                    .context("failed to write synthetic denied-domain DNS response to tap")?;
                capture_frame(
                    capture,
                    &frame,
                    "failed to capture a synthetic rootless denied-domain DNS response frame",
                );
                log_dns_answer(
                    flow_log,
                    SocketAddr::new(udp.meta.dst_ip, 53),
                    dns_qname.as_deref(),
                    dns_qtype,
                    DnsAnswerMode::SyntheticEmpty,
                    response.len(),
                    &[],
                )?;
                return Ok(());
            }
        }

        if sandbox_policy.proxy_only {
            note_policy_violation(
                flow_log,
                leak_detected,
                &sandbox_policy,
                PolicyViolationTarget {
                    protocol: "dns",
                    remote: &format!("{}:53", udp.meta.dst_ip),
                    remote_ip: Some(udp.meta.dst_ip),
                    remote_port: Some(53),
                },
                &BlockReason::ProxyOnly,
            );
            let response = synthesize_empty_dns_response(&udp.payload)?;
            let frame = packet::build_udp_frame(
                addr_plan.gateway_mac,
                udp.meta.src_mac,
                udp.meta.dst_ip,
                udp.meta.src_ip,
                53,
                udp.src_port,
                &response,
            )?;
            tap.write_all(&frame)
                .context("failed to write synthetic proxy-only DNS response to tap")?;
            capture_frame(
                capture,
                &frame,
                "failed to capture a synthetic rootless proxy-only DNS response frame",
            );
            log_dns_answer(
                flow_log,
                SocketAddr::new(udp.meta.dst_ip, 53),
                dns_qname.as_deref(),
                dns_qtype,
                DnsAnswerMode::SyntheticEmpty,
                response.len(),
                &[],
            )?;
            return Ok(());
        }

        if !allow_ipv6_outbound && dns_query_type(&udp.payload) == Some(DNS_TYPE_AAAA) {
            log_dns_query(
                flow_log,
                SocketAddr::new(udp.meta.dst_ip, 53),
                dns_qname.as_deref(),
                dns_qtype,
            )?;
            let response = synthesize_empty_dns_response(&udp.payload)?;
            let frame = packet::build_udp_frame(
                addr_plan.gateway_mac,
                udp.meta.src_mac,
                udp.meta.dst_ip,
                udp.meta.src_ip,
                53,
                udp.src_port,
                &response,
            )?;
            tap.write_all(&frame)
                .context("failed to write synthetic DNS AAAA response to tap")?;
            capture_frame(
                capture,
                &frame,
                "failed to capture a synthetic rootless DNS AAAA response frame",
            );
            log_dns_answer(
                flow_log,
                SocketAddr::new(udp.meta.dst_ip, 53),
                dns_qname.as_deref(),
                dns_qtype,
                DnsAnswerMode::SyntheticEmpty,
                response.len(),
                &[],
            )?;
            return Ok(());
        }

        if sandbox_policy.offline {
            log_dns_query(
                flow_log,
                SocketAddr::new(udp.meta.dst_ip, 53),
                dns_qname.as_deref(),
                dns_qtype,
            )?;
            let response = synthesize_empty_dns_response(&udp.payload)?;
            let frame = packet::build_udp_frame(
                addr_plan.gateway_mac,
                udp.meta.src_mac,
                udp.meta.dst_ip,
                udp.meta.src_ip,
                53,
                udp.src_port,
                &response,
            )?;
            tap.write_all(&frame)
                .context("failed to write synthetic offline DNS response to tap")?;
            capture_frame(
                capture,
                &frame,
                "failed to capture a synthetic rootless offline DNS response frame",
            );
            log_dns_answer(
                flow_log,
                SocketAddr::new(udp.meta.dst_ip, 53),
                dns_qname.as_deref(),
                dns_qtype,
                DnsAnswerMode::SyntheticEmpty,
                response.len(),
                &[],
            )?;
            return Ok(());
        }

        let Some(upstream_ip) = dns_upstream else {
            util::warn(
                "rootless-internal DNS relay received a query, but no upstream resolver is configured",
            );
            return Ok(());
        };

        let server = SocketAddr::new(upstream_ip, 53);
        log_dns_query(flow_log, server, dns_qname.as_deref(), dns_qtype)?;
        let response = relay_dns_udp(upstream_ip, &udp.payload)?;
        let resolved_ips = dns_answer_ips(&response);
        if let Some(qname) = dns_qname.as_deref() {
            resolved_domains.note_resolution(qname, &resolved_ips);
        }
        let frame = packet::build_udp_frame(
            addr_plan.gateway_mac,
            udp.meta.src_mac,
            udp.meta.dst_ip,
            udp.meta.src_ip,
            53,
            udp.src_port,
            &response,
        )?;
        tap.write_all(&frame)
            .context("failed to write DNS UDP response to tap")?;
        capture_frame(
            capture,
            &frame,
            "failed to capture a rootless DNS UDP response frame",
        );
        log_dns_answer(
            flow_log,
            server,
            dns_qname.as_deref(),
            dns_qtype,
            DnsAnswerMode::Relayed,
            response.len(),
            &resolved_ips,
        )?;
        return Ok(());
    }

    if let Some(reason) = sandbox_policy.block_reason_for_remote_ip_with_domains(
        udp.meta.dst_ip,
        resolved_domains.domains_for_ip(udp.meta.dst_ip),
    ) {
        note_policy_violation(
            flow_log,
            leak_detected,
            &sandbox_policy,
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

    spawn_udp_worker(
        event_tx.clone(),
        UdpRelayRequest {
            gateway_mac: addr_plan.gateway_mac,
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

fn log_connect_attempt(
    flow_log: &mut Option<FlowLogger>,
    remote_addr: SocketAddr,
    via_proxy: bool,
) -> Result<()> {
    if let Some(logger) = flow_log.as_mut() {
        logger.log_connect_attempt(remote_addr, via_proxy)?;
    }
    Ok(())
}

fn log_connect_result(
    flow_log: &mut Option<FlowLogger>,
    remote_addr: SocketAddr,
    via_proxy: bool,
    status: ConnectResultStatus,
    error: Option<&str>,
) -> Result<()> {
    if let Some(logger) = flow_log.as_mut() {
        logger.log_connect_result(remote_addr, via_proxy, status, error)?;
    }
    Ok(())
}

fn log_dns_query(
    flow_log: &mut Option<FlowLogger>,
    server: SocketAddr,
    qname: Option<&str>,
    qtype: Option<&'static str>,
) -> Result<()> {
    if let Some(logger) = flow_log.as_mut() {
        logger.log_dns_query(server, qname, qtype)?;
    }
    Ok(())
}

fn log_dns_answer(
    flow_log: &mut Option<FlowLogger>,
    server: SocketAddr,
    qname: Option<&str>,
    qtype: Option<&'static str>,
    mode: DnsAnswerMode,
    bytes: usize,
    answer_ips: &[IpAddr],
) -> Result<()> {
    if let Some(logger) = flow_log.as_mut() {
        logger.log_dns_answer(server, qname, qtype, mode, bytes, answer_ips)?;
    }
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

fn deny_tcp_connect(
    tap: &mut TapHandle,
    addr_plan: &AddressPlan,
    capture: &mut Option<CaptureWriters>,
    tcp: &ParsedTcpPacket,
    reason: BlockReason,
) -> Result<()> {
    util::debug(format!(
        "rootless-internal denied TCP connect to {}:{} ({})",
        tcp.meta.dst_ip,
        tcp.dst_port,
        reason.describe()
    ));
    let rst = packet::build_tcp_frame(TcpReply {
        src_mac: addr_plan.gateway_mac,
        dst_mac: tcp.meta.src_mac,
        src_ip: tcp.meta.dst_ip,
        dst_ip: tcp.meta.src_ip,
        src_port: tcp.dst_port,
        dst_port: tcp.src_port,
        seq: 0,
        ack: tcp.sequence_number.wrapping_add(1),
        syn: false,
        ack_flag: true,
        fin: false,
        rst: true,
        psh: false,
        payload: &[],
    })?;
    tap.write_all(&rst)
        .context("failed to write TCP RST after sandbox policy denial")?;
    capture_frame(
        capture,
        &rst,
        "failed to capture a rootless TCP RST frame after sandbox policy denial",
    );
    Ok(())
}

fn drain_remote_events(
    tap: &mut TapHandle,
    addr_plan: &AddressPlan,
    child_mac: &mut Option<[u8; 6]>,
    event_rx: &Receiver<RemoteEvent>,
    connections: &mut HashMap<FlowKey, ConnectionState>,
    capture: &mut Option<CaptureWriters>,
    flow_log: &mut Option<FlowLogger>,
) -> Result<()> {
    loop {
        match event_rx.try_recv() {
            Ok(RemoteEvent::Frame(frame)) => {
                tap.write_all(&frame)
                    .context("failed to write a rootless remote frame into tap")?;
                capture_frame(
                    capture,
                    &frame,
                    "failed to capture a rootless remote->child frame",
                );
            }
            Ok(RemoteEvent::TcpData { key, payload }) => {
                let Some(mac) = *child_mac else {
                    continue;
                };
                let Some(connection) = connections.get_mut(&key) else {
                    continue;
                };
                let seq = connection.session.reserve_engine_payload_seq(payload.len());
                let frame = packet::build_tcp_frame(TcpReply {
                    src_mac: addr_plan.gateway_mac,
                    dst_mac: mac,
                    src_ip: key.remote_ip,
                    dst_ip: key.child_ip,
                    src_port: key.remote_port,
                    dst_port: key.child_port,
                    seq,
                    ack: connection.session.child_next_seq,
                    syn: false,
                    ack_flag: true,
                    fin: false,
                    rst: false,
                    psh: true,
                    payload: &payload,
                })?;
                tap.write_all(&frame)
                    .context("failed to write remote TCP payload into tap")?;
                capture_frame(
                    capture,
                    &frame,
                    "failed to capture a rootless remote->child TCP payload frame",
                );
            }
            Ok(RemoteEvent::TcpClosed { key }) => {
                let Some(mac) = *child_mac else {
                    connections.remove(&key);
                    continue;
                };
                if let Some(connection) = connections.get_mut(&key) {
                    log_flow_end_once(connection, flow_log, &key)?;
                    let seq = connection.session.reserve_engine_fin_seq();
                    let frame = packet::build_tcp_frame(TcpReply {
                        src_mac: addr_plan.gateway_mac,
                        dst_mac: mac,
                        src_ip: key.remote_ip,
                        dst_ip: key.child_ip,
                        src_port: key.remote_port,
                        dst_port: key.child_port,
                        seq,
                        ack: connection.session.child_next_seq,
                        syn: false,
                        ack_flag: true,
                        fin: true,
                        rst: false,
                        psh: false,
                        payload: &[],
                    })?;
                    tap.write_all(&frame)
                        .context("failed to write remote TCP FIN into tap")?;
                    capture_frame(
                        capture,
                        &frame,
                        "failed to capture a rootless remote->child TCP FIN frame",
                    );
                }
            }
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => break,
        }
    }

    Ok(())
}

fn flush_remaining_flow_end_events(
    connections: &mut HashMap<FlowKey, ConnectionState>,
    flow_log: &mut Option<FlowLogger>,
) -> Result<()> {
    for (key, connection) in connections.iter_mut() {
        log_flow_end_once(connection, flow_log, key)?;
    }
    Ok(())
}

fn log_flow_end_once(
    connection: &mut ConnectionState,
    flow_log: &mut Option<FlowLogger>,
    key: &FlowKey,
) -> Result<()> {
    if connection.flow_end_logged {
        return Ok(());
    }
    if let Some(logger) = flow_log.as_mut() {
        logger.log_flow_end("tcp", key.remote_addr())?;
    }
    connection.flow_end_logged = true;
    Ok(())
}

fn capture_frame(capture: &mut Option<CaptureWriters>, frame: &[u8], message: &str) {
    let Some(writer) = capture.as_mut() else {
        return;
    };

    if let Err(err) = writer.write(frame) {
        util::warn(format!(
            "{message}: {err:#}. Disabling rootless capture for the rest of this run"
        ));
        *capture = None;
    }
}

fn spawn_udp_worker(event_tx: Sender<RemoteEvent>, request: UdpRelayRequest) {
    thread::spawn(move || {
        let remote_addr = SocketAddr::new(request.remote_ip, request.remote_port);
        let child_probe = packet::build_udp_ip_packet(
            request.child_ip,
            request.remote_ip,
            request.child_port,
            request.remote_port,
            request.hop_limit,
            &request.payload,
        )
        .with_context(|| {
            format!(
                "failed to preserve the child UDP probe for ICMP synthesis toward {remote_addr}"
            )
        });

        let result = relay_udp_payload(remote_addr, request.hop_limit, &request.payload).and_then(
            |outcome| match outcome {
                UdpRelayOutcome::Payload(reply) => packet::build_udp_frame(
                    request.gateway_mac,
                    request.child_mac,
                    request.remote_ip,
                    request.child_ip,
                    request.remote_port,
                    request.child_port,
                    &reply,
                ),
                UdpRelayOutcome::IcmpError {
                    source_ip,
                    icmp_type,
                    code,
                } => {
                    let probe = match &child_probe {
                        Ok(probe) => probe.as_slice(),
                        Err(err) => {
                            return Err(anyhow::anyhow!(
                                "failed to preserve the child UDP probe for ICMP synthesis toward {remote_addr}: {err:#}"
                            ))
                        }
                    };
                    match (source_ip, request.child_ip) {
                        (IpAddr::V4(src_ip), IpAddr::V4(child_ip)) => {
                            packet::build_icmpv4_error_frame(Icmpv4ErrorFrame {
                                src_mac: request.gateway_mac,
                                dst_mac: request.child_mac,
                                src_ip,
                                dst_ip: child_ip,
                                icmp_type,
                                code,
                                quote: probe,
                            })
                        }
                        (IpAddr::V6(src_ip), IpAddr::V6(child_ip)) => {
                            packet::build_icmpv6_error_frame(Icmpv6ErrorFrame {
                                src_mac: request.gateway_mac,
                                dst_mac: request.child_mac,
                                src_ip,
                                dst_ip: child_ip,
                                icmp_type,
                                code,
                                quote: probe,
                            })
                        }
                        _ => anyhow::bail!(
                            "ICMP error family did not match the child probe family for {remote_addr}"
                        ),
                    }
                }
            },
        );

        match result {
            Ok(frame) => {
                let _ = event_tx.send(RemoteEvent::Frame(frame));
            }
            Err(err) => {
                util::debug(format!(
                    "rootless-internal could not complete an outbound UDP exchange for {remote_addr}: {err:#}"
                ));
            }
        }
    });
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
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let flags = OFlag::from_bits_truncate(
        fcntl(fd, FcntlArg::F_GETFL).context("failed to read tap fd flags")?,
    );
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .context("failed to set tap fd nonblocking")?;
    Ok(())
}
