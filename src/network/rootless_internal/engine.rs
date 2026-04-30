// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::collections::HashMap;
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
use crate::proxy::rootless_relay::ProxyUpstreamConfig;
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
    connect_remote, dns_query_type, relay_dns_udp, relay_udp_payload,
    synthesize_empty_dns_response, UdpRelayOutcome, DNS_TYPE_AAAA,
};

pub struct EngineConfig {
    pub dns_upstream: Option<IpAddr>,
    pub allow_ipv6_outbound: bool,
    pub proxy_upstream: Option<ProxyUpstreamConfig>,
    pub capture: Option<CaptureWriters>,
}

pub struct EngineHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<()>>>,
}

impl EngineHandle {
    pub fn start(tap: TapHandle, addr_plan: AddressPlan, config: EngineConfig) -> Result<Self> {
        set_nonblocking(tap.raw_fd())?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let join = thread::spawn(move || run_engine(tap, addr_plan, config, stop_for_thread));

        Ok(Self {
            stop,
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

pub(super) enum ConnectionCommand {
    Write(Vec<u8>),
    ShutdownWrite,
}

fn run_engine(
    mut tap: TapHandle,
    addr_plan: AddressPlan,
    mut config: EngineConfig,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let (event_tx, event_rx) = mpsc::channel();
    let mut child_mac = None;
    let mut connections: HashMap<FlowKey, ConnectionState> = HashMap::new();
    let mut buf = [0_u8; 65535];

    while !stop.load(Ordering::Relaxed) {
        drain_remote_events(
            &mut tap,
            &addr_plan,
            &mut child_mac,
            &event_rx,
            &mut connections,
            &mut config.capture,
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
                            &mut tap,
                            &addr_plan,
                            &event_tx,
                            &mut connections,
                            config.proxy_upstream.as_ref(),
                            &mut config.capture,
                            &tcp,
                        )?;
                    }
                    Ok(ParsedPacket::Udp(udp)) => {
                        child_mac.get_or_insert(udp.meta.src_mac);
                        handle_udp_packet(
                            &mut tap,
                            &addr_plan,
                            config.dns_upstream,
                            config.allow_ipv6_outbound,
                            &mut config.capture,
                            &event_tx,
                            &udp,
                        )?;
                    }
                    Ok(ParsedPacket::Icmpv4(icmp)) => {
                        child_mac.get_or_insert(icmp.meta.src_mac);
                        handle_icmpv4_packet(&event_tx, &addr_plan, &icmp)?;
                    }
                    Ok(ParsedPacket::Icmpv6(icmp)) => {
                        child_mac.get_or_insert(icmp.meta.src_mac);
                        handle_icmpv6_packet(&event_tx, &addr_plan, &icmp)?;
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

    Ok(())
}

fn handle_tcp_packet(
    tap: &mut TapHandle,
    addr_plan: &AddressPlan,
    event_tx: &Sender<RemoteEvent>,
    connections: &mut HashMap<FlowKey, ConnectionState>,
    proxy_upstream: Option<&ProxyUpstreamConfig>,
    capture: &mut Option<CaptureWriters>,
    tcp: &ParsedTcpPacket,
) -> Result<()> {
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
        let remote_addr = key.remote_addr();
        let command_tx = match connect_remote(
            remote_addr,
            proxy_upstream,
            event_tx.clone(),
            key.clone(),
        ) {
            Ok(command_tx) => command_tx,
            Err(err) => {
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

fn handle_udp_packet(
    tap: &mut TapHandle,
    addr_plan: &AddressPlan,
    dns_upstream: Option<IpAddr>,
    allow_ipv6_outbound: bool,
    capture: &mut Option<CaptureWriters>,
    event_tx: &Sender<RemoteEvent>,
    udp: &ParsedUdpPacket,
) -> Result<()> {
    if udp.dst_port == 53
        && (udp.meta.dst_ip == IpAddr::V4(addr_plan.gateway_ipv4)
            || udp.meta.dst_ip == IpAddr::V6(addr_plan.gateway_ipv6))
    {
        if !allow_ipv6_outbound && dns_query_type(&udp.payload) == Some(DNS_TYPE_AAAA) {
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
            return Ok(());
        }

        let Some(upstream_ip) = dns_upstream else {
            util::warn(
                "rootless-internal DNS relay received a query, but no upstream resolver is configured",
            );
            return Ok(());
        };

        let response = relay_dns_udp(upstream_ip, &udp.payload)?;
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

fn drain_remote_events(
    tap: &mut TapHandle,
    addr_plan: &AddressPlan,
    child_mac: &mut Option<[u8; 6]>,
    event_rx: &Receiver<RemoteEvent>,
    connections: &mut HashMap<FlowKey, ConnectionState>,
    capture: &mut Option<CaptureWriters>,
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
