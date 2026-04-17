use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::fcntl::{fcntl, FcntlArg, OFlag};

use crate::capture::FrameCaptureWriter;
use crate::proxy::rootless_relay::{self, OutboundStream, ProxyUpstreamConfig};
use crate::util;

use super::addr::AddressPlan;
use super::packet::{
    self, Icmpv4EchoFrame, Icmpv4ErrorFrame, Icmpv6EchoFrame, Icmpv6ErrorFrame, ParsedIcmpv4Packet,
    ParsedIcmpv6Packet, ParsedPacket, ParsedTcpPacket, ParsedUdpPacket, TcpReply,
};
use super::state::{FlowKey, TcpSession};
use super::tap::TapHandle;

pub struct EngineConfig {
    pub dns_upstream: Option<IpAddr>,
    pub allow_ipv6_outbound: bool,
    pub proxy_upstream: Option<ProxyUpstreamConfig>,
    pub capture: Option<FrameCaptureWriter>,
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

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    util::warn(format!(
                        "rootless-internal engine stopped with an error: {err:#}"
                    ));
                }
                Err(_) => util::warn("rootless-internal engine thread panicked"),
            }
        }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

#[derive(Debug)]
enum RemoteEvent {
    TcpData { key: FlowKey, payload: Vec<u8> },
    TcpClosed { key: FlowKey },
    Frame(Vec<u8>),
}

struct ConnectionState {
    session: TcpSession,
    command_tx: Sender<ConnectionCommand>,
}

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

#[derive(Debug, Eq, PartialEq)]
enum UdpRelayOutcome {
    Payload(Vec<u8>),
    IcmpError {
        source_ip: IpAddr,
        icmp_type: u8,
        code: u8,
    },
}

enum IcmpRelayOutcome {
    EchoReply(Vec<u8>),
    Error {
        source_ip: IpAddr,
        icmp_type: u8,
        code: u8,
    },
}

enum ConnectionCommand {
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
    let mut warned_icmp = false;
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
                        handle_icmpv4_packet(&event_tx, &addr_plan, &icmp, &mut warned_icmp)?;
                    }
                    Ok(ParsedPacket::Icmpv6(icmp)) => {
                        child_mac.get_or_insert(icmp.meta.src_mac);
                        handle_icmpv6_packet(&event_tx, &addr_plan, &icmp, &mut warned_icmp)?;
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
    capture: &mut Option<FrameCaptureWriter>,
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
    capture: &mut Option<FrameCaptureWriter>,
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
    capture: &mut Option<FrameCaptureWriter>,
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

fn handle_icmpv4_packet(
    event_tx: &Sender<RemoteEvent>,
    addr_plan: &AddressPlan,
    icmp: &ParsedIcmpv4Packet,
    warned_icmp: &mut bool,
) -> Result<()> {
    let (src_ip, dst_ip) = match (icmp.meta.src_ip, icmp.meta.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
        _ => return Ok(()),
    };

    let is_gateway_target = dst_ip == addr_plan.gateway_ipv4;
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

    if !*warned_icmp {
        util::warn(
            "ICMP is only partially supported by the current `rootless-internal` backend; echo requests from the child are relayed, but other outbound ICMPv4 message types are not yet handled",
        );
        *warned_icmp = true;
    }

    Ok(())
}

fn handle_icmpv6_packet(
    event_tx: &Sender<RemoteEvent>,
    addr_plan: &AddressPlan,
    icmp: &ParsedIcmpv6Packet,
    warned_icmp: &mut bool,
) -> Result<()> {
    let (src_ip, dst_ip) = match (icmp.meta.src_ip, icmp.meta.dst_ip) {
        (IpAddr::V6(src), IpAddr::V6(dst)) => (src, dst),
        _ => return Ok(()),
    };

    let is_gateway_target = dst_ip == addr_plan.gateway_ipv6;
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

    if !*warned_icmp {
        util::warn(
            "ICMP is only partially supported by the current `rootless-internal` backend; echo requests from the child are relayed, but other outbound ICMPv6 message types are not yet handled",
        );
        *warned_icmp = true;
    }

    Ok(())
}

fn capture_frame(capture: &mut Option<FrameCaptureWriter>, frame: &[u8], message: &str) {
    let Some(writer) = capture.as_mut() else {
        return;
    };

    if let Err(err) = writer.write_frame(frame) {
        util::warn(format!(
            "{message}: {err:#}. Disabling rootless capture for the rest of this run"
        ));
        *capture = None;
    }
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

        let result = relay_icmpv4_echo(request.remote_ip, request.hop_limit, &request.payload)
            .and_then(|outcome| match outcome {
                IcmpRelayOutcome::EchoReply(reply) => packet::build_icmpv4_echo_frame(Icmpv4EchoFrame {
                    src_mac: request.gateway_mac,
                    dst_mac: request.child_mac,
                    src_ip: request.remote_ip,
                    dst_ip: request.child_ip,
                    icmp_type: 0,
                    code: 0,
                    identifier: request.identifier,
                    sequence: request.sequence,
                    payload: if reply.is_empty() {
                        request.payload.as_slice()
                    } else {
                        reply.as_slice()
                    },
                }),
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

        let result = relay_icmpv6_echo(request.remote_ip, request.hop_limit, &request.payload)
            .and_then(|outcome| match outcome {
                IcmpRelayOutcome::EchoReply(reply) => packet::build_icmpv6_echo_frame(Icmpv6EchoFrame {
                    src_mac: request.gateway_mac,
                    dst_mac: request.child_mac,
                    src_ip: request.remote_ip,
                    dst_ip: request.child_ip,
                    icmp_type: 129,
                    code: 0,
                    identifier: request.identifier,
                    sequence: request.sequence,
                    payload: if reply.is_empty() {
                        request.payload.as_slice()
                    } else {
                        reply.as_slice()
                    },
                }),
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

fn relay_icmpv4_echo(
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    payload: &[u8],
) -> Result<IcmpRelayOutcome> {
    let output = run_ping_helper(remote_ip.to_string(), hop_limit, payload.len(), false)
        .with_context(|| {
            format!("failed to execute `ping` while relaying an ICMPv4 echo request to {remote_ip}")
        })?;
    parse_ping_helper_output(IpAddr::V4(remote_ip), false, &output)
}

fn relay_icmpv6_echo(
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    payload: &[u8],
) -> Result<IcmpRelayOutcome> {
    let output = run_ping_helper(remote_ip.to_string(), hop_limit, payload.len(), true)
        .with_context(|| {
            format!(
                "failed to execute `ping -6` while relaying an ICMPv6 echo request to {remote_ip}"
            )
        })?;
    parse_ping_helper_output(IpAddr::V6(remote_ip), true, &output)
}

fn run_ping_helper(
    remote_ip: String,
    hop_limit: u8,
    payload_len: usize,
    ipv6: bool,
) -> Result<std::process::Output> {
    let payload_len = payload_len.to_string();
    let hop_limit = hop_limit.to_string();
    let mut command = Command::new("ping");
    if ipv6 {
        command.arg("-6");
    }
    command.args([
        "-n",
        "-c",
        "1",
        "-W",
        "3",
        "-t",
        hop_limit.as_str(),
        "-s",
        payload_len.as_str(),
        remote_ip.as_str(),
    ]);
    command.output().context("failed to run the ping helper")
}

fn parse_ping_helper_output(
    remote_ip: IpAddr,
    ipv6: bool,
    output: &std::process::Output,
) -> Result<IcmpRelayOutcome> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if contains_ping_success(&stdout, &remote_ip) || contains_ping_success(&stderr, &remote_ip) {
        return Ok(IcmpRelayOutcome::EchoReply(Vec::new()));
    }

    if let Some(outcome) = parse_ping_error_lines(&stdout, ipv6)? {
        return Ok(outcome);
    }
    if let Some(outcome) = parse_ping_error_lines(&stderr, ipv6)? {
        return Ok(outcome);
    }

    anyhow::bail!(
        "the helper `ping` command could not reach {remote_ip} (status: {}). stdout: {} stderr: {}",
        output.status,
        stdout.trim(),
        stderr.trim(),
    )
}

fn contains_ping_success(output: &str, remote_ip: &IpAddr) -> bool {
    let remote = remote_ip.to_string();
    output.lines().any(|line| {
        line.contains("bytes from") && (line.contains(&remote) || line.contains("icmp_seq="))
    })
}

fn parse_ping_error_lines(output: &str, ipv6: bool) -> Result<Option<IcmpRelayOutcome>> {
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("From ") else {
            continue;
        };
        let source = rest
            .split_whitespace()
            .next()
            .map(|token| token.trim_end_matches(':'))
            .context("failed to parse the ICMP error source reported by ping")?;
        let source_ip: IpAddr = source
            .parse()
            .with_context(|| format!("failed to parse the ICMP error source IP `{source}`"))?;

        if line.contains("Time to live exceeded")
            || line.contains("Time exceeded")
            || line.contains("Hop limit exceeded")
        {
            return Ok(Some(IcmpRelayOutcome::Error {
                source_ip,
                icmp_type: if ipv6 { 3 } else { 11 },
                code: 0,
            }));
        }

        if line.contains("Destination")
            || line.contains("unreachable")
            || line.contains("Unreachable")
        {
            return Ok(Some(IcmpRelayOutcome::Error {
                source_ip,
                icmp_type: if ipv6 { 1 } else { 3 },
                code: parse_unreachable_code(line, ipv6),
            }));
        }
    }

    Ok(None)
}

fn parse_unreachable_code(line: &str, ipv6: bool) -> u8 {
    let line = line.to_ascii_lowercase();
    if ipv6 {
        if line.contains("no route") {
            0
        } else if line.contains("prohibited") || line.contains("administratively") {
            1
        } else if line.contains("scope") {
            2
        } else if line.contains("address unreachable") || line.contains("host unreachable") {
            3
        } else if line.contains("port unreachable") {
            4
        } else {
            0
        }
    } else if line.contains("net unreachable") {
        0
    } else if line.contains("host unreachable") {
        1
    } else if line.contains("protocol unreachable") {
        2
    } else if line.contains("port unreachable") {
        3
    } else if line.contains("fragmentation") {
        4
    } else if line.contains("source route failed") {
        5
    } else if line.contains("admin") || line.contains("filtered") || line.contains("prohibited") {
        13
    } else {
        0
    }
}

fn connect_remote(
    remote_addr: SocketAddr,
    proxy_upstream: Option<&ProxyUpstreamConfig>,
    event_tx: Sender<RemoteEvent>,
    key: FlowKey,
) -> Result<Sender<ConnectionCommand>> {
    let stream = if let Some(proxy_upstream) = proxy_upstream {
        rootless_relay::connect_via_proxy(proxy_upstream, remote_addr).with_context(|| {
            format!(
                "failed to connect to remote TCP destination {remote_addr} through the configured rootless upstream proxy"
            )
        })?
    } else {
        let stream = match remote_addr {
            SocketAddr::V4(addr) => {
                TcpStream::connect_timeout(&SocketAddr::V4(addr), Duration::from_secs(5))
            }
            SocketAddr::V6(addr) => {
                TcpStream::connect_timeout(&SocketAddr::V6(addr), Duration::from_secs(5))
            }
        }
        .with_context(|| format!("failed to connect to remote TCP destination {remote_addr}"))?;
        stream
            .set_nodelay(true)
            .context("failed to enable TCP_NODELAY for remote TCP socket")?;
        OutboundStream::Tcp(stream)
    };

    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("failed to configure the rootless outbound stream read timeout")?;

    let (command_tx, command_rx) = mpsc::channel();
    spawn_remote_worker(event_tx, key, stream, command_rx);
    Ok(command_tx)
}

fn spawn_remote_worker(
    event_tx: Sender<RemoteEvent>,
    key: FlowKey,
    mut stream: OutboundStream,
    command_rx: Receiver<ConnectionCommand>,
) {
    thread::spawn(move || {
        let mut buf = [0_u8; 8192];
        let mut write_closed = false;
        loop {
            match command_rx.recv_timeout(Duration::from_millis(10)) {
                Ok(ConnectionCommand::Write(payload)) => {
                    if stream.write_all(&payload).is_err() {
                        let _ = event_tx.send(RemoteEvent::TcpClosed { key: key.clone() });
                        break;
                    }
                }
                Ok(ConnectionCommand::ShutdownWrite) => {
                    write_closed = true;
                    let _ = stream.shutdown_write();
                }
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }

            match stream.read(&mut buf) {
                Ok(0) => {
                    let _ = event_tx.send(RemoteEvent::TcpClosed { key: key.clone() });
                    break;
                }
                Ok(n) => {
                    let _ = event_tx.send(RemoteEvent::TcpData {
                        key: key.clone(),
                        payload: buf[..n].to_vec(),
                    });
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                    ) =>
                {
                    if write_closed {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                Err(_) => {
                    let _ = event_tx.send(RemoteEvent::TcpClosed { key: key.clone() });
                    break;
                }
            }
        }
    });
}

fn relay_dns_udp(upstream_ip: IpAddr, payload: &[u8]) -> Result<Vec<u8>> {
    relay_dns_udp_to(SocketAddr::new(upstream_ip, 53), payload)
}

fn relay_dns_udp_to(upstream_addr: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    match relay_udp_payload(upstream_addr, 64, payload)? {
        UdpRelayOutcome::Payload(response) => Ok(response),
        UdpRelayOutcome::IcmpError {
            source_ip,
            icmp_type,
            code,
        } => anyhow::bail!(
            "received ICMP type {icmp_type} code {code} from {source_ip} while waiting for a DNS UDP response from {upstream_addr}"
        ),
    }
}

fn relay_udp_payload(
    remote_addr: SocketAddr,
    hop_limit: u8,
    payload: &[u8],
) -> Result<UdpRelayOutcome> {
    let bind_addr = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)
        .context("failed to bind UDP socket for the rootless-internal relay")?;
    configure_udp_probe_socket(&socket, remote_addr, hop_limit)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to set rootless UDP relay timeout")?;
    socket
        .connect(remote_addr)
        .with_context(|| format!("failed to connect the rootless UDP relay to {remote_addr}"))?;
    socket
        .send(payload)
        .with_context(|| format!("failed to send rootless UDP payload to {remote_addr}"))?;
    let mut buf = [0_u8; 4096];
    match socket.recv(&mut buf) {
        Ok(n) => Ok(UdpRelayOutcome::Payload(buf[..n].to_vec())),
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::TimedOut
                    | ErrorKind::WouldBlock
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::HostUnreachable
                    | ErrorKind::NetworkUnreachable
            ) =>
        {
            if let Some(error) = recv_udp_error(&socket)? {
                Ok(UdpRelayOutcome::IcmpError {
                    source_ip: error.source_ip,
                    icmp_type: error.icmp_type,
                    code: error.code,
                })
            } else {
                Err(err).with_context(|| {
                    format!("failed to receive a rootless UDP response from {remote_addr}")
                })
            }
        }
        Err(err) => Err(err).with_context(|| {
            format!("failed to receive a rootless UDP response from {remote_addr}")
        }),
    }
}

struct ReceivedUdpError {
    source_ip: IpAddr,
    icmp_type: u8,
    code: u8,
}

fn configure_udp_probe_socket(
    socket: &UdpSocket,
    remote_addr: SocketAddr,
    hop_limit: u8,
) -> Result<()> {
    if hop_limit > 0 {
        match remote_addr {
            SocketAddr::V4(_) => socket
                .set_ttl(u32::from(hop_limit))
                .context("failed to set the IPv4 UDP probe TTL")?,
            SocketAddr::V6(_) => {
                let fd = socket.as_raw_fd();
                let value: std::ffi::c_int = i32::from(hop_limit);
                let rc = unsafe {
                    nix::libc::setsockopt(
                        fd,
                        nix::libc::IPPROTO_IPV6,
                        nix::libc::IPV6_UNICAST_HOPS,
                        &value as *const _ as *const _,
                        size_of::<std::ffi::c_int>() as nix::libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to set the IPv6 UDP probe hop limit");
                }
            }
        }
    }

    let fd = socket.as_raw_fd();
    let enabled: std::ffi::c_int = 1;
    let (level, optname) = match remote_addr {
        SocketAddr::V4(_) => (nix::libc::SOL_IP, nix::libc::IP_RECVERR),
        SocketAddr::V6(_) => (nix::libc::SOL_IPV6, nix::libc::IPV6_RECVERR),
    };
    let rc = unsafe {
        nix::libc::setsockopt(
            fd,
            level,
            optname,
            &enabled as *const _ as *const _,
            size_of::<std::ffi::c_int>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to enable UDP error-queue delivery for rootless traceroute support");
    }

    Ok(())
}

fn recv_udp_error(socket: &UdpSocket) -> Result<Option<ReceivedUdpError>> {
    let fd = socket.as_raw_fd();
    let mut data = [0_u8; 512];
    let mut control = [0_u8; 512];
    let mut name: nix::libc::sockaddr_storage = unsafe { zeroed() };
    let mut iov = nix::libc::iovec {
        iov_base: data.as_mut_ptr() as *mut _,
        iov_len: data.len(),
    };
    let mut msg: nix::libc::msghdr = unsafe { zeroed() };
    msg.msg_name = &mut name as *mut _ as *mut _;
    msg.msg_namelen = size_of::<nix::libc::sockaddr_storage>() as nix::libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut _;
    msg.msg_controllen = control.len();

    let rc = unsafe { nix::libc::recvmsg(fd, &mut msg, nix::libc::MSG_ERRQUEUE) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
            return Ok(None);
        }
        return Err(err).context("failed to read the UDP error queue");
    }

    let mut cmsg = unsafe { nix::libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let level = unsafe { (*cmsg).cmsg_level };
        let ty = unsafe { (*cmsg).cmsg_type };
        if (level == nix::libc::SOL_IP && ty == nix::libc::IP_RECVERR)
            || (level == nix::libc::SOL_IPV6 && ty == nix::libc::IPV6_RECVERR)
        {
            let err_ptr =
                unsafe { nix::libc::CMSG_DATA(cmsg) as *const nix::libc::sock_extended_err };
            let err = unsafe { &*err_ptr };
            let offender_ptr = unsafe {
                (err_ptr as *const u8).add(size_of::<nix::libc::sock_extended_err>())
                    as *const nix::libc::sockaddr
            };
            let source_ip =
                sockaddr_to_ip(offender_ptr).unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            return Ok(Some(ReceivedUdpError {
                source_ip,
                icmp_type: err.ee_type,
                code: err.ee_code,
            }));
        }
        cmsg = unsafe { nix::libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    Ok(None)
}

fn sockaddr_to_ip(sockaddr: *const nix::libc::sockaddr) -> Option<IpAddr> {
    if sockaddr.is_null() {
        return None;
    }

    let family = unsafe { (*sockaddr).sa_family as i32 };
    match family {
        nix::libc::AF_INET => {
            let addr = unsafe { &*(sockaddr as *const nix::libc::sockaddr_in) };
            Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                addr.sin_addr.s_addr,
            ))))
        }
        nix::libc::AF_INET6 => {
            let addr = unsafe { &*(sockaddr as *const nix::libc::sockaddr_in6) };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

const DNS_HEADER_LEN: usize = 12;
const DNS_TYPE_AAAA: u16 = 28;

fn dns_query_type(payload: &[u8]) -> Option<u16> {
    if payload.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount != 1 {
        return None;
    }
    let question_end = dns_question_end(payload)?;
    let qtype_offset = question_end.checked_sub(4)?;
    Some(u16::from_be_bytes([
        payload[qtype_offset],
        payload[qtype_offset + 1],
    ]))
}

fn dns_question_end(payload: &[u8]) -> Option<usize> {
    let mut offset = DNS_HEADER_LEN;
    while offset < payload.len() {
        let label_len = payload[offset] as usize;
        offset += 1;
        if label_len == 0 {
            return offset.checked_add(4).filter(|end| *end <= payload.len());
        }
        offset = offset.checked_add(label_len)?;
    }
    None
}

fn synthesize_empty_dns_response(query: &[u8]) -> Result<Vec<u8>> {
    let question_end = dns_question_end(query).context("failed to parse DNS question")?;
    let mut response = query[..question_end].to_vec();
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let response_flags = (flags | 0x8000 | 0x0080) & !0x0200;
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[6..8].copy_from_slice(&0_u16.to_be_bytes());
    response[8..10].copy_from_slice(&0_u16.to_be_bytes());
    response[10..12].copy_from_slice(&0_u16.to_be_bytes());
    Ok(response)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::mpsc;

    #[test]
    fn relay_dns_udp_forwards_payload_and_response() {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let request = b"query".to_vec();
        let response = b"reply".to_vec();

        let join = thread::spawn({
            let request = request.clone();
            let response = response.clone();
            move || {
                let mut buf = [0_u8; 64];
                let (n, peer) = upstream.recv_from(&mut buf).unwrap();
                assert_eq!(&buf[..n], request.as_slice());
                upstream.send_to(&response, peer).unwrap();
            }
        });

        let actual = relay_dns_udp_to(upstream_addr, &request).unwrap();
        join.join().unwrap();
        assert_eq!(actual, response);
    }

    #[test]
    fn relay_udp_payload_forwards_payload_and_response() {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let request = b"udp-request".to_vec();
        let response = b"udp-response".to_vec();

        let join = thread::spawn({
            let request = request.clone();
            let response = response.clone();
            move || {
                let mut buf = [0_u8; 64];
                let (n, peer) = upstream.recv_from(&mut buf).unwrap();
                assert_eq!(&buf[..n], request.as_slice());
                upstream.send_to(&response, peer).unwrap();
            }
        });

        let actual = relay_udp_payload(upstream_addr, 64, &request).unwrap();
        join.join().unwrap();
        assert_eq!(actual, UdpRelayOutcome::Payload(response));
    }

    #[test]
    fn connect_remote_reaches_tcp_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            let _ = listener.accept().unwrap();
            accepted_tx.send(()).unwrap();
        });

        let (event_tx, _event_rx) = mpsc::channel();
        let key = FlowKey {
            child_ip: IpAddr::V4(Ipv4Addr::new(10, 240, 0, 2)),
            child_port: 40000,
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote_port: addr.port(),
        };
        let command_tx = connect_remote(addr, None, event_tx, key).unwrap();
        accepted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        drop(command_tx);
        join.join().unwrap();
    }

    #[test]
    fn dns_query_type_detects_aaaa_question() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00,
            0x01,
        ];
        assert_eq!(dns_query_type(&query), Some(DNS_TYPE_AAAA));
    }

    #[test]
    fn synthesize_empty_dns_response_preserves_question() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00,
            0x01,
        ];
        let response = synthesize_empty_dns_response(&query).unwrap();
        assert_eq!(&response[..2], &query[..2]);
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(&response[12..], &query[12..]);
        assert_ne!(response[2] & 0x80, 0);
    }
}
