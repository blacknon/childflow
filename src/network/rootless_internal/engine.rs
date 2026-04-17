use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{BorrowedFd, RawFd};
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
use super::packet::{self, ParsedPacket, ParsedTcpPacket, ParsedUdpPacket, TcpReply};
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
}

struct ConnectionState {
    session: TcpSession,
    command_tx: Sender<ConnectionCommand>,
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
    let mut warned_udp = false;
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
                            &udp,
                            &mut warned_udp,
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
    udp: &ParsedUdpPacket,
    warned_udp: &mut bool,
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

    if !*warned_udp {
        util::warn(
            "non-DNS UDP is not yet supported by the current `rootless-internal` backend; the engine will ignore those packets",
        );
        *warned_udp = true;
    }

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
    let bind_addr = match upstream_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)
        .context("failed to bind UDP socket for rootless-internal DNS relay")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to set DNS relay UDP timeout")?;
    socket
        .connect(upstream_addr)
        .with_context(|| format!("failed to connect rootless DNS relay to {upstream_addr}"))?;
    socket
        .send(payload)
        .with_context(|| format!("failed to send rootless DNS query to {upstream_addr}"))?;
    let mut buf = [0_u8; 4096];
    let n = socket
        .recv(&mut buf)
        .with_context(|| format!("failed to receive rootless DNS response from {upstream_addr}"))?;
    Ok(buf[..n].to_vec())
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
