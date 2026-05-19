use std::collections::HashMap;
use std::io::Write;
use std::sync::mpsc::{Receiver, TryRecvError};

use anyhow::{Context, Result};

use crate::capture::CaptureWriters;
use crate::flow_log::{ConnectResultStatus, DnsAnswerMode, FlowLogger};
use crate::util;

use super::super::addr::AddressPlan;
use super::super::packet::{self, TcpReply};
use super::super::state::FlowKey;
use super::super::tap::TapHandle;
use super::{ConnectionState, RemoteEvent};

pub(super) fn note_connect_attempt(
    flow_log: &mut Option<FlowLogger>,
    remote_addr: std::net::SocketAddr,
    via_proxy: bool,
) -> Result<()> {
    if let Some(logger) = flow_log.as_mut() {
        logger.log_connect_attempt(remote_addr, via_proxy)?;
    }
    Ok(())
}

pub(super) fn note_connect_result(
    flow_log: &mut Option<FlowLogger>,
    remote_addr: std::net::SocketAddr,
    via_proxy: bool,
    status: ConnectResultStatus,
    error: Option<&str>,
) -> Result<()> {
    if let Some(logger) = flow_log.as_mut() {
        logger.log_connect_result(remote_addr, via_proxy, status, error)?;
    }
    Ok(())
}

pub(super) fn note_dns_query(
    flow_log: &mut Option<FlowLogger>,
    server: std::net::SocketAddr,
    qname: Option<&str>,
    qtype: Option<&'static str>,
) -> Result<()> {
    if let Some(logger) = flow_log.as_mut() {
        logger.log_dns_query(server, qname, qtype)?;
    }
    Ok(())
}

pub(super) fn note_dns_answer(
    flow_log: &mut Option<FlowLogger>,
    server: std::net::SocketAddr,
    qname: Option<&str>,
    qtype: Option<&'static str>,
    mode: DnsAnswerMode,
    bytes: usize,
    answer_ips: &[std::net::IpAddr],
) -> Result<()> {
    if let Some(logger) = flow_log.as_mut() {
        logger.log_dns_answer(server, qname, qtype, mode, bytes, answer_ips)?;
    }
    Ok(())
}

pub(super) fn drain_remote_events(
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

pub(super) fn flush_remaining_flow_end_events(
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

pub(super) fn capture_frame(capture: &mut Option<CaptureWriters>, frame: &[u8], message: &str) {
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
