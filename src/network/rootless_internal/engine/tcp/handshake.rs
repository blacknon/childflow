use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::capture::CaptureWriters;
use crate::flow_log::{ConnectResultStatus, FlowLogger};
use crate::proxy::rootless_relay::ProxyUpstreamConfig;
use crate::sandbox::SandboxPolicy;
use crate::util;

use super::super::super::packet::{self, ParsedTcpPacket, TcpReply};
use super::super::super::state::TcpSession;
use super::super::super::transport::connect_remote;
use super::super::super::{addr::AddressPlan, state::FlowKey, tap::TapHandle};
use super::super::events::{capture_frame, note_connect_attempt, note_connect_result};
use super::super::{
    note_policy_violation, ConnectionState, PolicyViolationTarget, RemoteEvent, ResolvedDomainIndex,
};

pub(super) fn handle_tcp_syn(
    tap: &mut TapHandle,
    addr_plan: &AddressPlan,
    event_tx: &Sender<RemoteEvent>,
    connections: &mut HashMap<FlowKey, ConnectionState>,
    sandbox_policy: &SandboxPolicy,
    proxy_upstream: Option<&ProxyUpstreamConfig>,
    capture: &mut Option<CaptureWriters>,
    flow_log: &mut Option<FlowLogger>,
    leak_detected: &Arc<AtomicBool>,
    resolved_domains: &ResolvedDomainIndex,
    key: FlowKey,
    tcp: &ParsedTcpPacket,
) -> Result<()> {
    if let Some(reason) = sandbox_policy.block_reason_for_tcp_remote_ip_with_domains(
        key.remote_ip,
        proxy_upstream.is_some(),
        resolved_domains.domains_for_ip(key.remote_ip),
    ) {
        note_policy_violation(
            flow_log,
            leak_detected,
            sandbox_policy,
            PolicyViolationTarget {
                protocol: "tcp",
                remote: &format!("{}:{}", key.remote_ip, key.remote_port),
                remote_ip: Some(key.remote_ip),
                remote_port: Some(key.remote_port),
            },
            &reason,
        );
        return super::deny_tcp_connect(tap, addr_plan, capture, tcp, reason);
    }

    let command_tx = open_remote_connection(
        event_tx,
        flow_log,
        proxy_upstream,
        key.clone(),
        tcp.remote_addr(),
        tap,
        addr_plan,
        capture,
        tcp,
    )?;
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
    Ok(())
}

fn open_remote_connection(
    event_tx: &Sender<RemoteEvent>,
    flow_log: &mut Option<FlowLogger>,
    proxy_upstream: Option<&ProxyUpstreamConfig>,
    key: FlowKey,
    remote_addr: std::net::SocketAddr,
    tap: &mut TapHandle,
    addr_plan: &AddressPlan,
    capture: &mut Option<CaptureWriters>,
    tcp: &ParsedTcpPacket,
) -> Result<Sender<super::super::ConnectionCommand>> {
    note_connect_attempt(flow_log, remote_addr, proxy_upstream.is_some())?;
    match connect_remote(remote_addr, proxy_upstream, event_tx.clone(), key) {
        Ok(command_tx) => {
            note_connect_result(
                flow_log,
                remote_addr,
                proxy_upstream.is_some(),
                ConnectResultStatus::Ok,
                None,
            )?;
            Ok(command_tx)
        }
        Err(err) => {
            note_connect_result(
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
            Err(err)
        }
    }
}

trait ParsedTcpPacketExt {
    fn remote_addr(&self) -> std::net::SocketAddr;
}

impl ParsedTcpPacketExt for ParsedTcpPacket {
    fn remote_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.meta.dst_ip, self.dst_port)
    }
}
