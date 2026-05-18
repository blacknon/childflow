use std::io::Write;

use anyhow::{Context, Result};

use crate::capture::CaptureWriters;
use crate::flow_log::ConnectResultStatus;
use crate::util;

use super::super::packet::{self, ParsedTcpPacket, TcpReply};
use super::super::transport::connect_remote;
use super::events::{capture_frame, note_connect_attempt, note_connect_result};
use super::{
    note_policy_violation, ConnectionCommand, ConnectionState, FlowKey, PolicyViolationTarget,
    TcpPacketContext,
};

pub(super) fn handle_tcp_packet(ctx: TcpPacketContext<'_>, tcp: &ParsedTcpPacket) -> Result<()> {
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
                sandbox_policy,
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
        note_connect_attempt(flow_log, remote_addr, proxy_upstream.is_some())?;
        let command_tx = match connect_remote(
            remote_addr,
            proxy_upstream,
            event_tx.clone(),
            key.clone(),
        ) {
            Ok(command_tx) => {
                note_connect_result(
                    flow_log,
                    remote_addr,
                    proxy_upstream.is_some(),
                    ConnectResultStatus::Ok,
                    None,
                )?;
                command_tx
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
                return Ok(());
            }
        };
        let engine_isn = util::run_entropy();
        let session = super::super::state::TcpSession::new(tcp.sequence_number, engine_isn);
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

fn deny_tcp_connect(
    tap: &mut super::super::tap::TapHandle,
    addr_plan: &super::super::addr::AddressPlan,
    capture: &mut Option<CaptureWriters>,
    tcp: &ParsedTcpPacket,
    reason: crate::sandbox::BlockReason,
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
