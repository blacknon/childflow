use std::io::Write;

use anyhow::{Context, Result};

use crate::capture::CaptureWriters;
use crate::sandbox::BlockReason;

use super::super::addr::AddressPlan;
use super::super::packet::{self, ParsedTcpPacket, TcpReply};
use super::super::tap::TapHandle;
use super::{FlowKey, TcpPacketContext};

mod established;
mod handshake;

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
        return handshake::handle_tcp_syn(
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
            key,
            tcp,
        );
    }

    established::handle_established_tcp_packet(tap, addr_plan, connections, capture, key, tcp)
}

fn deny_tcp_connect(
    tap: &mut TapHandle,
    addr_plan: &AddressPlan,
    capture: &mut Option<CaptureWriters>,
    tcp: &ParsedTcpPacket,
    reason: BlockReason,
) -> Result<()> {
    crate::util::debug(format!(
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
    super::events::capture_frame(
        capture,
        &rst,
        "failed to capture a rootless TCP RST frame after sandbox policy denial",
    );
    Ok(())
}
