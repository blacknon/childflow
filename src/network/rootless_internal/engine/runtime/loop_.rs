use std::collections::HashMap;
use std::io::{ErrorKind, Read};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::util;

use super::super::events;
use super::super::tcp;
use super::super::udp;
use super::super::{
    handle_icmpv4_packet, handle_icmpv6_packet, packet, AddressPlan, ConnectionState, EngineConfig,
    ParsedPacket, ResolvedDomainIndex, TapHandle, TcpPacketContext, UdpPacketContext,
};

pub(super) fn run_engine(
    mut tap: TapHandle,
    addr_plan: AddressPlan,
    mut config: EngineConfig,
    stop: Arc<std::sync::atomic::AtomicBool>,
    leak_detected: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    let (event_tx, event_rx) = mpsc::channel();
    let mut child_mac = None;
    let mut connections: HashMap<_, ConnectionState> = HashMap::new();
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
            Ok(n) => handle_engine_frame(
                FrameDispatchContext {
                    tap: &mut tap,
                    addr_plan: &addr_plan,
                    config: &mut config,
                    event_tx: &event_tx,
                    leak_detected: &leak_detected,
                    child_mac: &mut child_mac,
                    connections: &mut connections,
                    resolved_domains: &mut resolved_domains,
                },
                &buf[..n],
            )?,
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

struct FrameDispatchContext<'a> {
    tap: &'a mut TapHandle,
    addr_plan: &'a AddressPlan,
    config: &'a mut EngineConfig,
    event_tx: &'a std::sync::mpsc::Sender<super::super::RemoteEvent>,
    leak_detected: &'a Arc<std::sync::atomic::AtomicBool>,
    child_mac: &'a mut Option<[u8; 6]>,
    connections:
        &'a mut HashMap<crate::network::rootless_internal::state::FlowKey, ConnectionState>,
    resolved_domains: &'a mut ResolvedDomainIndex,
}

fn handle_engine_frame(ctx: FrameDispatchContext<'_>, frame: &[u8]) -> Result<()> {
    let FrameDispatchContext {
        tap,
        addr_plan,
        config,
        event_tx,
        leak_detected,
        child_mac,
        connections,
        resolved_domains,
    } = ctx;

    events::capture_frame(
        &mut config.capture,
        frame,
        "failed to capture a child->engine frame from the rootless tap",
    );

    match packet::parse_frame(frame) {
        Ok(ParsedPacket::Tcp(tcp_packet)) => {
            child_mac.get_or_insert(tcp_packet.meta.src_mac);
            tcp::handle_tcp_packet(
                TcpPacketContext {
                    tap,
                    addr_plan,
                    event_tx,
                    connections,
                    sandbox_policy: &config.sandbox_policy,
                    proxy_upstream: config.proxy_upstream.as_ref(),
                    capture: &mut config.capture,
                    flow_log: &mut config.flow_log,
                    leak_detected,
                    resolved_domains,
                },
                &tcp_packet,
            )?;
        }
        Ok(ParsedPacket::Udp(udp_packet)) => {
            child_mac.get_or_insert(udp_packet.meta.src_mac);
            udp::handle_udp_packet(
                UdpPacketContext {
                    tap,
                    addr_plan,
                    dns_upstream: config.dns_upstream,
                    allow_ipv6_outbound: config.allow_ipv6_outbound,
                    sandbox_policy: &config.sandbox_policy,
                    capture: &mut config.capture,
                    event_tx,
                    flow_log: &mut config.flow_log,
                    leak_detected,
                    resolved_domains,
                },
                &udp_packet,
            )?;
        }
        Ok(ParsedPacket::Icmpv4(icmp_packet)) => {
            child_mac.get_or_insert(icmp_packet.meta.src_mac);
            handle_icmpv4_packet(
                event_tx,
                addr_plan,
                &config.sandbox_policy,
                &mut config.flow_log,
                leak_detected,
                resolved_domains,
                &icmp_packet,
            )?;
        }
        Ok(ParsedPacket::Icmpv6(icmp_packet)) => {
            child_mac.get_or_insert(icmp_packet.meta.src_mac);
            handle_icmpv6_packet(
                event_tx,
                addr_plan,
                &config.sandbox_policy,
                &mut config.flow_log,
                leak_detected,
                resolved_domains,
                &icmp_packet,
            )?;
        }
        Ok(ParsedPacket::Unsupported) => {}
        Err(err) => util::debug(format!(
            "rootless-internal engine ignored an unsupported frame: {err:#}"
        )),
    }

    Ok(())
}
