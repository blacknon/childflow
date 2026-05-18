use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;
use std::thread;

use anyhow::{Context, Result};

use crate::flow_log::DnsAnswerMode;
use crate::sandbox::BlockReason;
use crate::util;

use super::super::packet::{self, Icmpv4ErrorFrame, Icmpv6ErrorFrame, ParsedUdpPacket};
use super::super::transport::{
    dns_answer_ips, dns_query_name, dns_query_type, relay_dns_udp, relay_udp_payload,
    synthesize_empty_dns_response, UdpRelayOutcome, DNS_TYPE_AAAA,
};
use super::events::{capture_frame, note_dns_answer, note_dns_query};
use super::{note_policy_violation, PolicyViolationTarget, RemoteEvent, UdpPacketContext};

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

pub(super) fn handle_udp_packet(ctx: UdpPacketContext<'_>, udp: &ParsedUdpPacket) -> Result<()> {
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
                note_dns_query(
                    flow_log,
                    SocketAddr::new(udp.meta.dst_ip, 53),
                    dns_qname.as_deref(),
                    dns_qtype,
                )?;
                note_policy_violation(
                    flow_log,
                    leak_detected,
                    sandbox_policy,
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
                note_dns_answer(
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
                sandbox_policy,
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
            note_dns_answer(
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
            note_dns_query(
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
            note_dns_answer(
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
            note_dns_query(
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
            note_dns_answer(
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
        note_dns_query(flow_log, server, dns_qname.as_deref(), dns_qtype)?;
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
        note_dns_answer(
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
            sandbox_policy,
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

fn dns_query_type_name(payload: &[u8]) -> Option<&'static str> {
    match dns_query_type(payload) {
        Some(1) => Some("A"),
        Some(28) => Some("AAAA"),
        Some(_) => Some("other"),
        None => None,
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
