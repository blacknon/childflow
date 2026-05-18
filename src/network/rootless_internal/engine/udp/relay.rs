use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;
use std::thread;

use anyhow::Context;

use crate::util;

use super::super::super::packet::{self, Icmpv4ErrorFrame, Icmpv6ErrorFrame};
use super::super::super::transport::{relay_udp_payload, UdpRelayOutcome};
use super::super::RemoteEvent;

pub(super) struct UdpRelayRequest {
    pub(super) gateway_mac: [u8; 6],
    pub(super) child_mac: [u8; 6],
    pub(super) child_ip: IpAddr,
    pub(super) child_port: u16,
    pub(super) remote_ip: IpAddr,
    pub(super) remote_port: u16,
    pub(super) hop_limit: u8,
    pub(super) payload: Vec<u8>,
}

pub(super) fn spawn_udp_worker(event_tx: Sender<RemoteEvent>, request: UdpRelayRequest) {
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
