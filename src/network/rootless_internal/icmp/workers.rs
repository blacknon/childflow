use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::thread;

use crate::util;

use super::super::engine::RemoteEvent;
use super::super::packet::{
    self, Icmpv4EchoFrame, Icmpv4ErrorFrame, Icmpv6EchoFrame, Icmpv6ErrorFrame,
};
use super::relay;
use super::types::{
    IcmpRelayOutcome, Icmpv4EchoRequest, Icmpv4RawRequest, Icmpv6EchoRequest, Icmpv6RawRequest,
};

pub(super) fn spawn_icmpv4_echo_worker(event_tx: Sender<RemoteEvent>, request: Icmpv4EchoRequest) {
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

        let result =
            relay::relay_icmpv4_echo(request.remote_ip, request.hop_limit, &request.payload)
                .and_then(|outcome| match outcome {
                    IcmpRelayOutcome::Message(reply) => {
                        if reply.is_empty() {
                            packet::build_icmpv4_echo_frame(Icmpv4EchoFrame {
                                src_mac: request.gateway_mac,
                                dst_mac: request.child_mac,
                                src_ip: request.remote_ip,
                                dst_ip: request.child_ip,
                                icmp_type: 0,
                                code: 0,
                                identifier: request.identifier,
                                sequence: request.sequence,
                                payload: request.payload.as_slice(),
                            })
                        } else {
                            packet::build_icmpv4_frame_from_message(
                                request.gateway_mac,
                                request.child_mac,
                                request.remote_ip,
                                request.child_ip,
                                &reply,
                            )
                        }
                    }
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

pub(super) fn spawn_icmpv4_raw_worker(event_tx: Sender<RemoteEvent>, request: Icmpv4RawRequest) {
    thread::spawn(move || {
        let child_probe = packet::build_icmpv4_ip_packet_from_message(
            request.child_ip,
            request.remote_ip,
            request.hop_limit,
            &request.message,
        );

        let result =
            relay::relay_icmpv4_message(request.remote_ip, request.hop_limit, &request.message)
                .and_then(|outcome| match outcome {
                    IcmpRelayOutcome::Message(reply) => packet::build_icmpv4_frame_from_message(
                        request.gateway_mac,
                        request.child_mac,
                        request.remote_ip,
                        request.child_ip,
                        &reply,
                    ),
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
                util::warn(format!(
                    "rootless-internal could not complete a generic outbound ICMPv4 exchange for {}: {err:#}. This path depends on raw ICMP socket access on the host",
                    request.remote_ip
                ));
            }
        }
    });
}

pub(super) fn spawn_icmpv6_echo_worker(event_tx: Sender<RemoteEvent>, request: Icmpv6EchoRequest) {
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

        let result =
            relay::relay_icmpv6_echo(request.remote_ip, request.hop_limit, &request.payload)
                .and_then(|outcome| match outcome {
                    IcmpRelayOutcome::Message(reply) => {
                        if reply.is_empty() {
                            packet::build_icmpv6_echo_frame(Icmpv6EchoFrame {
                                src_mac: request.gateway_mac,
                                dst_mac: request.child_mac,
                                src_ip: request.remote_ip,
                                dst_ip: request.child_ip,
                                icmp_type: 129,
                                code: 0,
                                identifier: request.identifier,
                                sequence: request.sequence,
                                payload: request.payload.as_slice(),
                            })
                        } else {
                            packet::build_icmpv6_frame_from_message(
                                request.gateway_mac,
                                request.child_mac,
                                request.remote_ip,
                                request.child_ip,
                                &reply,
                            )
                        }
                    }
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

pub(super) fn spawn_icmpv6_raw_worker(event_tx: Sender<RemoteEvent>, request: Icmpv6RawRequest) {
    thread::spawn(move || {
        let child_probe = packet::build_icmpv6_ip_packet_from_message(
            request.child_ip,
            request.remote_ip,
            request.hop_limit,
            &request.message,
        );

        let result =
            relay::relay_icmpv6_message(request.remote_ip, request.hop_limit, &request.message)
                .and_then(|outcome| match outcome {
                    IcmpRelayOutcome::Message(reply) => packet::build_icmpv6_frame_from_message(
                        request.gateway_mac,
                        request.child_mac,
                        request.remote_ip,
                        request.child_ip,
                        &reply,
                    ),
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
                util::warn(format!(
                    "rootless-internal could not complete a generic outbound ICMPv6 exchange for {}: {err:#}. This path depends on raw ICMP socket access on the host",
                    request.remote_ip
                ));
            }
        }
    });
}

pub(super) fn should_relay_icmpv4_request(icmp_type: u8) -> bool {
    !matches!(icmp_type, 0 | 3 | 4 | 5 | 11 | 12)
}

pub(super) fn should_relay_icmpv6_request(icmp_type: u8, dst_ip: std::net::Ipv6Addr) -> bool {
    !dst_ip.is_multicast() && icmp_type >= 128 && !matches!(icmp_type, 128 | 129 | 130..=137 | 143)
}
