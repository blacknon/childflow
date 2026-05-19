use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::thread;

use crate::util;

use super::super::super::engine::RemoteEvent;
use super::super::relay;
use super::super::types::{IcmpRelayOutcome, Icmpv4EchoRequest, Icmpv4RawRequest};
use super::frames;

pub(in crate::network::rootless_internal::icmp) fn spawn_icmpv4_echo_worker(
    event_tx: Sender<RemoteEvent>,
    request: Icmpv4EchoRequest,
) {
    thread::spawn(move || {
        let child_probe = frames::v4::build_child_icmpv4_echo_probe(&request);

        let result = relay::relay_icmpv4_echo(
            request.remote_ip,
            request.hop_limit,
            request.identifier,
            request.sequence,
            &request.payload,
        )
        .and_then(|outcome| match outcome {
                    IcmpRelayOutcome::Message(reply) => {
                        frames::v4::build_icmpv4_echo_reply_frame(&request, &reply)
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
                        frames::v4::build_icmpv4_error_reply_frame(
                            &request, source_ip, icmp_type, code, probe,
                        )
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

pub(in crate::network::rootless_internal::icmp) fn spawn_icmpv4_raw_worker(
    event_tx: Sender<RemoteEvent>,
    request: Icmpv4RawRequest,
) {
    thread::spawn(move || {
        let child_probe = frames::v4::build_child_icmpv4_raw_probe(&request);

        let result =
            relay::relay_icmpv4_message(request.remote_ip, request.hop_limit, &request.message)
                .and_then(|outcome| match outcome {
                    IcmpRelayOutcome::Message(reply) => {
                        frames::v4::build_icmpv4_raw_reply_frame(&request, &reply)
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
                        frames::v4::build_icmpv4_error_reply_frame(
                            &request, source_ip, icmp_type, code, probe,
                        )
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
