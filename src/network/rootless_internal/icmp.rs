// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::mem::{size_of, MaybeUninit};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::util;

use super::addr::AddressPlan;
use super::engine::RemoteEvent;
use super::packet::{
    self, Icmpv4EchoFrame, Icmpv4ErrorFrame, Icmpv6EchoFrame, Icmpv6ErrorFrame, ParsedIcmpv4Packet,
    ParsedIcmpv6Packet,
};

struct Icmpv4EchoRequest {
    gateway_mac: [u8; 6],
    child_mac: [u8; 6],
    child_ip: std::net::Ipv4Addr,
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

struct Icmpv4RawRequest {
    gateway_mac: [u8; 6],
    child_mac: [u8; 6],
    child_ip: std::net::Ipv4Addr,
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    message: Vec<u8>,
}

struct Icmpv6EchoRequest {
    gateway_mac: [u8; 6],
    child_mac: [u8; 6],
    child_ip: std::net::Ipv6Addr,
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

struct Icmpv6RawRequest {
    gateway_mac: [u8; 6],
    child_mac: [u8; 6],
    child_ip: std::net::Ipv6Addr,
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    message: Vec<u8>,
}

enum IcmpRelayOutcome {
    Message(Vec<u8>),
    Error {
        source_ip: IpAddr,
        icmp_type: u8,
        code: u8,
    },
}

pub(super) fn handle_icmpv4_packet(
    event_tx: &Sender<RemoteEvent>,
    addr_plan: &AddressPlan,
    icmp: &ParsedIcmpv4Packet,
) -> Result<()> {
    let (src_ip, dst_ip) = match (icmp.meta.src_ip, icmp.meta.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
        _ => return Ok(()),
    };

    let is_gateway_target = dst_ip == addr_plan.gateway_ipv4;
    if icmp.icmp_type == 8 && icmp.code == 0 && !is_gateway_target {
        spawn_icmpv4_echo_worker(
            event_tx.clone(),
            Icmpv4EchoRequest {
                gateway_mac: addr_plan.gateway_mac,
                child_mac: icmp.meta.src_mac,
                child_ip: src_ip,
                remote_ip: dst_ip,
                hop_limit: icmp.meta.hop_limit,
                identifier: icmp.identifier,
                sequence: icmp.sequence,
                payload: icmp.payload.clone(),
            },
        );
        return Ok(());
    }

    if should_relay_icmpv4_request(icmp.icmp_type) && !is_gateway_target {
        spawn_icmpv4_raw_worker(
            event_tx.clone(),
            Icmpv4RawRequest {
                gateway_mac: addr_plan.gateway_mac,
                child_mac: icmp.meta.src_mac,
                child_ip: src_ip,
                remote_ip: dst_ip,
                hop_limit: icmp.meta.hop_limit,
                message: packet::build_icmpv4_message_from_parsed(icmp),
            },
        );
        return Ok(());
    }

    util::debug(format!(
        "ignoring unsupported outbound ICMPv4 type {} code {} toward {}",
        icmp.icmp_type, icmp.code, dst_ip
    ));

    Ok(())
}

pub(super) fn handle_icmpv6_packet(
    event_tx: &Sender<RemoteEvent>,
    addr_plan: &AddressPlan,
    icmp: &ParsedIcmpv6Packet,
) -> Result<()> {
    let (src_ip, dst_ip) = match (icmp.meta.src_ip, icmp.meta.dst_ip) {
        (IpAddr::V6(src), IpAddr::V6(dst)) => (src, dst),
        _ => return Ok(()),
    };

    let is_gateway_target = dst_ip == addr_plan.gateway_ipv6;
    if icmp.icmp_type == 128 && icmp.code == 0 && !is_gateway_target {
        spawn_icmpv6_echo_worker(
            event_tx.clone(),
            Icmpv6EchoRequest {
                gateway_mac: addr_plan.gateway_mac,
                child_mac: icmp.meta.src_mac,
                child_ip: src_ip,
                remote_ip: dst_ip,
                hop_limit: icmp.meta.hop_limit,
                identifier: icmp.identifier,
                sequence: icmp.sequence,
                payload: icmp.payload.clone(),
            },
        );
        return Ok(());
    }

    if should_relay_icmpv6_request(icmp.icmp_type, dst_ip) && !is_gateway_target {
        spawn_icmpv6_raw_worker(
            event_tx.clone(),
            Icmpv6RawRequest {
                gateway_mac: addr_plan.gateway_mac,
                child_mac: icmp.meta.src_mac,
                child_ip: src_ip,
                remote_ip: dst_ip,
                hop_limit: icmp.meta.hop_limit,
                message: packet::build_icmpv6_message_from_parsed(src_ip, dst_ip, icmp),
            },
        );
        return Ok(());
    }

    util::debug(format!(
        "ignoring unsupported outbound ICMPv6 type {} code {} toward {}",
        icmp.icmp_type, icmp.code, dst_ip
    ));

    Ok(())
}

fn spawn_icmpv4_echo_worker(event_tx: Sender<RemoteEvent>, request: Icmpv4EchoRequest) {
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

        let result = relay_icmpv4_echo(request.remote_ip, request.hop_limit, &request.payload)
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

fn spawn_icmpv4_raw_worker(event_tx: Sender<RemoteEvent>, request: Icmpv4RawRequest) {
    thread::spawn(move || {
        let child_probe = packet::build_icmpv4_ip_packet_from_message(
            request.child_ip,
            request.remote_ip,
            request.hop_limit,
            &request.message,
        );

        let result = relay_icmpv4_message(request.remote_ip, request.hop_limit, &request.message)
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

fn spawn_icmpv6_echo_worker(event_tx: Sender<RemoteEvent>, request: Icmpv6EchoRequest) {
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

        let result = relay_icmpv6_echo(request.remote_ip, request.hop_limit, &request.payload)
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

fn spawn_icmpv6_raw_worker(event_tx: Sender<RemoteEvent>, request: Icmpv6RawRequest) {
    thread::spawn(move || {
        let child_probe = packet::build_icmpv6_ip_packet_from_message(
            request.child_ip,
            request.remote_ip,
            request.hop_limit,
            &request.message,
        );

        let result = relay_icmpv6_message(request.remote_ip, request.hop_limit, &request.message)
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

fn relay_icmpv4_echo(
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    payload: &[u8],
) -> Result<IcmpRelayOutcome> {
    let output = run_ping_helper(remote_ip.to_string(), hop_limit, payload.len(), false)
        .with_context(|| {
            format!("failed to execute `ping` while relaying an ICMPv4 echo request to {remote_ip}")
        })?;
    parse_ping_helper_output(IpAddr::V4(remote_ip), false, &output)
}

fn relay_icmpv6_echo(
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    payload: &[u8],
) -> Result<IcmpRelayOutcome> {
    let output = run_ping_helper(remote_ip.to_string(), hop_limit, payload.len(), true)
        .with_context(|| {
            format!(
                "failed to execute `ping -6` while relaying an ICMPv6 echo request to {remote_ip}"
            )
        })?;
    parse_ping_helper_output(IpAddr::V6(remote_ip), true, &output)
}

fn relay_icmpv4_message(
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    message: &[u8],
) -> Result<IcmpRelayOutcome> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(nix::libc::IPPROTO_ICMP)),
    )
    .context("failed to create an ICMPv4 raw socket")?;
    socket
        .set_ttl_v4(u32::from(hop_limit))
        .context("failed to configure the ICMPv4 raw-socket TTL")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to configure the ICMPv4 raw-socket timeout")?;
    let remote = SockAddr::from(std::net::SocketAddr::new(IpAddr::V4(remote_ip), 0));
    socket
        .send_to(message, &remote)
        .with_context(|| format!("failed to send an ICMPv4 request toward {remote_ip}"))?;

    let mut buf = [MaybeUninit::<u8>::uninit(); 65535];
    loop {
        let (size, _) = socket
            .recv_from(&mut buf)
            .with_context(|| format!("failed to receive an ICMPv4 reply for {remote_ip}"))?;
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), size) };
        let packet = etherparse::Ipv4Slice::from_slice(bytes)
            .context("failed to parse the ICMPv4 raw-socket reply as IPv4")?;
        if packet.payload().ip_number != etherparse::IpNumber::ICMP {
            continue;
        }
        let source_ip = packet.header().source_addr();
        let message = packet.payload().payload.to_vec();
        if message.len() < 8 {
            continue;
        }
        if matches!(message[0], 3 | 4 | 5 | 11 | 12) {
            return Ok(IcmpRelayOutcome::Error {
                source_ip: IpAddr::V4(source_ip),
                icmp_type: message[0],
                code: message[1],
            });
        }
        return Ok(IcmpRelayOutcome::Message(message));
    }
}

fn relay_icmpv6_message(
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    message: &[u8],
) -> Result<IcmpRelayOutcome> {
    let socket = Socket::new(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::from(nix::libc::IPPROTO_ICMPV6)),
    )
    .context("failed to create an ICMPv6 raw socket")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to configure the ICMPv6 raw-socket timeout")?;

    let hop_limit = i32::from(hop_limit);
    let rc = unsafe {
        nix::libc::setsockopt(
            socket.as_raw_fd(),
            nix::libc::IPPROTO_IPV6,
            nix::libc::IPV6_UNICAST_HOPS,
            (&hop_limit as *const i32).cast(),
            size_of::<i32>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to configure the ICMPv6 raw-socket hop limit");
    }

    let checksum_offset = 2_i32;
    let rc = unsafe {
        nix::libc::setsockopt(
            socket.as_raw_fd(),
            nix::libc::IPPROTO_IPV6,
            nix::libc::IPV6_CHECKSUM,
            (&checksum_offset as *const i32).cast(),
            size_of::<i32>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to configure the ICMPv6 checksum offset");
    }

    let remote = SockAddr::from(std::net::SocketAddr::new(IpAddr::V6(remote_ip), 0));
    socket
        .send_to(message, &remote)
        .with_context(|| format!("failed to send an ICMPv6 request toward {remote_ip}"))?;

    let mut buf = [MaybeUninit::<u8>::uninit(); 65535];
    loop {
        let (size, addr) = socket
            .recv_from(&mut buf)
            .with_context(|| format!("failed to receive an ICMPv6 reply for {remote_ip}"))?;
        let source_ip = match addr.as_socket() {
            Some(std::net::SocketAddr::V6(addr)) => *addr.ip(),
            _ => continue,
        };
        let message =
            unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), size) }.to_vec();
        if message.len() < 8 {
            continue;
        }
        if (1..=4).contains(&message[0]) {
            return Ok(IcmpRelayOutcome::Error {
                source_ip: IpAddr::V6(source_ip),
                icmp_type: message[0],
                code: message[1],
            });
        }
        return Ok(IcmpRelayOutcome::Message(message));
    }
}

fn run_ping_helper(
    remote_ip: String,
    hop_limit: u8,
    payload_len: usize,
    ipv6: bool,
) -> Result<std::process::Output> {
    let payload_len = payload_len.to_string();
    let hop_limit = hop_limit.to_string();
    let mut command = Command::new("ping");
    if ipv6 {
        command.arg("-6");
    }
    command.args([
        "-n",
        "-c",
        "1",
        "-W",
        "3",
        "-t",
        hop_limit.as_str(),
        "-s",
        payload_len.as_str(),
        remote_ip.as_str(),
    ]);
    command.output().context("failed to run the ping helper")
}

fn parse_ping_helper_output(
    remote_ip: IpAddr,
    ipv6: bool,
    output: &std::process::Output,
) -> Result<IcmpRelayOutcome> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if contains_ping_success(&stdout, &remote_ip) || contains_ping_success(&stderr, &remote_ip) {
        return Ok(IcmpRelayOutcome::Message(Vec::new()));
    }

    if let Some(outcome) = parse_ping_error_lines(&stdout, ipv6)? {
        return Ok(outcome);
    }
    if let Some(outcome) = parse_ping_error_lines(&stderr, ipv6)? {
        return Ok(outcome);
    }

    anyhow::bail!(
        "the helper `ping` command could not reach {remote_ip} (status: {}). stdout: {} stderr: {}",
        output.status,
        stdout.trim(),
        stderr.trim(),
    )
}

fn should_relay_icmpv4_request(icmp_type: u8) -> bool {
    !matches!(icmp_type, 0 | 3 | 4 | 5 | 11 | 12)
}

fn should_relay_icmpv6_request(icmp_type: u8, dst_ip: std::net::Ipv6Addr) -> bool {
    !dst_ip.is_multicast() && icmp_type >= 128 && !matches!(icmp_type, 128 | 129 | 130..=137 | 143)
}

fn contains_ping_success(output: &str, remote_ip: &IpAddr) -> bool {
    let remote = remote_ip.to_string();
    output.lines().any(|line| {
        line.contains("bytes from") && (line.contains(&remote) || line.contains("icmp_seq="))
    })
}

fn parse_ping_error_lines(output: &str, ipv6: bool) -> Result<Option<IcmpRelayOutcome>> {
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("From ") else {
            continue;
        };
        let source = rest
            .split_whitespace()
            .next()
            .map(|token| token.trim_end_matches(':'))
            .context("failed to parse the ICMP error source reported by ping")?;
        let source_ip: IpAddr = source
            .parse()
            .with_context(|| format!("failed to parse the ICMP error source IP `{source}`"))?;

        if line.contains("Time to live exceeded")
            || line.contains("Time exceeded")
            || line.contains("Hop limit exceeded")
        {
            return Ok(Some(IcmpRelayOutcome::Error {
                source_ip,
                icmp_type: if ipv6 { 3 } else { 11 },
                code: 0,
            }));
        }

        if line.contains("Destination")
            || line.contains("unreachable")
            || line.contains("Unreachable")
        {
            return Ok(Some(IcmpRelayOutcome::Error {
                source_ip,
                icmp_type: if ipv6 { 1 } else { 3 },
                code: parse_unreachable_code(line, ipv6),
            }));
        }
    }

    Ok(None)
}

fn parse_unreachable_code(line: &str, ipv6: bool) -> u8 {
    let line = line.to_ascii_lowercase();
    if ipv6 {
        if line.contains("no route") {
            0
        } else if line.contains("prohibited") || line.contains("administratively") {
            1
        } else if line.contains("scope") {
            2
        } else if line.contains("address unreachable") || line.contains("host unreachable") {
            3
        } else if line.contains("port unreachable") {
            4
        } else {
            0
        }
    } else if line.contains("net unreachable") {
        0
    } else if line.contains("host unreachable") {
        1
    } else if line.contains("protocol unreachable") {
        2
    } else if line.contains("port unreachable") {
        3
    } else if line.contains("fragmentation") {
        4
    } else if line.contains("source route failed") {
        5
    } else if line.contains("admin") || line.contains("filtered") || line.contains("prohibited") {
        13
    } else {
        0
    }
}
