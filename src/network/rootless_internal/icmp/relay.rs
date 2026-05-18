// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::mem::{size_of, MaybeUninit};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::IcmpRelayOutcome;

pub(super) fn relay_icmpv4_echo(
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

pub(super) fn relay_icmpv6_echo(
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    payload: &[u8],
) -> Result<IcmpRelayOutcome> {
    let output = run_ping_helper(remote_ip.to_string(), hop_limit, payload.len(), true)
        .with_context(|| {
            format!("failed to execute `ping` while relaying an ICMPv6 echo request to {remote_ip}")
        })?;
    parse_ping_helper_output(IpAddr::V6(remote_ip), true, &output)
}

pub(super) fn relay_icmpv4_message(
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
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to configure the ICMPv4 raw-socket timeout")?;

    let ttl = i32::from(hop_limit);
    // SAFETY: `setsockopt` is invoked with a valid fd, correct buffer pointer, and matching length.
    let rc = unsafe {
        nix::libc::setsockopt(
            socket.as_raw_fd(),
            nix::libc::IPPROTO_IP,
            nix::libc::IP_TTL,
            (&ttl as *const i32).cast(),
            size_of::<i32>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to configure the ICMPv4 raw-socket TTL");
    }

    let remote = SockAddr::from(std::net::SocketAddr::new(IpAddr::V4(remote_ip), 0));
    socket
        .send_to(message, &remote)
        .with_context(|| format!("failed to send an ICMPv4 request toward {remote_ip}"))?;

    let mut buf = [MaybeUninit::<u8>::uninit(); 65535];
    loop {
        let (size, addr) = socket
            .recv_from(&mut buf)
            .with_context(|| format!("failed to receive an ICMPv4 reply for {remote_ip}"))?;
        let source_ip = match addr.as_socket() {
            Some(std::net::SocketAddr::V4(addr)) => *addr.ip(),
            _ => continue,
        };
        // SAFETY: `recv_from` initialized the first `size` bytes in `buf`.
        let packet = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), size) };
        if packet.len() < 20 {
            continue;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if packet.len() < header_len + 8 {
            continue;
        }
        let message = packet[header_len..].to_vec();
        if (3..=12).contains(&message[0]) {
            return Ok(IcmpRelayOutcome::Error {
                source_ip: IpAddr::V4(source_ip),
                icmp_type: message[0],
                code: message[1],
            });
        }
        return Ok(IcmpRelayOutcome::Message(message));
    }
}

pub(super) fn relay_icmpv6_message(
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
    // SAFETY: `setsockopt` is invoked with a valid fd, correct buffer pointer, and matching length.
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
    // SAFETY: `setsockopt` is invoked with a valid fd, correct buffer pointer, and matching length.
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
        // SAFETY: `recv_from` initialized the first `size` bytes in `buf`.
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

pub(super) fn parse_ping_helper_output(
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

pub(super) fn parse_unreachable_code(line: &str, ipv6: bool) -> u8 {
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
