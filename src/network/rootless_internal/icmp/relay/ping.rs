use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result};

use super::super::IcmpRelayOutcome;

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
