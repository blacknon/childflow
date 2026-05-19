use std::net::IpAddr;

use anyhow::{Context, Result};

use super::super::IcmpRelayOutcome;

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
