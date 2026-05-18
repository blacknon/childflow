use anyhow::Result;

use super::IcmpRelayOutcome;

mod ping;
mod raw;

pub(super) fn relay_icmpv4_echo(
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    payload: &[u8],
) -> Result<IcmpRelayOutcome> {
    ping::relay_icmpv4_echo(remote_ip, hop_limit, payload)
}

pub(super) fn relay_icmpv6_echo(
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    payload: &[u8],
) -> Result<IcmpRelayOutcome> {
    ping::relay_icmpv6_echo(remote_ip, hop_limit, payload)
}

pub(super) fn relay_icmpv4_message(
    remote_ip: std::net::Ipv4Addr,
    hop_limit: u8,
    message: &[u8],
) -> Result<IcmpRelayOutcome> {
    raw::relay_icmpv4_message(remote_ip, hop_limit, message)
}

pub(super) fn relay_icmpv6_message(
    remote_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    message: &[u8],
) -> Result<IcmpRelayOutcome> {
    raw::relay_icmpv6_message(remote_ip, hop_limit, message)
}

#[cfg(test)]
pub(super) fn parse_ping_helper_output(
    remote_ip: std::net::IpAddr,
    ipv6: bool,
    output: &std::process::Output,
) -> Result<IcmpRelayOutcome> {
    ping::parse_ping_helper_output(remote_ip, ipv6, output)
}

#[cfg(test)]
pub(super) fn parse_unreachable_code(line: &str, ipv6: bool) -> u8 {
    ping::parse_unreachable_code(line, ipv6)
}
