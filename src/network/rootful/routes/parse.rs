use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Context, Result};

use super::{InterfaceRoute, InterfaceRoute6};

pub(super) fn parse_default_route(output: &str) -> Result<InterfaceRoute> {
    if output.trim().is_empty() {
        return Ok(InterfaceRoute { gateway: None });
    }

    let line = output
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default();
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let gateway = tokens
        .windows(2)
        .find(|pair| pair[0] == "via")
        .map(|pair| pair[1].parse::<Ipv4Addr>())
        .transpose()
        .with_context(|| format!("failed to parse default gateway from route output: {line}"))?;

    Ok(InterfaceRoute { gateway })
}

pub(super) fn parse_default_route6(output: &str) -> Result<InterfaceRoute6> {
    if output.trim().is_empty() {
        return Ok(InterfaceRoute6 { gateway: None });
    }

    let line = output
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default();
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let gateway = tokens
        .windows(2)
        .find(|pair| pair[0] == "via")
        .map(|pair| pair[1].parse::<Ipv6Addr>())
        .transpose()
        .with_context(|| {
            format!("failed to parse IPv6 default gateway from route output: {line}")
        })?;

    Ok(InterfaceRoute6 { gateway })
}

pub(super) fn parse_route_get_src_v4(output: &str) -> Result<Ipv4Addr> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    tokens
        .windows(2)
        .find(|pair| pair[0] == "src")
        .ok_or_else(|| anyhow!("no `src` token found in route-get output: {output}"))?[1]
        .parse::<Ipv4Addr>()
        .with_context(|| {
            format!("failed to parse IPv4 `src` token from route-get output: {output}")
        })
}

pub(super) fn parse_route_get_src_v6(output: &str) -> Result<Ipv6Addr> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    tokens
        .windows(2)
        .find(|pair| pair[0] == "src")
        .ok_or_else(|| anyhow!("no `src` token found in route-get output: {output}"))?[1]
        .parse::<Ipv6Addr>()
        .with_context(|| {
            format!("failed to parse IPv6 `src` token from route-get output: {output}")
        })
}

pub(super) fn parse_route_get_dev(output: &str) -> Result<String> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    tokens
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .ok_or_else(|| anyhow!("no `dev` token found in route-get output: {output}"))?[1]
        .parse::<String>()
        .with_context(|| format!("failed to parse `dev` token from route-get output: {output}"))
}
