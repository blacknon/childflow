use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Context, Result};

use crate::util::{debug, run_command};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InterfaceRoute {
    pub(super) gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InterfaceRoute6 {
    pub(super) gateway: Option<Ipv6Addr>,
}

pub(super) fn discover_default_route_for_interface(iface: &str) -> Result<InterfaceRoute> {
    let output = run_command(
        "ip",
        vec![
            "route".into(),
            "show".into(),
            "default".into(),
            "dev".into(),
            iface.into(),
        ],
    )
    .with_context(|| format!("failed to inspect default route for interface {iface}"))?;

    parse_default_route(output.trim())
}

pub(super) fn discover_default_route6_for_interface(iface: &str) -> Result<InterfaceRoute6> {
    let output = run_command(
        "ip",
        vec![
            "-6".into(),
            "route".into(),
            "show".into(),
            "default".into(),
            "dev".into(),
            iface.into(),
        ],
    )
    .with_context(|| format!("failed to inspect IPv6 default route for interface {iface}"))?;

    parse_default_route6(output.trim())
}

fn parse_default_route(output: &str) -> Result<InterfaceRoute> {
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

fn parse_default_route6(output: &str) -> Result<InterfaceRoute6> {
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

pub(super) fn build_default_route_args(
    route_table: u32,
    iface: &str,
    gateway: Option<Ipv4Addr>,
) -> Vec<String> {
    let mut args = vec![
        "route".into(),
        "add".into(),
        "default".into(),
        "table".into(),
        route_table.to_string(),
    ];
    if let Some(gateway) = gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(iface.into());
    if gateway.is_none() {
        args.push("scope".into());
        args.push("link".into());
    }
    args
}

pub(super) fn build_default_route_delete_args(
    route_table: u32,
    iface: &str,
    gateway: Option<Ipv4Addr>,
) -> Vec<String> {
    let mut args = vec![
        "route".into(),
        "del".into(),
        "default".into(),
        "table".into(),
        route_table.to_string(),
    ];
    if let Some(gateway) = gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(iface.into());
    if gateway.is_none() {
        args.push("scope".into());
        args.push("link".into());
    }
    args
}

pub(super) fn build_default_route6_args(
    route_table: u32,
    iface: &str,
    gateway: Option<Ipv6Addr>,
) -> Vec<String> {
    let mut args = vec![
        "-6".into(),
        "route".into(),
        "add".into(),
        "default".into(),
        "table".into(),
        route_table.to_string(),
    ];
    if let Some(gateway) = gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(iface.into());
    args
}

pub(super) fn build_default_route6_delete_args(
    route_table: u32,
    iface: &str,
    gateway: Option<Ipv6Addr>,
) -> Vec<String> {
    let mut args = vec![
        "-6".into(),
        "route".into(),
        "del".into(),
        "default".into(),
        "table".into(),
        route_table.to_string(),
    ];
    if let Some(gateway) = gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(iface.into());
    args
}

pub(super) fn discover_rootful_egress_ips(
    iface: Option<&str>,
) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
    let ipv4 = discover_route_get_src_v4(iface).with_context(|| match iface {
        Some(iface) => format!(
            "failed to determine the rootful IPv4 egress source address for interface {iface}"
        ),
        None => "failed to determine the rootful IPv4 egress source address from the default route"
            .to_string(),
    })?;

    let ipv6 = match discover_route_get_src_v6(iface) {
        Ok(value) => value,
        Err(err) => {
            debug(format!(
                "could not determine a rootful IPv6 egress source address: {err:#}. IPv6 synthetic egress capture may be unavailable on this host"
            ));
            None
        }
    };

    Ok((Some(ipv4), ipv6))
}

pub(super) fn discover_rootful_wire_egress_iface(iface: Option<&str>) -> Result<String> {
    match iface {
        Some(iface) => Ok(iface.to_string()),
        None => discover_route_get_dev_v4().context(
            "failed to determine the rootful wire-egress interface from the default route",
        ),
    }
}

fn discover_route_get_src_v4(iface: Option<&str>) -> Result<Ipv4Addr> {
    let mut args = vec!["route".into(), "get".into(), "1.1.1.1".into()];
    if let Some(iface) = iface {
        args.push("oif".into());
        args.push(iface.into());
    }
    let output = run_command("ip", args).context("failed to inspect IPv4 route-get output")?;
    parse_route_get_src_v4(&output)
}

fn discover_route_get_dev_v4() -> Result<String> {
    let output = run_command("ip", vec!["route".into(), "get".into(), "1.1.1.1".into()])
        .context("failed to inspect IPv4 route-get output")?;
    parse_route_get_dev(&output)
}

fn discover_route_get_src_v6(iface: Option<&str>) -> Result<Option<Ipv6Addr>> {
    let mut args = vec![
        "-6".into(),
        "route".into(),
        "get".into(),
        "2606:4700:4700::1111".into(),
    ];
    if let Some(iface) = iface {
        args.push("oif".into());
        args.push(iface.into());
    }
    let output = run_command("ip", args).context("failed to inspect IPv6 route-get output")?;
    parse_route_get_src_v6(&output).map(Some)
}

fn parse_route_get_src_v4(output: &str) -> Result<Ipv4Addr> {
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

fn parse_route_get_src_v6(output: &str) -> Result<Ipv6Addr> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    tokens
        .windows(2)
        .find(|pair| pair[0] == "src")
        .ok_or_else(|| anyhow!("no `src` token found in IPv6 route-get output: {output}"))?[1]
        .parse::<Ipv6Addr>()
        .with_context(|| {
            format!("failed to parse IPv6 `src` token from route-get output: {output}")
        })
}

fn parse_route_get_dev(output: &str) -> Result<String> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    Ok(tokens
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .ok_or_else(|| anyhow!("no `dev` token found in route-get output: {output}"))?[1]
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_route_accepts_gateway() {
        let route =
            parse_default_route("default via 192.0.2.1 dev eth0 proto dhcp metric 100").unwrap();
        assert_eq!(
            route,
            InterfaceRoute {
                gateway: Some(Ipv4Addr::new(192, 0, 2, 1))
            }
        );
    }

    #[test]
    fn parse_default_route_accepts_direct_link_route() {
        let route = parse_default_route("default dev tun0 scope link").unwrap();
        assert_eq!(route, InterfaceRoute { gateway: None });
    }

    #[test]
    fn parse_default_route6_accepts_gateway() {
        let route = parse_default_route6("default via 2001:db8::1 dev eth0 metric 100").unwrap();
        assert_eq!(
            route,
            InterfaceRoute6 {
                gateway: Some("2001:db8::1".parse().unwrap())
            }
        );
    }

    #[test]
    fn parse_default_route6_accepts_direct_link_route() {
        let route = parse_default_route6("default dev tun0 metric 1024 pref medium").unwrap();
        assert_eq!(route, InterfaceRoute6 { gateway: None });
    }

    #[test]
    fn parse_default_route_rejects_invalid_gateway() {
        let err = parse_default_route("default via not-an-ip dev eth0").unwrap_err();
        assert!(err.to_string().contains("failed to parse default gateway"));
    }

    #[test]
    fn parse_route_get_src_v4_extracts_source_address() {
        let parsed =
            parse_route_get_src_v4("1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.10 uid 1000")
                .unwrap();
        assert_eq!(parsed, Ipv4Addr::new(192, 0, 2, 10));
    }

    #[test]
    fn parse_route_get_src_v6_extracts_source_address() {
        let parsed = parse_route_get_src_v6(
            "2606:4700:4700::1111 from :: via 2001:db8::1 dev eth0 src 2001:db8::10 metric 1024 pref medium",
        )
        .unwrap();
        assert_eq!(parsed, "2001:db8::10".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn parse_route_get_dev_extracts_interface_name() {
        let parsed =
            parse_route_get_dev("1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.10 uid 1000").unwrap();
        assert_eq!(parsed, "eth0");
    }
}
