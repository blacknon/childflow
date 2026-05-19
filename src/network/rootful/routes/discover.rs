use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};

use crate::util::{debug, run_command};

use super::{
    parse_default_route, parse_default_route6, parse_route_get_dev, parse_route_get_src_v4,
    parse_route_get_src_v6, InterfaceRoute, InterfaceRoute6,
};

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
