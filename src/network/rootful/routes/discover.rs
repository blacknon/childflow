use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};

use crate::linux_net;
use crate::util::{debug, read_file_trimmed};

use super::{InterfaceRoute, InterfaceRoute6};

pub(super) fn discover_default_route_for_interface(iface: &str) -> Result<InterfaceRoute> {
    let routes =
        read_file_trimmed("/proc/net/route").context("failed to read `/proc/net/route`")?;
    parse_default_route_for_interface(iface, &routes)
        .with_context(|| format!("failed to inspect default route for interface {iface}"))
}

pub(super) fn discover_default_route6_for_interface(iface: &str) -> Result<InterfaceRoute6> {
    let routes = read_file_trimmed("/proc/net/ipv6_route")
        .context("failed to read `/proc/net/ipv6_route`")?;
    parse_default_route6_for_interface(iface, &routes)
        .with_context(|| format!("failed to inspect IPv6 default route for interface {iface}"))
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
    match iface {
        Some(iface) => {
            linux_net::discover_egress_src_v4_on_iface("1.1.1.1".parse().unwrap(), iface)
                .context("failed to determine the IPv4 source address from the selected interface")
        }
        None => linux_net::discover_egress_src_v4("1.1.1.1".parse().unwrap())
            .context("failed to determine the IPv4 source address from the default route"),
    }
}

fn discover_route_get_dev_v4() -> Result<String> {
    let source_ip = linux_net::discover_egress_src_v4("1.1.1.1".parse().unwrap())
        .context("failed to determine the IPv4 source address from the default route")?;
    linux_net::discover_interface_for_source_ip(source_ip.into())
        .context("failed to determine the IPv4 egress interface from the default route")
}

fn discover_route_get_src_v6(iface: Option<&str>) -> Result<Option<Ipv6Addr>> {
    match iface {
        Some(iface) => linux_net::discover_egress_src_v6_on_iface(
            "2606:4700:4700::1111".parse().unwrap(),
            iface,
        )
        .context("failed to determine the IPv6 source address from the selected interface")
        .map(Some),
        None => linux_net::discover_egress_src_v6("2606:4700:4700::1111".parse().unwrap())
            .context("failed to determine the IPv6 source address from the default route")
            .map(Some),
    }
}

fn parse_default_route_for_interface(iface: &str, routes: &str) -> Result<InterfaceRoute> {
    for line in routes.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[0] != iface || fields[1] != "00000000" {
            continue;
        }

        let flags = u16::from_str_radix(fields[3], 16).with_context(|| {
            format!(
                "failed to parse IPv4 route flags `{}` for interface `{iface}`",
                fields[3]
            )
        })?;
        if flags & nix::libc::RTF_UP == 0 {
            continue;
        }

        let gateway = parse_proc_ipv4_hex(fields[2])?;
        return Ok(InterfaceRoute {
            gateway: if gateway.is_unspecified() {
                None
            } else {
                Some(gateway)
            },
        });
    }

    Ok(InterfaceRoute { gateway: None })
}

fn parse_default_route6_for_interface(iface: &str, routes: &str) -> Result<InterfaceRoute6> {
    for line in routes.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        if fields[0] != "00000000000000000000000000000000"
            || fields[1] != "00000000"
            || fields[9] != iface
        {
            continue;
        }

        let flags = u32::from_str_radix(fields[8], 16).with_context(|| {
            format!(
                "failed to parse IPv6 route flags `{}` for interface `{iface}`",
                fields[8]
            )
        })?;
        if flags & (nix::libc::RTF_UP as u32) == 0 {
            continue;
        }

        let gateway = parse_proc_ipv6_hex(fields[4])?;
        return Ok(InterfaceRoute6 {
            gateway: if gateway.is_unspecified() {
                None
            } else {
                Some(gateway)
            },
        });
    }

    Ok(InterfaceRoute6 { gateway: None })
}

fn parse_proc_ipv4_hex(hex: &str) -> Result<Ipv4Addr> {
    if hex.len() != 8 {
        anyhow::bail!("expected an 8-digit IPv4 route hex string, got `{hex}`");
    }
    let raw = u32::from_str_radix(hex, 16)
        .with_context(|| format!("failed to parse IPv4 route hex `{hex}`"))?;
    Ok(Ipv4Addr::from(raw.to_le_bytes()))
}

fn parse_proc_ipv6_hex(hex: &str) -> Result<Ipv6Addr> {
    if hex.len() != 32 {
        anyhow::bail!("expected a 32-digit IPv6 route hex string, got `{hex}`");
    }
    let mut octets = [0_u8; 16];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let chunk = std::str::from_utf8(chunk).expect("route hex chunks are ASCII");
        octets[idx] = u8::from_str_radix(chunk, 16)
            .with_context(|| format!("failed to parse IPv6 route hex byte `{chunk}` in `{hex}`"))?;
    }
    Ok(Ipv6Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_route_for_interface_reads_gateway_from_proc_route() {
        let routes = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        let route = parse_default_route_for_interface("eth0", routes).unwrap();
        assert_eq!(route.gateway, Some("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn parse_default_route_for_interface_treats_zero_gateway_as_on_link() {
        let routes = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t00000000\t0001\t0\t0\t100\t00000000\t0\t0\t0
";
        let route = parse_default_route_for_interface("eth0", routes).unwrap();
        assert_eq!(route.gateway, None);
    }

    #[test]
    fn parse_default_route6_for_interface_reads_gateway_from_proc_ipv6_route() {
        let routes = "\
00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 fe800000000000000202b3fffe1e8329 00000000 00000000 00000064 00000003 eth0
";
        let route = parse_default_route6_for_interface("eth0", routes).unwrap();
        assert_eq!(
            route.gateway,
            Some("fe80::202:b3ff:fe1e:8329".parse().unwrap())
        );
    }
}
