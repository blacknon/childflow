use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;

mod discover;
mod parse;

use self::parse::{
    parse_default_route, parse_default_route6, parse_route_get_dev, parse_route_get_src_v4,
    parse_route_get_src_v6,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InterfaceRoute {
    pub(super) gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InterfaceRoute6 {
    pub(super) gateway: Option<Ipv6Addr>,
}

pub(super) fn discover_default_route_for_interface(iface: &str) -> Result<InterfaceRoute> {
    discover::discover_default_route_for_interface(iface)
}

pub(super) fn discover_default_route6_for_interface(iface: &str) -> Result<InterfaceRoute6> {
    discover::discover_default_route6_for_interface(iface)
}

pub(super) fn discover_rootful_egress_ips(
    iface: Option<&str>,
) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
    discover::discover_rootful_egress_ips(iface)
}

pub(super) fn discover_rootful_wire_egress_iface(iface: Option<&str>) -> Result<String> {
    discover::discover_rootful_wire_egress_iface(iface)
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

#[allow(dead_code)]
fn _keep_result_visible(_: Result<()>) {}
