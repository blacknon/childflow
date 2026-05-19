use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;

mod discover;

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
