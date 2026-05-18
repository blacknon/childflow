use anyhow::{Context, Result};

use crate::network::rootless_internal::route;

use super::RootlessChildBootstrap;

pub(super) fn bring_rootless_child_links_up(
    config: &RootlessChildBootstrap,
    tap_name: &str,
) -> Result<()> {
    let gateway_mac = render_mac(config.gateway_mac);

    crate::util::run_command("ip", route::lo_up_args())
        .context("failed to bring loopback up inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::addr_add_v4_args(tap_name, config.child_ipv4, config.child_ipv4_prefix_len),
    )
    .context(
        "failed to assign IPv4 address to tap0 inside the rootless-internal child namespace",
    )?;

    crate::util::run_command(
        "ip",
        route::addr_add_v6_args(tap_name, config.child_ipv6, config.child_ipv6_prefix_len),
    )
    .context(
        "failed to assign IPv6 address to tap0 inside the rootless-internal child namespace",
    )?;

    crate::util::run_command("ip", route::link_up_args(tap_name))
        .context("failed to bring tap0 up inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::neigh_add_v4_args(config.gateway_ipv4, &gateway_mac, tap_name),
    )
    .context("failed to install the IPv4 gateway neighbor entry for tap0 inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::neigh_add_v6_args(config.gateway_ipv6, &gateway_mac, tap_name),
    )
    .context("failed to install the IPv6 gateway neighbor entry for tap0 inside the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::default_route_v4_args(config.gateway_ipv4, tap_name),
    )
    .context("failed to install IPv4 default route for the rootless-internal child namespace")?;

    crate::util::run_command(
        "ip",
        route::default_route_v6_args(config.gateway_ipv6, tap_name),
    )
    .context("failed to install IPv6 default route for the rootless-internal child namespace")?;

    Ok(())
}

fn render_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
