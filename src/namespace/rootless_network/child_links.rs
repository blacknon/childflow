use anyhow::{Context, Result};

use crate::linux_net;

use super::RootlessChildBootstrap;

pub(super) fn bring_rootless_child_links_up(
    config: &RootlessChildBootstrap,
    tap_name: &str,
) -> Result<()> {
    let gateway_mac = render_mac(config.gateway_mac);

    linux_net::loopback_set_up()
        .context("failed to bring loopback up inside the rootless-internal child namespace")?;

    linux_net::addr_add_v4(tap_name, config.child_ipv4, config.child_ipv4_prefix_len).context(
        "failed to assign IPv4 address to tap0 inside the rootless-internal child namespace",
    )?;

    linux_net::addr_add_v6(tap_name, config.child_ipv6, config.child_ipv6_prefix_len).context(
        "failed to assign IPv6 address to tap0 inside the rootless-internal child namespace",
    )?;

    linux_net::link_set_up(tap_name)
        .context("failed to bring tap0 up inside the rootless-internal child namespace")?;

    linux_net::neigh_add_v4(tap_name, config.gateway_ipv4, &gateway_mac)
    .context("failed to install the IPv4 gateway neighbor entry for tap0 inside the rootless-internal child namespace")?;

    linux_net::neigh_add_v6(tap_name, config.gateway_ipv6, &gateway_mac)
    .context("failed to install the IPv6 gateway neighbor entry for tap0 inside the rootless-internal child namespace")?;

    linux_net::default_route_add_v4(tap_name, config.gateway_ipv4).context(
        "failed to install IPv4 default route for the rootless-internal child namespace",
    )?;

    linux_net::default_route_add_v6(tap_name, config.gateway_ipv6).context(
        "failed to install IPv6 default route for the rootless-internal child namespace",
    )?;

    Ok(())
}

fn render_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
