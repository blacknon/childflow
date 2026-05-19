mod child_links;
mod tap;

use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildNetworkBootstrap {
    RootlessInternal(RootlessChildBootstrap),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootlessChildBootstrap {
    pub tap_name: String,
    pub gateway_mac: [u8; 6],
    pub child_ipv4: Ipv4Addr,
    pub gateway_ipv4: Ipv4Addr,
    pub child_ipv6: Ipv6Addr,
    pub gateway_ipv6: Ipv6Addr,
    pub child_ipv4_prefix_len: u8,
    pub child_ipv6_prefix_len: u8,
}

pub(super) fn apply_child_network_bootstrap(
    bootstrap: &ChildNetworkBootstrap,
) -> Result<Option<File>> {
    match bootstrap {
        ChildNetworkBootstrap::RootlessInternal(config) => {
            let (tap_file, actual_tap_name) = tap::create_tap_device(&config.tap_name)?;
            child_links::bring_rootless_child_links_up(config, &actual_tap_name)?;
            Ok(Some(tap_file))
        }
    }
}
