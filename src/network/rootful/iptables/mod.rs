use anyhow::Result;
use ipnetwork::IpNetwork;

use super::cleanup::{replace_action_flag, run_ip6tables, run_iptables};
use super::routes::{discover_default_route6_for_interface, discover_default_route_for_interface};
use super::NetworkContext;
use crate::cli::DefaultPolicy;
use crate::sandbox::{
    SandboxPolicy, BLOCK_METADATA_IPV4, BLOCK_METADATA_IPV6, PRIVATE_IPV4_CIDRS, PRIVATE_IPV6_CIDRS,
};

mod forwarding;
mod policy;
mod routing;
mod tproxy;
