// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod network;
mod policy;
mod reason;

#[cfg(test)]
mod tests;

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnetwork::IpNetwork;

use crate::cli::{Cli, DefaultPolicy};

pub use self::network::{is_metadata_ip, is_private_ip};
pub use self::reason::BlockReason;

pub const PRIVATE_IPV4_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

pub const PRIVATE_IPV6_CIDRS: &[&str] = &["::1/128", "fc00::/7", "fe80::/10"];

pub const BLOCK_METADATA_IPV4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
pub const BLOCK_METADATA_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SandboxPolicy {
    pub offline: bool,
    pub block_private: bool,
    pub block_metadata: bool,
    pub default_policy: DefaultPolicy,
    pub allow_cidrs: Vec<IpNetwork>,
    pub deny_cidrs: Vec<IpNetwork>,
    pub allow_domains_exact: Vec<String>,
    pub allow_domains: Vec<String>,
    pub deny_domains_exact: Vec<String>,
    pub deny_domains: Vec<String>,
    pub proxy_only: bool,
    pub fail_on_leak: bool,
}
