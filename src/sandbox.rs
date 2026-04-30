// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::cli::Cli;

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SandboxPolicy {
    pub offline: bool,
    pub block_private: bool,
    pub block_metadata: bool,
}

impl SandboxPolicy {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            offline: cli.offline,
            block_private: cli.block_private,
            block_metadata: cli.block_metadata,
        }
    }

    pub fn active_controls(&self) -> Vec<&'static str> {
        let mut controls = Vec::new();
        if self.offline {
            controls.push("offline");
        }
        if self.block_private {
            controls.push("block-private");
        }
        if self.block_metadata {
            controls.push("block-metadata");
        }
        controls
    }

    pub fn block_reason_for_remote_ip(&self, ip: IpAddr) -> Option<BlockReason> {
        if self.offline {
            return Some(BlockReason::Offline);
        }
        if self.block_metadata && is_metadata_ip(ip) {
            return Some(BlockReason::Metadata);
        }
        if self.block_private && is_private_ip(ip) {
            return Some(BlockReason::Private);
        }
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReason {
    Offline,
    Metadata,
    Private,
}

impl BlockReason {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Offline => "blocked by `--offline`",
            Self::Metadata => "blocked by `--block-metadata`",
            Self::Private => "blocked by `--block-private`",
        }
    }
}

pub fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value == BLOCK_METADATA_IPV4,
        IpAddr::V6(value) => value == BLOCK_METADATA_IPV6,
    }
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => is_private_ipv4(value),
        IpAddr::V6(value) => is_private_ipv6(value),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_reason_prioritizes_offline() {
        let policy = SandboxPolicy {
            offline: true,
            block_private: true,
            block_metadata: true,
        };

        assert_eq!(
            policy.block_reason_for_remote_ip(IpAddr::V4(BLOCK_METADATA_IPV4)),
            Some(BlockReason::Offline)
        );
    }

    #[test]
    fn metadata_ips_are_not_misclassified() {
        assert!(is_metadata_ip(IpAddr::V4(BLOCK_METADATA_IPV4)));
        assert!(is_metadata_ip(IpAddr::V6(BLOCK_METADATA_IPV6)));
        assert!(!is_metadata_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
    }

    #[test]
    fn private_ranges_cover_ipv4_and_ipv6_local_scopes() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_private_ip(IpAddr::V6("fd00::1".parse().unwrap())));
        assert!(is_private_ip(IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }
}
