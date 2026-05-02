// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::IpNetwork;

use crate::cli::{Cli, DefaultPolicy};
use crate::domain::matches_domain_rule;

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
    pub allow_domains: Vec<String>,
    pub deny_domains: Vec<String>,
    pub proxy_only: bool,
    pub fail_on_leak: bool,
}

impl SandboxPolicy {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            offline: cli.offline,
            block_private: cli.block_private,
            block_metadata: cli.block_metadata,
            default_policy: cli.default_policy,
            allow_cidrs: cli.allow_cidrs.clone(),
            deny_cidrs: cli.deny_cidrs.clone(),
            allow_domains: cli.allow_domains.clone(),
            deny_domains: cli.deny_domains.clone(),
            proxy_only: cli.proxy_only,
            fail_on_leak: cli.fail_on_leak,
        }
    }

    pub fn active_controls(&self) -> Vec<String> {
        let mut controls = Vec::new();
        if self.offline {
            controls.push("offline".to_string());
        }
        if self.block_private {
            controls.push("block-private".to_string());
        }
        if self.block_metadata {
            controls.push("block-metadata".to_string());
        }
        if matches!(self.default_policy, DefaultPolicy::Deny) {
            controls.push("default-policy=deny".to_string());
        }
        for cidr in &self.allow_cidrs {
            controls.push(format!("allow-cidr={cidr}"));
        }
        for cidr in &self.deny_cidrs {
            controls.push(format!("deny-cidr={cidr}"));
        }
        for domain in &self.allow_domains {
            controls.push(format!("allow-domain={domain}"));
        }
        for domain in &self.deny_domains {
            controls.push(format!("deny-domain={domain}"));
        }
        if self.proxy_only {
            controls.push("proxy-only".to_string());
        }
        if self.fail_on_leak {
            controls.push("fail-on-leak".to_string());
        }
        controls
    }

    #[allow(dead_code)]
    pub fn block_reason_for_remote_ip(&self, ip: IpAddr) -> Option<BlockReason> {
        self.block_reason_for_remote_ip_with_domains(ip, None)
    }

    pub fn block_reason_for_remote_ip_with_domains(
        &self,
        ip: IpAddr,
        resolved_domains: Option<&BTreeSet<String>>,
    ) -> Option<BlockReason> {
        self.block_reason_for_remote(ip, None, resolved_domains)
    }

    pub fn block_reason_for_dns_name(&self, qname: &str) -> Option<BlockReason> {
        if let Some(domain) = self.matching_denied_domain_name(qname) {
            return Some(BlockReason::DeniedDomain(domain.to_string()));
        }
        if matches!(self.default_policy, DefaultPolicy::Deny)
            && !self.allow_domains.is_empty()
            && !self.matches_allowed_domain_name(qname)
        {
            return Some(BlockReason::DefaultDeny);
        }
        None
    }

    #[allow(dead_code)]
    pub fn block_reason_for_tcp_remote_ip(
        &self,
        ip: IpAddr,
        is_proxied: bool,
    ) -> Option<BlockReason> {
        self.block_reason_for_tcp_remote_ip_with_domains(ip, is_proxied, None)
    }

    pub fn block_reason_for_tcp_remote_ip_with_domains(
        &self,
        ip: IpAddr,
        is_proxied: bool,
        resolved_domains: Option<&BTreeSet<String>>,
    ) -> Option<BlockReason> {
        self.block_reason_for_remote(ip, Some(is_proxied), resolved_domains)
    }

    fn block_reason_for_remote(
        &self,
        ip: IpAddr,
        is_proxied: Option<bool>,
        resolved_domains: Option<&BTreeSet<String>>,
    ) -> Option<BlockReason> {
        if self.offline {
            return Some(BlockReason::Offline);
        }
        if self.block_metadata && is_metadata_ip(ip) {
            return Some(BlockReason::Metadata);
        }
        if self.block_private && is_private_ip(ip) {
            return Some(BlockReason::Private);
        }
        if let Some(cidr) = self.deny_cidrs.iter().find(|cidr| cidr.contains(ip)) {
            return Some(BlockReason::DeniedCidr(*cidr));
        }
        if let Some(domain) = self.matching_denied_domain(resolved_domains) {
            return Some(BlockReason::DeniedDomain(domain.to_string()));
        }
        if self.allow_cidrs.iter().any(|cidr| cidr.contains(ip)) {
            return None;
        }
        if self.matches_allowed_domain(resolved_domains) {
            return None;
        }
        if matches!(self.default_policy, DefaultPolicy::Deny) {
            return Some(BlockReason::DefaultDeny);
        }
        if is_proxied != Some(true) && self.proxy_only {
            return Some(BlockReason::ProxyOnly);
        }
        None
    }

    fn matching_denied_domain(&self, resolved_domains: Option<&BTreeSet<String>>) -> Option<&str> {
        let domains = resolved_domains?;
        self.deny_domains.iter().find_map(|rule| {
            domains
                .iter()
                .any(|qname| matches_domain_rule(qname, rule))
                .then_some(rule.as_str())
        })
    }

    fn matching_denied_domain_name<'a>(&'a self, qname: &str) -> Option<&'a str> {
        self.deny_domains
            .iter()
            .find_map(|rule| matches_domain_rule(qname, rule).then_some(rule.as_str()))
    }

    fn matches_allowed_domain(&self, resolved_domains: Option<&BTreeSet<String>>) -> bool {
        let Some(domains) = resolved_domains else {
            return false;
        };
        self.allow_domains
            .iter()
            .any(|rule| domains.iter().any(|qname| matches_domain_rule(qname, rule)))
    }

    fn matches_allowed_domain_name(&self, qname: &str) -> bool {
        self.allow_domains
            .iter()
            .any(|rule| matches_domain_rule(qname, rule))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockReason {
    Offline,
    Metadata,
    Private,
    DeniedCidr(IpNetwork),
    DeniedDomain(String),
    DefaultDeny,
    ProxyOnly,
}

impl BlockReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Metadata => "metadata",
            Self::Private => "private",
            Self::DeniedCidr(_) => "deny_cidr",
            Self::DeniedDomain(_) => "deny_domain",
            Self::DefaultDeny => "default_deny",
            Self::ProxyOnly => "proxy_only",
        }
    }

    pub fn control(&self) -> &'static str {
        match self {
            Self::Offline => "--offline",
            Self::Metadata => "--block-metadata",
            Self::Private => "--block-private",
            Self::DeniedCidr(_) => "--deny-cidr",
            Self::DeniedDomain(_) => "--deny-domain",
            Self::DefaultDeny => "--default-policy",
            Self::ProxyOnly => "--proxy-only",
        }
    }

    pub fn matched_cidr(&self) -> Option<IpNetwork> {
        match self {
            Self::DeniedCidr(cidr) => Some(*cidr),
            _ => None,
        }
    }

    pub fn matched_domain(&self) -> Option<&str> {
        match self {
            Self::DeniedDomain(domain) => Some(domain.as_str()),
            _ => None,
        }
    }

    pub fn describe(&self) -> Cow<'static, str> {
        match self {
            Self::Offline => Cow::Borrowed("blocked by `--offline`"),
            Self::Metadata => Cow::Borrowed("blocked by `--block-metadata`"),
            Self::Private => Cow::Borrowed("blocked by `--block-private`"),
            Self::DeniedCidr(cidr) => Cow::Owned(format!("blocked by `--deny-cidr {cidr}`")),
            Self::DeniedDomain(domain) => {
                Cow::Owned(format!("blocked by `--deny-domain {domain}`"))
            }
            Self::DefaultDeny => Cow::Borrowed("blocked by `--default-policy deny`"),
            Self::ProxyOnly => Cow::Borrowed("blocked by `--proxy-only`"),
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
            default_policy: DefaultPolicy::Deny,
            allow_cidrs: vec!["169.254.169.254/32".parse().unwrap()],
            deny_cidrs: Vec::new(),
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            proxy_only: false,
            fail_on_leak: false,
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

    #[test]
    fn active_controls_are_reported_in_stable_order() {
        let policy = SandboxPolicy {
            offline: true,
            block_private: true,
            block_metadata: true,
            default_policy: DefaultPolicy::Deny,
            allow_cidrs: vec!["192.0.2.0/24".parse().unwrap()],
            deny_cidrs: vec!["198.51.100.0/24".parse().unwrap()],
            allow_domains: vec!["example.com".into()],
            deny_domains: vec!["blocked.example.com".into()],
            proxy_only: true,
            fail_on_leak: true,
        };

        assert_eq!(
            policy.active_controls(),
            vec![
                "offline".to_string(),
                "block-private".to_string(),
                "block-metadata".to_string(),
                "default-policy=deny".to_string(),
                "allow-cidr=192.0.2.0/24".to_string(),
                "deny-cidr=198.51.100.0/24".to_string(),
                "allow-domain=example.com".to_string(),
                "deny-domain=blocked.example.com".to_string(),
                "proxy-only".to_string(),
                "fail-on-leak".to_string(),
            ]
        );
    }

    #[test]
    fn block_metadata_reason_is_more_specific_than_block_private() {
        let policy = SandboxPolicy {
            offline: false,
            block_private: true,
            block_metadata: true,
            default_policy: DefaultPolicy::Allow,
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            proxy_only: false,
            fail_on_leak: false,
        };

        assert_eq!(
            policy.block_reason_for_remote_ip(IpAddr::V4(BLOCK_METADATA_IPV4)),
            Some(BlockReason::Metadata)
        );
    }

    #[test]
    fn deny_cidr_blocks_matching_destination() {
        let policy = SandboxPolicy {
            offline: false,
            block_private: false,
            block_metadata: false,
            default_policy: DefaultPolicy::Allow,
            allow_cidrs: Vec::new(),
            deny_cidrs: vec!["203.0.113.0/24".parse().unwrap()],
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            proxy_only: false,
            fail_on_leak: false,
        };

        assert_eq!(
            policy.block_reason_for_remote_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            Some(BlockReason::DeniedCidr("203.0.113.0/24".parse().unwrap()))
        );
    }

    #[test]
    fn default_deny_allows_matching_allow_cidr() {
        let policy = SandboxPolicy {
            offline: false,
            block_private: false,
            block_metadata: false,
            default_policy: DefaultPolicy::Deny,
            allow_cidrs: vec!["203.0.113.0/24".parse().unwrap()],
            deny_cidrs: Vec::new(),
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            proxy_only: false,
            fail_on_leak: false,
        };

        assert_eq!(
            policy.block_reason_for_remote_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            None
        );
        assert_eq!(
            policy.block_reason_for_remote_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
            Some(BlockReason::DefaultDeny)
        );
    }

    #[test]
    fn deny_cidr_is_more_specific_than_allow_cidr() {
        let policy = SandboxPolicy {
            offline: false,
            block_private: false,
            block_metadata: false,
            default_policy: DefaultPolicy::Deny,
            allow_cidrs: vec!["203.0.113.0/24".parse().unwrap()],
            deny_cidrs: vec!["203.0.113.128/25".parse().unwrap()],
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            proxy_only: false,
            fail_on_leak: false,
        };

        assert_eq!(
            policy.block_reason_for_remote_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))),
            Some(BlockReason::DeniedCidr("203.0.113.128/25".parse().unwrap()))
        );
    }

    #[test]
    fn proxy_only_blocks_direct_traffic_when_not_proxied() {
        let policy = SandboxPolicy {
            offline: false,
            block_private: false,
            block_metadata: false,
            default_policy: DefaultPolicy::Allow,
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            proxy_only: true,
            fail_on_leak: false,
        };

        assert_eq!(
            policy.block_reason_for_remote_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
            Some(BlockReason::ProxyOnly)
        );
        assert_eq!(
            policy
                .block_reason_for_tcp_remote_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), true),
            None
        );
    }

    #[test]
    fn block_reason_exposes_stable_schema_fields() {
        let reason = BlockReason::DeniedCidr("203.0.113.0/24".parse().unwrap());

        assert_eq!(reason.code(), "deny_cidr");
        assert_eq!(reason.control(), "--deny-cidr");
        assert_eq!(
            reason.matched_cidr(),
            Some("203.0.113.0/24".parse().unwrap())
        );
        assert_eq!(reason.matched_domain(), None);
    }

    #[test]
    fn deny_domain_blocks_matching_resolved_name() {
        let policy = SandboxPolicy {
            offline: false,
            block_private: false,
            block_metadata: false,
            default_policy: DefaultPolicy::Allow,
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            allow_domains: Vec::new(),
            deny_domains: vec!["example.com".into()],
            proxy_only: false,
            fail_on_leak: false,
        };
        let resolved = BTreeSet::from(["api.example.com".to_string()]);

        let reason = policy
            .block_reason_for_tcp_remote_ip_with_domains(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                false,
                Some(&resolved),
            )
            .unwrap();

        assert_eq!(reason.code(), "deny_domain");
        assert_eq!(reason.control(), "--deny-domain");
        assert_eq!(reason.matched_domain(), Some("example.com"));
    }

    #[test]
    fn default_deny_allows_matching_allow_domain() {
        let policy = SandboxPolicy {
            offline: false,
            block_private: false,
            block_metadata: false,
            default_policy: DefaultPolicy::Deny,
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            allow_domains: vec!["example.com".into()],
            deny_domains: Vec::new(),
            proxy_only: false,
            fail_on_leak: false,
        };
        let resolved = BTreeSet::from(["api.example.com".to_string()]);

        assert_eq!(
            policy.block_reason_for_remote_ip_with_domains(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                Some(&resolved),
            ),
            None
        );
        assert_eq!(policy.block_reason_for_dns_name("api.example.com"), None);
    }

    #[test]
    fn default_deny_blocks_unmatched_dns_name_when_allow_domains_exist() {
        let policy = SandboxPolicy {
            offline: false,
            block_private: false,
            block_metadata: false,
            default_policy: DefaultPolicy::Deny,
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            allow_domains: vec!["example.com".into()],
            deny_domains: Vec::new(),
            proxy_only: false,
            fail_on_leak: false,
        };

        assert_eq!(
            policy.block_reason_for_dns_name("blocked.test"),
            Some(BlockReason::DefaultDeny)
        );
    }
}
