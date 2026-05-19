use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

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
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
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
        allow_domains_exact: vec!["auth.example.com".into()],
        allow_domains: vec!["example.com".into()],
        deny_domains_exact: vec!["blocked.auth.example.com".into()],
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
            "allow-domain-exact=auth.example.com".to_string(),
            "allow-domain=example.com".to_string(),
            "deny-domain-exact=blocked.auth.example.com".to_string(),
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
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
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
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
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
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
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
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
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
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
        deny_domains: Vec::new(),
        proxy_only: true,
        fail_on_leak: false,
    };

    assert_eq!(
        policy.block_reason_for_remote_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
        Some(BlockReason::ProxyOnly)
    );
    assert_eq!(
        policy.block_reason_for_tcp_remote_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), true),
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
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
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
fn deny_domain_exact_blocks_only_exact_resolved_name() {
    let policy = SandboxPolicy {
        offline: false,
        block_private: false,
        block_metadata: false,
        default_policy: DefaultPolicy::Allow,
        allow_cidrs: Vec::new(),
        deny_cidrs: Vec::new(),
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: vec!["auth.example.com".into()],
        deny_domains: vec!["example.com".into()],
        proxy_only: false,
        fail_on_leak: false,
    };
    let resolved = BTreeSet::from(["auth.example.com".to_string()]);

    let reason = policy
        .block_reason_for_tcp_remote_ip_with_domains(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            false,
            Some(&resolved),
        )
        .unwrap();

    assert_eq!(reason.code(), "deny_domain_exact");
    assert_eq!(reason.control(), "--deny-domain-exact");
    assert_eq!(reason.matched_domain(), Some("auth.example.com"));
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
        allow_domains_exact: Vec::new(),
        allow_domains: vec!["example.com".into()],
        deny_domains_exact: Vec::new(),
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
fn default_deny_allows_matching_allow_domain_exact() {
    let policy = SandboxPolicy {
        offline: false,
        block_private: false,
        block_metadata: false,
        default_policy: DefaultPolicy::Deny,
        allow_cidrs: Vec::new(),
        deny_cidrs: Vec::new(),
        allow_domains_exact: vec!["auth.example.com".into()],
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
        deny_domains: Vec::new(),
        proxy_only: false,
        fail_on_leak: false,
    };
    let resolved = BTreeSet::from(["auth.example.com".to_string()]);

    assert_eq!(
        policy.block_reason_for_remote_ip_with_domains(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            Some(&resolved),
        ),
        None
    );
    assert_eq!(policy.block_reason_for_dns_name("auth.example.com"), None);
    assert_eq!(
        policy.block_reason_for_dns_name("api.auth.example.com"),
        Some(BlockReason::DefaultDeny)
    );
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
        allow_domains_exact: Vec::new(),
        allow_domains: vec!["example.com".into()],
        deny_domains_exact: Vec::new(),
        deny_domains: Vec::new(),
        proxy_only: false,
        fail_on_leak: false,
    };

    assert_eq!(
        policy.block_reason_for_dns_name("blocked.test"),
        Some(BlockReason::DefaultDeny)
    );
}
