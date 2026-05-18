use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::domain::{matches_domain_rule, matches_exact_domain_rule};

use super::{is_metadata_ip, is_private_ip, BlockReason, Cli, DefaultPolicy, SandboxPolicy};

impl SandboxPolicy {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            offline: cli.offline,
            block_private: cli.block_private,
            block_metadata: cli.block_metadata,
            default_policy: cli.default_policy,
            allow_cidrs: cli.allow_cidrs.clone(),
            deny_cidrs: cli.deny_cidrs.clone(),
            allow_domains_exact: cli.allow_domains_exact.clone(),
            allow_domains: cli.allow_domains.clone(),
            deny_domains_exact: cli.deny_domains_exact.clone(),
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
        for domain in &self.allow_domains_exact {
            controls.push(format!("allow-domain-exact={domain}"));
        }
        for domain in &self.allow_domains {
            controls.push(format!("allow-domain={domain}"));
        }
        for domain in &self.deny_domains_exact {
            controls.push(format!("deny-domain-exact={domain}"));
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
        if let Some(domain) = self.matching_denied_exact_domain_name(qname) {
            return Some(BlockReason::DeniedExactDomain(domain.to_string()));
        }
        if let Some(domain) = self.matching_denied_domain_name(qname) {
            return Some(BlockReason::DeniedDomain(domain.to_string()));
        }
        if matches!(self.default_policy, DefaultPolicy::Deny)
            && (!self.allow_domains_exact.is_empty() || !self.allow_domains.is_empty())
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
        if let Some(domain) = self.matching_denied_exact_domain(resolved_domains) {
            return Some(BlockReason::DeniedExactDomain(domain.to_string()));
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

    fn matching_denied_exact_domain(
        &self,
        resolved_domains: Option<&BTreeSet<String>>,
    ) -> Option<&str> {
        let domains = resolved_domains?;
        self.deny_domains_exact.iter().find_map(|rule| {
            domains
                .iter()
                .any(|qname| matches_exact_domain_rule(qname, rule))
                .then_some(rule.as_str())
        })
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

    fn matching_denied_exact_domain_name<'a>(&'a self, qname: &str) -> Option<&'a str> {
        self.deny_domains_exact
            .iter()
            .find_map(|rule| matches_exact_domain_rule(qname, rule).then_some(rule.as_str()))
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
        self.allow_domains_exact.iter().any(|rule| {
            domains
                .iter()
                .any(|qname| matches_exact_domain_rule(qname, rule))
        }) || self
            .allow_domains
            .iter()
            .any(|rule| domains.iter().any(|qname| matches_domain_rule(qname, rule)))
    }

    fn matches_allowed_domain_name(&self, qname: &str) -> bool {
        self.allow_domains_exact
            .iter()
            .any(|rule| matches_exact_domain_rule(qname, rule))
            || self
                .allow_domains
                .iter()
                .any(|rule| matches_domain_rule(qname, rule))
    }
}
