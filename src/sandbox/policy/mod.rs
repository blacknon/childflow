use std::collections::BTreeSet;
use std::net::IpAddr;

use super::{is_metadata_ip, is_private_ip, BlockReason, Cli, DefaultPolicy, SandboxPolicy};

mod controls;
mod domains;

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
}
