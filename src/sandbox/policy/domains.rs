use std::collections::BTreeSet;

use crate::domain::{matches_domain_rule, matches_exact_domain_rule};

use super::SandboxPolicy;

impl SandboxPolicy {
    pub(super) fn matching_denied_exact_domain(
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

    pub(super) fn matching_denied_domain(
        &self,
        resolved_domains: Option<&BTreeSet<String>>,
    ) -> Option<&str> {
        let domains = resolved_domains?;
        self.deny_domains.iter().find_map(|rule| {
            domains
                .iter()
                .any(|qname| matches_domain_rule(qname, rule))
                .then_some(rule.as_str())
        })
    }

    pub(super) fn matching_denied_exact_domain_name<'a>(&'a self, qname: &str) -> Option<&'a str> {
        self.deny_domains_exact
            .iter()
            .find_map(|rule| matches_exact_domain_rule(qname, rule).then_some(rule.as_str()))
    }

    pub(super) fn matching_denied_domain_name<'a>(&'a self, qname: &str) -> Option<&'a str> {
        self.deny_domains
            .iter()
            .find_map(|rule| matches_domain_rule(qname, rule).then_some(rule.as_str()))
    }

    pub(super) fn matches_allowed_domain(
        &self,
        resolved_domains: Option<&BTreeSet<String>>,
    ) -> bool {
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

    pub(super) fn matches_allowed_domain_name(&self, qname: &str) -> bool {
        self.allow_domains_exact
            .iter()
            .any(|rule| matches_exact_domain_rule(qname, rule))
            || self
                .allow_domains
                .iter()
                .any(|rule| matches_domain_rule(qname, rule))
    }
}
