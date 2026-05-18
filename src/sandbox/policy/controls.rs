use super::{DefaultPolicy, SandboxPolicy};

impl SandboxPolicy {
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
}
