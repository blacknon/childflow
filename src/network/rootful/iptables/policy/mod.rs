use anyhow::Result;

use super::*;

mod allow;
mod deny;
mod offline;

impl NetworkContext {
    pub(crate) fn install_sandbox_policy_rules(&mut self, policy: SandboxPolicy) -> Result<()> {
        if policy.offline {
            return self.install_offline_drop_rules();
        }

        if !policy.block_private
            && !policy.block_metadata
            && policy.deny_cidrs.is_empty()
            && !matches!(policy.default_policy, DefaultPolicy::Deny)
            && !policy.proxy_only
        {
            return Ok(());
        }

        self.install_sandbox_subnet_bypass_rules()?;

        if policy.block_metadata {
            self.install_metadata_drop_rules()?;
        }

        if policy.block_private {
            self.install_private_range_drop_rules()?;
        }

        self.install_deny_cidr_drop_rules(&policy.deny_cidrs)?;

        if policy.proxy_only {
            self.install_proxy_only_rules(&policy)?;
        } else if matches!(policy.default_policy, DefaultPolicy::Deny) {
            self.install_default_deny_rules(&policy.allow_cidrs)?;
        }

        Ok(())
    }
}
