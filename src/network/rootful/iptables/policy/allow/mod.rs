use anyhow::Result;

use super::*;

mod default_deny;
mod proxy_only;

impl NetworkContext {
    pub(super) fn install_proxy_only_rules(&mut self, policy: &SandboxPolicy) -> Result<()> {
        proxy_only::install_proxy_only_rules(self, policy)
    }

    pub(super) fn install_default_deny_rules(&mut self, allow_cidrs: &[IpNetwork]) -> Result<()> {
        default_deny::install_default_deny_rules(self, allow_cidrs)
    }
}
