use anyhow::Result;

use super::*;

mod chains;
mod routing;

#[derive(Clone)]
struct TproxySettings {
    listen_port: u16,
    divert_chain: String,
    tproxy_chain: String,
    tproxy_mark: u32,
    tproxy_table: u32,
    tproxy_priority: u32,
}

impl NetworkContext {
    pub(crate) fn install_tproxy_rules(&mut self) -> Result<()> {
        let Some(settings) = self.tproxy_settings() else {
            return Ok(());
        };

        chains::install_tproxy_chains(self, &settings)?;
        routing::install_tproxy_policy_routing(self, &settings)?;
        Ok(())
    }

    fn tproxy_settings(&self) -> Option<TproxySettings> {
        Some(TproxySettings {
            listen_port: self.tproxy_port?,
            divert_chain: self.divert_chain.clone().expect("divert chain missing"),
            tproxy_chain: self.tproxy_chain.clone().expect("tproxy chain missing"),
            tproxy_mark: self.tproxy_mark.expect("tproxy mark missing"),
            tproxy_table: self.tproxy_table.expect("tproxy table missing"),
            tproxy_priority: self.tproxy_priority.expect("tproxy priority missing"),
        })
    }
}
