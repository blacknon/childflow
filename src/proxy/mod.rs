pub mod env;
pub mod rootful_tproxy;
pub mod rootless_connect;
pub mod types;

use anyhow::Result;

use crate::cli::Cli;
use crate::network::NetworkBackend;

pub use rootful_tproxy::TproxyHandle;

pub enum ProxyPlan {
    RootfulTransparent(rootful_tproxy::TransparentProxyPlan),
    RootlessExplicit(rootless_connect::RootlessConnectProxyPlan),
}

impl ProxyPlan {
    pub fn from_cli(cli: &Cli) -> Result<Option<Self>> {
        if cli.proxy.is_none() {
            return Ok(None);
        }

        match cli.network_backend {
            NetworkBackend::Rootful => {
                Ok(rootful_tproxy::TransparentProxyPlan::from_cli(cli)
                    .map(Self::RootfulTransparent))
            }
            NetworkBackend::RootlessInternal => Ok(Some(Self::RootlessExplicit(
                rootless_connect::RootlessConnectProxyPlan::from_cli(cli)?,
            ))),
        }
    }

    pub fn child_env(&self) -> Vec<(String, String)> {
        match self {
            Self::RootfulTransparent(_) => Vec::new(),
            Self::RootlessExplicit(plan) => plan.child_env().to_vec(),
        }
    }

    pub fn transparent_rootful(&self) -> Option<&rootful_tproxy::TransparentProxyPlan> {
        match self {
            Self::RootfulTransparent(plan) => Some(plan),
            Self::RootlessExplicit(_) => None,
        }
    }
}
