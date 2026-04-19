// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

#[cfg(test)]
pub mod env;
pub mod rootful_tproxy;
pub mod rootless_relay;
#[cfg(test)]
pub mod types;

use anyhow::Result;

use crate::cli::Cli;
use crate::network::NetworkBackend;

pub use rootful_tproxy::TproxyHandle;

pub enum ProxyPlan {
    RootfulTransparent(rootful_tproxy::TransparentProxyPlan),
    RootlessRelay(rootless_relay::RootlessRelayProxyPlan),
}

impl ProxyPlan {
    pub fn from_cli(cli: &Cli) -> Result<Option<Self>> {
        if cli.proxy.is_none() {
            return Ok(None);
        }

        match cli.selected_backend() {
            NetworkBackend::Rootful => {
                Ok(rootful_tproxy::TransparentProxyPlan::from_cli(cli)
                    .map(Self::RootfulTransparent))
            }
            NetworkBackend::RootlessInternal => Ok(Some(Self::RootlessRelay(
                rootless_relay::RootlessRelayProxyPlan::from_cli(cli)?,
            ))),
        }
    }

    pub fn child_env(&self) -> Vec<(String, String)> {
        match self {
            Self::RootfulTransparent(_) => Vec::new(),
            Self::RootlessRelay(_) => Vec::new(),
        }
    }

    pub fn transparent_rootful(&self) -> Option<&rootful_tproxy::TransparentProxyPlan> {
        match self {
            Self::RootfulTransparent(plan) => Some(plan),
            Self::RootlessRelay(_) => None,
        }
    }

    pub fn rootless_upstream(&self) -> Option<&rootless_relay::ProxyUpstreamConfig> {
        match self {
            Self::RootfulTransparent(_) => None,
            Self::RootlessRelay(plan) => Some(plan.upstream()),
        }
    }
}
