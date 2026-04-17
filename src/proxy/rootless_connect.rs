use anyhow::{bail, Context, Result};

use crate::cli::Cli;

use super::env::{build_explicit_proxy_env, render_proxy_uri};

pub struct RootlessConnectProxyPlan {
    child_env: Vec<(String, String)>,
}

impl RootlessConnectProxyPlan {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        if cli.proxy_insecure {
            bail!(
                "`--proxy-insecure` is not supported by the `rootless-internal` backend because its current explicit proxy path only injects proxy environment variables"
            );
        }

        let proxy = cli
            .proxy
            .as_ref()
            .context("rootless explicit proxy planning requires `--proxy`")?;
        let uri = render_proxy_uri(cli)?
            .context("rootless explicit proxy planning requires a rendered proxy URI")?;
        let child_env = build_explicit_proxy_env(proxy, &uri)
            .into_iter()
            .map(|var| (var.key, var.value))
            .collect();

        Ok(Self { child_env })
    }

    pub fn child_env(&self) -> &[(String, String)] {
        &self.child_env
    }
}
