// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod load;
mod path;
pub(crate) mod serde_impl;

#[cfg(test)]
mod tests;

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::cli::{
    Cli, DefaultPolicy, DoctorFormat, OutputView, ProxySpec, ReportFormat, SummaryFormat,
};
use crate::network::NetworkBackend;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_point: Option<OutputView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<NetworkBackend>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts_file: Option<PathBuf>,
    #[serde(
        default,
        deserialize_with = "crate::profile::serde_impl::deserialize_optional_proxy_spec",
        serialize_with = "crate::profile::serde_impl::serialize_optional_proxy_spec",
        skip_serializing_if = "Option::is_none"
    )]
    pub proxy: Option<ProxySpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_insecure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctor_format: Option<DoctorFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_format: Option<ReportFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_format: Option<SummaryFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_log: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_private: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_metadata: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_policy: Option<DefaultPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_cidrs: Option<Vec<IpNetwork>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_cidrs: Option<Vec<IpNetwork>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_domains_exact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_domains_exact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_on_leak: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

impl Profile {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let resolved = path::normalize_profile_path(path)?;
        Self::load_inner(&resolved, &mut Vec::new())
    }

    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            extends: None,
            capture: cli.output.clone(),
            capture_point: Some(cli.output_view),
            backend: Some(cli.selected_backend()),
            dns: cli.dns,
            hosts_file: cli.hosts_file.clone(),
            proxy: cli.proxy.clone(),
            proxy_user: cli.proxy_user.clone(),
            proxy_password: cli.proxy_password.clone(),
            proxy_insecure: cli.proxy_insecure.then_some(true),
            summary: cli.summary.then_some(true),
            doctor_format: cli.doctor.then_some(cli.doctor_format),
            report_format: cli.report.as_ref().map(|_| cli.report_format),
            summary_format: cli.summary.then_some(cli.summary_format),
            flow_log: cli.flow_log.clone(),
            offline: cli.offline.then_some(true),
            block_private: cli.block_private.then_some(true),
            block_metadata: cli.block_metadata.then_some(true),
            default_policy: Some(cli.default_policy),
            allow_cidrs: (!cli.allow_cidrs.is_empty()).then_some(cli.allow_cidrs.clone()),
            deny_cidrs: (!cli.deny_cidrs.is_empty()).then_some(cli.deny_cidrs.clone()),
            allow_domains_exact: (!cli.allow_domains_exact.is_empty())
                .then_some(cli.allow_domains_exact.clone()),
            allow_domains: (!cli.allow_domains.is_empty()).then_some(cli.allow_domains.clone()),
            deny_domains_exact: (!cli.deny_domains_exact.is_empty())
                .then_some(cli.deny_domains_exact.clone()),
            deny_domains: (!cli.deny_domains.is_empty()).then_some(cli.deny_domains.clone()),
            proxy_only: cli.proxy_only.then_some(true),
            fail_on_leak: cli.fail_on_leak.then_some(true),
            iface: cli.iface.clone(),
            command: (!cli.command.is_empty()).then_some(cli.command.clone()),
        }
    }

    pub fn render_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("failed to render effective profile as TOML")
    }
}
