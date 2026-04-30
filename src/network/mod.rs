// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

pub mod rootful;
pub mod rootless_internal;
pub mod types;

use anyhow::Result;
use nix::unistd::Pid;

use crate::capture::CapturePlan;
use crate::cli::Cli;
use crate::cli::OutputView;
use crate::dns::DnsPlan;
use crate::namespace::{ChildNetworkBootstrap, NamespaceMode};
use crate::proxy::ProxyPlan;

pub use types::{NetworkBackend, NetworkPlan};

pub enum ChildBootstrap {
    Rootful,
    RootlessInternal(rootless_internal::ChildBootstrap),
}

impl ChildBootstrap {
    pub fn namespace_bootstrap(&self) -> Option<ChildNetworkBootstrap> {
        match self {
            Self::Rootful => None,
            Self::RootlessInternal(bootstrap) => Some(bootstrap.namespace_bootstrap()),
        }
    }
}

pub enum NetworkContext {
    Rootful(Box<rootful::NetworkContext>),
    RootlessInternal(rootless_internal::NetworkContext),
}

impl NetworkContext {
    pub fn capture_plan(
        &self,
        output_path: &std::path::Path,
        output_view: OutputView,
    ) -> Result<Option<CapturePlan>> {
        match self {
            Self::Rootful(ctx) => ctx.capture_plan(output_path, output_view).map(Some),
            Self::RootlessInternal(ctx) => Ok(match output_view {
                OutputView::WireEgress => ctx.capture_plan(),
                _ => None,
            }),
        }
    }

    pub fn dns_bind_addrs(&self) -> Option<(std::net::Ipv4Addr, std::net::Ipv6Addr)> {
        match self {
            Self::Rootful(ctx) => Some(ctx.dns_bind_addrs()),
            Self::RootlessInternal(_) => None,
        }
    }
}

pub fn namespace_mode(backend: NetworkBackend) -> NamespaceMode {
    match backend {
        NetworkBackend::Rootful => NamespaceMode::Rootful,
        NetworkBackend::RootlessInternal => NamespaceMode::RootlessInternal,
    }
}

pub fn prepare_child_bootstrap(cli: &Cli, plan: &NetworkPlan) -> Result<ChildBootstrap> {
    match cli.selected_backend() {
        NetworkBackend::Rootful => Ok(ChildBootstrap::Rootful),
        NetworkBackend::RootlessInternal => {
            rootless_internal::ChildBootstrap::prepare(plan).map(ChildBootstrap::RootlessInternal)
        }
    }
}

pub fn setup(params: NetworkSetupParams<'_>) -> Result<NetworkContext> {
    match params.cli.selected_backend() {
        NetworkBackend::Rootful => rootful::NetworkContext::setup(
            params.plan,
            params.run_id,
            params.child_pid,
            params.cli,
            params.tproxy_port,
        )
        .map(Box::new)
        .map(NetworkContext::Rootful),
        NetworkBackend::RootlessInternal => match params.child_bootstrap {
            ChildBootstrap::RootlessInternal(bootstrap) => rootless_internal::setup(
                params.plan,
                params.run_id,
                params.child_pid,
                params.cli,
                params.tproxy_port,
                rootless_internal::RootlessSetupParams {
                    dns_plan: params.dns_plan,
                    child_bootstrap: bootstrap,
                    proxy_plan: params.proxy_plan,
                },
            )
            .map(NetworkContext::RootlessInternal),
            ChildBootstrap::Rootful => unreachable!(
                "rootless-internal backend must not be paired with rootful child bootstrap"
            ),
        },
    }
}

pub struct NetworkSetupParams<'a> {
    pub plan: &'a NetworkPlan,
    pub run_id: &'a str,
    pub child_pid: Pid,
    pub cli: &'a Cli,
    pub dns_plan: &'a DnsPlan,
    pub tproxy_port: Option<u16>,
    pub child_bootstrap: &'a mut ChildBootstrap,
    pub proxy_plan: Option<&'a ProxyPlan>,
}
