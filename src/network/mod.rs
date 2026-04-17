pub mod rootful;
pub mod rootless_internal;
pub mod types;

use anyhow::Result;
use nix::unistd::Pid;

use crate::cli::Cli;
use crate::dns::DnsPlan;
use crate::namespace::{ChildNetworkBootstrap, NamespaceMode};

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
    Rootful(rootful::NetworkContext),
    RootlessInternal(rootless_internal::NetworkContext),
}

impl NetworkContext {
    pub fn capture_interface(&self) -> Option<&str> {
        match self {
            Self::Rootful(ctx) => Some(ctx.host_veth()),
            Self::RootlessInternal(ctx) => ctx.capture_interface(),
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
    match cli.network_backend {
        NetworkBackend::Rootful => Ok(ChildBootstrap::Rootful),
        NetworkBackend::RootlessInternal => {
            rootless_internal::ChildBootstrap::prepare(plan).map(ChildBootstrap::RootlessInternal)
        }
    }
}

pub fn setup(
    plan: &NetworkPlan,
    run_id: &str,
    child_pid: Pid,
    cli: &Cli,
    dns_plan: &DnsPlan,
    tproxy_port: Option<u16>,
    child_bootstrap: &mut ChildBootstrap,
) -> Result<NetworkContext> {
    match cli.network_backend {
        NetworkBackend::Rootful => {
            rootful::NetworkContext::setup(plan, run_id, child_pid, cli, tproxy_port)
                .map(NetworkContext::Rootful)
        }
        NetworkBackend::RootlessInternal => match child_bootstrap {
            ChildBootstrap::RootlessInternal(bootstrap) => rootless_internal::setup(
                plan,
                run_id,
                child_pid,
                cli,
                dns_plan,
                tproxy_port,
                bootstrap,
            )
            .map(NetworkContext::RootlessInternal),
            ChildBootstrap::Rootful => unreachable!(
                "rootless-internal backend must not be paired with rootful child bootstrap"
            ),
        },
    }
}
