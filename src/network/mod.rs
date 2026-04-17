pub mod rootful;
pub mod rootless_internal;
pub mod types;

use anyhow::{bail, Result};
use nix::unistd::Pid;

use crate::cli::Cli;
use crate::namespace::NamespaceMode;

pub use types::{NetworkBackend, NetworkPlan};

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
}

pub fn namespace_mode(backend: NetworkBackend) -> Result<NamespaceMode> {
    match backend {
        NetworkBackend::Rootful => Ok(NamespaceMode::Rootful),
        NetworkBackend::RootlessInternal => bail!(
            "`rootless-internal` backend is experimental and not yet ready for namespace bootstrap in this phase"
        ),
    }
}

pub fn setup(
    plan: &NetworkPlan,
    run_id: &str,
    child_pid: Pid,
    cli: &Cli,
    tproxy_port: Option<u16>,
) -> Result<NetworkContext> {
    match cli.network_backend {
        NetworkBackend::Rootful => {
            rootful::NetworkContext::setup(plan, run_id, child_pid, cli, tproxy_port)
                .map(NetworkContext::Rootful)
        }
        NetworkBackend::RootlessInternal => {
            rootless_internal::setup(plan, run_id, child_pid, cli, tproxy_port)
                .map(NetworkContext::RootlessInternal)
        }
    }
}
