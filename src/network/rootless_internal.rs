use anyhow::{bail, Result};
use nix::unistd::Pid;

use crate::cli::Cli;

use super::types::NetworkPlan;

pub struct NetworkContext;

impl NetworkContext {
    pub fn capture_interface(&self) -> Option<&str> {
        None
    }
}

pub fn setup(
    _plan: &NetworkPlan,
    _run_id: &str,
    _child_pid: Pid,
    _cli: &Cli,
    _tproxy_port: Option<u16>,
) -> Result<NetworkContext> {
    bail!(
        "`rootless-internal` backend is experimental and not yet implemented in this phase. Phase 1 only adds backend selection, validation, and preflight scaffolding."
    );
}
