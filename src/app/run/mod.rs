use anyhow::Result;
use nix::unistd::{fork, pipe, ForkResult};
use std::os::unix::net::UnixStream;

use crate::cli::Cli;
use crate::dns::DnsPlan;
use crate::hosts::HostsPlan;
use crate::network;
use crate::proxy::ProxyPlan;
use crate::util;

mod child;
mod parent;

pub(super) fn run_command_tree(cli: &Cli) -> Result<i32> {
    let backend = cli.selected_backend();

    let namespace_mode = network::namespace_mode(backend);
    let run_id = util::unique_run_id();
    let network_plan = network::NetworkPlan::new();
    let child_bootstrap = network::prepare_child_bootstrap(cli, &network_plan)?;
    let dns_plan = DnsPlan::prepare(
        &run_id,
        backend,
        cli.dns,
        network_plan.host_ipv4(),
        network_plan.host_ipv6(),
    )?;
    let hosts_plan = HostsPlan::prepare(&run_id, cli.hosts_file.as_deref())?;
    let proxy_plan = ProxyPlan::from_cli(cli)?;
    let child_proxy_env = proxy_plan
        .as_ref()
        .map(ProxyPlan::child_env)
        .unwrap_or_default();

    let (read_fd, write_fd) = pipe()?;
    let (namespace_ready_read_fd, namespace_ready_write_fd) = pipe()?;
    let (ready_read_fd, ready_write_fd) = pipe()?;
    let (tap_parent, tap_child) = UnixStream::pair()?;

    match unsafe { fork()? } {
        ForkResult::Child => child::run_child_process(
            cli,
            namespace_mode,
            child_bootstrap.namespace_bootstrap(),
            dns_plan.resolv_conf_path(),
            dns_plan.resolv_conf_required(),
            hosts_plan.hosts_path(),
            child_proxy_env,
            read_fd,
            namespace_ready_write_fd,
            ready_write_fd,
            ready_read_fd,
            namespace_ready_read_fd,
            write_fd,
            tap_child,
            tap_parent,
        ),
        ForkResult::Parent { child } => parent::run_parent_process(
            cli,
            &run_id,
            backend,
            child,
            network_plan,
            dns_plan,
            proxy_plan,
            child_bootstrap,
            read_fd,
            write_fd,
            namespace_ready_read_fd,
            namespace_ready_write_fd,
            ready_read_fd,
            ready_write_fd,
            tap_parent,
            tap_child,
        ),
    }
}
