// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod capture;
mod cleanup;
mod iptables;
mod lifecycle;
mod netns;
mod routes;
mod setup;
mod sysctl;

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use nix::unistd::Pid;

use self::cleanup::CleanupAction;
use self::routes::{discover_rootful_egress_ips, discover_rootful_wire_egress_iface};
use super::types::NetworkPlan;
use crate::cli::{Cli, OutputView};
use crate::sandbox::SandboxPolicy;
use crate::util::debug;

pub struct NetworkContext {
    host_veth: String,
    child_veth: String,
    host_ipv4: Ipv4Addr,
    child_ipv4: Ipv4Addr,
    subnet_v4_cidr: String,
    host_ipv6: Ipv6Addr,
    child_ipv6: Ipv6Addr,
    subnet_v6_cidr: String,
    egress_ipv4: Option<Ipv4Addr>,
    egress_ipv6: Option<Ipv6Addr>,
    wire_egress_iface: Option<String>,
    iface: Option<String>,
    route_mark: Option<u32>,
    route_table: Option<u32>,
    route_priority: Option<u32>,
    tproxy_mark: Option<u32>,
    tproxy_table: Option<u32>,
    tproxy_priority: Option<u32>,
    divert_chain: Option<String>,
    tproxy_chain: Option<String>,
    tproxy_port: Option<u16>,
    cleanup_actions: Vec<CleanupAction>,
}

impl NetworkContext {
    pub fn setup(
        plan: &NetworkPlan,
        run_id: &str,
        child_pid: Pid,
        cli: &Cli,
        tproxy_port: Option<u16>,
    ) -> Result<Self> {
        let mut ctx = Self {
            host_veth: plan.host_veth.clone(),
            child_veth: plan.child_veth.clone(),
            host_ipv4: plan.host_ipv4,
            child_ipv4: plan.child_ipv4,
            subnet_v4_cidr: plan.subnet_v4_cidr.clone(),
            host_ipv6: plan.host_ipv6,
            child_ipv6: plan.child_ipv6,
            subnet_v6_cidr: plan.subnet_v6_cidr.clone(),
            egress_ipv4: None,
            egress_ipv6: None,
            wire_egress_iface: None,
            iface: cli.iface.clone(),
            route_mark: cli.iface.as_ref().map(|_| plan.route_mark),
            route_table: cli.iface.as_ref().map(|_| plan.route_table),
            route_priority: cli.iface.as_ref().map(|_| plan.route_priority),
            tproxy_mark: tproxy_port.map(|_| plan.tproxy_mark),
            tproxy_table: tproxy_port.map(|_| plan.tproxy_table),
            tproxy_priority: tproxy_port.map(|_| plan.tproxy_priority),
            divert_chain: tproxy_port.map(|_| plan.divert_chain.clone()),
            tproxy_chain: tproxy_port.map(|_| plan.tproxy_chain.clone()),
            tproxy_port,
            cleanup_actions: Vec::new(),
        };

        debug(format!(
            "setting up run_id={run_id} host_veth={} child_veth={}",
            ctx.host_veth, ctx.child_veth
        ));

        if cli.output.is_some() && matches!(cli.output_view, OutputView::Egress | OutputView::Both)
        {
            let (egress_ipv4, egress_ipv6) = discover_rootful_egress_ips(cli.iface.as_deref())?;
            ctx.egress_ipv4 = egress_ipv4;
            ctx.egress_ipv6 = egress_ipv6;
        }

        if cli.output.is_some() && cli.output_view == OutputView::WireEgress {
            ctx.wire_egress_iface = Some(discover_rootful_wire_egress_iface(cli.iface.as_deref())?);
        }

        ctx.prepare_sysctls()?;
        ctx.create_veth_pair(child_pid)?;
        ctx.configure_child_namespace(child_pid)?;
        ctx.install_sandbox_policy_rules(SandboxPolicy::from_cli(cli))?;
        ctx.install_forwarding_rules()?;
        ctx.install_interface_forcing()?;
        ctx.install_tproxy_rules()?;

        Ok(ctx)
    }
}
