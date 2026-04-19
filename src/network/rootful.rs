// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsFd;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use nix::sched::{setns, CloneFlags};
use nix::unistd::Pid;

use super::types::NetworkPlan;
use crate::cli::Cli;
use crate::util::{debug, read_file_trimmed, run_command, warn};

pub struct NetworkContext {
    host_veth: String,
    child_veth: String,
    host_ipv4: Ipv4Addr,
    child_ipv4: Ipv4Addr,
    subnet_v4_cidr: String,
    host_ipv6: Ipv6Addr,
    child_ipv6: Ipv6Addr,
    subnet_v6_cidr: String,
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

enum CleanupAction {
    RestoreFile {
        path: String,
        value: String,
    },
    RunCommand {
        label: &'static str,
        program: &'static str,
        args: Vec<String>,
    },
    RunIptables {
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    },
    RunIp6tables {
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    },
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

        ctx.prepare_sysctls()?;
        ctx.create_veth_pair(child_pid)?;
        ctx.configure_child_namespace(child_pid)?;
        ctx.install_forwarding_rules()?;
        ctx.install_interface_forcing()?;
        ctx.install_tproxy_rules()?;

        Ok(ctx)
    }

    pub fn host_veth(&self) -> &str {
        &self.host_veth
    }

    pub fn dns_bind_addrs(&self) -> (Ipv4Addr, Ipv6Addr) {
        (self.host_ipv4, self.host_ipv6)
    }

    fn push_cleanup_command(
        &mut self,
        label: &'static str,
        program: &'static str,
        args: Vec<String>,
    ) {
        self.cleanup_actions.push(CleanupAction::RunCommand {
            label,
            program,
            args,
        });
    }

    fn push_cleanup_iptables(
        &mut self,
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    ) {
        self.cleanup_actions
            .push(CleanupAction::RunIptables { label, table, args });
    }

    fn push_cleanup_ip6tables(
        &mut self,
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    ) {
        self.cleanup_actions
            .push(CleanupAction::RunIp6tables { label, table, args });
    }

    fn push_restore_file(&mut self, path: impl Into<String>, value: impl Into<String>) {
        self.cleanup_actions.push(CleanupAction::RestoreFile {
            path: path.into(),
            value: value.into(),
        });
    }

    fn prepare_sysctls(&mut self) -> Result<()> {
        let ipv4_path = "/proc/sys/net/ipv4/ip_forward";
        let ipv4_old = read_file_trimmed(ipv4_path)?;
        fs::write(ipv4_path, "1\n").with_context(|| {
            format!(
                "failed to enable net.ipv4.ip_forward via {ipv4_path}. Check whether `/proc/sys` is writable on this host"
            )
        })?;
        self.push_restore_file(ipv4_path, ipv4_old);

        let ipv6_path = "/proc/sys/net/ipv6/conf/all/forwarding";
        let ipv6_old = read_file_trimmed(ipv6_path)?;
        fs::write(ipv6_path, "1\n").with_context(|| {
            format!(
                "failed to enable net.ipv6.conf.all.forwarding via {ipv6_path}. Check whether IPv6 forwarding is permitted on this host"
            )
        })?;
        self.push_restore_file(ipv6_path, ipv6_old);

        if let Some(iface) = &self.iface {
            let path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
            if Path::new(&path).exists() {
                let old = read_file_trimmed(&path)?;
                fs::write(&path, "0\n").with_context(|| {
                    format!(
                        "failed to set rp_filter=0 on {iface}. Check whether the host allows reverse-path filtering changes for that interface"
                    )
                })?;
                self.push_restore_file(path, old);
            }
        }

        Ok(())
    }

    fn create_veth_pair(&mut self, child_pid: Pid) -> Result<()> {
        run_command(
            "ip",
            vec![
                "link".into(),
                "add".into(),
                self.host_veth.clone(),
                "type".into(),
                "veth".into(),
                "peer".into(),
                "name".into(),
                self.child_veth.clone(),
            ],
        )
        .with_context(|| {
            format!(
                "failed to create veth pair {} <-> {}. Check that `ip` is available and the host permits network namespace setup",
                self.host_veth, self.child_veth
            )
        })?;
        self.push_cleanup_command(
            "delete host veth pair",
            "ip",
            vec!["link".into(), "del".into(), self.host_veth.clone()],
        );

        run_command(
            "ip",
            vec![
                "addr".into(),
                "add".into(),
                format!("{}/30", self.host_ipv4),
                "dev".into(),
                self.host_veth.clone(),
            ],
        )
        .with_context(|| format!("failed to assign host IPv4 address to {}", self.host_veth))?;

        run_command(
            "ip",
            vec![
                "-6".into(),
                "addr".into(),
                "add".into(),
                format!("{}/64", self.host_ipv6),
                "dev".into(),
                self.host_veth.clone(),
                "nodad".into(),
            ],
        )
        .with_context(|| format!("failed to assign host IPv6 address to {}", self.host_veth))?;

        run_command(
            "ip",
            vec![
                "link".into(),
                "set".into(),
                self.host_veth.clone(),
                "up".into(),
            ],
        )
        .with_context(|| format!("failed to bring {} up", self.host_veth))?;

        let host_rpf = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.host_veth);
        if Path::new(&host_rpf).exists() {
            let old = read_file_trimmed(&host_rpf)?;
            fs::write(&host_rpf, "0\n").with_context(|| {
                format!(
                    "failed to set rp_filter=0 on {} after veth creation",
                    self.host_veth
                )
            })?;
            self.push_restore_file(host_rpf, old);
        }

        run_command(
            "ip",
            vec![
                "link".into(),
                "set".into(),
                self.child_veth.clone(),
                "netns".into(),
                child_pid.as_raw().to_string(),
            ],
        )
        .with_context(|| {
            format!(
                "failed to move {} into child netns (pid {}). Check whether the child namespace still exists",
                self.child_veth, child_pid
            )
        })?;

        Ok(())
    }

    fn configure_child_namespace(&self, child_pid: Pid) -> Result<()> {
        with_netns(child_pid, || {
            run_command(
                "ip",
                vec!["link".into(), "set".into(), "lo".into(), "up".into()],
            )
            .context("failed to bring loopback up inside child netns")?;

            run_command(
                "ip",
                vec![
                    "addr".into(),
                    "add".into(),
                    format!("{}/30", self.child_ipv4),
                    "dev".into(),
                    self.child_veth.clone(),
                ],
            )
            .context("failed to assign child veth IPv4 address")?;

            run_command(
                "ip",
                vec![
                    "-6".into(),
                    "addr".into(),
                    "add".into(),
                    format!("{}/64", self.child_ipv6),
                    "dev".into(),
                    self.child_veth.clone(),
                    "nodad".into(),
                ],
            )
            .context("failed to assign child veth IPv6 address")?;

            run_command(
                "ip",
                vec![
                    "link".into(),
                    "set".into(),
                    self.child_veth.clone(),
                    "up".into(),
                ],
            )
            .context("failed to bring child veth up")?;

            run_command(
                "ip",
                vec![
                    "route".into(),
                    "add".into(),
                    "default".into(),
                    "via".into(),
                    self.host_ipv4.to_string(),
                    "dev".into(),
                    self.child_veth.clone(),
                ],
            )
            .context("failed to add child IPv4 default route")?;

            run_command(
                "ip",
                vec![
                    "-6".into(),
                    "route".into(),
                    "add".into(),
                    "default".into(),
                    "via".into(),
                    self.host_ipv6.to_string(),
                    "dev".into(),
                    self.child_veth.clone(),
                ],
            )
            .context("failed to add child IPv6 default route")?;

            Ok(())
        })
        .context("failed to bootstrap the child network namespace")
    }

    fn install_forwarding_rules(&mut self) -> Result<()> {
        let forward_in_v4 = vec![
            "-A".into(),
            "FORWARD".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "ACCEPT".into(),
        ];
        run_iptables("filter", forward_in_v4.clone())
            .context("failed to install IPv4 FORWARD rule for child -> uplink")?;
        self.push_cleanup_iptables(
            "remove IPv4 FORWARD child->uplink",
            "filter",
            replace_action_flag(&forward_in_v4, "-A", "-D"),
        );

        let forward_out_v4 = vec![
            "-A".into(),
            "FORWARD".into(),
            "-o".into(),
            self.host_veth.clone(),
            "-m".into(),
            "conntrack".into(),
            "--ctstate".into(),
            "ESTABLISHED,RELATED".into(),
            "-j".into(),
            "ACCEPT".into(),
        ];
        run_iptables("filter", forward_out_v4.clone())
            .context("failed to install IPv4 FORWARD rule for uplink -> child")?;
        self.push_cleanup_iptables(
            "remove IPv4 FORWARD uplink->child",
            "filter",
            replace_action_flag(&forward_out_v4, "-A", "-D"),
        );

        let mut nat_args = vec![
            "-A".into(),
            "POSTROUTING".into(),
            "-s".into(),
            self.subnet_v4_cidr.clone(),
        ];
        if let Some(iface) = &self.iface {
            nat_args.push("-o".into());
            nat_args.push(iface.clone());
        }
        nat_args.push("-j".into());
        nat_args.push("MASQUERADE".into());
        run_iptables("nat", nat_args.clone()).context("failed to install IPv4 MASQUERADE rule")?;
        self.push_cleanup_iptables(
            "remove IPv4 MASQUERADE",
            "nat",
            replace_action_flag(&nat_args, "-A", "-D"),
        );

        let forward_in_v6 = vec![
            "-A".into(),
            "FORWARD".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "ACCEPT".into(),
        ];
        run_ip6tables("filter", forward_in_v6.clone())
            .context("failed to install IPv6 FORWARD rule for child -> uplink")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 FORWARD child->uplink",
            "filter",
            replace_action_flag(&forward_in_v6, "-A", "-D"),
        );

        let forward_out_v6 = vec![
            "-A".into(),
            "FORWARD".into(),
            "-o".into(),
            self.host_veth.clone(),
            "-m".into(),
            "conntrack".into(),
            "--ctstate".into(),
            "ESTABLISHED,RELATED".into(),
            "-j".into(),
            "ACCEPT".into(),
        ];
        run_ip6tables("filter", forward_out_v6.clone())
            .context("failed to install IPv6 FORWARD rule for uplink -> child")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 FORWARD uplink->child",
            "filter",
            replace_action_flag(&forward_out_v6, "-A", "-D"),
        );

        let mut nat6_args = vec![
            "-A".into(),
            "POSTROUTING".into(),
            "-s".into(),
            self.subnet_v6_cidr.clone(),
        ];
        if let Some(iface) = &self.iface {
            nat6_args.push("-o".into());
            nat6_args.push(iface.clone());
        }
        nat6_args.push("-j".into());
        nat6_args.push("MASQUERADE".into());
        run_ip6tables("nat", nat6_args.clone())
            .context("failed to install IPv6 MASQUERADE rule")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 MASQUERADE",
            "nat",
            replace_action_flag(&nat6_args, "-A", "-D"),
        );

        Ok(())
    }

    fn install_interface_forcing(&mut self) -> Result<()> {
        let Some(iface) = self.iface.clone() else {
            return Ok(());
        };

        let route_info = discover_default_route_for_interface(&iface).with_context(|| {
            format!(
                "failed to discover the IPv4 default route for interface {iface}. Check `ip route show default dev {iface}` on the host"
            )
        })?;
        let route6_info = discover_default_route6_for_interface(&iface).with_context(|| {
            format!(
                "failed to discover the IPv6 default route for interface {iface}. Check `ip -6 route show default dev {iface}` on the host"
            )
        })?;

        let route_mark = self
            .route_mark
            .expect("route_mark must be set when iface is set");
        let route_table = self
            .route_table
            .expect("route_table must be set when iface is set");
        let route_priority = self
            .route_priority
            .expect("route_priority must be set when iface is set");

        let mark_v4_args = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            route_mark.to_string(),
        ];
        run_iptables("mangle", mark_v4_args.clone())
            .context("failed to install mark rule for interface forcing")?;
        self.push_cleanup_iptables(
            "remove IPv4 interface-forcing mark rule",
            "mangle",
            replace_action_flag(&mark_v4_args, "-A", "-D"),
        );

        let mark_v6_args = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            route_mark.to_string(),
        ];
        run_ip6tables("mangle", mark_v6_args.clone())
            .context("failed to install IPv6 mark rule for interface forcing")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 interface-forcing mark rule",
            "mangle",
            replace_action_flag(&mark_v6_args, "-A", "-D"),
        );

        run_command(
            "ip",
            vec![
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                route_mark.to_string(),
                "lookup".into(),
                route_table.to_string(),
                "priority".into(),
                route_priority.to_string(),
            ],
        )
        .context("failed to install policy routing rule for interface forcing")?;
        self.push_cleanup_command(
            "remove IPv4 interface-forcing policy rule",
            "ip",
            vec![
                "rule".into(),
                "del".into(),
                "priority".into(),
                route_priority.to_string(),
            ],
        );

        run_command(
            "ip",
            vec![
                "-6".into(),
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                route_mark.to_string(),
                "lookup".into(),
                route_table.to_string(),
                "priority".into(),
                route_priority.to_string(),
            ],
        )
        .context("failed to install IPv6 policy routing rule for interface forcing")?;
        self.push_cleanup_command(
            "remove IPv6 interface-forcing policy rule",
            "ip",
            vec![
                "-6".into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                route_priority.to_string(),
            ],
        );

        run_command(
            "ip",
            build_default_route_args(route_table, &iface, route_info.gateway),
        )
        .with_context(|| {
            format!("failed to install route table {route_table} for forced interface {iface}")
        })?;
        self.push_cleanup_command(
            "remove IPv4 forced-interface route",
            "ip",
            build_default_route_delete_args(route_table, &iface, route_info.gateway),
        );

        run_command(
            "ip",
            build_default_route6_args(route_table, &iface, route6_info.gateway),
        )
        .with_context(|| {
            format!("failed to install IPv6 route table {route_table} for forced interface {iface}")
        })?;
        self.push_cleanup_command(
            "remove IPv6 forced-interface route",
            "ip",
            build_default_route6_delete_args(route_table, &iface, route6_info.gateway),
        );

        Ok(())
    }

    fn install_tproxy_rules(&mut self) -> Result<()> {
        let Some(listen_port) = self.tproxy_port else {
            return Ok(());
        };

        let divert_chain = self.divert_chain.clone().expect("divert chain missing");
        let tproxy_chain = self.tproxy_chain.clone().expect("tproxy chain missing");
        let tproxy_mark = self.tproxy_mark.expect("tproxy mark missing");
        let tproxy_table = self.tproxy_table.expect("tproxy table missing");
        let tproxy_priority = self.tproxy_priority.expect("tproxy priority missing");

        run_iptables("mangle", vec!["-N".into(), divert_chain.clone()])
            .context("failed to create DIVERT chain")?;
        self.push_cleanup_iptables(
            "delete IPv4 DIVERT chain",
            "mangle",
            vec!["-X".into(), divert_chain.clone()],
        );
        self.push_cleanup_iptables(
            "flush IPv4 DIVERT chain",
            "mangle",
            vec!["-F".into(), divert_chain.clone()],
        );

        run_ip6tables("mangle", vec!["-N".into(), divert_chain.clone()])
            .context("failed to create IPv6 DIVERT chain")?;
        self.push_cleanup_ip6tables(
            "delete IPv6 DIVERT chain",
            "mangle",
            vec!["-X".into(), divert_chain.clone()],
        );
        self.push_cleanup_ip6tables(
            "flush IPv6 DIVERT chain",
            "mangle",
            vec!["-F".into(), divert_chain.clone()],
        );

        let divert_mark_v4 = vec![
            "-A".into(),
            divert_chain.clone(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            tproxy_mark.to_string(),
        ];
        run_iptables("mangle", divert_mark_v4.clone())
            .context("failed to populate DIVERT mark rule")?;
        self.push_cleanup_iptables(
            "remove IPv4 DIVERT mark rule",
            "mangle",
            replace_action_flag(&divert_mark_v4, "-A", "-D"),
        );

        let divert_mark_v6 = vec![
            "-A".into(),
            divert_chain.clone(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            tproxy_mark.to_string(),
        ];
        run_ip6tables("mangle", divert_mark_v6.clone())
            .context("failed to populate IPv6 DIVERT mark rule")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 DIVERT mark rule",
            "mangle",
            replace_action_flag(&divert_mark_v6, "-A", "-D"),
        );

        let divert_accept_v4 = vec![
            "-A".into(),
            divert_chain.clone(),
            "-j".into(),
            "ACCEPT".into(),
        ];
        run_iptables("mangle", divert_accept_v4.clone())
            .context("failed to populate DIVERT accept rule")?;
        self.push_cleanup_iptables(
            "remove IPv4 DIVERT accept rule",
            "mangle",
            replace_action_flag(&divert_accept_v4, "-A", "-D"),
        );

        let divert_accept_v6 = vec![
            "-A".into(),
            divert_chain.clone(),
            "-j".into(),
            "ACCEPT".into(),
        ];
        run_ip6tables("mangle", divert_accept_v6.clone())
            .context("failed to populate IPv6 DIVERT accept rule")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 DIVERT accept rule",
            "mangle",
            replace_action_flag(&divert_accept_v6, "-A", "-D"),
        );

        let divert_hook_v4 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-p".into(),
            "tcp".into(),
            "-m".into(),
            "socket".into(),
            "--transparent".into(),
            "-j".into(),
            divert_chain.clone(),
        ];
        run_iptables("mangle", divert_hook_v4.clone())
            .context("failed to install transparent socket DIVERT rule")?;
        self.push_cleanup_iptables(
            "remove IPv4 DIVERT PREROUTING hook",
            "mangle",
            replace_action_flag(&divert_hook_v4, "-A", "-D"),
        );

        let divert_hook_v6 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-p".into(),
            "tcp".into(),
            "-m".into(),
            "socket".into(),
            "--transparent".into(),
            "-j".into(),
            divert_chain.clone(),
        ];
        run_ip6tables("mangle", divert_hook_v6.clone())
            .context("failed to install IPv6 transparent socket DIVERT rule")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 DIVERT PREROUTING hook",
            "mangle",
            replace_action_flag(&divert_hook_v6, "-A", "-D"),
        );

        run_iptables("mangle", vec!["-N".into(), tproxy_chain.clone()])
            .context("failed to create TPROXY chain")?;
        self.push_cleanup_iptables(
            "delete IPv4 TPROXY chain",
            "mangle",
            vec!["-X".into(), tproxy_chain.clone()],
        );
        self.push_cleanup_iptables(
            "flush IPv4 TPROXY chain",
            "mangle",
            vec!["-F".into(), tproxy_chain.clone()],
        );

        run_ip6tables("mangle", vec!["-N".into(), tproxy_chain.clone()])
            .context("failed to create IPv6 TPROXY chain")?;
        self.push_cleanup_ip6tables(
            "delete IPv6 TPROXY chain",
            "mangle",
            vec!["-X".into(), tproxy_chain.clone()],
        );
        self.push_cleanup_ip6tables(
            "flush IPv6 TPROXY chain",
            "mangle",
            vec!["-F".into(), tproxy_chain.clone()],
        );

        let tproxy_hook_v4 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            tproxy_chain.clone(),
        ];
        run_iptables("mangle", tproxy_hook_v4.clone())
            .context("failed to hook TPROXY chain from PREROUTING")?;
        self.push_cleanup_iptables(
            "remove IPv4 TPROXY PREROUTING hook",
            "mangle",
            replace_action_flag(&tproxy_hook_v4, "-A", "-D"),
        );

        let tproxy_hook_v6 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            tproxy_chain.clone(),
        ];
        run_ip6tables("mangle", tproxy_hook_v6.clone())
            .context("failed to hook IPv6 TPROXY chain from PREROUTING")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 TPROXY PREROUTING hook",
            "mangle",
            replace_action_flag(&tproxy_hook_v6, "-A", "-D"),
        );

        let subnet_bypass_v4 = vec![
            "-A".into(),
            tproxy_chain.clone(),
            "-d".into(),
            self.subnet_v4_cidr.clone(),
            "-j".into(),
            "RETURN".into(),
        ];
        run_iptables("mangle", subnet_bypass_v4.clone())
            .context("failed to install subnet bypass rule in TPROXY chain")?;
        self.push_cleanup_iptables(
            "remove IPv4 TPROXY subnet bypass",
            "mangle",
            replace_action_flag(&subnet_bypass_v4, "-A", "-D"),
        );

        let subnet_bypass_v6 = vec![
            "-A".into(),
            tproxy_chain.clone(),
            "-d".into(),
            self.subnet_v6_cidr.clone(),
            "-j".into(),
            "RETURN".into(),
        ];
        run_ip6tables("mangle", subnet_bypass_v6.clone())
            .context("failed to install IPv6 subnet bypass rule in TPROXY chain")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 TPROXY subnet bypass",
            "mangle",
            replace_action_flag(&subnet_bypass_v6, "-A", "-D"),
        );

        let tproxy_v4 = vec![
            "-A".into(),
            tproxy_chain.clone(),
            "-p".into(),
            "tcp".into(),
            "-j".into(),
            "TPROXY".into(),
            "--on-port".into(),
            listen_port.to_string(),
            "--tproxy-mark".into(),
            format!("0x{tproxy_mark:x}/0xffffffff"),
        ];
        run_iptables("mangle", tproxy_v4.clone())
            .with_context(|| format!("failed to install TPROXY rule to port {listen_port}"))?;
        self.push_cleanup_iptables(
            "remove IPv4 TPROXY redirect",
            "mangle",
            replace_action_flag(&tproxy_v4, "-A", "-D"),
        );

        let tproxy_v6 = vec![
            "-A".into(),
            tproxy_chain.clone(),
            "-p".into(),
            "tcp".into(),
            "-j".into(),
            "TPROXY".into(),
            "--on-port".into(),
            listen_port.to_string(),
            "--tproxy-mark".into(),
            format!("0x{tproxy_mark:x}/0xffffffff"),
        ];
        run_ip6tables("mangle", tproxy_v6.clone())
            .with_context(|| format!("failed to install IPv6 TPROXY rule to port {listen_port}"))?;
        self.push_cleanup_ip6tables(
            "remove IPv6 TPROXY redirect",
            "mangle",
            replace_action_flag(&tproxy_v6, "-A", "-D"),
        );

        run_command(
            "ip",
            vec![
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                tproxy_mark.to_string(),
                "lookup".into(),
                tproxy_table.to_string(),
                "priority".into(),
                tproxy_priority.to_string(),
            ],
        )
        .context("failed to install TPROXY policy routing rule")?;
        self.push_cleanup_command(
            "remove IPv4 TPROXY policy rule",
            "ip",
            vec![
                "rule".into(),
                "del".into(),
                "priority".into(),
                tproxy_priority.to_string(),
            ],
        );

        run_command(
            "ip",
            vec![
                "-6".into(),
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                tproxy_mark.to_string(),
                "lookup".into(),
                tproxy_table.to_string(),
                "priority".into(),
                tproxy_priority.to_string(),
            ],
        )
        .context("failed to install IPv6 TPROXY policy routing rule")?;
        self.push_cleanup_command(
            "remove IPv6 TPROXY policy rule",
            "ip",
            vec![
                "-6".into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                tproxy_priority.to_string(),
            ],
        );

        run_command(
            "ip",
            vec![
                "route".into(),
                "add".into(),
                "local".into(),
                "0.0.0.0/0".into(),
                "dev".into(),
                "lo".into(),
                "table".into(),
                tproxy_table.to_string(),
            ],
        )
        .context("failed to install local route for TPROXY table")?;
        self.push_cleanup_command(
            "remove IPv4 TPROXY local route",
            "ip",
            vec![
                "route".into(),
                "del".into(),
                "local".into(),
                "0.0.0.0/0".into(),
                "dev".into(),
                "lo".into(),
                "table".into(),
                tproxy_table.to_string(),
            ],
        );

        run_command(
            "ip",
            vec![
                "-6".into(),
                "route".into(),
                "add".into(),
                "local".into(),
                "::/0".into(),
                "dev".into(),
                "lo".into(),
                "table".into(),
                tproxy_table.to_string(),
            ],
        )
        .context("failed to install IPv6 local route for TPROXY table")?;
        self.push_cleanup_command(
            "remove IPv6 TPROXY local route",
            "ip",
            vec![
                "-6".into(),
                "route".into(),
                "del".into(),
                "local".into(),
                "::/0".into(),
                "dev".into(),
                "lo".into(),
                "table".into(),
                tproxy_table.to_string(),
            ],
        );

        Ok(())
    }

    fn cleanup_best_effort(&mut self) {
        let mut failures = Vec::new();

        while let Some(action) = self.cleanup_actions.pop() {
            match run_cleanup_action(&action) {
                Ok(()) => {}
                Err(err) if is_ignorable_cleanup_error(&action, &err) => {
                    debug(format!("{err:#}"));
                }
                Err(err) => {
                    failures.push(format!("{err:#}"));
                }
            }
        }

        if failures.is_empty() {
            return;
        }

        warn(format!(
            "cleanup left {} warning(s). Re-run with `CHILDFLOW_DEBUG=1` for detailed cleanup diagnostics.",
            failures.len()
        ));
        for failure in failures {
            debug(failure);
        }
    }
}

impl Drop for NetworkContext {
    fn drop(&mut self) {
        self.cleanup_best_effort();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterfaceRoute {
    gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterfaceRoute6 {
    gateway: Option<Ipv6Addr>,
}

fn discover_default_route_for_interface(iface: &str) -> Result<InterfaceRoute> {
    let output = run_command(
        "ip",
        vec![
            "route".into(),
            "show".into(),
            "default".into(),
            "dev".into(),
            iface.into(),
        ],
    )
    .with_context(|| format!("failed to inspect default route for interface {iface}"))?;

    parse_default_route(output.trim())
}

fn discover_default_route6_for_interface(iface: &str) -> Result<InterfaceRoute6> {
    let output = run_command(
        "ip",
        vec![
            "-6".into(),
            "route".into(),
            "show".into(),
            "default".into(),
            "dev".into(),
            iface.into(),
        ],
    )
    .with_context(|| format!("failed to inspect IPv6 default route for interface {iface}"))?;

    parse_default_route6(output.trim())
}

fn parse_default_route(output: &str) -> Result<InterfaceRoute> {
    if output.trim().is_empty() {
        return Ok(InterfaceRoute { gateway: None });
    }

    let line = output
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default();
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let gateway = tokens
        .windows(2)
        .find(|pair| pair[0] == "via")
        .map(|pair| pair[1].parse::<Ipv4Addr>())
        .transpose()
        .with_context(|| format!("failed to parse default gateway from route output: {line}"))?;

    Ok(InterfaceRoute { gateway })
}

fn parse_default_route6(output: &str) -> Result<InterfaceRoute6> {
    if output.trim().is_empty() {
        return Ok(InterfaceRoute6 { gateway: None });
    }

    let line = output
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default();
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let gateway = tokens
        .windows(2)
        .find(|pair| pair[0] == "via")
        .map(|pair| pair[1].parse::<Ipv6Addr>())
        .transpose()
        .with_context(|| {
            format!("failed to parse IPv6 default gateway from route output: {line}")
        })?;

    Ok(InterfaceRoute6 { gateway })
}

fn build_default_route_args(
    route_table: u32,
    iface: &str,
    gateway: Option<Ipv4Addr>,
) -> Vec<String> {
    let mut args = vec![
        "route".into(),
        "add".into(),
        "default".into(),
        "table".into(),
        route_table.to_string(),
    ];
    if let Some(gateway) = gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(iface.into());
    if gateway.is_none() {
        args.push("scope".into());
        args.push("link".into());
    }
    args
}

fn build_default_route_delete_args(
    route_table: u32,
    iface: &str,
    gateway: Option<Ipv4Addr>,
) -> Vec<String> {
    let mut args = vec![
        "route".into(),
        "del".into(),
        "default".into(),
        "table".into(),
        route_table.to_string(),
    ];
    if let Some(gateway) = gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(iface.into());
    if gateway.is_none() {
        args.push("scope".into());
        args.push("link".into());
    }
    args
}

fn build_default_route6_args(
    route_table: u32,
    iface: &str,
    gateway: Option<Ipv6Addr>,
) -> Vec<String> {
    let mut args = vec![
        "-6".into(),
        "route".into(),
        "add".into(),
        "default".into(),
        "table".into(),
        route_table.to_string(),
    ];
    if let Some(gateway) = gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(iface.into());
    args
}

fn build_default_route6_delete_args(
    route_table: u32,
    iface: &str,
    gateway: Option<Ipv6Addr>,
) -> Vec<String> {
    let mut args = vec![
        "-6".into(),
        "route".into(),
        "del".into(),
        "default".into(),
        "table".into(),
        route_table.to_string(),
    ];
    if let Some(gateway) = gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(iface.into());
    args
}

fn with_netns<T, F>(pid: Pid, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let original = fs::File::open("/proc/self/ns/net").context("failed to open current netns")?;
    let target_path = format!("/proc/{}/ns/net", pid.as_raw());
    let target = fs::File::open(&target_path)
        .with_context(|| format!("failed to open target netns {target_path}"))?;

    setns(target.as_fd(), CloneFlags::CLONE_NEWNET).context("setns(target) failed")?;
    let result = f();
    let restore = setns(original.as_fd(), CloneFlags::CLONE_NEWNET);

    match (result, restore) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(anyhow!("failed to restore original netns: {err}")),
        (Err(err), Err(restore_err)) => Err(anyhow!(
            "{err:#}; additionally failed to restore original netns: {restore_err}"
        )),
    }
}

fn run_cleanup_action(action: &CleanupAction) -> Result<()> {
    match action {
        CleanupAction::RestoreFile { path, value } => {
            fs::write(&path, format!("{value}\n")).with_context(|| format!("cleanup `{path}`"))
        }
        CleanupAction::RunCommand {
            label,
            program,
            args,
        } => run_command(program, args.to_vec())
            .map(|_| ())
            .with_context(|| format!("cleanup `{label}`")),
        CleanupAction::RunIptables { label, table, args } => run_iptables(table, args.to_vec())
            .map(|_| ())
            .with_context(|| format!("cleanup `{label}`")),
        CleanupAction::RunIp6tables { label, table, args } => run_ip6tables(table, args.to_vec())
            .map(|_| ())
            .with_context(|| format!("cleanup `{label}`")),
    }
}

fn is_ignorable_cleanup_error(action: &CleanupAction, err: &anyhow::Error) -> bool {
    match action {
        CleanupAction::RestoreFile { path, .. } => {
            path.contains("/proc/sys/net/ipv4/conf/")
                && path.ends_with("/rp_filter")
                && error_chain_has_io_kind(err, std::io::ErrorKind::NotFound)
        }
        CleanupAction::RunCommand { label, .. } => {
            *label == "delete host veth pair" && error_chain_contains(err, "Cannot find device")
        }
        CleanupAction::RunIptables { .. } | CleanupAction::RunIp6tables { .. } => false,
    }
}

fn error_chain_has_io_kind(err: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    err.chain()
        .filter_map(|source| source.downcast_ref::<std::io::Error>())
        .any(|io_err| io_err.kind() == kind)
}

fn error_chain_contains(err: &anyhow::Error, needle: &str) -> bool {
    err.chain()
        .any(|source| source.to_string().contains(needle))
}

fn replace_action_flag(args: &[String], from: &str, to: &str) -> Vec<String> {
    let mut replaced = args.to_vec();
    if let Some(slot) = replaced.iter_mut().find(|arg| arg.as_str() == from) {
        *slot = to.to_string();
    }
    replaced
}

fn run_iptables(table: &str, mut args: Vec<String>) -> Result<String> {
    let mut final_args = Vec::with_capacity(args.len() + 3);
    final_args.push("-w".into());
    final_args.push("-t".into());
    final_args.push(table.into());
    final_args.append(&mut args);
    run_command("iptables", final_args)
}

fn run_ip6tables(table: &str, mut args: Vec<String>) -> Result<String> {
    let mut final_args = Vec::with_capacity(args.len() + 3);
    final_args.push("-w".into());
    final_args.push("-t".into());
    final_args.push(table.into());
    final_args.append(&mut args);
    run_command("ip6tables", final_args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_route_accepts_gateway() {
        let route =
            parse_default_route("default via 192.0.2.1 dev eth0 proto dhcp metric 100").unwrap();
        assert_eq!(
            route,
            InterfaceRoute {
                gateway: Some(Ipv4Addr::new(192, 0, 2, 1))
            }
        );
    }

    #[test]
    fn parse_default_route_accepts_direct_link_route() {
        let route = parse_default_route("default dev tun0 scope link").unwrap();
        assert_eq!(route, InterfaceRoute { gateway: None });
    }

    #[test]
    fn parse_default_route6_accepts_gateway() {
        let route = parse_default_route6("default via 2001:db8::1 dev eth0 metric 100").unwrap();
        assert_eq!(
            route,
            InterfaceRoute6 {
                gateway: Some("2001:db8::1".parse().unwrap())
            }
        );
    }

    #[test]
    fn parse_default_route6_accepts_direct_link_route() {
        let route = parse_default_route6("default dev tun0 metric 1024 pref medium").unwrap();
        assert_eq!(route, InterfaceRoute6 { gateway: None });
    }

    #[test]
    fn parse_default_route_rejects_invalid_gateway() {
        let err = parse_default_route("default via not-an-ip dev eth0").unwrap_err();
        assert!(err.to_string().contains("failed to parse default gateway"));
    }

    #[test]
    fn replace_action_flag_swaps_the_first_matching_token() {
        let replaced =
            replace_action_flag(&["-A".into(), "FORWARD".into(), "-A".into()], "-A", "-D");
        assert_eq!(replaced, vec!["-D", "FORWARD", "-A"]);
    }

    #[test]
    fn error_chain_has_io_kind_finds_context_wrapped_not_found() {
        let err = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("cleanup `/proc/sys/net/ipv4/conf/test/rp_filter`");
        assert!(error_chain_has_io_kind(&err, std::io::ErrorKind::NotFound));
    }

    #[test]
    fn error_chain_contains_finds_nested_command_error_message() {
        let err = anyhow!("command failed: `ip link del cfh123`")
            .context("stderr: Cannot find device \"cfh123\"")
            .context("cleanup `delete host veth pair`");
        assert!(error_chain_contains(&err, "Cannot find device"));
    }
}
