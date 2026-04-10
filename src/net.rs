use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsFd;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use nix::sched::{setns, CloneFlags};
use nix::unistd::Pid;

use crate::cli::Cli;
use crate::util::{read_file_trimmed, run_command};

#[derive(Clone)]
pub struct NetworkPlan {
    host_veth: String,
    child_veth: String,
    host_ipv4: Ipv4Addr,
    child_ipv4: Ipv4Addr,
    subnet_v4_cidr: String,
    host_ipv6: Ipv6Addr,
    child_ipv6: Ipv6Addr,
    subnet_v6_cidr: String,
    route_table: u32,
    tproxy_table: u32,
    route_priority: u32,
    tproxy_priority: u32,
    route_mark: u32,
    tproxy_mark: u32,
    divert_chain: String,
    tproxy_chain: String,
}

impl NetworkPlan {
    pub fn new() -> Self {
        let entropy = crate::util::run_entropy();
        let (host_ipv4, child_ipv4, subnet_v4_cidr) = allocate_ipv4_subnet(entropy);
        let (host_ipv6, child_ipv6, subnet_v6_cidr) = allocate_ipv6_subnet(entropy);
        let suffix = format!("{:06x}", entropy & 0x00ff_ffff);

        Self {
            host_veth: format!("cfh{}", &suffix[..6]),
            child_veth: format!("cfc{}", &suffix[..6]),
            host_ipv4,
            child_ipv4,
            subnet_v4_cidr,
            host_ipv6,
            child_ipv6,
            subnet_v6_cidr,
            route_table: 10_000 + (entropy % 10_000),
            tproxy_table: 10_001 + (entropy % 10_000),
            route_priority: 10_000 + (entropy % 1_000),
            tproxy_priority: 10_001 + (entropy % 1_000),
            route_mark: 0x10000 | (entropy & 0x0fff),
            tproxy_mark: 0x20000 | (entropy & 0x0fff),
            divert_chain: format!("CFD{}", &suffix[..6]),
            tproxy_chain: format!("CFT{}", &suffix[..6]),
        }
    }

    pub fn host_ipv4(&self) -> Ipv4Addr {
        self.host_ipv4
    }

    pub fn host_ipv6(&self) -> Ipv6Addr {
        self.host_ipv6
    }
}

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
    host_veth_rp_filter_old: Option<String>,
    iface_rp_filter_old: Option<String>,
    ip_forward_old: Option<String>,
    ipv6_forward_old: Option<String>,
    route_mark: Option<u32>,
    route_table: Option<u32>,
    route_priority: Option<u32>,
    tproxy_mark: Option<u32>,
    tproxy_table: Option<u32>,
    tproxy_priority: Option<u32>,
    divert_chain: Option<String>,
    tproxy_chain: Option<String>,
    tproxy_port: Option<u16>,
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
            host_veth_rp_filter_old: None,
            iface_rp_filter_old: None,
            ip_forward_old: None,
            ipv6_forward_old: None,
            route_mark: cli.iface.as_ref().map(|_| plan.route_mark),
            route_table: cli.iface.as_ref().map(|_| plan.route_table),
            route_priority: cli.iface.as_ref().map(|_| plan.route_priority),
            tproxy_mark: tproxy_port.map(|_| plan.tproxy_mark),
            tproxy_table: tproxy_port.map(|_| plan.tproxy_table),
            tproxy_priority: tproxy_port.map(|_| plan.tproxy_priority),
            divert_chain: tproxy_port.map(|_| plan.divert_chain.clone()),
            tproxy_chain: tproxy_port.map(|_| plan.tproxy_chain.clone()),
            tproxy_port,
        };

        ctx.prepare_sysctls()?;
        ctx.create_veth_pair(child_pid)?;
        ctx.configure_child_namespace(child_pid)?;
        ctx.install_forwarding_rules()?;
        ctx.install_interface_forcing()?;
        ctx.install_tproxy_rules()?;

        let _ = run_id; // retained for log / debugging extension points.
        Ok(ctx)
    }

    pub fn host_veth(&self) -> &str {
        &self.host_veth
    }

    fn prepare_sysctls(&mut self) -> Result<()> {
        self.ip_forward_old = Some(read_file_trimmed("/proc/sys/net/ipv4/ip_forward")?);
        fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")
            .context("failed to enable net.ipv4.ip_forward")?;
        self.ipv6_forward_old = Some(read_file_trimmed("/proc/sys/net/ipv6/conf/all/forwarding")?);
        fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1\n")
            .context("failed to enable net.ipv6.conf.all.forwarding")?;

        let host_veth_path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.host_veth);
        // The veth does not exist yet; this one is restored later after the device appears.
        self.host_veth_rp_filter_old = Some("0".to_string());
        let _ = host_veth_path;

        if let Some(iface) = &self.iface {
            let path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
            if Path::new(&path).exists() {
                let old = read_file_trimmed(&path)?;
                fs::write(&path, "0\n")
                    .with_context(|| format!("failed to set rp_filter=0 on {iface}"))?;
                self.iface_rp_filter_old = Some(old);
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
        .context("failed to create veth pair")?;

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
        .context("failed to assign host veth IPv4 address")?;

        run_command(
            "ip",
            vec![
                "-6".into(),
                "addr".into(),
                "add".into(),
                format!("{}/64", self.host_ipv6),
                "dev".into(),
                self.host_veth.clone(),
            ],
        )
        .context("failed to assign host veth IPv6 address")?;

        run_command(
            "ip",
            vec![
                "link".into(),
                "set".into(),
                self.host_veth.clone(),
                "up".into(),
            ],
        )
        .context("failed to bring host veth up")?;

        let host_rpf = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.host_veth);
        if Path::new(&host_rpf).exists() {
            let old = read_file_trimmed(&host_rpf)?;
            self.host_veth_rp_filter_old = Some(old);
            fs::write(&host_rpf, "0\n")
                .with_context(|| format!("failed to set rp_filter=0 on {}", self.host_veth))?;
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
        .with_context(|| format!("failed to move {} into child netns", self.child_veth))?;

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
    }

    fn install_forwarding_rules(&self) -> Result<()> {
        run_iptables(
            "filter",
            vec![
                "-A".into(),
                "FORWARD".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        )
        .context("failed to install IPv4 FORWARD rule for child -> uplink")?;

        run_iptables(
            "filter",
            vec![
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
            ],
        )
        .context("failed to install IPv4 FORWARD rule for uplink -> child")?;

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

        run_iptables("nat", nat_args).context("failed to install IPv4 MASQUERADE rule")?;

        run_ip6tables(
            "filter",
            vec![
                "-A".into(),
                "FORWARD".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        )
        .context("failed to install IPv6 FORWARD rule for child -> uplink")?;

        run_ip6tables(
            "filter",
            vec![
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
            ],
        )
        .context("failed to install IPv6 FORWARD rule for uplink -> child")?;

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

        run_ip6tables("nat", nat6_args).context("failed to install IPv6 MASQUERADE rule")?;
        Ok(())
    }

    fn install_interface_forcing(&self) -> Result<()> {
        let Some(iface) = &self.iface else {
            return Ok(());
        };

        let route_info = discover_default_route_for_interface(iface)?;

        run_iptables(
            "mangle",
            vec![
                "-A".into(),
                "PREROUTING".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-j".into(),
                "MARK".into(),
                "--set-mark".into(),
                self.route_mark
                    .expect("route_mark must be set when iface is set")
                    .to_string(),
            ],
        )
        .context("failed to install mark rule for interface forcing")?;

        run_ip6tables(
            "mangle",
            vec![
                "-A".into(),
                "PREROUTING".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-j".into(),
                "MARK".into(),
                "--set-mark".into(),
                self.route_mark
                    .expect("route_mark must be set when iface is set")
                    .to_string(),
            ],
        )
        .context("failed to install IPv6 mark rule for interface forcing")?;

        run_command(
            "ip",
            vec![
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                self.route_mark.expect("route_mark missing").to_string(),
                "lookup".into(),
                self.route_table.expect("route_table missing").to_string(),
                "priority".into(),
                self.route_priority
                    .expect("route_priority missing")
                    .to_string(),
            ],
        )
        .context("failed to install policy routing rule for interface forcing")?;

        run_command(
            "ip",
            vec![
                "-6".into(),
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                self.route_mark.expect("route_mark missing").to_string(),
                "lookup".into(),
                self.route_table.expect("route_table missing").to_string(),
                "priority".into(),
                self.route_priority
                    .expect("route_priority missing")
                    .to_string(),
            ],
        )
        .context("failed to install IPv6 policy routing rule for interface forcing")?;

        let mut route_args = vec![
            "route".into(),
            "add".into(),
            "default".into(),
            "table".into(),
            self.route_table.expect("route_table missing").to_string(),
        ];
        if let Some(gateway) = route_info.gateway {
            route_args.push("via".into());
            route_args.push(gateway.to_string());
        }
        route_args.push("dev".into());
        route_args.push(iface.clone());
        if route_info.gateway.is_none() {
            route_args.push("scope".into());
            route_args.push("link".into());
        }

        run_command("ip", route_args).with_context(|| {
            format!(
                "failed to install route table {} for forced interface {iface}",
                self.route_table.expect("route_table missing")
            )
        })?;

        let route6_info = discover_default_route6_for_interface(iface)?;
        let mut route6_args = vec![
            "-6".into(),
            "route".into(),
            "add".into(),
            "default".into(),
            "table".into(),
            self.route_table.expect("route_table missing").to_string(),
        ];
        if let Some(gateway) = route6_info.gateway {
            route6_args.push("via".into());
            route6_args.push(gateway.to_string());
        }
        route6_args.push("dev".into());
        route6_args.push(iface.clone());

        run_command("ip", route6_args).with_context(|| {
            format!(
                "failed to install IPv6 route table {} for forced interface {iface}",
                self.route_table.expect("route_table missing")
            )
        })?;

        Ok(())
    }

    fn install_tproxy_rules(&self) -> Result<()> {
        let Some(listen_port) = self.tproxy_port else {
            return Ok(());
        };

        let divert_chain = self.divert_chain.as_ref().expect("divert chain missing");
        let tproxy_chain = self.tproxy_chain.as_ref().expect("tproxy chain missing");
        let tproxy_mark = self.tproxy_mark.expect("tproxy mark missing");
        let tproxy_table = self.tproxy_table.expect("tproxy table missing");
        let tproxy_priority = self.tproxy_priority.expect("tproxy priority missing");

        run_iptables("mangle", vec!["-N".into(), divert_chain.clone()])
            .context("failed to create DIVERT chain")?;
        run_ip6tables("mangle", vec!["-N".into(), divert_chain.clone()])
            .context("failed to create IPv6 DIVERT chain")?;
        run_iptables(
            "mangle",
            vec![
                "-A".into(),
                divert_chain.clone(),
                "-j".into(),
                "MARK".into(),
                "--set-mark".into(),
                tproxy_mark.to_string(),
            ],
        )
        .context("failed to populate DIVERT mark rule")?;
        run_ip6tables(
            "mangle",
            vec![
                "-A".into(),
                divert_chain.clone(),
                "-j".into(),
                "MARK".into(),
                "--set-mark".into(),
                tproxy_mark.to_string(),
            ],
        )
        .context("failed to populate IPv6 DIVERT mark rule")?;
        run_iptables(
            "mangle",
            vec![
                "-A".into(),
                divert_chain.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        )
        .context("failed to populate DIVERT accept rule")?;
        run_ip6tables(
            "mangle",
            vec![
                "-A".into(),
                divert_chain.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        )
        .context("failed to populate IPv6 DIVERT accept rule")?;
        run_iptables(
            "mangle",
            vec![
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
            ],
        )
        .context("failed to install transparent socket DIVERT rule")?;
        run_ip6tables(
            "mangle",
            vec![
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
            ],
        )
        .context("failed to install IPv6 transparent socket DIVERT rule")?;

        run_iptables("mangle", vec!["-N".into(), tproxy_chain.clone()])
            .context("failed to create TPROXY chain")?;
        run_ip6tables("mangle", vec!["-N".into(), tproxy_chain.clone()])
            .context("failed to create IPv6 TPROXY chain")?;
        run_iptables(
            "mangle",
            vec![
                "-A".into(),
                "PREROUTING".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-j".into(),
                tproxy_chain.clone(),
            ],
        )
        .context("failed to hook TPROXY chain from PREROUTING")?;
        run_ip6tables(
            "mangle",
            vec![
                "-A".into(),
                "PREROUTING".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-j".into(),
                tproxy_chain.clone(),
            ],
        )
        .context("failed to hook IPv6 TPROXY chain from PREROUTING")?;

        run_iptables(
            "mangle",
            vec![
                "-A".into(),
                tproxy_chain.clone(),
                "-d".into(),
                self.subnet_v4_cidr.clone(),
                "-j".into(),
                "RETURN".into(),
            ],
        )
        .context("failed to install subnet bypass rule in TPROXY chain")?;
        run_ip6tables(
            "mangle",
            vec![
                "-A".into(),
                tproxy_chain.clone(),
                "-d".into(),
                self.subnet_v6_cidr.clone(),
                "-j".into(),
                "RETURN".into(),
            ],
        )
        .context("failed to install IPv6 subnet bypass rule in TPROXY chain")?;

        run_iptables(
            "mangle",
            vec![
                "-A".into(),
                tproxy_chain.clone(),
                "-p".into(),
                "tcp".into(),
                "-j".into(),
                "TPROXY".into(),
                "--on-port".into(),
                listen_port.to_string(),
                "--tproxy-mark".into(),
                format!("0x{:x}/0xffffffff", tproxy_mark),
            ],
        )
        .with_context(|| format!("failed to install TPROXY rule to port {listen_port}"))?;
        run_ip6tables(
            "mangle",
            vec![
                "-A".into(),
                tproxy_chain.clone(),
                "-p".into(),
                "tcp".into(),
                "-j".into(),
                "TPROXY".into(),
                "--on-port".into(),
                listen_port.to_string(),
                "--tproxy-mark".into(),
                format!("0x{:x}/0xffffffff", tproxy_mark),
            ],
        )
        .with_context(|| format!("failed to install IPv6 TPROXY rule to port {listen_port}"))?;

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

        Ok(())
    }

    fn cleanup_best_effort(&self) {
        if let Some(tproxy_priority) = self.tproxy_priority {
            let _ = run_command(
                "ip",
                vec![
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    tproxy_priority.to_string(),
                ],
            );
            let _ = run_command(
                "ip",
                vec![
                    "-6".into(),
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    tproxy_priority.to_string(),
                ],
            );
        }
        if let Some(tproxy_table) = self.tproxy_table {
            let _ = run_command(
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
            let _ = run_command(
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
        }
        if let Some(chain) = &self.tproxy_chain {
            let _ = run_iptables(
                "mangle",
                vec![
                    "-D".into(),
                    "PREROUTING".into(),
                    "-i".into(),
                    self.host_veth.clone(),
                    "-j".into(),
                    chain.clone(),
                ],
            );
            let _ = run_iptables("mangle", vec!["-F".into(), chain.clone()]);
            let _ = run_iptables("mangle", vec!["-X".into(), chain.clone()]);
            let _ = run_ip6tables(
                "mangle",
                vec![
                    "-D".into(),
                    "PREROUTING".into(),
                    "-i".into(),
                    self.host_veth.clone(),
                    "-j".into(),
                    chain.clone(),
                ],
            );
            let _ = run_ip6tables("mangle", vec!["-F".into(), chain.clone()]);
            let _ = run_ip6tables("mangle", vec!["-X".into(), chain.clone()]);
        }
        if let Some(chain) = &self.divert_chain {
            let _ = run_iptables(
                "mangle",
                vec![
                    "-D".into(),
                    "PREROUTING".into(),
                    "-i".into(),
                    self.host_veth.clone(),
                    "-p".into(),
                    "tcp".into(),
                    "-m".into(),
                    "socket".into(),
                    "--transparent".into(),
                    "-j".into(),
                    chain.clone(),
                ],
            );
            let _ = run_iptables("mangle", vec!["-F".into(), chain.clone()]);
            let _ = run_iptables("mangle", vec!["-X".into(), chain.clone()]);
            let _ = run_ip6tables(
                "mangle",
                vec![
                    "-D".into(),
                    "PREROUTING".into(),
                    "-i".into(),
                    self.host_veth.clone(),
                    "-p".into(),
                    "tcp".into(),
                    "-m".into(),
                    "socket".into(),
                    "--transparent".into(),
                    "-j".into(),
                    chain.clone(),
                ],
            );
            let _ = run_ip6tables("mangle", vec!["-F".into(), chain.clone()]);
            let _ = run_ip6tables("mangle", vec!["-X".into(), chain.clone()]);
        }

        if let Some(route_priority) = self.route_priority {
            let _ = run_command(
                "ip",
                vec![
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    route_priority.to_string(),
                ],
            );
            let _ = run_command(
                "ip",
                vec![
                    "-6".into(),
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    route_priority.to_string(),
                ],
            );
        }
        if let (Some(route_table), Some(iface)) = (self.route_table, self.iface.as_ref()) {
            let route_info = discover_default_route_for_interface(iface).ok();
            let mut args = vec![
                "route".into(),
                "del".into(),
                "default".into(),
                "table".into(),
                route_table.to_string(),
            ];
            if let Some(info) = route_info {
                if let Some(gateway) = info.gateway {
                    args.push("via".into());
                    args.push(gateway.to_string());
                }
                args.push("dev".into());
                args.push(iface.clone());
                if info.gateway.is_none() {
                    args.push("scope".into());
                    args.push("link".into());
                }
            }
            let _ = run_command("ip", args);
            let route6_info = discover_default_route6_for_interface(iface).ok();
            let mut args6 = vec![
                "-6".into(),
                "route".into(),
                "del".into(),
                "default".into(),
                "table".into(),
                route_table.to_string(),
            ];
            if let Some(info) = route6_info {
                if let Some(gateway) = info.gateway {
                    args6.push("via".into());
                    args6.push(gateway.to_string());
                }
                args6.push("dev".into());
                args6.push(iface.clone());
            }
            let _ = run_command("ip", args6);
            let _ = run_iptables(
                "mangle",
                vec![
                    "-D".into(),
                    "PREROUTING".into(),
                    "-i".into(),
                    self.host_veth.clone(),
                    "-j".into(),
                    "MARK".into(),
                    "--set-mark".into(),
                    self.route_mark.unwrap_or_default().to_string(),
                ],
            );
            let _ = run_ip6tables(
                "mangle",
                vec![
                    "-D".into(),
                    "PREROUTING".into(),
                    "-i".into(),
                    self.host_veth.clone(),
                    "-j".into(),
                    "MARK".into(),
                    "--set-mark".into(),
                    self.route_mark.unwrap_or_default().to_string(),
                ],
            );
        }

        let mut nat_args = vec![
            "-D".into(),
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
        let _ = run_iptables("nat", nat_args);
        let mut nat6_args = vec![
            "-D".into(),
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
        let _ = run_ip6tables("nat", nat6_args);

        let _ = run_iptables(
            "filter",
            vec![
                "-D".into(),
                "FORWARD".into(),
                "-o".into(),
                self.host_veth.clone(),
                "-m".into(),
                "conntrack".into(),
                "--ctstate".into(),
                "ESTABLISHED,RELATED".into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        );
        let _ = run_ip6tables(
            "filter",
            vec![
                "-D".into(),
                "FORWARD".into(),
                "-o".into(),
                self.host_veth.clone(),
                "-m".into(),
                "conntrack".into(),
                "--ctstate".into(),
                "ESTABLISHED,RELATED".into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        );
        let _ = run_ip6tables(
            "filter",
            vec![
                "-D".into(),
                "FORWARD".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        );
        let _ = run_iptables(
            "filter",
            vec![
                "-D".into(),
                "FORWARD".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        );

        if let Some(old) = &self.iface_rp_filter_old {
            if let Some(iface) = &self.iface {
                let path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
                let _ = fs::write(path, format!("{old}\n"));
            }
        }
        if let Some(old) = &self.host_veth_rp_filter_old {
            let path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.host_veth);
            let _ = fs::write(path, format!("{old}\n"));
        }

        let _ = run_command(
            "ip",
            vec!["link".into(), "del".into(), self.host_veth.clone()],
        );

        if let Some(old) = &self.ip_forward_old {
            let _ = fs::write("/proc/sys/net/ipv4/ip_forward", format!("{old}\n"));
        }
        if let Some(old) = &self.ipv6_forward_old {
            let _ = fs::write("/proc/sys/net/ipv6/conf/all/forwarding", format!("{old}\n"));
        }
    }
}

impl Drop for NetworkContext {
    fn drop(&mut self) {
        self.cleanup_best_effort();
    }
}

#[derive(Clone, Copy)]
struct InterfaceRoute {
    gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Copy)]
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

    if output.trim().is_empty() {
        return Ok(InterfaceRoute { gateway: None });
    }

    let tokens: Vec<&str> = output.split_whitespace().collect();
    let gateway = tokens
        .windows(2)
        .find(|pair| pair[0] == "via")
        .map(|pair| pair[1].parse::<Ipv4Addr>())
        .transpose()
        .with_context(|| format!("failed to parse default gateway from route output: {output}"))?;

    Ok(InterfaceRoute { gateway })
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

    if output.trim().is_empty() {
        return Ok(InterfaceRoute6 { gateway: None });
    }

    let tokens: Vec<&str> = output.split_whitespace().collect();
    let gateway = tokens
        .windows(2)
        .find(|pair| pair[0] == "via")
        .map(|pair| pair[1].parse::<Ipv6Addr>())
        .transpose()
        .with_context(|| {
            format!("failed to parse IPv6 default gateway from route output: {output}")
        })?;

    Ok(InterfaceRoute6 { gateway })
}

fn allocate_ipv4_subnet(entropy: u32) -> (Ipv4Addr, Ipv4Addr, String) {
    let octet3 = ((entropy >> 8) & 0xff) as u8;
    let block = ((entropy & 0x3f) as u8) * 4;
    let host_ip = Ipv4Addr::new(10, 240, octet3, block + 1);
    let child_ip = Ipv4Addr::new(10, 240, octet3, block + 2);
    let subnet_cidr = format!("10.240.{octet3}.{block}/30");
    (host_ip, child_ip, subnet_cidr)
}

fn allocate_ipv6_subnet(entropy: u32) -> (Ipv6Addr, Ipv6Addr, String) {
    let upper = ((entropy >> 16) & 0xffff) as u16;
    let lower = (entropy & 0xffff) as u16;
    let subnet = format!("fd42:{upper:04x}:{lower:04x}::/64");
    let host_ip = Ipv6Addr::new(0xfd42, upper, lower, 0, 0, 0, 0, 1);
    let child_ip = Ipv6Addr::new(0xfd42, upper, lower, 0, 0, 0, 0, 2);
    (host_ip, child_ip, subnet)
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
