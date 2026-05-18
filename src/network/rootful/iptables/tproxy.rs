use anyhow::Context;

use super::*;

impl NetworkContext {
    pub(crate) fn install_tproxy_rules(&mut self) -> Result<()> {
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
}
