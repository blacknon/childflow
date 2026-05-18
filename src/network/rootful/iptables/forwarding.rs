use anyhow::Context;

use super::*;

impl NetworkContext {
    pub(crate) fn install_forwarding_rules(&mut self) -> Result<()> {
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
}
