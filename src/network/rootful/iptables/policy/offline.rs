use anyhow::Context;

use super::*;

impl NetworkContext {
    pub(super) fn install_offline_drop_rules(&mut self) -> Result<()> {
        let drop_v4 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "DROP".into(),
        ];
        run_iptables("mangle", drop_v4.clone())
            .context("failed to install IPv4 offline drop rule")?;
        self.push_cleanup_iptables(
            "remove IPv4 offline drop rule",
            "mangle",
            replace_action_flag(&drop_v4, "-A", "-D"),
        );

        let drop_v6 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "DROP".into(),
        ];
        run_ip6tables("mangle", drop_v6.clone())
            .context("failed to install IPv6 offline drop rule")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 offline drop rule",
            "mangle",
            replace_action_flag(&drop_v6, "-A", "-D"),
        );
        Ok(())
    }

    pub(super) fn install_sandbox_subnet_bypass_rules(&mut self) -> Result<()> {
        let bypass_v4 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-d".into(),
            self.subnet_v4_cidr.clone(),
            "-j".into(),
            "RETURN".into(),
        ];
        run_iptables("mangle", bypass_v4.clone())
            .context("failed to install IPv4 sandbox-subnet bypass rule")?;
        self.push_cleanup_iptables(
            "remove IPv4 sandbox-subnet bypass rule",
            "mangle",
            replace_action_flag(&bypass_v4, "-A", "-D"),
        );

        let bypass_v6 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-d".into(),
            self.subnet_v6_cidr.clone(),
            "-j".into(),
            "RETURN".into(),
        ];
        run_ip6tables("mangle", bypass_v6.clone())
            .context("failed to install IPv6 sandbox-subnet bypass rule")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 sandbox-subnet bypass rule",
            "mangle",
            replace_action_flag(&bypass_v6, "-A", "-D"),
        );
        Ok(())
    }

    pub(super) fn install_metadata_drop_rules(&mut self) -> Result<()> {
        let metadata_v4 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-d".into(),
            BLOCK_METADATA_IPV4.to_string(),
            "-j".into(),
            "DROP".into(),
        ];
        run_iptables("mangle", metadata_v4.clone())
            .context("failed to install IPv4 metadata drop rule")?;
        self.push_cleanup_iptables(
            "remove IPv4 metadata drop rule",
            "mangle",
            replace_action_flag(&metadata_v4, "-A", "-D"),
        );

        let metadata_v6 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-d".into(),
            BLOCK_METADATA_IPV6.to_string(),
            "-j".into(),
            "DROP".into(),
        ];
        run_ip6tables("mangle", metadata_v6.clone())
            .context("failed to install IPv6 metadata drop rule")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 metadata drop rule",
            "mangle",
            replace_action_flag(&metadata_v6, "-A", "-D"),
        );
        Ok(())
    }
}
