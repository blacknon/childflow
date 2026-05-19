use anyhow::Context;

use super::*;

impl NetworkContext {
    pub(super) fn install_private_range_drop_rules(&mut self) -> Result<()> {
        for cidr in PRIVATE_IPV4_CIDRS {
            let args = vec![
                "-A".into(),
                "PREROUTING".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-d".into(),
                (*cidr).to_string(),
                "-j".into(),
                "DROP".into(),
            ];
            run_iptables("mangle", args.clone()).with_context(|| {
                format!("failed to install IPv4 private-range drop rule for {cidr}")
            })?;
            self.push_cleanup_iptables(
                "remove IPv4 private-range drop rule",
                "mangle",
                replace_action_flag(&args, "-A", "-D"),
            );
        }

        for cidr in PRIVATE_IPV6_CIDRS {
            let args = vec![
                "-A".into(),
                "PREROUTING".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-d".into(),
                (*cidr).to_string(),
                "-j".into(),
                "DROP".into(),
            ];
            run_ip6tables("mangle", args.clone()).with_context(|| {
                format!("failed to install IPv6 private-range drop rule for {cidr}")
            })?;
            self.push_cleanup_ip6tables(
                "remove IPv6 private-range drop rule",
                "mangle",
                replace_action_flag(&args, "-A", "-D"),
            );
        }
        Ok(())
    }

    pub(super) fn install_deny_cidr_drop_rules(&mut self, deny_cidrs: &[IpNetwork]) -> Result<()> {
        for cidr in deny_cidrs {
            match cidr {
                IpNetwork::V4(_) => {
                    let args = vec![
                        "-A".into(),
                        "PREROUTING".into(),
                        "-i".into(),
                        self.host_veth.clone(),
                        "-d".into(),
                        cidr.to_string(),
                        "-j".into(),
                        "DROP".into(),
                    ];
                    run_iptables("mangle", args.clone()).with_context(|| {
                        format!("failed to install IPv4 deny-cidr drop rule for {cidr}")
                    })?;
                    self.push_cleanup_iptables(
                        "remove IPv4 deny-cidr drop rule",
                        "mangle",
                        replace_action_flag(&args, "-A", "-D"),
                    );
                }
                IpNetwork::V6(_) => {
                    let args = vec![
                        "-A".into(),
                        "PREROUTING".into(),
                        "-i".into(),
                        self.host_veth.clone(),
                        "-d".into(),
                        cidr.to_string(),
                        "-j".into(),
                        "DROP".into(),
                    ];
                    run_ip6tables("mangle", args.clone()).with_context(|| {
                        format!("failed to install IPv6 deny-cidr drop rule for {cidr}")
                    })?;
                    self.push_cleanup_ip6tables(
                        "remove IPv6 deny-cidr drop rule",
                        "mangle",
                        replace_action_flag(&args, "-A", "-D"),
                    );
                }
            }
        }
        Ok(())
    }
}
