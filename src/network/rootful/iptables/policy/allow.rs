use anyhow::Context;

use super::*;

impl NetworkContext {
    pub(super) fn install_proxy_only_rules(&mut self, policy: &SandboxPolicy) -> Result<()> {
        if matches!(policy.default_policy, DefaultPolicy::Deny) {
            for cidr in &policy.allow_cidrs {
                match cidr {
                    IpNetwork::V4(_) => {
                        let args = vec![
                            "-A".into(),
                            "PREROUTING".into(),
                            "-i".into(),
                            self.host_veth.clone(),
                            "-p".into(),
                            "tcp".into(),
                            "-d".into(),
                            cidr.to_string(),
                            "-j".into(),
                            "RETURN".into(),
                        ];
                        run_iptables("mangle", args.clone()).with_context(|| {
                            format!(
                                "failed to install IPv4 proxy-only allow-cidr bypass rule for {cidr}"
                            )
                        })?;
                        self.push_cleanup_iptables(
                            "remove IPv4 proxy-only allow-cidr bypass rule",
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
                            "-p".into(),
                            "tcp".into(),
                            "-d".into(),
                            cidr.to_string(),
                            "-j".into(),
                            "RETURN".into(),
                        ];
                        run_ip6tables("mangle", args.clone()).with_context(|| {
                            format!(
                                "failed to install IPv6 proxy-only allow-cidr bypass rule for {cidr}"
                            )
                        })?;
                        self.push_cleanup_ip6tables(
                            "remove IPv6 proxy-only allow-cidr bypass rule",
                            "mangle",
                            replace_action_flag(&args, "-A", "-D"),
                        );
                    }
                }
            }
        } else {
            let allow_tcp_v4 = vec![
                "-A".into(),
                "PREROUTING".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-p".into(),
                "tcp".into(),
                "-j".into(),
                "RETURN".into(),
            ];
            run_iptables("mangle", allow_tcp_v4.clone())
                .context("failed to install IPv4 proxy-only TCP bypass rule")?;
            self.push_cleanup_iptables(
                "remove IPv4 proxy-only TCP bypass rule",
                "mangle",
                replace_action_flag(&allow_tcp_v4, "-A", "-D"),
            );

            let allow_tcp_v6 = vec![
                "-A".into(),
                "PREROUTING".into(),
                "-i".into(),
                self.host_veth.clone(),
                "-p".into(),
                "tcp".into(),
                "-j".into(),
                "RETURN".into(),
            ];
            run_ip6tables("mangle", allow_tcp_v6.clone())
                .context("failed to install IPv6 proxy-only TCP bypass rule")?;
            self.push_cleanup_ip6tables(
                "remove IPv6 proxy-only TCP bypass rule",
                "mangle",
                replace_action_flag(&allow_tcp_v6, "-A", "-D"),
            );
        }

        let drop_v4 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "DROP".into(),
        ];
        run_iptables("mangle", drop_v4.clone())
            .context("failed to install IPv4 proxy-only drop rule")?;
        self.push_cleanup_iptables(
            "remove IPv4 proxy-only drop rule",
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
            .context("failed to install IPv6 proxy-only drop rule")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 proxy-only drop rule",
            "mangle",
            replace_action_flag(&drop_v6, "-A", "-D"),
        );
        Ok(())
    }

    pub(super) fn install_default_deny_rules(&mut self, allow_cidrs: &[IpNetwork]) -> Result<()> {
        for cidr in allow_cidrs {
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
                        "RETURN".into(),
                    ];
                    run_iptables("mangle", args.clone()).with_context(|| {
                        format!("failed to install IPv4 allow-cidr bypass rule for {cidr}")
                    })?;
                    self.push_cleanup_iptables(
                        "remove IPv4 allow-cidr bypass rule",
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
                        "RETURN".into(),
                    ];
                    run_ip6tables("mangle", args.clone()).with_context(|| {
                        format!("failed to install IPv6 allow-cidr bypass rule for {cidr}")
                    })?;
                    self.push_cleanup_ip6tables(
                        "remove IPv6 allow-cidr bypass rule",
                        "mangle",
                        replace_action_flag(&args, "-A", "-D"),
                    );
                }
            }
        }

        let drop_v4 = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "DROP".into(),
        ];
        run_iptables("mangle", drop_v4.clone())
            .context("failed to install IPv4 default-deny drop rule")?;
        self.push_cleanup_iptables(
            "remove IPv4 default-deny drop rule",
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
            .context("failed to install IPv6 default-deny drop rule")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 default-deny drop rule",
            "mangle",
            replace_action_flag(&drop_v6, "-A", "-D"),
        );
        Ok(())
    }
}
