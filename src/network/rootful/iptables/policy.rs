use anyhow::Context;

use super::*;

impl NetworkContext {
    pub(crate) fn install_sandbox_policy_rules(&mut self, policy: SandboxPolicy) -> Result<()> {
        if policy.offline {
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
            return Ok(());
        }

        if !policy.block_private
            && !policy.block_metadata
            && policy.deny_cidrs.is_empty()
            && !matches!(policy.default_policy, DefaultPolicy::Deny)
            && !policy.proxy_only
        {
            return Ok(());
        }

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

        if policy.block_metadata {
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
        }

        if policy.block_private {
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
        }

        for cidr in &policy.deny_cidrs {
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

        if policy.proxy_only {
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
        } else if matches!(policy.default_policy, DefaultPolicy::Deny) {
            for cidr in &policy.allow_cidrs {
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
        }

        Ok(())
    }
}
