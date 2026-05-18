use anyhow::Context;

use super::super::{
    replace_action_flag, run_ip6tables, run_iptables, DefaultPolicy, IpNetwork, NetworkContext,
    Result, SandboxPolicy,
};

pub(super) fn install_proxy_only_rules(
    ctx: &mut NetworkContext,
    policy: &SandboxPolicy,
) -> Result<()> {
    if matches!(policy.default_policy, DefaultPolicy::Deny) {
        install_proxy_only_allow_cidrs(ctx, &policy.allow_cidrs)?;
    } else {
        install_proxy_only_tcp_bypass(ctx)?;
    }

    install_proxy_only_drop_rules(ctx)
}

fn install_proxy_only_allow_cidrs(
    ctx: &mut NetworkContext,
    allow_cidrs: &[IpNetwork],
) -> Result<()> {
    for cidr in allow_cidrs {
        match cidr {
            IpNetwork::V4(_) => {
                let args = vec![
                    "-A".into(),
                    "PREROUTING".into(),
                    "-i".into(),
                    ctx.host_veth.clone(),
                    "-p".into(),
                    "tcp".into(),
                    "-d".into(),
                    cidr.to_string(),
                    "-j".into(),
                    "RETURN".into(),
                ];
                run_iptables("mangle", args.clone()).with_context(|| {
                    format!("failed to install IPv4 proxy-only allow-cidr bypass rule for {cidr}")
                })?;
                ctx.push_cleanup_iptables(
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
                    ctx.host_veth.clone(),
                    "-p".into(),
                    "tcp".into(),
                    "-d".into(),
                    cidr.to_string(),
                    "-j".into(),
                    "RETURN".into(),
                ];
                run_ip6tables("mangle", args.clone()).with_context(|| {
                    format!("failed to install IPv6 proxy-only allow-cidr bypass rule for {cidr}")
                })?;
                ctx.push_cleanup_ip6tables(
                    "remove IPv6 proxy-only allow-cidr bypass rule",
                    "mangle",
                    replace_action_flag(&args, "-A", "-D"),
                );
            }
        }
    }

    Ok(())
}

fn install_proxy_only_tcp_bypass(ctx: &mut NetworkContext) -> Result<()> {
    let allow_tcp_v4 = vec![
        "-A".into(),
        "PREROUTING".into(),
        "-i".into(),
        ctx.host_veth.clone(),
        "-p".into(),
        "tcp".into(),
        "-j".into(),
        "RETURN".into(),
    ];
    run_iptables("mangle", allow_tcp_v4.clone())
        .context("failed to install IPv4 proxy-only TCP bypass rule")?;
    ctx.push_cleanup_iptables(
        "remove IPv4 proxy-only TCP bypass rule",
        "mangle",
        replace_action_flag(&allow_tcp_v4, "-A", "-D"),
    );

    let allow_tcp_v6 = allow_tcp_v4.clone();
    run_ip6tables("mangle", allow_tcp_v6.clone())
        .context("failed to install IPv6 proxy-only TCP bypass rule")?;
    ctx.push_cleanup_ip6tables(
        "remove IPv6 proxy-only TCP bypass rule",
        "mangle",
        replace_action_flag(&allow_tcp_v6, "-A", "-D"),
    );
    Ok(())
}

fn install_proxy_only_drop_rules(ctx: &mut NetworkContext) -> Result<()> {
    let drop_v4 = vec![
        "-A".into(),
        "PREROUTING".into(),
        "-i".into(),
        ctx.host_veth.clone(),
        "-j".into(),
        "DROP".into(),
    ];
    run_iptables("mangle", drop_v4.clone())
        .context("failed to install IPv4 proxy-only drop rule")?;
    ctx.push_cleanup_iptables(
        "remove IPv4 proxy-only drop rule",
        "mangle",
        replace_action_flag(&drop_v4, "-A", "-D"),
    );

    let drop_v6 = drop_v4.clone();
    run_ip6tables("mangle", drop_v6.clone())
        .context("failed to install IPv6 proxy-only drop rule")?;
    ctx.push_cleanup_ip6tables(
        "remove IPv6 proxy-only drop rule",
        "mangle",
        replace_action_flag(&drop_v6, "-A", "-D"),
    );
    Ok(())
}
