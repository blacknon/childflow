use anyhow::Context;

use super::super::{
    replace_action_flag, run_ip6tables, run_iptables, IpNetwork, NetworkContext, Result,
};

pub(super) fn install_default_deny_rules(
    ctx: &mut NetworkContext,
    allow_cidrs: &[IpNetwork],
) -> Result<()> {
    install_default_deny_allow_cidrs(ctx, allow_cidrs)?;
    install_default_deny_drop_rules(ctx)
}

fn install_default_deny_allow_cidrs(
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
                    "-d".into(),
                    cidr.to_string(),
                    "-j".into(),
                    "RETURN".into(),
                ];
                run_iptables("mangle", args.clone()).with_context(|| {
                    format!("failed to install IPv4 allow-cidr bypass rule for {cidr}")
                })?;
                ctx.push_cleanup_iptables(
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
                    ctx.host_veth.clone(),
                    "-d".into(),
                    cidr.to_string(),
                    "-j".into(),
                    "RETURN".into(),
                ];
                run_ip6tables("mangle", args.clone()).with_context(|| {
                    format!("failed to install IPv6 allow-cidr bypass rule for {cidr}")
                })?;
                ctx.push_cleanup_ip6tables(
                    "remove IPv6 allow-cidr bypass rule",
                    "mangle",
                    replace_action_flag(&args, "-A", "-D"),
                );
            }
        }
    }

    Ok(())
}

fn install_default_deny_drop_rules(ctx: &mut NetworkContext) -> Result<()> {
    let drop_v4 = vec![
        "-A".into(),
        "PREROUTING".into(),
        "-i".into(),
        ctx.host_veth.clone(),
        "-j".into(),
        "DROP".into(),
    ];
    run_iptables("mangle", drop_v4.clone())
        .context("failed to install IPv4 default-deny drop rule")?;
    ctx.push_cleanup_iptables(
        "remove IPv4 default-deny drop rule",
        "mangle",
        replace_action_flag(&drop_v4, "-A", "-D"),
    );

    let drop_v6 = drop_v4.clone();
    run_ip6tables("mangle", drop_v6.clone())
        .context("failed to install IPv6 default-deny drop rule")?;
    ctx.push_cleanup_ip6tables(
        "remove IPv6 default-deny drop rule",
        "mangle",
        replace_action_flag(&drop_v6, "-A", "-D"),
    );
    Ok(())
}
