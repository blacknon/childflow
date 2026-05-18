use anyhow::Context;

use super::super::{
    replace_action_flag, run_ip6tables, run_iptables, NetworkContext, Result, TproxySettings,
};

pub(super) fn install_divert_chain(
    ctx: &mut NetworkContext,
    settings: &TproxySettings,
) -> Result<()> {
    run_iptables("mangle", vec!["-N".into(), settings.divert_chain.clone()])
        .context("failed to create DIVERT chain")?;
    ctx.push_cleanup_iptables(
        "delete IPv4 DIVERT chain",
        "mangle",
        vec!["-X".into(), settings.divert_chain.clone()],
    );
    ctx.push_cleanup_iptables(
        "flush IPv4 DIVERT chain",
        "mangle",
        vec!["-F".into(), settings.divert_chain.clone()],
    );

    run_ip6tables("mangle", vec!["-N".into(), settings.divert_chain.clone()])
        .context("failed to create IPv6 DIVERT chain")?;
    ctx.push_cleanup_ip6tables(
        "delete IPv6 DIVERT chain",
        "mangle",
        vec!["-X".into(), settings.divert_chain.clone()],
    );
    ctx.push_cleanup_ip6tables(
        "flush IPv6 DIVERT chain",
        "mangle",
        vec!["-F".into(), settings.divert_chain.clone()],
    );

    install_divert_mark_rules(ctx, settings)?;
    install_divert_accept_rules(ctx, settings)?;
    install_divert_hooks(ctx, settings)?;
    Ok(())
}

fn install_divert_mark_rules(ctx: &mut NetworkContext, settings: &TproxySettings) -> Result<()> {
    let divert_mark_v4 = vec![
        "-A".into(),
        settings.divert_chain.clone(),
        "-j".into(),
        "MARK".into(),
        "--set-mark".into(),
        settings.tproxy_mark.to_string(),
    ];
    run_iptables("mangle", divert_mark_v4.clone())
        .context("failed to populate DIVERT mark rule")?;
    ctx.push_cleanup_iptables(
        "remove IPv4 DIVERT mark rule",
        "mangle",
        replace_action_flag(&divert_mark_v4, "-A", "-D"),
    );

    let divert_mark_v6 = divert_mark_v4.clone();
    run_ip6tables("mangle", divert_mark_v6.clone())
        .context("failed to populate IPv6 DIVERT mark rule")?;
    ctx.push_cleanup_ip6tables(
        "remove IPv6 DIVERT mark rule",
        "mangle",
        replace_action_flag(&divert_mark_v6, "-A", "-D"),
    );
    Ok(())
}

fn install_divert_accept_rules(ctx: &mut NetworkContext, settings: &TproxySettings) -> Result<()> {
    let divert_accept_v4 = vec![
        "-A".into(),
        settings.divert_chain.clone(),
        "-j".into(),
        "ACCEPT".into(),
    ];
    run_iptables("mangle", divert_accept_v4.clone())
        .context("failed to populate DIVERT accept rule")?;
    ctx.push_cleanup_iptables(
        "remove IPv4 DIVERT accept rule",
        "mangle",
        replace_action_flag(&divert_accept_v4, "-A", "-D"),
    );

    let divert_accept_v6 = divert_accept_v4.clone();
    run_ip6tables("mangle", divert_accept_v6.clone())
        .context("failed to populate IPv6 DIVERT accept rule")?;
    ctx.push_cleanup_ip6tables(
        "remove IPv6 DIVERT accept rule",
        "mangle",
        replace_action_flag(&divert_accept_v6, "-A", "-D"),
    );
    Ok(())
}

fn install_divert_hooks(ctx: &mut NetworkContext, settings: &TproxySettings) -> Result<()> {
    let divert_hook_v4 = vec![
        "-A".into(),
        "PREROUTING".into(),
        "-i".into(),
        ctx.host_veth.clone(),
        "-p".into(),
        "tcp".into(),
        "-m".into(),
        "socket".into(),
        "--transparent".into(),
        "-j".into(),
        settings.divert_chain.clone(),
    ];
    run_iptables("mangle", divert_hook_v4.clone())
        .context("failed to install transparent socket DIVERT rule")?;
    ctx.push_cleanup_iptables(
        "remove IPv4 DIVERT PREROUTING hook",
        "mangle",
        replace_action_flag(&divert_hook_v4, "-A", "-D"),
    );

    let divert_hook_v6 = divert_hook_v4.clone();
    run_ip6tables("mangle", divert_hook_v6.clone())
        .context("failed to install IPv6 transparent socket DIVERT rule")?;
    ctx.push_cleanup_ip6tables(
        "remove IPv6 DIVERT PREROUTING hook",
        "mangle",
        replace_action_flag(&divert_hook_v6, "-A", "-D"),
    );
    Ok(())
}
