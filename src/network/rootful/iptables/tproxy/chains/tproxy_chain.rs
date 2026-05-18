use anyhow::Context;

use super::super::{
    replace_action_flag, run_ip6tables, run_iptables, NetworkContext, Result, TproxySettings,
};

pub(super) fn install_tproxy_chain(
    ctx: &mut NetworkContext,
    settings: &TproxySettings,
) -> Result<()> {
    run_iptables("mangle", vec!["-N".into(), settings.tproxy_chain.clone()])
        .context("failed to create TPROXY chain")?;
    ctx.push_cleanup_iptables(
        "delete IPv4 TPROXY chain",
        "mangle",
        vec!["-X".into(), settings.tproxy_chain.clone()],
    );
    ctx.push_cleanup_iptables(
        "flush IPv4 TPROXY chain",
        "mangle",
        vec!["-F".into(), settings.tproxy_chain.clone()],
    );

    run_ip6tables("mangle", vec!["-N".into(), settings.tproxy_chain.clone()])
        .context("failed to create IPv6 TPROXY chain")?;
    ctx.push_cleanup_ip6tables(
        "delete IPv6 TPROXY chain",
        "mangle",
        vec!["-X".into(), settings.tproxy_chain.clone()],
    );
    ctx.push_cleanup_ip6tables(
        "flush IPv6 TPROXY chain",
        "mangle",
        vec!["-F".into(), settings.tproxy_chain.clone()],
    );

    install_tproxy_hooks(ctx, settings)?;
    install_subnet_bypass_rules(ctx, settings)?;
    install_tproxy_redirect_rules(ctx, settings)?;
    Ok(())
}

fn install_tproxy_hooks(ctx: &mut NetworkContext, settings: &TproxySettings) -> Result<()> {
    let tproxy_hook_v4 = vec![
        "-A".into(),
        "PREROUTING".into(),
        "-i".into(),
        ctx.host_veth.clone(),
        "-j".into(),
        settings.tproxy_chain.clone(),
    ];
    run_iptables("mangle", tproxy_hook_v4.clone())
        .context("failed to hook TPROXY chain from PREROUTING")?;
    ctx.push_cleanup_iptables(
        "remove IPv4 TPROXY PREROUTING hook",
        "mangle",
        replace_action_flag(&tproxy_hook_v4, "-A", "-D"),
    );

    let tproxy_hook_v6 = tproxy_hook_v4.clone();
    run_ip6tables("mangle", tproxy_hook_v6.clone())
        .context("failed to hook IPv6 TPROXY chain from PREROUTING")?;
    ctx.push_cleanup_ip6tables(
        "remove IPv6 TPROXY PREROUTING hook",
        "mangle",
        replace_action_flag(&tproxy_hook_v6, "-A", "-D"),
    );
    Ok(())
}

fn install_subnet_bypass_rules(ctx: &mut NetworkContext, settings: &TproxySettings) -> Result<()> {
    let subnet_bypass_v4 = vec![
        "-A".into(),
        settings.tproxy_chain.clone(),
        "-d".into(),
        ctx.subnet_v4_cidr.clone(),
        "-j".into(),
        "RETURN".into(),
    ];
    run_iptables("mangle", subnet_bypass_v4.clone())
        .context("failed to install subnet bypass rule in TPROXY chain")?;
    ctx.push_cleanup_iptables(
        "remove IPv4 TPROXY subnet bypass",
        "mangle",
        replace_action_flag(&subnet_bypass_v4, "-A", "-D"),
    );

    let subnet_bypass_v6 = vec![
        "-A".into(),
        settings.tproxy_chain.clone(),
        "-d".into(),
        ctx.subnet_v6_cidr.clone(),
        "-j".into(),
        "RETURN".into(),
    ];
    run_ip6tables("mangle", subnet_bypass_v6.clone())
        .context("failed to install IPv6 subnet bypass rule in TPROXY chain")?;
    ctx.push_cleanup_ip6tables(
        "remove IPv6 TPROXY subnet bypass",
        "mangle",
        replace_action_flag(&subnet_bypass_v6, "-A", "-D"),
    );
    Ok(())
}

fn install_tproxy_redirect_rules(
    ctx: &mut NetworkContext,
    settings: &TproxySettings,
) -> Result<()> {
    let tproxy_v4 = vec![
        "-A".into(),
        settings.tproxy_chain.clone(),
        "-p".into(),
        "tcp".into(),
        "-j".into(),
        "TPROXY".into(),
        "--on-port".into(),
        settings.listen_port.to_string(),
        "--tproxy-mark".into(),
        format!("0x{:x}/0xffffffff", settings.tproxy_mark),
    ];
    run_iptables("mangle", tproxy_v4.clone()).with_context(|| {
        format!(
            "failed to install TPROXY rule to port {}",
            settings.listen_port
        )
    })?;
    ctx.push_cleanup_iptables(
        "remove IPv4 TPROXY redirect",
        "mangle",
        replace_action_flag(&tproxy_v4, "-A", "-D"),
    );

    let tproxy_v6 = tproxy_v4.clone();
    run_ip6tables("mangle", tproxy_v6.clone()).with_context(|| {
        format!(
            "failed to install IPv6 TPROXY rule to port {}",
            settings.listen_port
        )
    })?;
    ctx.push_cleanup_ip6tables(
        "remove IPv6 TPROXY redirect",
        "mangle",
        replace_action_flag(&tproxy_v6, "-A", "-D"),
    );
    Ok(())
}
