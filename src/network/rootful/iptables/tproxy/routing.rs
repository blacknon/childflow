use anyhow::Context;

use super::{NetworkContext, Result, TproxySettings};
use crate::util::run_command;

pub(super) fn install_tproxy_policy_routing(
    ctx: &mut NetworkContext,
    settings: &TproxySettings,
) -> Result<()> {
    install_policy_rules(ctx, settings)?;
    install_local_routes(ctx, settings)?;
    Ok(())
}

fn install_policy_rules(ctx: &mut NetworkContext, settings: &TproxySettings) -> Result<()> {
    run_command(
        "ip",
        vec![
            "rule".into(),
            "add".into(),
            "fwmark".into(),
            settings.tproxy_mark.to_string(),
            "lookup".into(),
            settings.tproxy_table.to_string(),
            "priority".into(),
            settings.tproxy_priority.to_string(),
        ],
    )
    .context("failed to install TPROXY policy routing rule")?;
    ctx.push_cleanup_command(
        "remove IPv4 TPROXY policy rule",
        "ip",
        vec![
            "rule".into(),
            "del".into(),
            "priority".into(),
            settings.tproxy_priority.to_string(),
        ],
    );

    run_command(
        "ip",
        vec![
            "-6".into(),
            "rule".into(),
            "add".into(),
            "fwmark".into(),
            settings.tproxy_mark.to_string(),
            "lookup".into(),
            settings.tproxy_table.to_string(),
            "priority".into(),
            settings.tproxy_priority.to_string(),
        ],
    )
    .context("failed to install IPv6 TPROXY policy routing rule")?;
    ctx.push_cleanup_command(
        "remove IPv6 TPROXY policy rule",
        "ip",
        vec![
            "-6".into(),
            "rule".into(),
            "del".into(),
            "priority".into(),
            settings.tproxy_priority.to_string(),
        ],
    );

    Ok(())
}

fn install_local_routes(ctx: &mut NetworkContext, settings: &TproxySettings) -> Result<()> {
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
            settings.tproxy_table.to_string(),
        ],
    )
    .context("failed to install local route for TPROXY table")?;
    ctx.push_cleanup_command(
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
            settings.tproxy_table.to_string(),
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
            settings.tproxy_table.to_string(),
        ],
    )
    .context("failed to install IPv6 local route for TPROXY table")?;
    ctx.push_cleanup_command(
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
            settings.tproxy_table.to_string(),
        ],
    );

    Ok(())
}
