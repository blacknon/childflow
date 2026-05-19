use anyhow::Context;

use super::{NetworkContext, Result, TproxySettings};
use crate::linux_net;

pub(super) fn install_tproxy_policy_routing(
    ctx: &mut NetworkContext,
    settings: &TproxySettings,
) -> Result<()> {
    install_policy_rules(ctx, settings)?;
    install_local_routes(ctx, settings)?;
    Ok(())
}

fn install_policy_rules(ctx: &mut NetworkContext, settings: &TproxySettings) -> Result<()> {
    linux_net::policy_rule_add_v4(
        settings.tproxy_mark,
        settings.tproxy_table,
        settings.tproxy_priority,
    )
    .context("failed to install TPROXY policy routing rule")?;
    ctx.push_cleanup_policy_rule_v4(
        settings.tproxy_mark,
        settings.tproxy_table,
        settings.tproxy_priority,
    );

    linux_net::policy_rule_add_v6(
        settings.tproxy_mark,
        settings.tproxy_table,
        settings.tproxy_priority,
    )
    .context("failed to install IPv6 TPROXY policy routing rule")?;
    ctx.push_cleanup_policy_rule_v6(
        settings.tproxy_mark,
        settings.tproxy_table,
        settings.tproxy_priority,
    );

    Ok(())
}

fn install_local_routes(ctx: &mut NetworkContext, settings: &TproxySettings) -> Result<()> {
    linux_net::route_add_local_v4_table(settings.tproxy_table)
        .context("failed to install local route for TPROXY table")?;
    ctx.push_cleanup_local_route_v4(settings.tproxy_table);

    linux_net::route_add_local_v6_table(settings.tproxy_table)
        .context("failed to install IPv6 local route for TPROXY table")?;
    ctx.push_cleanup_local_route_v6(settings.tproxy_table);

    Ok(())
}
