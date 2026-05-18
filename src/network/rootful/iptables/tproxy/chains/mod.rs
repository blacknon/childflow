use anyhow::Result;

use super::{NetworkContext, TproxySettings};

mod divert;
mod tproxy_chain;

pub(super) fn install_tproxy_chains(
    ctx: &mut NetworkContext,
    settings: &TproxySettings,
) -> Result<()> {
    divert::install_divert_chain(ctx, settings)?;
    tproxy_chain::install_tproxy_chain(ctx, settings)?;
    Ok(())
}
