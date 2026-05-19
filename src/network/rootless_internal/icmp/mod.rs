// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod handlers;
mod relay;

#[cfg(test)]
mod tests;

mod types;
mod workers;

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use anyhow::Result;

use crate::flow_log::FlowLogger;
use crate::sandbox::SandboxPolicy;

use super::addr::AddressPlan;
use super::engine::{RemoteEvent, ResolvedDomainIndex};
use super::packet::{ParsedIcmpv4Packet, ParsedIcmpv6Packet};

use self::types::IcmpRelayOutcome;

pub(super) fn handle_icmpv4_packet(
    event_tx: &Sender<RemoteEvent>,
    addr_plan: &AddressPlan,
    sandbox_policy: &SandboxPolicy,
    flow_log: &mut Option<FlowLogger>,
    leak_detected: &Arc<AtomicBool>,
    resolved_domains: &ResolvedDomainIndex,
    icmp: &ParsedIcmpv4Packet,
) -> Result<()> {
    handlers::handle_icmpv4_packet(
        event_tx,
        addr_plan,
        sandbox_policy,
        flow_log,
        leak_detected,
        resolved_domains,
        icmp,
    )
}

pub(super) fn handle_icmpv6_packet(
    event_tx: &Sender<RemoteEvent>,
    addr_plan: &AddressPlan,
    sandbox_policy: &SandboxPolicy,
    flow_log: &mut Option<FlowLogger>,
    leak_detected: &Arc<AtomicBool>,
    resolved_domains: &ResolvedDomainIndex,
    icmp: &ParsedIcmpv6Packet,
) -> Result<()> {
    handlers::handle_icmpv6_packet(
        event_tx,
        addr_plan,
        sandbox_policy,
        flow_log,
        leak_detected,
        resolved_domains,
        icmp,
    )
}
