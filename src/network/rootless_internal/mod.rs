// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

pub mod addr;
pub mod engine;
pub mod packet;
pub mod route;
pub mod state;
pub mod tap;

use anyhow::{Context, Result};
use nix::unistd::Pid;

use crate::capture::FrameCaptureWriter;
use crate::cli::Cli;
use crate::dns::DnsPlan;
use crate::namespace;
use crate::proxy::ProxyPlan;

use super::types::NetworkPlan;

pub struct ChildBootstrap {
    tap: Option<tap::TapHandle>,
    addr_plan: addr::AddressPlan,
}

impl ChildBootstrap {
    pub fn prepare(plan: &NetworkPlan) -> Result<Self> {
        let addr_plan = addr::AddressPlan::from_network_plan(plan);
        Ok(Self {
            tap: None,
            addr_plan,
        })
    }

    pub fn namespace_bootstrap(&self) -> namespace::ChildNetworkBootstrap {
        namespace::ChildNetworkBootstrap::RootlessInternal(namespace::RootlessChildBootstrap {
            tap_name: self.addr_plan.tap_name.clone(),
            gateway_mac: self.addr_plan.gateway_mac,
            child_ipv4: self.addr_plan.child_ipv4,
            gateway_ipv4: self.addr_plan.gateway_ipv4,
            child_ipv6: self.addr_plan.child_ipv6,
            gateway_ipv6: self.addr_plan.gateway_ipv6,
            child_ipv4_prefix_len: self.addr_plan.child_ipv4_prefix_len,
            child_ipv6_prefix_len: self.addr_plan.child_ipv6_prefix_len,
        })
    }

    pub fn addr_plan(&self) -> &addr::AddressPlan {
        &self.addr_plan
    }

    pub fn set_tap(&mut self, tap: tap::TapHandle) {
        self.tap = Some(tap);
    }

    pub fn take_tap(&mut self) -> tap::TapHandle {
        self.tap
            .take()
            .expect("rootless tap handle must be populated before engine startup")
    }
}

pub struct NetworkContext {
    _engine: engine::EngineHandle,
}

impl NetworkContext {
    pub fn capture_mode(&self) -> Option<crate::capture::CaptureMode> {
        None
    }
}

pub struct RootlessSetupParams<'a> {
    pub dns_plan: &'a DnsPlan,
    pub child_bootstrap: &'a mut ChildBootstrap,
    pub proxy_plan: Option<&'a ProxyPlan>,
}

pub fn setup(
    _plan: &NetworkPlan,
    _run_id: &str,
    _child_pid: Pid,
    cli: &Cli,
    _tproxy_port: Option<u16>,
    params: RootlessSetupParams<'_>,
) -> Result<NetworkContext> {
    let addr_plan = params.child_bootstrap.addr_plan().clone();
    let dns_upstream = params.dns_plan.rootless_upstream();
    let capture = cli
        .output
        .as_deref()
        .map(FrameCaptureWriter::open_rootless)
        .transpose()
        .context("failed to open the rootless tap capture output")?;
    let engine = engine::EngineHandle::start(
        params.child_bootstrap.take_tap(),
        addr_plan.clone(),
        engine::EngineConfig {
            dns_upstream,
            allow_ipv6_outbound: engine::detect_ipv6_outbound(),
            proxy_upstream: params
                .proxy_plan
                .and_then(ProxyPlan::rootless_upstream)
                .cloned(),
            capture,
        },
    )
    .context("failed to start the rootless-internal userspace networking engine")?;

    Ok(NetworkContext { _engine: engine })
}