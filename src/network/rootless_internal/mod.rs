// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

pub mod addr;
pub mod engine;
mod icmp;
pub mod packet;
pub mod route;
pub mod state;
pub mod tap;
mod transport;

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use nix::unistd::Pid;

use crate::capture::{
    derive_output_paths, CaptureMetadata, CaptureMode, CapturePlan, CaptureWriters,
    RootfulEgressRewrite,
};
use crate::cli::{Cli, OutputView};
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
    engine: engine::EngineHandle,
    capture_plan: Option<CapturePlan>,
}

impl NetworkContext {
    pub fn shutdown(self) -> Result<()> {
        self.engine.shutdown()
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
    let capture_plan = discover_rootless_capture_plan(cli)?;
    let capture = match (cli.output.as_deref(), cli.output_view) {
        (Some(output_path), OutputView::Child) => Some(
            CaptureWriters::open_child_only(
                output_path,
                CaptureMetadata::new(
                    "child",
                    "rootless-internal",
                    "isolated",
                    addr_plan.tap_name.clone(),
                ),
            )
            .context("failed to open the rootless tap capture output")?,
        ),
        (Some(output_path), OutputView::Egress) => Some(
            CaptureWriters::open_synthetic_egress(
                output_path,
                discover_rootless_egress_rewrite(&addr_plan)?,
                CaptureMetadata::new("egress", "rootless-internal", "logical", "logical-egress"),
            )
            .context("failed to open the rootless logical-egress capture output")?,
        ),
        (Some(_), OutputView::WireEgress) => None,
        (Some(output_path), OutputView::Both) => {
            let (child_output_path, egress_output_path) =
                derive_output_paths(output_path, cli.output_view)?;
            Some(
                CaptureWriters::open_child_and_synthetic_egress(
                    &child_output_path,
                    &egress_output_path,
                    discover_rootless_egress_rewrite(&addr_plan)?,
                    CaptureMetadata::new(
                        "child",
                        "rootless-internal",
                        "isolated",
                        addr_plan.tap_name.clone(),
                    ),
                    CaptureMetadata::new(
                        "egress",
                        "rootless-internal",
                        "logical",
                        "logical-egress",
                    ),
                )
                .context("failed to open the rootless child and logical-egress capture outputs")?,
            )
        }
        (None, _) => None,
    };
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

    Ok(NetworkContext {
        engine,
        capture_plan,
    })
}

impl NetworkContext {
    pub fn capture_plan(&self) -> Option<CapturePlan> {
        self.capture_plan.clone()
    }
}

fn discover_rootless_egress_rewrite(addr_plan: &addr::AddressPlan) -> Result<RootfulEgressRewrite> {
    let host_egress_ipv4 = Some(discover_route_get_src_v4().context(
        "failed to determine the rootless IPv4 egress source address from the default route",
    )?);
    let host_egress_ipv6 = match discover_route_get_src_v6() {
        Ok(value) => value,
        Err(err) => {
            crate::util::debug(format!(
                "could not determine a rootless IPv6 egress source address: {err:#}. IPv6 logical-egress capture may be unavailable on this host"
            ));
            None
        }
    };

    Ok(RootfulEgressRewrite {
        child_ipv4: addr_plan.child_ipv4,
        child_ipv6: addr_plan.child_ipv6,
        host_egress_ipv4,
        host_egress_ipv6,
    })
}

fn discover_route_get_src_v4() -> Result<std::net::Ipv4Addr> {
    let output =
        crate::util::run_command("ip", vec!["route".into(), "get".into(), "1.1.1.1".into()])
            .context("failed to inspect IPv4 route-get output")?;
    parse_route_get_src_v4(&output)
}

fn discover_rootless_capture_plan(cli: &Cli) -> Result<Option<CapturePlan>> {
    let Some(output_path) = cli.output.as_ref() else {
        return Ok(None);
    };
    match cli.output_view {
        OutputView::WireEgress => {
            discover_rootless_wire_egress_capture_plan(output_path.clone()).map(Some)
        }
        _ => Ok(None),
    }
}

fn discover_rootless_wire_egress_capture_plan(output_path: PathBuf) -> Result<CapturePlan> {
    let interface_name = discover_route_get_dev_v4()
        .context("failed to determine the rootless wire-egress interface from the default route")?;
    Ok(CapturePlan::ChildOnly {
        mode: CaptureMode::AfPacket {
            interface_name: interface_name.clone(),
        },
        output_path,
        metadata: CaptureMetadata::new("wire-egress", "rootless-internal", "wire", interface_name),
    })
}

fn discover_route_get_dev_v4() -> Result<String> {
    let output =
        crate::util::run_command("ip", vec!["route".into(), "get".into(), "1.1.1.1".into()])
            .context("failed to inspect IPv4 route-get output")?;
    parse_route_get_dev(&output)
}

fn discover_route_get_src_v6() -> Result<Option<std::net::Ipv6Addr>> {
    let output = crate::util::run_command(
        "ip",
        vec![
            "-6".into(),
            "route".into(),
            "get".into(),
            "2606:4700:4700::1111".into(),
        ],
    )
    .context("failed to inspect IPv6 route-get output")?;
    parse_route_get_src_v6(&output).map(Some)
}

fn parse_route_get_src_v4(output: &str) -> Result<std::net::Ipv4Addr> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    tokens
        .windows(2)
        .find(|pair| pair[0] == "src")
        .ok_or_else(|| anyhow::anyhow!("no `src` token found in route-get output: {output}"))?[1]
        .parse::<std::net::Ipv4Addr>()
        .with_context(|| {
            format!("failed to parse IPv4 `src` token from route-get output: {output}")
        })
}

fn parse_route_get_src_v6(output: &str) -> Result<std::net::Ipv6Addr> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    tokens
        .windows(2)
        .find(|pair| pair[0] == "src")
        .ok_or_else(|| anyhow::anyhow!("no `src` token found in IPv6 route-get output: {output}"))?
        [1]
    .parse::<std::net::Ipv6Addr>()
    .with_context(|| format!("failed to parse IPv6 `src` token from route-get output: {output}"))
}

fn parse_route_get_dev(output: &str) -> Result<String> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    Ok(tokens
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .ok_or_else(|| anyhow!("no `dev` token found in route-get output: {output}"))?[1]
        .to_string())
}
