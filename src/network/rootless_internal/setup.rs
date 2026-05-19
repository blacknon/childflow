// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use anyhow::{Context, Result};
use nix::unistd::Pid;

use super::{addr, engine, routes, ChildBootstrap, NetworkContext};
use crate::capture::{derive_output_paths, CaptureMetadata, CaptureWriters};
use crate::cli::{Cli, OutputView};
use crate::dns::DnsPlan;
use crate::flow_log::FlowLogger;
use crate::network::types::NetworkPlan;
use crate::proxy::ProxyPlan;
use crate::sandbox::SandboxPolicy;

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
    let sandbox_policy = SandboxPolicy::from_cli(cli);
    let dns_upstream = if sandbox_policy.offline {
        None
    } else {
        params.dns_plan.rootless_upstream()
    };
    let capture_plan = routes::discover_rootless_capture_plan(cli)?;
    let capture = open_capture_writers(cli, &addr_plan)?;
    let flow_log = cli
        .flow_log
        .as_deref()
        .map(FlowLogger::open)
        .transpose()
        .context("failed to open the rootless flow log output")?;
    let engine = engine::EngineHandle::start(
        params.child_bootstrap.take_tap(),
        addr_plan.clone(),
        engine::EngineConfig {
            dns_upstream,
            allow_ipv6_outbound: engine::detect_ipv6_outbound(),
            sandbox_policy,
            proxy_upstream: params
                .proxy_plan
                .and_then(ProxyPlan::rootless_upstream)
                .cloned(),
            capture,
            flow_log,
        },
    )
    .context("failed to start the rootless-internal userspace networking engine")?;

    Ok(NetworkContext {
        engine,
        capture_plan,
    })
}

fn open_capture_writers(
    cli: &Cli,
    addr_plan: &addr::AddressPlan,
) -> Result<Option<CaptureWriters>> {
    Ok(match (cli.output.as_deref(), cli.output_view) {
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
                routes::discover_rootless_egress_rewrite(addr_plan)?,
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
                    routes::discover_rootless_egress_rewrite(addr_plan)?,
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
    })
}
