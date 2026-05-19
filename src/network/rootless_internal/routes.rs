// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use super::addr;
use crate::capture::{CaptureMetadata, CaptureMode, CapturePlan, RootfulEgressRewrite};
use crate::cli::{Cli, OutputView};

pub(super) fn discover_rootless_egress_rewrite(
    addr_plan: &addr::AddressPlan,
) -> Result<RootfulEgressRewrite> {
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

pub(super) fn discover_rootless_capture_plan(cli: &Cli) -> Result<Option<CapturePlan>> {
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

fn discover_route_get_src_v4() -> Result<std::net::Ipv4Addr> {
    let output =
        crate::util::run_command("ip", vec!["route".into(), "get".into(), "1.1.1.1".into()])
            .context("failed to inspect IPv4 route-get output")?;
    parse_route_get_src_v4(&output)
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
        .ok_or_else(|| anyhow!("no `src` token found in route-get output: {output}"))?[1]
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
        .ok_or_else(|| anyhow!("no `src` token found in IPv6 route-get output: {output}"))?[1]
        .parse::<std::net::Ipv6Addr>()
        .with_context(|| {
            format!("failed to parse IPv6 `src` token from route-get output: {output}")
        })
}

fn parse_route_get_dev(output: &str) -> Result<String> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    Ok(tokens
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .ok_or_else(|| anyhow!("no `dev` token found in route-get output: {output}"))?[1]
        .to_string())
}
