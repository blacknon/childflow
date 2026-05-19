// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::path::PathBuf;

use anyhow::{Context, Result};

use super::addr;
use crate::capture::{CaptureMetadata, CaptureMode, CapturePlan, RootfulEgressRewrite};
use crate::cli::{Cli, OutputView};
use crate::linux_net;

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
    linux_net::discover_egress_src_v4("1.1.1.1".parse().unwrap())
        .context("failed to determine the IPv4 source address from the default route")
}

fn discover_route_get_dev_v4() -> Result<String> {
    let source_ip = discover_route_get_src_v4()?;
    linux_net::discover_interface_for_source_ip(source_ip.into())
        .context("failed to determine the IPv4 egress interface from the default route")
}

fn discover_route_get_src_v6() -> Result<Option<std::net::Ipv6Addr>> {
    linux_net::discover_egress_src_v6("2606:4700:4700::1111".parse().unwrap())
        .context("failed to determine the IPv6 source address from the default route")
        .map(Some)
}
