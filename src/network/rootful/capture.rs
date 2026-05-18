use std::path::Path;

use anyhow::{anyhow, Result};

use super::NetworkContext;
use crate::capture::{
    derive_output_paths, CaptureMetadata, CaptureMode, CapturePlan, RootfulEgressRewrite,
};
use crate::cli::OutputView;

impl NetworkContext {
    pub fn dns_bind_addrs(&self) -> (std::net::Ipv4Addr, std::net::Ipv6Addr) {
        (self.host_ipv4, self.host_ipv6)
    }

    pub fn capture_plan(&self, output_path: &Path, output_view: OutputView) -> Result<CapturePlan> {
        let mode = CaptureMode::AfPacket {
            interface_name: self.host_veth.clone(),
        };

        match output_view {
            OutputView::Child => Ok(CapturePlan::ChildOnly {
                mode,
                output_path: output_path.to_path_buf(),
                metadata: CaptureMetadata::new(
                    "child",
                    "rootful",
                    "isolated",
                    self.host_veth.clone(),
                ),
            }),
            OutputView::Egress => Ok(CapturePlan::RootfulSyntheticEgress {
                mode,
                output_path: output_path.to_path_buf(),
                rewrite: self.rootful_egress_rewrite()?,
            }),
            OutputView::WireEgress => Ok(CapturePlan::ChildOnly {
                mode: CaptureMode::AfPacket {
                    interface_name: self.rootful_wire_egress_iface()?.to_string(),
                },
                output_path: output_path.to_path_buf(),
                metadata: CaptureMetadata::new(
                    "wire-egress",
                    "rootful",
                    "wire",
                    self.rootful_wire_egress_iface()?.to_string(),
                ),
            }),
            OutputView::Both => {
                let (child_output_path, egress_output_path) =
                    derive_output_paths(output_path, output_view)?;
                Ok(CapturePlan::RootfulChildAndSyntheticEgress {
                    mode,
                    child_output_path,
                    egress_output_path,
                    rewrite: self.rootful_egress_rewrite()?,
                })
            }
        }
    }

    fn rootful_egress_rewrite(&self) -> Result<RootfulEgressRewrite> {
        if self.egress_ipv4.is_none() && self.egress_ipv6.is_none() {
            return Err(anyhow!(
                "failed to determine any rootful host egress address for the synthetic `--capture-point egress` capture. Check the host default route or retry with `--iface` to pin the egress interface."
            ));
        }

        Ok(RootfulEgressRewrite {
            child_ipv4: self.child_ipv4,
            child_ipv6: self.child_ipv6,
            host_egress_ipv4: self.egress_ipv4,
            host_egress_ipv6: self.egress_ipv6,
        })
    }

    fn rootful_wire_egress_iface(&self) -> Result<&str> {
        self.wire_egress_iface.as_deref().ok_or_else(|| {
            anyhow!(
                "failed to determine the rootful wire-egress interface for `--capture-point wire-egress`. Check the host default route or retry with `--iface` to pin the egress interface."
            )
        })
    }
}
