// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod rewrite;
#[cfg(test)]
mod tests;
mod writer;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

use crate::cli::OutputView;

pub use self::writer::{CaptureHandle, CaptureWriters};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureMode {
    AfPacket { interface_name: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapturePlan {
    ChildOnly {
        mode: CaptureMode,
        output_path: PathBuf,
        metadata: CaptureMetadata,
    },
    RootfulSyntheticEgress {
        mode: CaptureMode,
        output_path: PathBuf,
        rewrite: RootfulEgressRewrite,
    },
    RootfulChildAndSyntheticEgress {
        mode: CaptureMode,
        child_output_path: PathBuf,
        egress_output_path: PathBuf,
        rewrite: RootfulEgressRewrite,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RootfulEgressRewrite {
    pub child_ipv4: Ipv4Addr,
    pub child_ipv6: Ipv6Addr,
    pub host_egress_ipv4: Option<Ipv4Addr>,
    pub host_egress_ipv6: Option<Ipv6Addr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureMetadata {
    view: &'static str,
    backend: &'static str,
    kind: &'static str,
    interface_name: String,
}

impl CaptureMetadata {
    pub fn new(
        view: &'static str,
        backend: &'static str,
        kind: &'static str,
        interface_name: impl Into<String>,
    ) -> Self {
        Self {
            view,
            backend,
            kind,
            interface_name: interface_name.into(),
        }
    }

    pub(crate) fn description(&self) -> String {
        format!(
            "childflow view={} backend={} kind={} interface={}",
            self.view, self.backend, self.kind, self.interface_name
        )
    }
}

pub fn derive_output_paths(base: &Path, output_view: OutputView) -> Result<(PathBuf, PathBuf)> {
    match output_view {
        OutputView::Child | OutputView::Egress | OutputView::WireEgress => {
            Ok((base.to_path_buf(), base.to_path_buf()))
        }
        OutputView::Both => {
            let parent = base.parent().unwrap_or_else(|| Path::new("."));
            let file_name = base
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow!("output path must end with a valid UTF-8 file name"))?;
            let stem = file_name.strip_suffix(".pcapng").unwrap_or(file_name);
            Ok((
                parent.join(format!("{stem}.child.pcapng")),
                parent.join(format!("{stem}.egress.pcapng")),
            ))
        }
    }
}

pub fn requested_view_name(output_view: OutputView) -> &'static str {
    match output_view {
        OutputView::Child => "child",
        OutputView::Egress => "egress",
        OutputView::WireEgress => "wire-egress",
        OutputView::Both => "both",
    }
}

pub fn effective_view_name(output_view: OutputView) -> &'static str {
    match output_view {
        OutputView::Both => "child+egress",
        _ => requested_view_name(output_view),
    }
}
