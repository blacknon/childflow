// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod helpers;
mod rootful;
mod rootless;

use crate::network::NetworkBackend;

use super::PreflightReport;

pub use self::helpers::find_missing_commands;

pub(super) fn inspect(backend: NetworkBackend, proxy_requested: bool) -> PreflightReport {
    match backend {
        NetworkBackend::Rootful => rootful::inspect_rootful(proxy_requested),
        NetworkBackend::RootlessInternal => rootless::inspect_rootless_internal(),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn parse_proc_u64(path: &str) -> anyhow::Result<Option<u64>> {
    helpers::parse_proc_u64(path)
}
