// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod rootful;
mod rootless;
mod support;

use crate::network::NetworkBackend;

use self::support::{
    current_euid, current_username, inspect_af_packet_capability, inspect_tun_capability,
    missing_commands, missing_paths, read_proc_u64, subid_entry_exists, unwritable_paths,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CapabilityStatus {
    Available,
    Limited,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CapabilityCheck {
    pub(super) key: &'static str,
    pub(super) label: String,
    pub(super) status: CapabilityStatus,
    pub(super) detail: String,
}

#[derive(Clone, Debug, Default)]
pub(super) struct CapabilityReport {
    checks: Vec<CapabilityCheck>,
}

impl CapabilityReport {
    pub(super) fn push(
        &mut self,
        key: &'static str,
        label: impl Into<String>,
        status: CapabilityStatus,
        detail: impl Into<String>,
    ) {
        self.checks.push(CapabilityCheck {
            key,
            label: label.into(),
            status,
            detail: detail.into(),
        });
    }

    pub(super) fn checks(&self) -> &[CapabilityCheck] {
        &self.checks
    }
}

pub(super) fn inspect_capabilities(backend: NetworkBackend) -> CapabilityReport {
    match backend {
        NetworkBackend::Rootful => rootful::inspect_rootful_capabilities(),
        NetworkBackend::RootlessInternal => rootless::inspect_rootless_internal_capabilities(),
    }
}

pub(super) fn render_capability_status(status: &CapabilityStatus) -> &'static str {
    support::render_capability_status(status)
}

pub(super) fn inspect_apparmor_userns_capability(euid: u32) -> CapabilityStatus {
    support::inspect_apparmor_userns_capability(euid)
}

pub(super) fn render_apparmor_userns_detail(euid: u32) -> String {
    support::render_apparmor_userns_detail(euid)
}
