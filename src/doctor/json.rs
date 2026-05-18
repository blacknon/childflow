// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use serde::Serialize;

use crate::preflight::{self, CheckStatus};

use super::capabilities::{CapabilityCheck, CapabilityReport, CapabilityStatus};

#[derive(Serialize)]
pub(super) struct DoctorJsonReport {
    backend: String,
    uid: u32,
    euid: u32,
    status: String,
    capabilities: Vec<DoctorJsonCapability>,
    preflight: Vec<DoctorJsonPreflightCheck>,
}

impl DoctorJsonReport {
    pub(super) fn from_reports(
        backend: String,
        status: String,
        uid: u32,
        euid: u32,
        capability_report: &CapabilityReport,
        preflight_checks: &[preflight::PreflightCheck],
    ) -> Self {
        Self {
            backend,
            uid,
            euid,
            status,
            capabilities: capability_report
                .checks()
                .iter()
                .map(DoctorJsonCapability::from_check)
                .collect(),
            preflight: preflight_checks
                .iter()
                .map(DoctorJsonPreflightCheck::from_check)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct DoctorJsonCapability {
    key: String,
    label: String,
    status: String,
    detail: String,
}

impl DoctorJsonCapability {
    fn from_check(check: &CapabilityCheck) -> Self {
        Self {
            key: check.key.to_string(),
            label: check.label.clone(),
            status: render_capability_status_json(&check.status).to_string(),
            detail: check.detail.clone(),
        }
    }
}

#[derive(Serialize)]
struct DoctorJsonPreflightCheck {
    label: String,
    status: String,
    detail: String,
    hint: Option<String>,
}

impl DoctorJsonPreflightCheck {
    fn from_check(check: &preflight::PreflightCheck) -> Self {
        Self {
            label: check.label.clone(),
            status: render_status_json(&check.status).to_string(),
            detail: check.detail.clone(),
            hint: check.hint.clone(),
        }
    }
}

fn render_status_json(status: &CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "ok",
        CheckStatus::Warning => "warning",
        CheckStatus::Fatal => "fatal",
    }
}

fn render_capability_status_json(status: &CapabilityStatus) -> &'static str {
    match status {
        CapabilityStatus::Available => "available",
        CapabilityStatus::Limited => "limited",
        CapabilityStatus::Unavailable => "unavailable",
    }
}
