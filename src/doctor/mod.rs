// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod capabilities;
mod json;

#[cfg(test)]
mod tests;

use anyhow::Result;

use crate::cli::{Cli, DoctorFormat};
use crate::preflight::{self, CheckStatus};

use self::capabilities::{inspect_capabilities, render_capability_status};
use self::json::DoctorJsonReport;

pub fn run(cli: &Cli) -> Result<i32> {
    let report = preflight::inspect(cli.selected_backend(), false);
    let capability_report = inspect_capabilities(cli.selected_backend());
    let status_line = overall_status(&report);

    match cli.doctor_format {
        DoctorFormat::Text => render_doctor_text(
            report.backend_name(),
            status_line,
            current_uid(),
            current_euid(),
            &capability_report,
            report.checks(),
        ),
        DoctorFormat::Json => {
            let json = DoctorJsonReport::from_reports(
                report.backend_name().to_string(),
                status_line.to_string(),
                current_uid(),
                current_euid(),
                &capability_report,
                report.checks(),
            );
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    Ok(if report.has_fatal() { 1 } else { 0 })
}

fn overall_status(report: &preflight::PreflightReport) -> &'static str {
    if report.has_fatal() {
        "blocked"
    } else if report.has_warnings() {
        "ready with warnings"
    } else {
        "ready"
    }
}

fn render_doctor_text(
    backend_name: &str,
    status_line: &str,
    uid: u32,
    euid: u32,
    capability_report: &capabilities::CapabilityReport,
    checks: &[preflight::PreflightCheck],
) {
    println!("childflow doctor");
    println!("backend: {backend_name}");
    println!("user: uid {uid} / euid {euid}");
    println!("status: {status_line}");
    println!();

    println!("capabilities");
    for capability in capability_report.checks() {
        println!(
            "[{}] {}",
            render_capability_status(&capability.status),
            capability.label
        );
        println!("  {}", capability.detail);
    }
    println!();

    println!("preflight");
    for check in checks {
        println!("[{}] {}", render_status(&check.status), check.label);
        println!("  {}", check.detail);
        if let Some(hint) = &check.hint {
            println!("  hint: {hint}");
        }
    }
}

fn render_status(status: &CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "OK",
        CheckStatus::Warning => "WARN",
        CheckStatus::Fatal => "FATAL",
    }
}

fn current_uid() -> u32 {
    // SAFETY: `getuid` has no preconditions and reads no caller-provided memory.
    unsafe { nix::libc::getuid() }
}

fn current_euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and reads no caller-provided memory.
    unsafe { nix::libc::geteuid() }
}
