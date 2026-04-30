// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use anyhow::Result;

use crate::cli::Cli;
use crate::preflight::{self, CheckStatus};

pub fn run(cli: &Cli) -> Result<i32> {
    let report = preflight::inspect(cli.selected_backend(), false);
    let status_line = if report.has_fatal() {
        "blocked"
    } else if report.has_warnings() {
        "ready with warnings"
    } else {
        "ready"
    };

    println!("childflow doctor");
    println!("backend: {}", report.backend_name());
    println!(
        "user: uid {} / euid {}",
        unsafe { nix::libc::getuid() },
        unsafe { nix::libc::geteuid() }
    );
    println!("status: {status_line}");
    println!();

    for check in report.checks() {
        println!("[{}] {}", render_status(&check.status), check.label);
        println!("  {}", check.detail);
        if let Some(hint) = &check.hint {
            println!("  hint: {hint}");
        }
    }

    Ok(if report.has_fatal() { 1 } else { 0 })
}

fn render_status(status: &CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "OK",
        CheckStatus::Warning => "WARN",
        CheckStatus::Fatal => "FATAL",
    }
}
