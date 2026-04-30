// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use crate::capture::derive_output_paths;
use crate::cli::{Cli, OutputView};
use crate::sandbox::SandboxPolicy;
use crate::util::render_command;

pub fn print_run_summary(cli: &Cli, exit_code: i32) {
    let sandbox_policy = SandboxPolicy::from_cli(cli);
    let command = cli
        .command
        .split_first()
        .map(|(program, args)| render_command(program, args))
        .unwrap_or_else(|| "<none>".to_string());

    eprintln!("childflow summary");
    eprintln!("backend: {}", backend_name(cli));
    eprintln!("command: {command}");
    eprintln!(
        "sandbox controls: {}",
        format_controls(&sandbox_policy.active_controls())
    );
    eprintln!("capture: {}", format_capture(cli));
    eprintln!("exit: {exit_code}");
}

fn backend_name(cli: &Cli) -> &'static str {
    match cli.selected_backend() {
        crate::network::NetworkBackend::Rootful => "rootful",
        crate::network::NetworkBackend::RootlessInternal => "rootless-internal",
    }
}

fn format_controls(controls: &[&str]) -> String {
    if controls.is_empty() {
        return "none".to_string();
    }
    controls.join(", ")
}

fn format_capture(cli: &Cli) -> String {
    let Some(output) = cli.output.as_ref() else {
        return "disabled".to_string();
    };

    match cli.output_view {
        OutputView::Both => match derive_output_paths(output, cli.output_view) {
            Ok((child, egress)) => {
                format!("child={}, egress={}", child.display(), egress.display())
            }
            Err(_) => output.display().to_string(),
        },
        _ => output.display().to_string(),
    }
}
