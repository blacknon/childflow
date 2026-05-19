// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod build;
mod json;
mod text;
mod types;

#[cfg(test)]
mod tests;

use crate::capture::{derive_output_paths, effective_view_name, requested_view_name};
use crate::cli::{Cli, OutputView, SummaryFormat};
use crate::report::FlowLogReport;
use crate::sandbox::SandboxPolicy;
use crate::util::render_command;

use self::build::{build_capture_summary, build_flow_log_summary};
use self::types::{
    SummaryCaptureReport, SummaryCountEntry, SummaryDnsPolicyRow, SummaryEventCounts,
    SummaryFlowLogReport, SummaryJsonReport, SummaryTopDnsName, SummaryTopDnsPolicyCorrelation,
    SummaryTopTarget,
};

pub fn print_run_summary(cli: &Cli, exit_code: i32) {
    let rendered = match cli.summary_format {
        SummaryFormat::Text => text::render_run_summary(cli, exit_code),
        SummaryFormat::Json => json::render_run_summary_json(cli, exit_code),
    };
    eprint!("{rendered}");
}

fn backend_name(cli: &Cli) -> &'static str {
    match cli.selected_backend() {
        crate::network::NetworkBackend::Rootful => "rootful",
        crate::network::NetworkBackend::RootlessInternal => "rootless-internal",
    }
}

fn summary_command(cli: &Cli) -> String {
    cli.command
        .split_first()
        .map(|(program, args)| render_command(program, args))
        .unwrap_or_else(|| "<none>".to_string())
}

fn summary_controls(cli: &Cli) -> Vec<String> {
    SandboxPolicy::from_cli(cli).active_controls()
}

fn format_controls(controls: &[String]) -> String {
    if controls.is_empty() {
        return "none".to_string();
    }
    controls.join(", ")
}

fn format_capture(cli: &Cli) -> String {
    let Some(output) = cli.output.as_ref() else {
        return "disabled".to_string();
    };

    let requested = requested_view_name(cli.output_view);
    let effective = effective_view_name(cli.output_view);

    match cli.output_view {
        OutputView::Both => match derive_output_paths(output, cli.output_view) {
            Ok((child, egress)) => {
                format!(
                    "requested={requested}, effective={effective}, child={}, egress={}",
                    child.display(),
                    egress.display()
                )
            }
            Err(_) => format!(
                "requested={requested}, effective={effective}, output={}",
                output.display()
            ),
        },
        _ => format!(
            "requested={requested}, effective={effective}, output={}",
            output.display()
        ),
    }
}

fn format_flow_log(cli: &Cli) -> String {
    cli.flow_log
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "disabled".to_string())
}

fn with_flow_log_report(cli: &Cli, render: impl FnOnce(&FlowLogReport) -> String) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => render(&report),
        Err(_) => "unavailable".to_string(),
    }
}
