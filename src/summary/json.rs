// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use crate::cli::Cli;

use super::{
    backend_name, build_capture_summary, build_flow_log_summary, summary_command, summary_controls,
    SummaryJsonReport,
};

pub(super) fn render_run_summary_json(cli: &Cli, exit_code: i32) -> String {
    let summary = SummaryJsonReport {
        backend: backend_name(cli).to_string(),
        command: summary_command(cli),
        exit_code,
        sandbox_controls: summary_controls(cli),
        capture: build_capture_summary(cli),
        flow_log: build_flow_log_summary(cli),
    };

    serde_json::to_string_pretty(&summary).expect("summary JSON should serialize") + "\n"
}
