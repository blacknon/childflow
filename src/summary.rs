// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use crate::capture::derive_output_paths;
use crate::cli::{Cli, OutputView};
use crate::report::FlowLogReport;
use crate::sandbox::SandboxPolicy;
use crate::util::render_command;

pub fn print_run_summary(cli: &Cli, exit_code: i32) {
    eprint!("{}", render_run_summary(cli, exit_code));
}

fn render_run_summary(cli: &Cli, exit_code: i32) -> String {
    let sandbox_policy = SandboxPolicy::from_cli(cli);
    let command = cli
        .command
        .split_first()
        .map(|(program, args)| render_command(program, args))
        .unwrap_or_else(|| "<none>".to_string());

    format!(
        "childflow summary\nbackend: {}\ncommand: {command}\nsandbox controls: {}\ncapture: {}\nflow-log: {}\nflow-log events: {}\nexit: {exit_code}\n",
        backend_name(cli),
        format_controls(&sandbox_policy.active_controls()),
        format_capture(cli),
        format_flow_log(cli),
        format_flow_log_events(cli)
    )
}

fn backend_name(cli: &Cli) -> &'static str {
    match cli.selected_backend() {
        crate::network::NetworkBackend::Rootful => "rootful",
        crate::network::NetworkBackend::RootlessInternal => "rootless-internal",
    }
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

fn format_flow_log(cli: &Cli) -> String {
    cli.flow_log
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "disabled".to_string())
}

fn format_flow_log_events(cli: &Cli) -> String {
    let Some(path) = cli.flow_log.as_ref() else {
        return "disabled".to_string();
    };

    match FlowLogReport::from_path(path) {
        Ok(report) => report.render_event_counts_compact(),
        Err(_) => "unavailable".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::cli::{DefaultPolicy, ProxySpec};
    use crate::network::NetworkBackend;

    fn make_cli() -> Cli {
        Cli {
            dump_profile: false,
            output: None,
            output_view: OutputView::Child,
            root: false,
            doctor: false,
            report: None,
            report_format: crate::cli::ReportFormat::Text,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            hosts_file: None,
            proxy: None,
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            summary: true,
            flow_log: None,
            offline: false,
            block_private: false,
            block_metadata: false,
            default_policy: DefaultPolicy::Allow,
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            proxy_only: false,
            fail_on_leak: false,
            iface: None,
            command: vec!["curl".into(), "https://example.com".into()],
        }
    }

    #[test]
    fn render_run_summary_lists_active_sandbox_controls() {
        let mut cli = make_cli();
        cli.offline = true;
        cli.block_metadata = true;

        let rendered = render_run_summary(&cli, 7);

        assert!(rendered.contains("backend: rootless-internal"));
        assert!(rendered.contains("sandbox controls: offline, block-metadata"));
        assert!(rendered.contains("capture: disabled"));
        assert!(rendered.contains("flow-log: disabled"));
        assert!(rendered.contains("flow-log events: disabled"));
        assert!(rendered.contains("exit: 7"));
    }

    #[test]
    fn render_run_summary_expands_both_capture_outputs() {
        let mut cli = make_cli();
        cli.root = true;
        cli.output = Some(PathBuf::from("/tmp/capture.pcapng"));
        cli.flow_log = Some(PathBuf::from("/tmp/flow.jsonl"));
        cli.output_view = OutputView::Both;
        cli.proxy = Some("http://127.0.0.1:8080".parse::<ProxySpec>().unwrap());

        let rendered = render_run_summary(&cli, 0);

        assert!(rendered.contains("backend: rootful"));
        assert!(rendered.contains(
            "capture: child=/tmp/capture.child.pcapng, egress=/tmp/capture.egress.pcapng"
        ));
        assert!(rendered.contains("flow-log: /tmp/flow.jsonl"));
        assert!(rendered.contains("flow-log events: unavailable"));
        assert!(rendered.contains("command: curl https://example.com"));
    }

    #[test]
    fn render_run_summary_counts_flow_log_events() {
        let mut cli = make_cli();
        let flow_log_path = unique_temp_flow_log_path("summary-flow-log");
        fs::write(
            &flow_log_path,
            concat!(
                "{\"event\":\"connect_attempt\",\"ts_ms\":1}\n",
                "{\"event\":\"connect_result\",\"ts_ms\":2}\n",
                "{\"event\":\"policy_violation\",\"ts_ms\":3}\n",
                "{\"event\":\"flow_end\",\"ts_ms\":4}\n"
            ),
        )
        .unwrap();
        cli.flow_log = Some(flow_log_path.clone());

        let rendered = render_run_summary(&cli, 0);

        assert!(rendered.contains("flow-log events: total=4"));
        assert!(rendered.contains("connect_attempt=1"));
        assert!(rendered.contains("connect_result=1"));
        assert!(rendered.contains("policy_violation=1"));
        assert!(rendered.contains("flow_end=1"));

        let _ = fs::remove_file(flow_log_path);
    }

    fn unique_temp_flow_log_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "childflow-{prefix}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }
}
