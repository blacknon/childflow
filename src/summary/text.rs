// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use crate::cli::Cli;
use crate::observability::summary as observability_summary;

use super::{
    backend_name, format_capture, format_controls, format_flow_log, summary_command,
    summary_controls, with_flow_log_report,
};

pub(super) fn render_run_summary(cli: &Cli, exit_code: i32) -> String {
    let command = summary_command(cli);
    let sandbox_controls = summary_controls(cli);

    format!(
        "childflow summary\nbackend: {}\ncommand: {command}\nsandbox controls: {}\ncapture: {}\nflow-log: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\nexit: {exit_code}\n",
        backend_name(cli),
        format_controls(&sandbox_controls),
        format_capture(cli),
        format_flow_log(cli),
        observability_summary::FLOW_LOG_EVENTS,
        format_flow_log_events(cli),
        observability_summary::FLOW_LOG_DNS_NAMES,
        format_flow_log_dns_names(cli),
        observability_summary::FLOW_LOG_DNS_POLICY_ROWS,
        format_flow_log_dns_policy_rows(cli),
        observability_summary::FLOW_LOG_TOP_DNS_POLICY_CORRELATION,
        format_flow_log_top_dns_policy_correlation(cli),
        observability_summary::FLOW_LOG_TOP_TARGET,
        format_flow_log_top_target(cli),
        observability_summary::FLOW_LOG_POLICY_VIOLATIONS,
        format_flow_log_policy_violations(cli),
        observability_summary::FLOW_LOG_POLICY_CONTROLS,
        format_flow_log_policy_controls(cli),
        observability_summary::FLOW_LOG_POLICY_MATCHED_DOMAINS,
        format_flow_log_policy_matched_domains(cli),
        observability_summary::FLOW_LOG_CONNECT_ERRORS,
        format_flow_log_connect_errors(cli),
        observability_summary::FLOW_LOG_RUNTIME_FAILURES,
        format_flow_log_runtime_failures(cli),
        observability_summary::FLOW_LOG_RUNTIME_FAILURE_PHASES,
        format_flow_log_runtime_failure_phases(cli)
    )
}

fn format_flow_log_events(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::event_counts)
}

fn format_flow_log_top_target(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::top_target)
}

fn format_flow_log_dns_names(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::dns_names)
}

fn format_flow_log_dns_policy_rows(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::dns_policy_rows)
}

fn format_flow_log_top_dns_policy_correlation(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::top_dns_policy_correlation)
}

fn format_flow_log_connect_errors(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::connect_errors)
}

fn format_flow_log_policy_violations(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::policy_violations)
}

fn format_flow_log_policy_controls(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::policy_controls)
}

fn format_flow_log_policy_matched_domains(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::policy_matched_domains)
}

fn format_flow_log_runtime_failures(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::runtime_failures)
}

fn format_flow_log_runtime_failure_phases(cli: &Cli) -> String {
    with_flow_log_report(cli, FlowLogReportRender::runtime_failure_phases)
}

struct FlowLogReportRender;

impl FlowLogReportRender {
    fn event_counts(report: &crate::report::FlowLogReport) -> String {
        report.render_event_counts_compact()
    }

    fn top_target(report: &crate::report::FlowLogReport) -> String {
        report.render_top_target_compact()
    }

    fn dns_names(report: &crate::report::FlowLogReport) -> String {
        report.render_top_dns_name_compact()
    }

    fn dns_policy_rows(report: &crate::report::FlowLogReport) -> String {
        report.render_dns_policy_rows_compact(2)
    }

    fn top_dns_policy_correlation(report: &crate::report::FlowLogReport) -> String {
        report.render_top_dns_policy_correlation_compact()
    }

    fn connect_errors(report: &crate::report::FlowLogReport) -> String {
        report.render_connect_errors_compact(3)
    }

    fn policy_violations(report: &crate::report::FlowLogReport) -> String {
        report.render_policy_violations_compact(3)
    }

    fn policy_controls(report: &crate::report::FlowLogReport) -> String {
        report.render_policy_controls_compact(3)
    }

    fn policy_matched_domains(report: &crate::report::FlowLogReport) -> String {
        report.render_policy_matched_domains_compact(3)
    }

    fn runtime_failures(report: &crate::report::FlowLogReport) -> String {
        report.render_runtime_failures_compact(3)
    }

    fn runtime_failure_phases(report: &crate::report::FlowLogReport) -> String {
        report.render_runtime_failure_phases_compact(3)
    }
}
