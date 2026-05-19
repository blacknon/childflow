use super::super::super::FlowLogReport;

pub(in crate::report::render::markdown) fn append_dns_overview(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    rendered.push_str("\n## DNS overview\n\n");
    rendered.push_str(&format!(
        "- top DNS name: {}\n- top DNS target correlation: {}\n- top DNS policy correlation: {}\n",
        report.render_top_dns_name_compact(),
        report.render_top_dns_target_correlation_compact(),
        report.render_top_dns_policy_correlation_compact()
    ));
}

pub(in crate::report::render::markdown) fn append_policy_overview(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    rendered.push_str("\n## Policy overview\n\n");
    rendered.push_str(&format!(
        "- policy violations: {}\n- policy controls: {}\n- matched domains: {}\n",
        report.render_policy_violations_compact(5),
        report.render_policy_controls_compact(5),
        report.render_policy_matched_domains_compact(5)
    ));
}

pub(in crate::report::render::markdown) fn append_runtime_overview(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    rendered.push_str("\n## Runtime overview\n\n");
    rendered.push_str(&format!(
        "- connect errors: {}\n- runtime failures: {}\n- runtime failure phases: {}\n",
        report.render_connect_errors_compact(5),
        report.render_runtime_failures_compact(5),
        report.render_runtime_failure_phases_compact(5)
    ));
}
