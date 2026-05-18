use std::collections::BTreeMap;

use super::super::super::super::{render_ranked_string_counts, top_count_entries, FlowLogReport};

pub(in crate::report::render::markdown) fn render_markdown_highlights(
    report: &FlowLogReport,
) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "- proxy usage: proxied connect attempts={}, direct connect attempts={}",
        report.proxied_connect_attempts, report.direct_connect_attempts
    ));

    if let Some((target, stats)) = report.top_connection_targets(1).into_iter().next() {
        lines.push(format!(
            "- top connection target: `{target}` (attempts={}, ok={}, error={}, flow_end={}, dns_names={}, matched_domains={})",
            stats.connect_attempts,
            stats.connect_ok,
            stats.connect_error,
            stats.flow_end,
            report.render_dns_names_for_target(target),
            report.render_matched_domains_for_target(target, 3)
        ));
    } else {
        lines.push("- top connection target: none".to_string());
    }

    if let Some((qname, stats)) = report.top_dns_names(1).into_iter().next() {
        lines.push(format!(
            "- top DNS name: `{qname}` (queries={}, answers={}, answer_ips={}, targets={})",
            stats.queries,
            stats.answers,
            FlowLogReport::render_dns_answer_ips(stats),
            report.render_top_targets_for_dns_name(qname, 3)
        ));
    } else {
        lines.push("- top DNS name: none".to_string());
    }

    if let Some(correlation) = report.top_dns_target_correlations(1, 1).into_iter().next() {
        let target = correlation
            .targets
            .first()
            .map(|target| report.render_dns_correlated_target(target))
            .unwrap_or_else(|| "none".to_string());
        lines.push(format!(
            "- top DNS target correlation: `{}` -> {}",
            correlation.qname, target
        ));
    } else {
        lines.push("- top DNS target correlation: none".to_string());
    }

    if let Some(correlation) = report.top_dns_policy_correlations(1, 1).into_iter().next() {
        lines.push(format!(
            "- top DNS policy correlation: `{}` (answer_ips={}, matched_domains={}, targets={})",
            correlation.qname,
            report.render_answer_ip_list(&correlation.answer_ips),
            render_ranked_string_counts(&correlation.matched_domains),
            report.render_dns_target_list(&correlation.targets)
        ));
    } else {
        lines.push("- top DNS policy correlation: none".to_string());
    }

    lines.push(render_markdown_count_highlight(
        "most common policy violation",
        &report.policy_reason_counts,
    ));
    lines.push(render_markdown_count_highlight(
        "most common policy control",
        &report.policy_control_counts,
    ));
    lines.push(render_markdown_count_highlight(
        "most common matched domain",
        &report.policy_matched_domain_counts,
    ));
    lines.push(render_markdown_count_highlight(
        "most common connect error",
        &report.connect_error_counts,
    ));
    lines.push(render_markdown_count_highlight(
        "most common runtime failure",
        &report.runtime_failure_reason_counts,
    ));
    lines.push(render_markdown_count_highlight(
        "most common runtime failure phase",
        &report.runtime_failure_phase_counts,
    ));

    lines.join("\n") + "\n\n"
}

fn render_markdown_count_highlight(label: &str, counts: &BTreeMap<String, usize>) -> String {
    match top_count_entries(counts, 1).into_iter().next() {
        Some((key, count)) => format!("- {label}: `{key}` ({count})"),
        None => format!("- {label}: none"),
    }
}
