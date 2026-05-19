use std::collections::BTreeMap;

use super::super::super::super::{render_ranked_string_counts, top_count_entries, FlowLogReport};

pub(in crate::report::render::markdown) fn append_protocols(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    rendered.push_str("\n## Protocols\n\n");
    if report.protocol_counts.is_empty() {
        rendered.push_str("_none_\n");
    } else {
        rendered.push_str("| Protocol | Count |\n| --- | ---: |\n");
        for (protocol, count) in top_count_entries(&report.protocol_counts, usize::MAX) {
            rendered.push_str(&format!("| {protocol} | {count} |\n"));
        }
    }
}

pub(in crate::report::render::markdown) fn append_top_dns_names(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    rendered.push_str("\n## Top DNS names\n\n");
    if report.dns_name_counts.is_empty() {
        rendered.push_str("_none_\n");
    } else {
        rendered.push_str(
            "| DNS name | Queries | Answers | Answer IPs |\n| --- | ---: | ---: | --- |\n",
        );
        for (qname, stats) in report.top_dns_names(10) {
            rendered.push_str(&format!(
                "| `{qname}` | {} | {} | {} |\n",
                stats.queries,
                stats.answers,
                FlowLogReport::render_dns_answer_ips(stats)
            ));
        }
    }
}

pub(in crate::report::render::markdown) fn append_dns_target_correlations(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    rendered.push_str("\n## DNS target correlations\n\n");
    let correlations = report.top_dns_target_correlations(10, 3);
    if correlations.is_empty() {
        rendered.push_str("_none_\n");
    } else {
        rendered.push_str("| DNS name | Answer IPs | Correlated targets |\n| --- | --- | --- |\n");
        for correlation in correlations {
            rendered.push_str(&format!(
                "| `{}` | {} | {} |\n",
                correlation.qname,
                report.render_answer_ip_list(&correlation.answer_ips),
                report.render_dns_target_list(&correlation.targets)
            ));
        }
    }
}

pub(in crate::report::render::markdown) fn append_dns_policy_correlations(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    rendered.push_str("\n## DNS policy correlations\n\n");
    let correlations = report.top_dns_policy_correlations(10, 3);
    if correlations.is_empty() {
        rendered.push_str("_none_\n");
    } else {
        rendered.push_str(
            "| DNS name | Answer IPs | Matched domains | Correlated targets |\n| --- | --- | --- | --- |\n",
        );
        for correlation in correlations {
            rendered.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                correlation.qname,
                report.render_answer_ip_list(&correlation.answer_ips),
                render_ranked_string_counts(&correlation.matched_domains),
                report.render_dns_target_list(&correlation.targets)
            ));
        }
    }
}

pub(in crate::report::render::markdown) fn append_proxy_usage(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    rendered.push_str("\n## Proxy usage\n\n");
    rendered.push_str("| Metric | Count |\n| --- | ---: |\n");
    rendered.push_str(&format!(
        "| proxied_connect_attempts | {} |\n| direct_connect_attempts | {} |\n",
        report.proxied_connect_attempts, report.direct_connect_attempts
    ));
}

pub(in crate::report::render::markdown) fn append_policy_violations(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    append_ranked_count_table(
        rendered,
        "\n## Policy violations\n\n",
        "| Reason code | Count |\n| --- | ---: |\n",
        &report.policy_reason_counts,
        |key| key.to_string(),
    );
}

pub(in crate::report::render::markdown) fn append_policy_controls(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    append_ranked_count_table(
        rendered,
        "\n## Policy controls\n\n",
        "| Control | Count |\n| --- | ---: |\n",
        &report.policy_control_counts,
        |key| format!("`{key}`"),
    );
}

pub(in crate::report::render::markdown) fn append_policy_matched_domains(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    append_ranked_count_table(
        rendered,
        "\n## Policy matched domains\n\n",
        "| Domain | Count |\n| --- | ---: |\n",
        &report.policy_matched_domain_counts,
        |key| format!("`{key}`"),
    );
}

pub(in crate::report::render::markdown) fn append_connect_errors(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    append_ranked_count_table(
        rendered,
        "\n## Connect errors\n\n",
        "| Error | Count |\n| --- | ---: |\n",
        &report.connect_error_counts,
        |key| key.to_string(),
    );
}

pub(in crate::report::render::markdown) fn append_runtime_failures(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    append_ranked_count_table(
        rendered,
        "\n## Runtime failures\n\n",
        "| Reason code | Count |\n| --- | ---: |\n",
        &report.runtime_failure_reason_counts,
        |key| key.to_string(),
    );
}

pub(in crate::report::render::markdown) fn append_runtime_failure_phases(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    append_ranked_count_table(
        rendered,
        "\n## Runtime failure phases\n\n",
        "| Phase | Count |\n| --- | ---: |\n",
        &report.runtime_failure_phase_counts,
        |key| key.to_string(),
    );
}

pub(in crate::report::render::markdown) fn append_top_connection_targets(
    report: &FlowLogReport,
    rendered: &mut String,
) {
    rendered.push_str("\n## Top connection targets\n\n");
    if report.connection_targets.is_empty() {
        rendered.push_str("_none_\n");
    } else {
        rendered.push_str(
            "| Target | Attempts | OK | Error | Flow end | DNS names | Matched domains |\n| --- | ---: | ---: | ---: | ---: | --- | --- |\n",
        );
        for (target, stats) in report.top_connection_targets(10) {
            rendered.push_str(&format!(
                "| `{target}` | {} | {} | {} | {} | {} | {} |\n",
                stats.connect_attempts,
                stats.connect_ok,
                stats.connect_error,
                stats.flow_end,
                report.render_dns_names_for_target(target),
                report.render_matched_domains_for_target(target, 3)
            ));
        }
    }
}

fn append_ranked_count_table<F>(
    rendered: &mut String,
    heading: &str,
    header: &str,
    counts: &BTreeMap<String, usize>,
    render_key: F,
) where
    F: Fn(&str) -> String,
{
    rendered.push_str(heading);
    if counts.is_empty() {
        rendered.push_str("_none_\n");
    } else {
        rendered.push_str(header);
        for (key, count) in top_count_entries(counts, usize::MAX) {
            rendered.push_str(&format!("| {} | {count} |\n", render_key(key)));
        }
    }
}
