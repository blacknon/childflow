use std::collections::BTreeMap;
use std::path::Path;

use super::super::{render_ranked_string_counts, top_count_entries, FlowLogReport};

impl FlowLogReport {
    pub fn render_markdown(&self, path: &Path) -> String {
        let mut rendered = format!(
            "# childflow report\n\n- flow-log: `{}`\n- schema-version: `{}`\n\n## Highlights\n\n{}\n## Event counts\n\n| Metric | Count |\n| --- | ---: |\n| total | {} |\n| dns_query | {} |\n| dns_answer | {} |\n| connect_attempt | {} |\n| connect_result | {} |\n| policy_violation | {} |\n| flow_end | {} |\n| runtime_failure | {} |\n| unknown_event | {} |\n",
            path.display(),
            self.render_schema_versions(),
            self.render_markdown_highlights(),
            self.total,
            self.dns_query,
            self.dns_answer,
            self.connect_attempt,
            self.connect_result,
            self.policy_violation,
            self.flow_end,
            self.runtime_failure,
            self.unknown_event
        );

        rendered.push_str("\n## DNS overview\n\n");
        rendered.push_str(&format!(
            "- top DNS name: {}\n- top DNS target correlation: {}\n- top DNS policy correlation: {}\n",
            self.render_top_dns_name_compact(),
            self.render_top_dns_target_correlation_compact(),
            self.render_top_dns_policy_correlation_compact()
        ));

        rendered.push_str("\n## Policy overview\n\n");
        rendered.push_str(&format!(
            "- policy violations: {}\n- policy controls: {}\n- matched domains: {}\n",
            self.render_policy_violations_compact(5),
            self.render_policy_controls_compact(5),
            self.render_policy_matched_domains_compact(5)
        ));

        rendered.push_str("\n## Runtime overview\n\n");
        rendered.push_str(&format!(
            "- connect errors: {}\n- runtime failures: {}\n- runtime failure phases: {}\n",
            self.render_connect_errors_compact(5),
            self.render_runtime_failures_compact(5),
            self.render_runtime_failure_phases_compact(5)
        ));

        rendered.push_str("\n## Protocols\n\n");
        if self.protocol_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Protocol | Count |\n| --- | ---: |\n");
            for (protocol, count) in top_count_entries(&self.protocol_counts, usize::MAX) {
                rendered.push_str(&format!("| {protocol} | {count} |\n"));
            }
        }

        rendered.push_str("\n## Top DNS names\n\n");
        if self.dns_name_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str(
                "| DNS name | Queries | Answers | Answer IPs |\n| --- | ---: | ---: | --- |\n",
            );
            for (qname, stats) in self.top_dns_names(10) {
                rendered.push_str(&format!(
                    "| `{qname}` | {} | {} | {} |\n",
                    stats.queries,
                    stats.answers,
                    Self::render_dns_answer_ips(stats)
                ));
            }
        }

        rendered.push_str("\n## DNS target correlations\n\n");
        let dns_target_correlations = self.top_dns_target_correlations(10, 3);
        if dns_target_correlations.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered
                .push_str("| DNS name | Answer IPs | Correlated targets |\n| --- | --- | --- |\n");
            for correlation in dns_target_correlations {
                rendered.push_str(&format!(
                    "| `{}` | {} | {} |\n",
                    correlation.qname,
                    self.render_answer_ip_list(&correlation.answer_ips),
                    self.render_dns_target_list(&correlation.targets)
                ));
            }
        }

        rendered.push_str("\n## DNS policy correlations\n\n");
        let dns_policy_correlations = self.top_dns_policy_correlations(10, 3);
        if dns_policy_correlations.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str(
                "| DNS name | Answer IPs | Matched domains | Correlated targets |\n| --- | --- | --- | --- |\n",
            );
            for correlation in dns_policy_correlations {
                rendered.push_str(&format!(
                    "| `{}` | {} | {} | {} |\n",
                    correlation.qname,
                    self.render_answer_ip_list(&correlation.answer_ips),
                    render_ranked_string_counts(&correlation.matched_domains),
                    self.render_dns_target_list(&correlation.targets)
                ));
            }
        }

        rendered.push_str("\n## Proxy usage\n\n");
        rendered.push_str("| Metric | Count |\n| --- | ---: |\n");
        rendered.push_str(&format!(
            "| proxied_connect_attempts | {} |\n| direct_connect_attempts | {} |\n",
            self.proxied_connect_attempts, self.direct_connect_attempts
        ));

        rendered.push_str("\n## Policy violations\n\n");
        if self.policy_reason_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Reason code | Count |\n| --- | ---: |\n");
            for (reason, count) in top_count_entries(&self.policy_reason_counts, usize::MAX) {
                rendered.push_str(&format!("| {reason} | {count} |\n"));
            }
        }

        rendered.push_str("\n## Policy controls\n\n");
        if self.policy_control_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Control | Count |\n| --- | ---: |\n");
            for (control, count) in top_count_entries(&self.policy_control_counts, usize::MAX) {
                rendered.push_str(&format!("| `{control}` | {count} |\n"));
            }
        }

        rendered.push_str("\n## Policy matched domains\n\n");
        if self.policy_matched_domain_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Domain | Count |\n| --- | ---: |\n");
            for (domain, count) in top_count_entries(&self.policy_matched_domain_counts, usize::MAX)
            {
                rendered.push_str(&format!("| `{domain}` | {count} |\n"));
            }
        }

        rendered.push_str("\n## Connect errors\n\n");
        if self.connect_error_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Error | Count |\n| --- | ---: |\n");
            for (error, count) in top_count_entries(&self.connect_error_counts, usize::MAX) {
                rendered.push_str(&format!("| {error} | {count} |\n"));
            }
        }

        rendered.push_str("\n## Runtime failures\n\n");
        if self.runtime_failure_reason_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Reason code | Count |\n| --- | ---: |\n");
            for (reason, count) in
                top_count_entries(&self.runtime_failure_reason_counts, usize::MAX)
            {
                rendered.push_str(&format!("| {reason} | {count} |\n"));
            }
        }

        rendered.push_str("\n## Runtime failure phases\n\n");
        if self.runtime_failure_phase_counts.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str("| Phase | Count |\n| --- | ---: |\n");
            for (phase, count) in top_count_entries(&self.runtime_failure_phase_counts, usize::MAX)
            {
                rendered.push_str(&format!("| {phase} | {count} |\n"));
            }
        }

        rendered.push_str("\n## Top connection targets\n\n");
        if self.connection_targets.is_empty() {
            rendered.push_str("_none_\n");
        } else {
            rendered.push_str(
                "| Target | Attempts | OK | Error | Flow end | DNS names | Matched domains |\n| --- | ---: | ---: | ---: | ---: | --- | --- |\n",
            );
            for (target, stats) in self.top_connection_targets(10) {
                rendered.push_str(&format!(
                    "| `{target}` | {} | {} | {} | {} | {} | {} |\n",
                    stats.connect_attempts,
                    stats.connect_ok,
                    stats.connect_error,
                    stats.flow_end,
                    self.render_dns_names_for_target(target),
                    self.render_matched_domains_for_target(target, 3)
                ));
            }
        }

        rendered
    }

    fn render_markdown_highlights(&self) -> String {
        let mut lines = Vec::new();

        lines.push(format!(
            "- proxy usage: proxied connect attempts={}, direct connect attempts={}",
            self.proxied_connect_attempts, self.direct_connect_attempts
        ));

        if let Some((target, stats)) = self.top_connection_targets(1).into_iter().next() {
            lines.push(format!(
                "- top connection target: `{target}` (attempts={}, ok={}, error={}, flow_end={}, dns_names={}, matched_domains={})",
                stats.connect_attempts,
                stats.connect_ok,
                stats.connect_error,
                stats.flow_end,
                self.render_dns_names_for_target(target),
                self.render_matched_domains_for_target(target, 3)
            ));
        } else {
            lines.push("- top connection target: none".to_string());
        }

        if let Some((qname, stats)) = self.top_dns_names(1).into_iter().next() {
            lines.push(format!(
                "- top DNS name: `{qname}` (queries={}, answers={}, answer_ips={}, targets={})",
                stats.queries,
                stats.answers,
                Self::render_dns_answer_ips(stats),
                self.render_top_targets_for_dns_name(qname, 3)
            ));
        } else {
            lines.push("- top DNS name: none".to_string());
        }

        if let Some(correlation) = self.top_dns_target_correlations(1, 1).into_iter().next() {
            let target = correlation
                .targets
                .first()
                .map(|target| self.render_dns_correlated_target(target))
                .unwrap_or_else(|| "none".to_string());
            lines.push(format!(
                "- top DNS target correlation: `{}` -> {}",
                correlation.qname, target
            ));
        } else {
            lines.push("- top DNS target correlation: none".to_string());
        }

        if let Some(correlation) = self.top_dns_policy_correlations(1, 1).into_iter().next() {
            lines.push(format!(
                "- top DNS policy correlation: `{}` (answer_ips={}, matched_domains={}, targets={})",
                correlation.qname,
                self.render_answer_ip_list(&correlation.answer_ips),
                render_ranked_string_counts(&correlation.matched_domains),
                self.render_dns_target_list(&correlation.targets)
            ));
        } else {
            lines.push("- top DNS policy correlation: none".to_string());
        }

        lines.push(self.render_markdown_count_highlight(
            "most common policy violation",
            &self.policy_reason_counts,
        ));
        lines.push(self.render_markdown_count_highlight(
            "most common policy control",
            &self.policy_control_counts,
        ));
        lines.push(self.render_markdown_count_highlight(
            "most common matched domain",
            &self.policy_matched_domain_counts,
        ));
        lines.push(self.render_markdown_count_highlight(
            "most common connect error",
            &self.connect_error_counts,
        ));
        lines.push(self.render_markdown_count_highlight(
            "most common runtime failure",
            &self.runtime_failure_reason_counts,
        ));
        lines.push(self.render_markdown_count_highlight(
            "most common runtime failure phase",
            &self.runtime_failure_phase_counts,
        ));

        lines.join("\n") + "\n\n"
    }

    fn render_markdown_count_highlight(
        &self,
        label: &str,
        counts: &BTreeMap<String, usize>,
    ) -> String {
        match top_count_entries(counts, 1).into_iter().next() {
            Some((key, count)) => format!("- {label}: `{key}` ({count})"),
            None => format!("- {label}: none"),
        }
    }
}
