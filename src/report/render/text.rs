use std::path::Path;

use super::super::{render_ranked_string_counts, top_count_entries, FlowLogReport};

impl FlowLogReport {
    pub fn render_text(&self, path: &Path) -> String {
        let mut rendered = format!(
            "childflow report\nflow-log: {}\nschema-version: {}\nevents:\n  total: {}\n  dns_query: {}\n  dns_answer: {}\n  connect_attempt: {}\n  connect_result: {}\n  policy_violation: {}\n  flow_end: {}\n  runtime_failure: {}\n  unknown_event: {}\n",
            path.display(),
            self.render_schema_versions(),
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

        rendered.push_str("protocols:\n");
        if self.protocol_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (protocol, count) in top_count_entries(&self.protocol_counts, usize::MAX) {
                rendered.push_str(&format!("  {protocol}: {count}\n"));
            }
        }

        rendered.push_str("top-dns-names:\n");
        if self.dns_name_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (qname, stats) in self.top_dns_names(10) {
                rendered.push_str(&format!(
                    "  {qname}: queries={}, answers={}, answer_ips={}\n",
                    stats.queries,
                    stats.answers,
                    Self::render_dns_answer_ips(stats)
                ));
            }
        }

        rendered.push_str("dns-target-correlations:\n");
        let dns_target_correlations = self.top_dns_target_correlations(10, 3);
        if dns_target_correlations.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for correlation in dns_target_correlations {
                rendered.push_str(&format!(
                    "  {}: answer_ips={}, targets={}\n",
                    correlation.qname,
                    self.render_answer_ip_list(&correlation.answer_ips),
                    self.render_dns_target_list(&correlation.targets)
                ));
            }
        }

        rendered.push_str("dns-policy-correlations:\n");
        let dns_policy_correlations = self.top_dns_policy_correlations(10, 3);
        if dns_policy_correlations.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for correlation in dns_policy_correlations {
                rendered.push_str(&format!(
                    "  {}: answer_ips={}, matched_domains={}, targets={}\n",
                    correlation.qname,
                    self.render_answer_ip_list(&correlation.answer_ips),
                    render_ranked_string_counts(&correlation.matched_domains),
                    self.render_dns_target_list(&correlation.targets)
                ));
            }
        }

        rendered.push_str("proxy-usage:\n");
        rendered.push_str(&format!(
            "  proxied_connect_attempts: {}\n  direct_connect_attempts: {}\n",
            self.proxied_connect_attempts, self.direct_connect_attempts
        ));

        rendered.push_str("policy-violations:\n");
        if self.policy_reason_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (reason, count) in top_count_entries(&self.policy_reason_counts, usize::MAX) {
                rendered.push_str(&format!("  {reason}: {count}\n"));
            }
        }

        rendered.push_str("policy-controls:\n");
        if self.policy_control_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (control, count) in top_count_entries(&self.policy_control_counts, usize::MAX) {
                rendered.push_str(&format!("  {control}: {count}\n"));
            }
        }

        rendered.push_str("policy-matched-domains:\n");
        if self.policy_matched_domain_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (domain, count) in top_count_entries(&self.policy_matched_domain_counts, usize::MAX)
            {
                rendered.push_str(&format!("  {domain}: {count}\n"));
            }
        }

        rendered.push_str("connect-errors:\n");
        if self.connect_error_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (error, count) in top_count_entries(&self.connect_error_counts, usize::MAX) {
                rendered.push_str(&format!("  {error}: {count}\n"));
            }
        }

        rendered.push_str("runtime-failures:\n");
        if self.runtime_failure_reason_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (reason, count) in
                top_count_entries(&self.runtime_failure_reason_counts, usize::MAX)
            {
                rendered.push_str(&format!("  {reason}: {count}\n"));
            }
        }

        rendered.push_str("runtime-failure-phases:\n");
        if self.runtime_failure_phase_counts.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (phase, count) in top_count_entries(&self.runtime_failure_phase_counts, usize::MAX)
            {
                rendered.push_str(&format!("  {phase}: {count}\n"));
            }
        }

        rendered.push_str("top-connection-targets:\n");
        if self.connection_targets.is_empty() {
            rendered.push_str("  <none>\n");
        } else {
            for (target, stats) in self.top_connection_targets(10) {
                rendered.push_str(&format!(
                    "  {target}: attempts={}, ok={}, error={}, flow_end={}, dns_names={}, matched_domains={}\n",
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
}
