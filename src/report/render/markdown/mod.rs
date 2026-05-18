use std::path::Path;

use super::super::FlowLogReport;

mod sections;

impl FlowLogReport {
    pub fn render_markdown(&self, path: &Path) -> String {
        let mut rendered = format!(
            "# childflow report\n\n- flow-log: `{}`\n- schema-version: `{}`\n\n## Highlights\n\n{}\n## Event counts\n\n| Metric | Count |\n| --- | ---: |\n| total | {} |\n| dns_query | {} |\n| dns_answer | {} |\n| connect_attempt | {} |\n| connect_result | {} |\n| policy_violation | {} |\n| flow_end | {} |\n| runtime_failure | {} |\n| unknown_event | {} |\n",
            path.display(),
            self.render_schema_versions(),
            sections::highlights::render_markdown_highlights(self),
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

        sections::overview::append_dns_overview(self, &mut rendered);
        sections::overview::append_policy_overview(self, &mut rendered);
        sections::overview::append_runtime_overview(self, &mut rendered);
        sections::tables::append_protocols(self, &mut rendered);
        sections::tables::append_top_dns_names(self, &mut rendered);
        sections::tables::append_dns_target_correlations(self, &mut rendered);
        sections::tables::append_dns_policy_correlations(self, &mut rendered);
        sections::tables::append_proxy_usage(self, &mut rendered);
        sections::tables::append_policy_violations(self, &mut rendered);
        sections::tables::append_policy_controls(self, &mut rendered);
        sections::tables::append_policy_matched_domains(self, &mut rendered);
        sections::tables::append_connect_errors(self, &mut rendered);
        sections::tables::append_runtime_failures(self, &mut rendered);
        sections::tables::append_runtime_failure_phases(self, &mut rendered);
        sections::tables::append_top_connection_targets(self, &mut rendered);

        rendered
    }
}
