use super::super::*;

impl FlowLogReport {
    pub(crate) fn render_schema_versions(&self) -> String {
        if self.schema_versions.is_empty() {
            return "unknown".to_string();
        }

        self.schema_versions
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(crate) fn render_dns_names_for_target(&self, target: &str) -> String {
        let dns_names = self.dns_names_for_target(target);
        if dns_names.is_empty() {
            "none".to_string()
        } else {
            dns_names.join(", ")
        }
    }

    pub(crate) fn render_top_targets_for_dns_name(&self, qname: &str, limit: usize) -> String {
        self.render_dns_target_list(&self.correlated_targets_for_dns_name(qname, limit))
    }

    pub(crate) fn render_dns_target_list(&self, targets: &[DnsCorrelatedTarget]) -> String {
        if targets.is_empty() {
            return "none".to_string();
        }
        targets
            .iter()
            .map(|target| self.render_dns_correlated_target(target))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(crate) fn render_dns_correlated_target(&self, target: &DnsCorrelatedTarget) -> String {
        let matched_domains = render_ranked_string_counts(&target.matched_domains);
        format!(
            "{} (attempts={}, ok={}, error={}, flow_end={}, matched_domains={})",
            target.target,
            target.connect_attempts,
            target.connect_ok,
            target.connect_error,
            target.flow_end,
            matched_domains
        )
    }

    pub(crate) fn render_matched_domains_for_target(&self, target: &str, limit: usize) -> String {
        let counts = self
            .matched_domain_entries_for_target(target, limit)
            .into_iter()
            .map(|(key, count)| RankedStringCount {
                key: key.to_string(),
                count,
            })
            .collect::<Vec<_>>();
        render_ranked_string_counts(&counts)
    }

    pub(crate) fn render_dns_answer_ips(stats: &DnsNameStats) -> String {
        if stats.answer_ips.is_empty() {
            "none".to_string()
        } else {
            stats
                .answer_ips
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        }
    }
}
