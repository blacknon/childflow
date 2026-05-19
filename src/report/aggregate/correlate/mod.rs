use std::collections::BTreeMap;

mod dns;
mod policy;
mod render;

use super::*;

impl FlowLogReport {
    pub fn render_event_counts_compact(&self) -> String {
        format!(
            "total={}, dns_query={}, dns_answer={}, connect_attempt={}, connect_result={}, policy_violation={}, flow_end={}, runtime_failure={}, unknown_event={}",
            self.total,
            self.dns_query,
            self.dns_answer,
            self.connect_attempt,
            self.connect_result,
            self.policy_violation,
            self.flow_end,
            self.runtime_failure,
            self.unknown_event
        )
    }

    pub fn top_connection_targets(&self, limit: usize) -> Vec<(&str, &ConnectionTargetStats)> {
        let mut entries = self
            .connection_targets
            .iter()
            .map(|(target, stats)| (target.as_str(), stats))
            .collect::<Vec<_>>();
        entries.sort_by(|(left_target, left_stats), (right_target, right_stats)| {
            right_stats
                .connect_attempts
                .cmp(&left_stats.connect_attempts)
                .then_with(|| right_stats.connect_error.cmp(&left_stats.connect_error))
                .then_with(|| right_stats.connect_ok.cmp(&left_stats.connect_ok))
                .then_with(|| left_target.cmp(right_target))
        });
        entries.truncate(limit);
        entries
    }

    pub fn top_dns_names(&self, limit: usize) -> Vec<(&str, &DnsNameStats)> {
        let mut entries = self
            .dns_name_counts
            .iter()
            .map(|(qname, stats)| (qname.as_str(), stats))
            .collect::<Vec<_>>();
        entries.sort_by(|(left_name, left_stats), (right_name, right_stats)| {
            right_stats
                .queries
                .cmp(&left_stats.queries)
                .then_with(|| right_stats.answers.cmp(&left_stats.answers))
                .then_with(|| left_name.cmp(right_name))
        });
        entries.truncate(limit);
        entries
    }

    pub fn matched_domain_entries_for_dns_name(
        &self,
        qname: &str,
        limit: usize,
    ) -> Vec<RankedStringCount> {
        let Some(stats) = self.dns_name_counts.get(qname) else {
            return Vec::new();
        };
        let mut counts = BTreeMap::new();
        for ip in &stats.answer_ips {
            if let Some(per_ip) = self.policy_matched_domains_by_ip.get(ip) {
                for (domain, count) in per_ip {
                    *counts.entry(domain.clone()).or_insert(0) += count;
                }
            }
        }
        top_count_entries(&counts, limit)
            .into_iter()
            .map(|(key, count)| RankedStringCount {
                key: key.to_string(),
                count,
            })
            .collect()
    }
}
