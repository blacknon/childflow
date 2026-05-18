use super::*;

impl FlowLogReport {
    pub fn render_top_dns_name_compact(&self) -> String {
        let Some((qname, stats)) = self.top_dns_names(1).into_iter().next() else {
            return "none".to_string();
        };

        format!(
            "{qname} (queries={}, answers={}, answer_ips={}, targets={})",
            stats.queries,
            stats.answers,
            Self::render_dns_answer_ips(stats),
            self.render_top_targets_for_dns_name(qname, 3)
        )
    }

    pub fn render_top_dns_policy_correlation_compact(&self) -> String {
        let Some(correlation) = self.top_dns_policy_correlations(1, 1).into_iter().next() else {
            return "none".to_string();
        };

        format!(
            "{} (answer_ips={}, matched_domains={}, targets={})",
            correlation.qname,
            if correlation.answer_ips.is_empty() {
                "none".to_string()
            } else {
                correlation.answer_ips.join(", ")
            },
            render_ranked_string_counts(&correlation.matched_domains),
            self.render_dns_target_list(&correlation.targets)
        )
    }

    pub fn render_top_dns_target_correlation_compact(&self) -> String {
        let Some(correlation) = self.top_dns_target_correlations(1, 1).into_iter().next() else {
            return "none".to_string();
        };
        let target = correlation
            .targets
            .first()
            .map(|target| self.render_dns_correlated_target(target))
            .unwrap_or_else(|| "none".to_string());

        format!("{} -> {}", correlation.qname, target)
    }

    pub fn render_top_target_compact(&self) -> String {
        let Some((target, stats)) = self.top_connection_targets(1).into_iter().next() else {
            return "none".to_string();
        };

        format!(
            "{target} (attempts={}, ok={}, error={}, flow_end={}, dns_names={}, matched_domains={})",
            stats.connect_attempts,
            stats.connect_ok,
            stats.connect_error,
            stats.flow_end,
            self.render_dns_names_for_target(target),
            self.render_matched_domains_for_target(target, 3)
        )
    }

    pub fn render_dns_policy_rows_compact(&self, limit: usize) -> String {
        let rows = self.top_dns_policy_rows(limit, 1);
        if rows.is_empty() {
            return "none".to_string();
        }

        rows.into_iter()
            .map(|row| {
                let answer_ips = if row.answer_ips.is_empty() {
                    "none".to_string()
                } else {
                    row.answer_ips.join(", ")
                };
                let matched_domains = render_ranked_string_counts(&row.matched_domains);
                match row.target {
                    Some(target) => format!(
                        "{} -> {} (answer_ips={}, matched_domains={}, attempts={}, ok={}, error={}, flow_end={})",
                        row.qname,
                        target,
                        answer_ips,
                        matched_domains,
                        row.connect_attempts,
                        row.connect_ok,
                        row.connect_error,
                        row.flow_end
                    ),
                    None => format!(
                        "{} -> no-target (answer_ips={}, matched_domains={})",
                        row.qname, answer_ips, matched_domains
                    ),
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn render_policy_violations_compact(&self, limit: usize) -> String {
        if self.policy_reason_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.policy_reason_counts, limit)
            .into_iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn render_policy_controls_compact(&self, limit: usize) -> String {
        if self.policy_control_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.policy_control_counts, limit)
            .into_iter()
            .map(|(control, count)| format!("{control}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn render_policy_matched_domains_compact(&self, limit: usize) -> String {
        if self.policy_matched_domain_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.policy_matched_domain_counts, limit)
            .into_iter()
            .map(|(domain, count)| format!("{domain}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn render_connect_errors_compact(&self, limit: usize) -> String {
        if self.connect_error_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.connect_error_counts, limit)
            .into_iter()
            .map(|(error, count)| format!("{error}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn render_runtime_failures_compact(&self, limit: usize) -> String {
        if self.runtime_failure_reason_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.runtime_failure_reason_counts, limit)
            .into_iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn render_runtime_failure_phases_compact(&self, limit: usize) -> String {
        if self.runtime_failure_phase_counts.is_empty() {
            return "none".to_string();
        }

        top_count_entries(&self.runtime_failure_phase_counts, limit)
            .into_iter()
            .map(|(phase, count)| format!("{phase}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

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
