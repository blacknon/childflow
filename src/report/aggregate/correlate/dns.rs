use super::*;

impl FlowLogReport {
    pub fn dns_names_for_target(&self, target: &str) -> Vec<String> {
        let Some(ip) = target_ip_string(target) else {
            return Vec::new();
        };
        self.dns_name_counts
            .iter()
            .filter_map(|(qname, stats)| stats.answer_ips.contains(&ip).then_some(qname.clone()))
            .collect()
    }

    pub fn matched_domain_entries_for_target(
        &self,
        target: &str,
        limit: usize,
    ) -> Vec<(&str, usize)> {
        let Some(ip) = target_ip_string(target) else {
            return Vec::new();
        };
        self.policy_matched_domains_by_ip
            .get(&ip)
            .map(|counts| top_count_entries(counts, limit))
            .unwrap_or_default()
    }

    pub fn correlated_targets_for_dns_name(
        &self,
        qname: &str,
        limit: usize,
    ) -> Vec<DnsCorrelatedTarget> {
        let Some(stats) = self.dns_name_counts.get(qname) else {
            return Vec::new();
        };
        let mut targets = self
            .connection_targets
            .iter()
            .filter_map(|(target, target_stats)| {
                let ip = target_ip_string(target)?;
                stats.answer_ips.contains(&ip).then(|| DnsCorrelatedTarget {
                    target: target.clone(),
                    connect_attempts: target_stats.connect_attempts,
                    connect_ok: target_stats.connect_ok,
                    connect_error: target_stats.connect_error,
                    flow_end: target_stats.flow_end,
                    matched_domains: self
                        .matched_domain_entries_for_target(target, usize::MAX)
                        .into_iter()
                        .map(|(key, count)| RankedStringCount {
                            key: key.to_string(),
                            count,
                        })
                        .collect(),
                })
            })
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| {
            right
                .connect_attempts
                .cmp(&left.connect_attempts)
                .then_with(|| right.connect_error.cmp(&left.connect_error))
                .then_with(|| right.connect_ok.cmp(&left.connect_ok))
                .then_with(|| left.target.cmp(&right.target))
        });
        targets.truncate(limit);
        targets
    }

    pub fn top_dns_target_correlations(
        &self,
        dns_limit: usize,
        target_limit: usize,
    ) -> Vec<DnsTargetCorrelation> {
        self.top_dns_names(dns_limit)
            .into_iter()
            .map(|(qname, stats)| DnsTargetCorrelation {
                qname: qname.to_string(),
                queries: stats.queries,
                answers: stats.answers,
                answer_ips: stats.answer_ips.iter().cloned().collect(),
                targets: self.correlated_targets_for_dns_name(qname, target_limit),
            })
            .collect()
    }

    pub fn top_dns_policy_correlations(
        &self,
        dns_limit: usize,
        target_limit: usize,
    ) -> Vec<DnsPolicyCorrelation> {
        self.top_dns_names(dns_limit)
            .into_iter()
            .filter_map(|(qname, stats)| {
                let targets = self.correlated_targets_for_dns_name(qname, target_limit);
                let matched_domains = self.matched_domain_entries_for_dns_name(qname, usize::MAX);
                if targets.is_empty() && matched_domains.is_empty() {
                    return None;
                }
                Some(DnsPolicyCorrelation {
                    qname: qname.to_string(),
                    queries: stats.queries,
                    answers: stats.answers,
                    answer_ips: stats.answer_ips.iter().cloned().collect(),
                    matched_domains,
                    targets,
                })
            })
            .collect()
    }

    pub fn top_dns_policy_rows(&self, dns_limit: usize, target_limit: usize) -> Vec<DnsPolicyRow> {
        let mut rows = Vec::new();
        for correlation in self.top_dns_policy_correlations(dns_limit, target_limit) {
            if correlation.targets.is_empty() {
                rows.push(DnsPolicyRow {
                    qname: correlation.qname,
                    queries: correlation.queries,
                    answers: correlation.answers,
                    answer_ips: correlation.answer_ips,
                    target: None,
                    target_ip: None,
                    connect_attempts: 0,
                    connect_ok: 0,
                    connect_error: 0,
                    flow_end: 0,
                    matched_domains: correlation.matched_domains,
                });
                continue;
            }

            for target in correlation.targets {
                let target_ip = target_ip_string(&target.target);
                rows.push(DnsPolicyRow {
                    qname: correlation.qname.clone(),
                    queries: correlation.queries,
                    answers: correlation.answers,
                    answer_ips: correlation.answer_ips.clone(),
                    target: Some(target.target.clone()),
                    target_ip,
                    connect_attempts: target.connect_attempts,
                    connect_ok: target.connect_ok,
                    connect_error: target.connect_error,
                    flow_end: target.flow_end,
                    matched_domains: target.matched_domains,
                });
            }
        }

        rows.sort_by(|left, right| {
            right
                .connect_attempts
                .cmp(&left.connect_attempts)
                .then_with(|| right.connect_error.cmp(&left.connect_error))
                .then_with(|| right.connect_ok.cmp(&left.connect_ok))
                .then_with(|| left.qname.cmp(&right.qname))
                .then_with(|| left.target.cmp(&right.target))
        });
        rows
    }
}
