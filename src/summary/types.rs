use crate::report::DnsCorrelatedTarget;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct SummaryJsonReport {
    pub(super) backend: String,
    pub(super) command: String,
    pub(super) exit_code: i32,
    pub(super) sandbox_controls: Vec<String>,
    pub(super) capture: SummaryCaptureReport,
    pub(super) flow_log: SummaryFlowLogReport,
}

#[derive(Debug, Serialize)]
pub(super) struct SummaryCaptureReport {
    pub(super) status: String,
    pub(super) requested: Option<String>,
    pub(super) effective: Option<String>,
    pub(super) output: Option<String>,
    pub(super) child_output: Option<String>,
    pub(super) egress_output: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct SummaryFlowLogReport {
    pub(super) status: String,
    pub(super) path: Option<String>,
    pub(super) event_counts: Option<SummaryEventCounts>,
    pub(super) top_dns_name: Option<SummaryTopDnsName>,
    pub(super) dns_policy_rows: Vec<SummaryDnsPolicyRow>,
    pub(super) top_dns_policy_correlation: Option<SummaryTopDnsPolicyCorrelation>,
    pub(super) top_target: Option<SummaryTopTarget>,
    pub(super) policy_violations: Vec<SummaryCountEntry>,
    pub(super) policy_controls: Vec<SummaryCountEntry>,
    pub(super) policy_matched_domains: Vec<SummaryCountEntry>,
    pub(super) connect_errors: Vec<SummaryCountEntry>,
    pub(super) runtime_failures: Vec<SummaryCountEntry>,
    pub(super) runtime_failure_phases: Vec<SummaryCountEntry>,
}

#[derive(Debug, Serialize)]
pub(super) struct SummaryEventCounts {
    pub(super) total: usize,
    pub(super) dns_query: usize,
    pub(super) dns_answer: usize,
    pub(super) connect_attempt: usize,
    pub(super) connect_result: usize,
    pub(super) policy_violation: usize,
    pub(super) flow_end: usize,
    pub(super) runtime_failure: usize,
    pub(super) unknown_event: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct SummaryTopDnsName {
    pub(super) qname: String,
    pub(super) queries: usize,
    pub(super) answers: usize,
    pub(super) answer_ips: Vec<String>,
    pub(super) targets: Vec<DnsCorrelatedTarget>,
}

#[derive(Debug, Serialize)]
pub(super) struct SummaryDnsPolicyRow {
    pub(super) qname: String,
    pub(super) queries: usize,
    pub(super) answers: usize,
    pub(super) answer_ips: Vec<String>,
    pub(super) target: Option<String>,
    pub(super) target_ip: Option<String>,
    pub(super) connect_attempts: usize,
    pub(super) connect_ok: usize,
    pub(super) connect_error: usize,
    pub(super) flow_end: usize,
    pub(super) matched_domains: Vec<SummaryCountEntry>,
}

#[derive(Debug, Serialize)]
pub(super) struct SummaryTopDnsPolicyCorrelation {
    pub(super) qname: String,
    pub(super) queries: usize,
    pub(super) answers: usize,
    pub(super) answer_ips: Vec<String>,
    pub(super) matched_domains: Vec<SummaryCountEntry>,
    pub(super) targets: Vec<DnsCorrelatedTarget>,
}

#[derive(Debug, Serialize)]
pub(super) struct SummaryTopTarget {
    pub(super) target: String,
    pub(super) connect_attempts: usize,
    pub(super) connect_ok: usize,
    pub(super) connect_error: usize,
    pub(super) flow_end: usize,
    pub(super) dns_names: Vec<String>,
    pub(super) matched_domains: Vec<SummaryCountEntry>,
}

#[derive(Debug, Serialize)]
pub(super) struct SummaryCountEntry {
    pub(super) key: String,
    pub(super) count: usize,
}
