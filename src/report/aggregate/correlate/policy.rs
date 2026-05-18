use super::*;

impl FlowLogReport {
    pub fn policy_violation_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.policy_reason_counts, limit)
    }

    pub fn policy_control_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.policy_control_counts, limit)
    }

    pub fn policy_matched_domain_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.policy_matched_domain_counts, limit)
    }

    pub fn connect_error_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.connect_error_counts, limit)
    }

    pub fn runtime_failure_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.runtime_failure_reason_counts, limit)
    }

    pub fn runtime_failure_phase_entries(&self, limit: usize) -> Vec<(&str, usize)> {
        top_count_entries(&self.runtime_failure_phase_counts, limit)
    }
}
