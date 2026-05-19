use super::FlowLogReport;

mod json;
mod markdown;
mod text;

impl FlowLogReport {
    pub(super) fn render_answer_ip_list(&self, answer_ips: &[String]) -> String {
        if answer_ips.is_empty() {
            "none".to_string()
        } else {
            answer_ips.join(", ")
        }
    }
}
