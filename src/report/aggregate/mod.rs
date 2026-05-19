use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;

use super::{
    render_ranked_string_counts, ConnectionTargetStats, DnsCorrelatedTarget, DnsNameStats,
    DnsPolicyCorrelation, DnsPolicyRow, DnsTargetCorrelation, FlowLogReport, RankedStringCount,
};

mod correlate;
mod ingest;

pub(crate) fn top_count_entries(
    counts: &BTreeMap<String, usize>,
    limit: usize,
) -> Vec<(&str, usize)> {
    let mut entries = counts
        .iter()
        .map(|(name, count)| (name.as_str(), *count))
        .collect::<Vec<_>>();
    entries.sort_by(|(left_name, left_count), (right_name, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_name.cmp(right_name))
    });
    entries.truncate(limit);
    entries
}

pub(crate) fn target_ip_string(target: &str) -> Option<String> {
    SocketAddr::from_str(target)
        .ok()
        .map(|addr| addr.ip().to_string())
}
