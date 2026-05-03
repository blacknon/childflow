// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

pub mod doctor {
    pub const ROOT_PRIVILEGES: &str = "root_privileges";
    pub const EXTERNAL_COMMANDS: &str = "external_commands";
    pub const FORWARDING_SYSCTLS: &str = "forwarding_sysctls";
    pub const AF_PACKET_CAPTURE: &str = "af_packet_capture";
    pub const NAMESPACE_HANDLES: &str = "namespace_handles";
    pub const USER_NAMESPACE_QUOTA: &str = "user_namespace_quota";
    pub const UNPRIVILEGED_USER_NAMESPACES: &str = "unprivileged_user_namespaces";
    pub const APPARMOR_USERNS_POLICY: &str = "apparmor_userns_policy";
    pub const UIDMAP_HELPERS: &str = "uidmap_helpers";
    pub const SUBUID_SUBGID_ENTRIES: &str = "subuid_subgid_entries";
    pub const TUN_TAP_DEVICE: &str = "tun_tap_device";
}

pub mod report {
    pub const FLOW_LOG: &str = "flow_log";
    pub const SCHEMA_VERSIONS: &str = "schema_versions";
    pub const EVENT_COUNTS: &str = "event_counts";
    pub const PROTOCOLS: &str = "protocols";
    pub const SORTED_PROTOCOLS: &str = "sorted_protocols";
    pub const TOP_DNS_NAMES: &str = "top_dns_names";
    pub const DNS_TARGET_CORRELATIONS: &str = "dns_target_correlations";
    pub const DNS_POLICY_CORRELATIONS: &str = "dns_policy_correlations";
    pub const DNS_POLICY_ROWS: &str = "dns_policy_rows";
    pub const PROXY_USAGE: &str = "proxy_usage";
    pub const POLICY_VIOLATIONS: &str = "policy_violations";
    pub const SORTED_POLICY_VIOLATIONS: &str = "sorted_policy_violations";
    pub const POLICY_MATCHED_DOMAINS: &str = "policy_matched_domains";
    pub const SORTED_POLICY_MATCHED_DOMAINS: &str = "sorted_policy_matched_domains";
    pub const CONNECT_ERRORS: &str = "connect_errors";
    pub const SORTED_CONNECT_ERRORS: &str = "sorted_connect_errors";
    pub const RUNTIME_FAILURES: &str = "runtime_failures";
    pub const SORTED_RUNTIME_FAILURES: &str = "sorted_runtime_failures";
    pub const RUNTIME_FAILURE_PHASES: &str = "runtime_failure_phases";
    pub const SORTED_RUNTIME_FAILURE_PHASES: &str = "sorted_runtime_failure_phases";
    pub const TOP_CONNECTION_TARGETS: &str = "top_connection_targets";
}

pub mod summary {
    pub const FLOW_LOG_EVENTS: &str = "flow-log events";
    pub const FLOW_LOG_DNS_NAMES: &str = "flow-log dns names";
    pub const FLOW_LOG_TOP_TARGET: &str = "flow-log top target";
    pub const FLOW_LOG_POLICY_VIOLATIONS: &str = "flow-log policy violations";
    pub const FLOW_LOG_POLICY_MATCHED_DOMAINS: &str = "flow-log policy matched domains";
    pub const FLOW_LOG_CONNECT_ERRORS: &str = "flow-log connect errors";
    pub const FLOW_LOG_RUNTIME_FAILURES: &str = "flow-log runtime failures";
    pub const FLOW_LOG_RUNTIME_FAILURE_PHASES: &str = "flow-log runtime failure phases";
}
