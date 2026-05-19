use super::cleanup::CleanupAction;
use super::NetworkContext;
use std::net::{Ipv4Addr, Ipv6Addr};

impl NetworkContext {
    pub(super) fn push_cleanup_iptables(
        &mut self,
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    ) {
        self.cleanup_actions
            .push(CleanupAction::RunIptables { label, table, args });
    }

    pub(super) fn push_cleanup_ip6tables(
        &mut self,
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    ) {
        self.cleanup_actions
            .push(CleanupAction::RunIp6tables { label, table, args });
    }

    pub(super) fn push_restore_file(&mut self, path: impl Into<String>, value: impl Into<String>) {
        self.cleanup_actions.push(CleanupAction::RestoreFile {
            path: path.into(),
            value: value.into(),
        });
    }

    pub(super) fn push_cleanup_policy_rule_v4(&mut self, fwmark: u32, table: u32, priority: u32) {
        self.cleanup_actions
            .push(CleanupAction::DeletePolicyRuleV4 {
                fwmark,
                table,
                priority,
            });
    }

    pub(super) fn push_cleanup_policy_rule_v6(&mut self, fwmark: u32, table: u32, priority: u32) {
        self.cleanup_actions
            .push(CleanupAction::DeletePolicyRuleV6 {
                fwmark,
                table,
                priority,
            });
    }

    pub(super) fn push_cleanup_default_route_v4(
        &mut self,
        iface: impl Into<String>,
        gateway: Option<Ipv4Addr>,
        table: u32,
    ) {
        self.cleanup_actions
            .push(CleanupAction::DeleteDefaultRouteV4 {
                iface: iface.into(),
                gateway,
                table,
            });
    }

    pub(super) fn push_cleanup_default_route_v6(
        &mut self,
        iface: impl Into<String>,
        gateway: Option<Ipv6Addr>,
        table: u32,
    ) {
        self.cleanup_actions
            .push(CleanupAction::DeleteDefaultRouteV6 {
                iface: iface.into(),
                gateway,
                table,
            });
    }

    pub(super) fn push_cleanup_local_route_v4(&mut self, table: u32) {
        self.cleanup_actions
            .push(CleanupAction::DeleteLocalRouteV4 { table });
    }

    pub(super) fn push_cleanup_local_route_v6(&mut self, table: u32) {
        self.cleanup_actions
            .push(CleanupAction::DeleteLocalRouteV6 { table });
    }

    pub(super) fn push_cleanup_link(&mut self, iface: impl Into<String>) {
        self.cleanup_actions.push(CleanupAction::DeleteLink {
            iface: iface.into(),
        });
    }
}
