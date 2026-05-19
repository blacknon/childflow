use anyhow::Context;

use super::*;
use crate::linux_net;

impl NetworkContext {
    pub(crate) fn install_interface_forcing(&mut self) -> Result<()> {
        let Some(iface) = self.iface.clone() else {
            return Ok(());
        };

        let route_info = discover_default_route_for_interface(&iface).with_context(|| {
            format!(
                "failed to discover the IPv4 default route for interface {iface}. Check `ip route show default dev {iface}` on the host"
            )
        })?;
        let route6_info = discover_default_route6_for_interface(&iface).with_context(|| {
            format!(
                "failed to discover the IPv6 default route for interface {iface}. Check `ip -6 route show default dev {iface}` on the host"
            )
        })?;

        let route_mark = self
            .route_mark
            .expect("route_mark must be set when iface is set");
        let route_table = self
            .route_table
            .expect("route_table must be set when iface is set");
        let route_priority = self
            .route_priority
            .expect("route_priority must be set when iface is set");

        let mark_v4_args = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            route_mark.to_string(),
        ];
        run_iptables("mangle", mark_v4_args.clone())
            .context("failed to install mark rule for interface forcing")?;
        self.push_cleanup_iptables(
            "remove IPv4 interface-forcing mark rule",
            "mangle",
            replace_action_flag(&mark_v4_args, "-A", "-D"),
        );

        let mark_v6_args = vec![
            "-A".into(),
            "PREROUTING".into(),
            "-i".into(),
            self.host_veth.clone(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            route_mark.to_string(),
        ];
        run_ip6tables("mangle", mark_v6_args.clone())
            .context("failed to install IPv6 mark rule for interface forcing")?;
        self.push_cleanup_ip6tables(
            "remove IPv6 interface-forcing mark rule",
            "mangle",
            replace_action_flag(&mark_v6_args, "-A", "-D"),
        );

        linux_net::policy_rule_add_v4(route_mark, route_table, route_priority)
            .context("failed to install policy routing rule for interface forcing")?;
        self.push_cleanup_policy_rule_v4(route_mark, route_table, route_priority);

        linux_net::policy_rule_add_v6(route_mark, route_table, route_priority)
            .context("failed to install IPv6 policy routing rule for interface forcing")?;
        self.push_cleanup_policy_rule_v6(route_mark, route_table, route_priority);

        linux_net::route_add_default_v4_table(&iface, route_info.gateway, route_table)
            .with_context(|| {
                format!("failed to install route table {route_table} for forced interface {iface}")
            })?;
        self.push_cleanup_default_route_v4(iface.clone(), route_info.gateway, route_table);

        linux_net::route_add_default_v6_table(&iface, route6_info.gateway, route_table)
            .with_context(|| {
                format!(
                    "failed to install IPv6 route table {route_table} for forced interface {iface}"
                )
            })?;
        self.push_cleanup_default_route_v6(iface, route6_info.gateway, route_table);

        Ok(())
    }
}
