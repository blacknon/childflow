use anyhow::Context;

use super::*;

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

        run_command(
            "ip",
            vec![
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                route_mark.to_string(),
                "lookup".into(),
                route_table.to_string(),
                "priority".into(),
                route_priority.to_string(),
            ],
        )
        .context("failed to install policy routing rule for interface forcing")?;
        self.push_cleanup_command(
            "remove IPv4 interface-forcing policy rule",
            "ip",
            vec![
                "rule".into(),
                "del".into(),
                "priority".into(),
                route_priority.to_string(),
            ],
        );

        run_command(
            "ip",
            vec![
                "-6".into(),
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                route_mark.to_string(),
                "lookup".into(),
                route_table.to_string(),
                "priority".into(),
                route_priority.to_string(),
            ],
        )
        .context("failed to install IPv6 policy routing rule for interface forcing")?;
        self.push_cleanup_command(
            "remove IPv6 interface-forcing policy rule",
            "ip",
            vec![
                "-6".into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                route_priority.to_string(),
            ],
        );

        run_command(
            "ip",
            build_default_route_args(route_table, &iface, route_info.gateway),
        )
        .with_context(|| {
            format!("failed to install route table {route_table} for forced interface {iface}")
        })?;
        self.push_cleanup_command(
            "remove IPv4 forced-interface route",
            "ip",
            build_default_route_delete_args(route_table, &iface, route_info.gateway),
        );

        run_command(
            "ip",
            build_default_route6_args(route_table, &iface, route6_info.gateway),
        )
        .with_context(|| {
            format!("failed to install IPv6 route table {route_table} for forced interface {iface}")
        })?;
        self.push_cleanup_command(
            "remove IPv6 forced-interface route",
            "ip",
            build_default_route6_delete_args(route_table, &iface, route6_info.gateway),
        );

        Ok(())
    }
}
