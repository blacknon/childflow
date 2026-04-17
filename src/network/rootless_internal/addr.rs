use std::net::{Ipv4Addr, Ipv6Addr};

use crate::network::types::NetworkPlan;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressPlan {
    pub tap_name: String,
    pub gateway_mac: [u8; 6],
    pub gateway_ipv4: Ipv4Addr,
    pub child_ipv4: Ipv4Addr,
    pub child_ipv4_prefix_len: u8,
    pub gateway_ipv6: Ipv6Addr,
    pub child_ipv6: Ipv6Addr,
    pub child_ipv6_prefix_len: u8,
}

impl AddressPlan {
    pub fn from_network_plan(plan: &NetworkPlan) -> Self {
        Self {
            tap_name: "tap0".to_string(),
            gateway_mac: gateway_mac_from_plan(plan),
            gateway_ipv4: plan.host_ipv4,
            child_ipv4: plan.child_ipv4,
            child_ipv4_prefix_len: 30,
            gateway_ipv6: plan.host_ipv6,
            child_ipv6: plan.child_ipv6,
            child_ipv6_prefix_len: 64,
        }
    }

    pub fn child_ipv4_cidr(&self) -> String {
        format!("{}/{}", self.child_ipv4, self.child_ipv4_prefix_len)
    }

    pub fn child_ipv6_cidr(&self) -> String {
        format!("{}/{}", self.child_ipv6, self.child_ipv6_prefix_len)
    }

    pub fn gateway_mac_string(&self) -> String {
        render_mac(self.gateway_mac)
    }
}

fn gateway_mac_from_plan(plan: &NetworkPlan) -> [u8; 6] {
    let octets = plan.host_ipv4.octets();
    [0x02, 0xcf, octets[1], octets[2], octets[3], 0x01]
}

fn render_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::NetworkPlan;

    #[test]
    fn address_plan_uses_tap0_and_common_gateway_layout() {
        let plan = NetworkPlan::new();
        let addr = AddressPlan::from_network_plan(&plan);

        assert_eq!(addr.tap_name, "tap0");
        assert_eq!(addr.gateway_mac[0], 0x02);
        assert_eq!(addr.gateway_ipv4, plan.host_ipv4);
        assert_eq!(addr.child_ipv4, plan.child_ipv4);
        assert_eq!(addr.gateway_ipv6, plan.host_ipv6);
        assert_eq!(addr.child_ipv6, plan.child_ipv6);
        assert_eq!(addr.child_ipv4_prefix_len, 30);
        assert_eq!(addr.child_ipv6_prefix_len, 64);
    }

    #[test]
    fn address_plan_renders_child_cidrs() {
        let addr = AddressPlan {
            tap_name: "tap0".into(),
            gateway_mac: [0x02, 0xcf, 0x00, 0x01, 0x02, 0x01],
            gateway_ipv4: Ipv4Addr::new(10, 240, 1, 1),
            child_ipv4: Ipv4Addr::new(10, 240, 1, 2),
            child_ipv4_prefix_len: 30,
            gateway_ipv6: "fd42::1".parse().unwrap(),
            child_ipv6: "fd42::2".parse().unwrap(),
            child_ipv6_prefix_len: 64,
        };

        assert_eq!(addr.child_ipv4_cidr(), "10.240.1.2/30");
        assert_eq!(addr.child_ipv6_cidr(), "fd42::2/64");
        assert_eq!(addr.gateway_mac_string(), "02:cf:00:01:02:01");
    }
}
