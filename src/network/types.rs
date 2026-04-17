use std::net::{Ipv4Addr, Ipv6Addr};

use clap::ValueEnum;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum NetworkBackend {
    Rootful,
    RootlessInternal,
}

impl NetworkBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rootful => "rootful",
            Self::RootlessInternal => "rootless-internal",
        }
    }

    pub fn is_experimental(self) -> bool {
        matches!(self, Self::RootlessInternal)
    }
}

#[derive(Clone, Debug)]
pub struct NetworkPlan {
    pub(crate) host_veth: String,
    pub(crate) child_veth: String,
    pub(crate) host_ipv4: Ipv4Addr,
    pub(crate) child_ipv4: Ipv4Addr,
    pub(crate) subnet_v4_cidr: String,
    pub(crate) host_ipv6: Ipv6Addr,
    pub(crate) child_ipv6: Ipv6Addr,
    pub(crate) subnet_v6_cidr: String,
    pub(crate) route_table: u32,
    pub(crate) tproxy_table: u32,
    pub(crate) route_priority: u32,
    pub(crate) tproxy_priority: u32,
    pub(crate) route_mark: u32,
    pub(crate) tproxy_mark: u32,
    pub(crate) divert_chain: String,
    pub(crate) tproxy_chain: String,
}

impl NetworkPlan {
    pub fn new() -> Self {
        let entropy = crate::util::run_entropy();
        let (host_ipv4, child_ipv4, subnet_v4_cidr) = allocate_ipv4_subnet(entropy);
        let (host_ipv6, child_ipv6, subnet_v6_cidr) = allocate_ipv6_subnet(entropy);
        let suffix = format!("{:06x}", entropy & 0x00ff_ffff);

        Self {
            host_veth: format!("cfh{}", &suffix[..6]),
            child_veth: format!("cfc{}", &suffix[..6]),
            host_ipv4,
            child_ipv4,
            subnet_v4_cidr,
            host_ipv6,
            child_ipv6,
            subnet_v6_cidr,
            route_table: 10_000 + (entropy % 10_000),
            tproxy_table: 10_001 + (entropy % 10_000),
            route_priority: 10_000 + (entropy % 1_000),
            tproxy_priority: 10_001 + (entropy % 1_000),
            route_mark: 0x10000 | (entropy & 0x0fff),
            tproxy_mark: 0x20000 | (entropy & 0x0fff),
            divert_chain: format!("CFD{}", &suffix[..6]),
            tproxy_chain: format!("CFT{}", &suffix[..6]),
        }
    }

    pub fn host_ipv4(&self) -> Ipv4Addr {
        self.host_ipv4
    }

    pub fn host_ipv6(&self) -> Ipv6Addr {
        self.host_ipv6
    }
}

fn allocate_ipv4_subnet(entropy: u32) -> (Ipv4Addr, Ipv4Addr, String) {
    let octet3 = ((entropy >> 8) & 0xff) as u8;
    let block = ((entropy & 0x3f) as u8) * 4;
    let host_ip = Ipv4Addr::new(10, 240, octet3, block + 1);
    let child_ip = Ipv4Addr::new(10, 240, octet3, block + 2);
    let subnet_cidr = format!("10.240.{octet3}.{block}/30");
    (host_ip, child_ip, subnet_cidr)
}

fn allocate_ipv6_subnet(entropy: u32) -> (Ipv6Addr, Ipv6Addr, String) {
    let upper = ((entropy >> 16) & 0xffff) as u16;
    let lower = (entropy & 0xffff) as u16;
    let subnet = format!("fd42:{upper:04x}:{lower:04x}::/64");
    let host_ip = Ipv6Addr::new(0xfd42, upper, lower, 0, 0, 0, 0, 1);
    let child_ip = Ipv6Addr::new(0xfd42, upper, lower, 0, 0, 0, 0, 2);
    (host_ip, child_ip, subnet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_ipv4_subnet_uses_a_private_slash30() {
        let (host, child, cidr) = allocate_ipv4_subnet(0x1234_5678);

        assert_eq!(host, Ipv4Addr::new(10, 240, 0x56, 0x38 + 1));
        assert_eq!(child, Ipv4Addr::new(10, 240, 0x56, 0x38 + 2));
        assert_eq!(cidr, "10.240.86.56/30");
    }

    #[test]
    fn allocate_ipv6_subnet_uses_a_unique_ula_prefix() {
        let (host, child, cidr) = allocate_ipv6_subnet(0x1234_5678);

        assert_eq!(host, "fd42:1234:5678::1".parse().unwrap());
        assert_eq!(child, "fd42:1234:5678::2".parse().unwrap());
        assert_eq!(cidr, "fd42:1234:5678::/64");
    }
}
