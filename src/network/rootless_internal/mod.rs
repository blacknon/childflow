pub mod addr;
pub mod route;
pub mod tap;

use anyhow::{Context, Result};
use nix::unistd::Pid;

use crate::cli::Cli;
use crate::dns::DnsPlan;
use crate::namespace;

use super::types::NetworkPlan;

pub struct ChildBootstrap {
    tap: tap::TapHandle,
    addr_plan: addr::AddressPlan,
}

impl ChildBootstrap {
    pub fn prepare(plan: &NetworkPlan) -> Result<Self> {
        let addr_plan = addr::AddressPlan::from_network_plan(plan);
        let tap = tap::TapHandle::preopen(addr_plan.tap_name.clone())?;

        Ok(Self { tap, addr_plan })
    }

    pub fn namespace_bootstrap(&self) -> namespace::ChildNetworkBootstrap {
        self.tap.child_bootstrap(&self.addr_plan)
    }

    pub fn addr_plan(&self) -> &addr::AddressPlan {
        &self.addr_plan
    }

    pub fn tap_name(&self) -> &str {
        self.tap.name()
    }
}

pub struct RuntimeInfo {
    pub tap_name: String,
    pub gateway_ipv4: std::net::Ipv4Addr,
    pub child_ipv4: std::net::Ipv4Addr,
    pub gateway_ipv6: std::net::Ipv6Addr,
    pub child_ipv6: std::net::Ipv6Addr,
    pub dns_local_forwarder_expected: bool,
}

pub struct NetworkContext {
    runtime: RuntimeInfo,
}

impl NetworkContext {
    pub fn capture_interface(&self) -> Option<&str> {
        None
    }

    pub fn runtime(&self) -> &RuntimeInfo {
        &self.runtime
    }
}

pub fn setup(
    _plan: &NetworkPlan,
    _run_id: &str,
    child_pid: Pid,
    _cli: &Cli,
    dns_plan: &DnsPlan,
    _tproxy_port: Option<u16>,
    child_bootstrap: &ChildBootstrap,
) -> Result<NetworkContext> {
    namespace::configure_user_namespace(child_pid).context(
        "failed to configure the child user namespace for the `rootless-internal` backend",
    )?;

    let addr_plan = child_bootstrap.addr_plan();
    Ok(NetworkContext {
        runtime: RuntimeInfo {
            tap_name: child_bootstrap.tap_name().to_string(),
            gateway_ipv4: addr_plan.gateway_ipv4,
            child_ipv4: addr_plan.child_ipv4,
            gateway_ipv6: addr_plan.gateway_ipv6,
            child_ipv6: addr_plan.child_ipv6,
            dns_local_forwarder_expected: dns_plan.expects_local_forwarder(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::NetworkPlan;

    #[test]
    fn runtime_info_tracks_addr_plan() {
        let plan = NetworkPlan::new();
        let addr_plan = addr::AddressPlan::from_network_plan(&plan);
        let runtime = RuntimeInfo {
            tap_name: "tap0".into(),
            gateway_ipv4: addr_plan.gateway_ipv4,
            child_ipv4: addr_plan.child_ipv4,
            gateway_ipv6: addr_plan.gateway_ipv6,
            child_ipv6: addr_plan.child_ipv6,
            dns_local_forwarder_expected: true,
        };

        assert_eq!(runtime.tap_name, "tap0");
        assert!(runtime.dns_local_forwarder_expected);
        assert_eq!(runtime.gateway_ipv4, plan.host_ipv4);
        assert_eq!(runtime.child_ipv6, plan.child_ipv6);
    }
}
