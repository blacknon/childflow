pub mod addr;
pub mod engine;
pub mod packet;
pub mod route;
pub mod state;
pub mod tap;

use anyhow::{Context, Result};
use nix::unistd::Pid;

use crate::cli::Cli;
use crate::dns::DnsPlan;
use crate::namespace;

use super::types::NetworkPlan;

pub struct ChildBootstrap {
    tap: Option<tap::TapHandle>,
    addr_plan: addr::AddressPlan,
}

impl ChildBootstrap {
    pub fn prepare(plan: &NetworkPlan) -> Result<Self> {
        let addr_plan = addr::AddressPlan::from_network_plan(plan);
        Ok(Self {
            tap: None,
            addr_plan,
        })
    }

    pub fn namespace_bootstrap(&self) -> namespace::ChildNetworkBootstrap {
        namespace::ChildNetworkBootstrap::RootlessInternal(namespace::RootlessChildBootstrap {
            tap_name: self.addr_plan.tap_name.clone(),
            gateway_mac: self.addr_plan.gateway_mac,
            child_ipv4: self.addr_plan.child_ipv4,
            gateway_ipv4: self.addr_plan.gateway_ipv4,
            child_ipv6: self.addr_plan.child_ipv6,
            gateway_ipv6: self.addr_plan.gateway_ipv6,
            child_ipv4_prefix_len: self.addr_plan.child_ipv4_prefix_len,
            child_ipv6_prefix_len: self.addr_plan.child_ipv6_prefix_len,
        })
    }

    pub fn addr_plan(&self) -> &addr::AddressPlan {
        &self.addr_plan
    }

    pub fn tap_name(&self) -> &str {
        &self.addr_plan.tap_name
    }

    pub fn set_tap(&mut self, tap: tap::TapHandle) {
        self.tap = Some(tap);
    }

    pub fn take_tap(&mut self) -> tap::TapHandle {
        self.tap
            .take()
            .expect("rootless tap handle must be populated before engine startup")
    }
}

pub struct RuntimeInfo {
    pub tap_name: String,
    pub gateway_mac: [u8; 6],
    pub gateway_ipv4: std::net::Ipv4Addr,
    pub child_ipv4: std::net::Ipv4Addr,
    pub gateway_ipv6: std::net::Ipv6Addr,
    pub child_ipv6: std::net::Ipv6Addr,
    pub dns_upstream: Option<std::net::IpAddr>,
}

pub struct NetworkContext {
    runtime: RuntimeInfo,
    _engine: engine::EngineHandle,
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
    _child_pid: Pid,
    _cli: &Cli,
    dns_plan: &DnsPlan,
    _tproxy_port: Option<u16>,
    child_bootstrap: &mut ChildBootstrap,
) -> Result<NetworkContext> {
    let addr_plan = child_bootstrap.addr_plan().clone();
    let tap_name = child_bootstrap.tap_name().to_string();
    let dns_upstream = dns_plan.rootless_upstream();
    let engine = engine::EngineHandle::start(
        child_bootstrap.take_tap(),
        addr_plan.clone(),
        engine::EngineConfig {
            dns_upstream,
            allow_ipv6_outbound: engine::detect_ipv6_outbound(),
        },
    )
    .context("failed to start the rootless-internal userspace networking engine")?;

    Ok(NetworkContext {
        runtime: RuntimeInfo {
            tap_name,
            gateway_mac: addr_plan.gateway_mac,
            gateway_ipv4: addr_plan.gateway_ipv4,
            child_ipv4: addr_plan.child_ipv4,
            gateway_ipv6: addr_plan.gateway_ipv6,
            child_ipv6: addr_plan.child_ipv6,
            dns_upstream,
        },
        _engine: engine,
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
            gateway_mac: addr_plan.gateway_mac,
            gateway_ipv4: addr_plan.gateway_ipv4,
            child_ipv4: addr_plan.child_ipv4,
            gateway_ipv6: addr_plan.gateway_ipv6,
            child_ipv6: addr_plan.child_ipv6,
            dns_upstream: Some("1.1.1.1".parse().unwrap()),
        };

        assert_eq!(runtime.tap_name, "tap0");
        assert_eq!(runtime.gateway_mac, addr_plan.gateway_mac);
        assert_eq!(runtime.dns_upstream, Some("1.1.1.1".parse().unwrap()));
        assert_eq!(runtime.gateway_ipv4, plan.host_ipv4);
        assert_eq!(runtime.child_ipv6, plan.child_ipv6);
    }
}
