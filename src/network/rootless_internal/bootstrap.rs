// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use anyhow::Result;

use super::{addr, tap};
use crate::namespace;
use crate::network::types::NetworkPlan;

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

    pub fn set_tap(&mut self, tap: tap::TapHandle) {
        self.tap = Some(tap);
    }

    pub fn take_tap(&mut self) -> tap::TapHandle {
        self.tap
            .take()
            .expect("rootless tap handle must be populated before engine startup")
    }
}
