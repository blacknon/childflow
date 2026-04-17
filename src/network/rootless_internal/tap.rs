use std::fs::File;
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, RawFd};

use anyhow::{Context, Result};

use crate::namespace::{ChildNetworkBootstrap, RootlessChildBootstrap};

use super::addr::AddressPlan;

pub struct TapHandle {
    file: File,
    name: String,
}

impl TapHandle {
    pub fn preopen(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .context("failed to open `/dev/net/tun` for the rootless-internal tap bootstrap")?;

        Ok(Self { file, name })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn child_bootstrap(&self, addr_plan: &AddressPlan) -> ChildNetworkBootstrap {
        ChildNetworkBootstrap::RootlessInternal(RootlessChildBootstrap {
            tap_fd: self.raw_fd(),
            tap_name: self.name.clone(),
            child_ipv4: addr_plan.child_ipv4,
            gateway_ipv4: addr_plan.gateway_ipv4,
            child_ipv6: addr_plan.child_ipv6,
            gateway_ipv6: addr_plan.gateway_ipv6,
            child_ipv4_prefix_len: addr_plan.child_ipv4_prefix_len,
            child_ipv6_prefix_len: addr_plan.child_ipv6_prefix_len,
        })
    }
}
