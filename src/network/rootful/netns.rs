use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use nix::unistd::Pid;

use super::cleanup::with_netns;
use super::NetworkContext;
use crate::linux_net;
use crate::util::read_file_trimmed;

impl NetworkContext {
    pub(super) fn create_veth_pair(&mut self, child_pid: Pid) -> Result<()> {
        linux_net::veth_pair_create(&self.host_veth, &self.child_veth)
        .with_context(|| {
            format!(
                "failed to create veth pair {} <-> {}. Check that the host permits network namespace setup",
                self.host_veth, self.child_veth
            )
        })?;
        self.push_cleanup_link(self.host_veth.clone());

        linux_net::addr_add_v4(&self.host_veth, self.host_ipv4, 30)
            .with_context(|| format!("failed to assign host IPv4 address to {}", self.host_veth))?;

        linux_net::addr_add_v6(&self.host_veth, self.host_ipv6, 64)
            .with_context(|| format!("failed to assign host IPv6 address to {}", self.host_veth))?;

        linux_net::link_set_up(&self.host_veth)
            .with_context(|| format!("failed to bring {} up", self.host_veth))?;

        let host_rpf = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.host_veth);
        if Path::new(&host_rpf).exists() {
            let old = read_file_trimmed(&host_rpf)?;
            fs::write(&host_rpf, "0\n").with_context(|| {
                format!(
                    "failed to set rp_filter=0 on {} after veth creation",
                    self.host_veth
                )
            })?;
            self.push_restore_file(host_rpf, old);
        }

        linux_net::link_set_netns_pid(&self.child_veth, child_pid.as_raw())
        .with_context(|| {
            format!(
                "failed to move {} into child netns (pid {}). Check whether the child namespace still exists",
                self.child_veth, child_pid
            )
        })?;

        Ok(())
    }

    pub(super) fn configure_child_namespace(&self, child_pid: Pid) -> Result<()> {
        with_netns(child_pid, || {
            linux_net::loopback_set_up()
                .context("failed to bring loopback up inside child netns")?;

            linux_net::addr_add_v4(&self.child_veth, self.child_ipv4, 30)
                .context("failed to assign child veth IPv4 address")?;

            linux_net::addr_add_v6(&self.child_veth, self.child_ipv6, 64)
                .context("failed to assign child veth IPv6 address")?;

            linux_net::link_set_up(&self.child_veth).context("failed to bring child veth up")?;

            linux_net::default_route_add_v4(&self.child_veth, self.host_ipv4)
                .context("failed to add child IPv4 default route")?;

            linux_net::default_route_add_v6(&self.child_veth, self.host_ipv6)
                .context("failed to add child IPv6 default route")?;

            Ok(())
        })
        .context("failed to bootstrap the child network namespace")
    }
}
