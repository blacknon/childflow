use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use nix::unistd::Pid;

use super::cleanup::with_netns;
use super::NetworkContext;
use crate::util::{read_file_trimmed, run_command};

impl NetworkContext {
    pub(super) fn create_veth_pair(&mut self, child_pid: Pid) -> Result<()> {
        run_command(
            "ip",
            vec![
                "link".into(),
                "add".into(),
                self.host_veth.clone(),
                "type".into(),
                "veth".into(),
                "peer".into(),
                "name".into(),
                self.child_veth.clone(),
            ],
        )
        .with_context(|| {
            format!(
                "failed to create veth pair {} <-> {}. Check that `ip` is available and the host permits network namespace setup",
                self.host_veth, self.child_veth
            )
        })?;
        self.push_cleanup_command(
            "delete host veth pair",
            "ip",
            vec!["link".into(), "del".into(), self.host_veth.clone()],
        );

        run_command(
            "ip",
            vec![
                "addr".into(),
                "add".into(),
                format!("{}/30", self.host_ipv4),
                "dev".into(),
                self.host_veth.clone(),
            ],
        )
        .with_context(|| format!("failed to assign host IPv4 address to {}", self.host_veth))?;

        run_command(
            "ip",
            vec![
                "-6".into(),
                "addr".into(),
                "add".into(),
                format!("{}/64", self.host_ipv6),
                "dev".into(),
                self.host_veth.clone(),
                "nodad".into(),
            ],
        )
        .with_context(|| format!("failed to assign host IPv6 address to {}", self.host_veth))?;

        run_command(
            "ip",
            vec![
                "link".into(),
                "set".into(),
                self.host_veth.clone(),
                "up".into(),
            ],
        )
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

        run_command(
            "ip",
            vec![
                "link".into(),
                "set".into(),
                self.child_veth.clone(),
                "netns".into(),
                child_pid.as_raw().to_string(),
            ],
        )
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
            run_command(
                "ip",
                vec!["link".into(), "set".into(), "lo".into(), "up".into()],
            )
            .context("failed to bring loopback up inside child netns")?;

            run_command(
                "ip",
                vec![
                    "addr".into(),
                    "add".into(),
                    format!("{}/30", self.child_ipv4),
                    "dev".into(),
                    self.child_veth.clone(),
                ],
            )
            .context("failed to assign child veth IPv4 address")?;

            run_command(
                "ip",
                vec![
                    "-6".into(),
                    "addr".into(),
                    "add".into(),
                    format!("{}/64", self.child_ipv6),
                    "dev".into(),
                    self.child_veth.clone(),
                    "nodad".into(),
                ],
            )
            .context("failed to assign child veth IPv6 address")?;

            run_command(
                "ip",
                vec![
                    "link".into(),
                    "set".into(),
                    self.child_veth.clone(),
                    "up".into(),
                ],
            )
            .context("failed to bring child veth up")?;

            run_command(
                "ip",
                vec![
                    "route".into(),
                    "add".into(),
                    "default".into(),
                    "via".into(),
                    self.host_ipv4.to_string(),
                    "dev".into(),
                    self.child_veth.clone(),
                ],
            )
            .context("failed to add child IPv4 default route")?;

            run_command(
                "ip",
                vec![
                    "-6".into(),
                    "route".into(),
                    "add".into(),
                    "default".into(),
                    "via".into(),
                    self.host_ipv6.to_string(),
                    "dev".into(),
                    self.child_veth.clone(),
                ],
            )
            .context("failed to add child IPv6 default route")?;

            Ok(())
        })
        .context("failed to bootstrap the child network namespace")
    }
}
