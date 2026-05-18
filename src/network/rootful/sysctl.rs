use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use super::NetworkContext;
use crate::util::read_file_trimmed;

impl NetworkContext {
    pub(super) fn prepare_sysctls(&mut self) -> Result<()> {
        let ipv4_path = "/proc/sys/net/ipv4/ip_forward";
        let ipv4_old = read_file_trimmed(ipv4_path)?;
        fs::write(ipv4_path, "1\n").with_context(|| {
            format!(
                "failed to enable net.ipv4.ip_forward via {ipv4_path}. Check whether `/proc/sys` is writable on this host"
            )
        })?;
        self.push_restore_file(ipv4_path, ipv4_old);

        let ipv6_path = "/proc/sys/net/ipv6/conf/all/forwarding";
        let ipv6_old = read_file_trimmed(ipv6_path)?;
        fs::write(ipv6_path, "1\n").with_context(|| {
            format!(
                "failed to enable net.ipv6.conf.all.forwarding via {ipv6_path}. Check whether IPv6 forwarding is permitted on this host"
            )
        })?;
        self.push_restore_file(ipv6_path, ipv6_old);

        if let Some(iface) = &self.iface {
            let path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
            if Path::new(&path).exists() {
                let old = read_file_trimmed(&path)?;
                fs::write(&path, "0\n").with_context(|| {
                    format!(
                        "failed to set rp_filter=0 on {iface}. Check whether the host allows reverse-path filtering changes for that interface"
                    )
                })?;
                self.push_restore_file(path, old);
            }
        }

        Ok(())
    }
}
