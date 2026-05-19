use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use anyhow::{bail, Context, Result};

use super::{loopback_metadata_ip, privileged_ip_program};

pub(crate) struct LoopbackAliasGuard {
    _ip: Ipv4Addr,
}

impl LoopbackAliasGuard {
    pub(crate) fn add(ip: Ipv4Addr) -> Result<Self> {
        let output = privileged_ip_program()
            .args(["addr", "add", &format!("{ip}/32"), "dev", "lo"])
            .output()
            .context("failed to add loopback alias for metadata test")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") && !stderr.contains("Address already assigned") {
                bail!("failed to add loopback alias {ip}: {}", stderr.trim());
            }
            return Ok(Self { _ip: ip });
        }
        Ok(Self { _ip: ip })
    }
}

impl Drop for LoopbackAliasGuard {
    fn drop(&mut self) {}
}

pub(crate) fn discover_reachable_host_ipv4() -> Result<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .context("failed to bind UDP socket while discovering host IPv4")?;
    socket
        .connect((Ipv4Addr::new(1, 1, 1, 1), 80))
        .context("failed to connect UDP socket while discovering host IPv4")?;
    match socket
        .local_addr()
        .context("failed to query local UDP socket address")?
        .ip()
    {
        IpAddr::V4(ip) if !ip.is_loopback() => Ok(ip),
        other => bail!("expected a non-loopback IPv4 address for proxy reachability, got {other}"),
    }
}

#[allow(dead_code)]
pub(crate) fn metadata_alias_ip() -> Ipv4Addr {
    loopback_metadata_ip()
}

pub(crate) fn list_childflow_transient_links() -> Result<BTreeSet<String>> {
    let mut links = BTreeSet::new();
    for entry in std::fs::read_dir("/sys/class/net")
        .context("failed to read `/sys/class/net` while checking childflow cleanup")?
    {
        let entry = entry.context("failed to inspect an entry under `/sys/class/net`")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if is_childflow_transient_link(&name) {
            links.insert(name.into_owned());
        }
    }
    Ok(links)
}

fn is_childflow_transient_link(name: &str) -> bool {
    if name.len() != 9 {
        return false;
    }
    if !(name.starts_with("cfh") || name.starts_with("cfc")) {
        return false;
    }
    name[3..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
