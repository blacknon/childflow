use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{Context, Result};

use super::DnsPlan;

pub(super) fn maybe_write_resolv_conf(
    run_id: &str,
    content: &str,
) -> Result<Option<TempFileGuard>> {
    let path = PathBuf::from(format!("/tmp/childflow-resolv-{run_id}.conf"));
    std::fs::write(&path, content).with_context(|| {
        format!(
            "failed to write temporary resolv.conf at {}",
            path.display()
        )
    })?;

    Ok(Some(TempFileGuard { path }))
}

pub(super) fn prepare_rootful_dns_plan(
    run_id: &str,
    dns: Option<IpAddr>,
    inherited_dns_ipv4: Ipv4Addr,
    inherited_dns_ipv6: Ipv6Addr,
) -> Result<DnsPlan> {
    if let Some(dns) = dns {
        let content = format!("nameserver {dns}\noptions timeout:1 attempts:1\n");
        return Ok(DnsPlan {
            resolv_guard: maybe_write_resolv_conf(run_id, &content)?,
            rootful_upstream: None,
            rootless_upstream: None,
            resolv_conf_required: true,
        });
    }

    let host_resolv =
        std::fs::read_to_string("/etc/resolv.conf").context("failed to read /etc/resolv.conf")?;
    let inherited =
        build_inherited_dns_config(&host_resolv, inherited_dns_ipv4, inherited_dns_ipv6)?;

    Ok(DnsPlan {
        resolv_guard: maybe_write_resolv_conf(run_id, &inherited.resolv_conf)?,
        rootful_upstream: Some(inherited.upstream),
        rootless_upstream: None,
        resolv_conf_required: true,
    })
}

pub(super) fn prepare_rootless_dns_plan(
    run_id: &str,
    dns: Option<IpAddr>,
    gateway_ipv4: Ipv4Addr,
    gateway_ipv6: Ipv6Addr,
) -> Result<DnsPlan> {
    let (upstream, resolv_conf) = if let Some(dns) = dns {
        (
            dns,
            render_gateway_resolv_conf(&[], gateway_ipv4, gateway_ipv6, true),
        )
    } else {
        let host_resolv = std::fs::read_to_string("/etc/resolv.conf")
            .context("failed to read /etc/resolv.conf")?;
        let inherited = build_inherited_dns_config(&host_resolv, gateway_ipv4, gateway_ipv6)?;
        (
            inherited.upstream,
            render_gateway_resolv_conf(
                &inherited.preserved_lines,
                gateway_ipv4,
                gateway_ipv6,
                false,
            ),
        )
    };

    Ok(DnsPlan {
        resolv_guard: maybe_write_resolv_conf(run_id, &resolv_conf)?,
        rootful_upstream: None,
        rootless_upstream: Some(upstream),
        resolv_conf_required: dns.is_some(),
    })
}

pub(super) fn build_inherited_dns_config(
    host_resolv: &str,
    inherited_dns_ipv4: Ipv4Addr,
    inherited_dns_ipv6: Ipv6Addr,
) -> Result<InheritedDnsConfig> {
    let mut preserved_lines = Vec::new();
    let mut upstream = None;

    for line in host_resolv.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let addr = rest.trim();
            if let Ok(ip) = addr.parse::<IpAddr>() {
                if upstream.is_none() {
                    upstream = Some(ip);
                }
            }
            continue;
        }

        if trimmed.starts_with("search ")
            || trimmed.starts_with("domain ")
            || trimmed.starts_with("options ")
        {
            preserved_lines.push(trimmed.to_string());
        }
    }

    let upstream = upstream
        .ok_or_else(|| anyhow::anyhow!("no usable nameserver found in /etc/resolv.conf"))?;

    Ok(InheritedDnsConfig {
        upstream,
        resolv_conf: render_gateway_resolv_conf(
            &preserved_lines,
            inherited_dns_ipv4,
            inherited_dns_ipv6,
            false,
        ),
        preserved_lines,
    })
}

pub(super) fn render_gateway_resolv_conf(
    preserved_lines: &[String],
    gateway_ipv4: Ipv4Addr,
    gateway_ipv6: Ipv6Addr,
    force_default_options: bool,
) -> String {
    let mut output = preserved_lines.to_vec();
    output.push(format!("nameserver {gateway_ipv4}"));
    output.push(format!("nameserver {gateway_ipv6}"));
    if force_default_options || !output.iter().any(|line| line.starts_with("options ")) {
        output.push("options timeout:1 attempts:1".to_string());
    }
    format!("{}\n", output.join("\n"))
}

#[derive(Debug)]
pub(super) struct InheritedDnsConfig {
    pub(super) upstream: IpAddr,
    pub(super) resolv_conf: String,
    pub(super) preserved_lines: Vec<String>,
}

pub(super) struct TempFileGuard {
    pub(super) path: PathBuf,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
