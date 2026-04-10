#[cfg(not(target_os = "linux"))]
compile_error!("childflow is Linux-only. On macOS, use the Docker-based workflow in README.md.");

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
mod capture;
#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod cli;
#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
mod net;
#[cfg(target_os = "linux")]
mod tproxy;
#[cfg(target_os = "linux")]
mod util;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process;
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use nix::sys::wait::{waitpid, WaitStatus};
#[cfg(target_os = "linux")]
use nix::unistd::{fork, pipe, ForkResult};

#[cfg(target_os = "linux")]
use capture::CaptureHandle;
#[cfg(target_os = "linux")]
use cgroup::CgroupManager;
#[cfg(target_os = "linux")]
use cli::{Cli, ProxyScheme, ProxyType};
#[cfg(target_os = "linux")]
use dns::DnsHandle;
#[cfg(target_os = "linux")]
use net::{NetworkContext, NetworkPlan};
#[cfg(target_os = "linux")]
use tproxy::{ProxyServer, ProxyUpstreamConfig, TproxyHandle};

#[cfg(target_os = "linux")]
fn main() {
    let exit_code = match real_main() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("childflow: {err:#}");
            1
        }
    };

    process::exit(exit_code);
}

#[cfg(target_os = "linux")]
fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    cli.validate()?;
    util::ensure_root()?;

    let run_id = util::unique_run_id();
    let network_plan = NetworkPlan::new();
    let dns_config = prepare_dns_config(
        &run_id,
        cli.dns,
        network_plan.host_ipv4(),
        network_plan.host_ipv6(),
    )?;

    let (read_fd, write_fd) = pipe().context("failed to create bootstrap pipe")?;

    match unsafe { fork().context("fork failed")? } {
        ForkResult::Child => {
            drop(write_fd);
            let read_file = File::from(read_fd);
            if let Err(err) = namespace::child_enter_and_exec(
                read_file,
                dns_config.resolv_guard.as_ref().map(|g| g.path.as_path()),
                &cli.command,
            ) {
                eprintln!("childflow: child bootstrap failed: {err:#}");
                process::exit(127);
            }

            unreachable!("execvp must not return on success");
        }
        ForkResult::Parent { child } => {
            drop(read_fd);
            let mut release_file = File::from(write_fd);

            let cgroup = CgroupManager::create(&run_id, child)
                .with_context(|| format!("failed to create cgroup for pid {child}"))?;

            let proxy = if let Some(proxy_spec) = cli.proxy.clone() {
                let upstream = ProxyUpstreamConfig {
                    server: ProxyServer {
                        host: proxy_spec.host,
                        port: proxy_spec.port,
                    },
                    kind: match proxy_spec.scheme {
                        ProxyScheme::Http | ProxyScheme::Https => ProxyType::Http,
                        ProxyScheme::Socks5 => ProxyType::Socks5,
                    },
                    tls: matches!(proxy_spec.scheme, ProxyScheme::Https),
                    auth: match (cli.proxy_user.clone(), cli.proxy_password.clone()) {
                        (Some(username), Some(password)) => {
                            Some(tproxy::ProxyAuth { username, password })
                        }
                        _ => None,
                    },
                    insecure: cli.proxy_insecure,
                    bind_interface: cli.iface.clone(),
                };
                Some(TproxyHandle::start(upstream).context("failed to start transparent proxy")?)
            } else {
                None
            };

            let net = NetworkContext::setup(
                &network_plan,
                &run_id,
                child,
                &cli,
                proxy.as_ref().map(TproxyHandle::listen_port),
            )
            .context("failed to prepare namespaces / veth / routing / iptables")?;

            let dns = dns_config
                .upstream
                .map(|upstream| {
                    DnsHandle::start(network_plan.host_ipv4(), network_plan.host_ipv6(), upstream)
                })
                .transpose()
                .context("failed to start DNS forwarder")?;

            let capture =
                CaptureHandle::start(net.host_veth(), &cli.output).with_context(|| {
                    format!("failed to start packet capture on {}", net.host_veth())
                })?;

            release_file
                .write_all(&[1])
                .context("failed to release child after namespace bootstrap")?;
            drop(release_file);

            let status = waitpid(child, None).context("waitpid failed")?;

            // Give the AF_PACKET capture loop a moment to drain the final frames.
            thread::sleep(Duration::from_millis(250));

            drop(capture);
            drop(dns);
            drop(proxy);
            drop(net);
            drop(cgroup);

            Ok(wait_status_to_exit_code(status))
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_status_to_exit_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
        _ => 1,
    }
}

#[cfg(target_os = "linux")]
fn maybe_write_resolv_conf(run_id: &str, content: &str) -> Result<Option<TempFileGuard>> {
    let path = PathBuf::from(format!("/tmp/childflow-resolv-{run_id}.conf"));
    std::fs::write(&path, content).with_context(|| {
        format!(
            "failed to write temporary resolv.conf at {}",
            path.display()
        )
    })?;

    Ok(Some(TempFileGuard { path }))
}

#[cfg(target_os = "linux")]
fn prepare_dns_config(
    run_id: &str,
    dns: Option<IpAddr>,
    inherited_dns_ipv4: Ipv4Addr,
    inherited_dns_ipv6: Ipv6Addr,
) -> Result<DnsConfig> {
    if let Some(dns) = dns {
        let content = format!("nameserver {dns}\noptions timeout:1 attempts:1\n");
        return Ok(DnsConfig {
            resolv_guard: maybe_write_resolv_conf(run_id, &content)?,
            upstream: None,
        });
    }

    let host_resolv =
        std::fs::read_to_string("/etc/resolv.conf").context("failed to read /etc/resolv.conf")?;
    let inherited =
        build_inherited_dns_config(&host_resolv, inherited_dns_ipv4, inherited_dns_ipv6)?;

    Ok(DnsConfig {
        resolv_guard: maybe_write_resolv_conf(run_id, &inherited.resolv_conf)?,
        upstream: Some(inherited.upstream),
    })
}

#[cfg(target_os = "linux")]
fn build_inherited_dns_config(
    host_resolv: &str,
    inherited_dns_ipv4: Ipv4Addr,
    inherited_dns_ipv6: Ipv6Addr,
) -> Result<InheritedDnsConfig> {
    let mut output = Vec::new();
    let mut upstream = None;

    for line in host_resolv.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let addr = rest.trim();
            match addr.parse::<IpAddr>() {
                Ok(ip) => {
                    if upstream.is_none() {
                        upstream = Some(ip);
                    }
                }
                Err(_) => {}
            }
            continue;
        }

        if trimmed.starts_with("search ")
            || trimmed.starts_with("domain ")
            || trimmed.starts_with("options ")
        {
            output.push(trimmed.to_string());
        }
    }

    let upstream = upstream
        .ok_or_else(|| anyhow::anyhow!("no usable nameserver found in /etc/resolv.conf"))?;

    output.push(format!("nameserver {inherited_dns_ipv4}"));
    output.push(format!("nameserver {inherited_dns_ipv6}"));
    if !output.iter().any(|line| line.starts_with("options ")) {
        output.push("options timeout:1 attempts:1".to_string());
    }

    Ok(InheritedDnsConfig {
        upstream,
        resolv_conf: format!("{}\n", output.join("\n")),
    })
}

#[cfg(target_os = "linux")]
struct InheritedDnsConfig {
    upstream: IpAddr,
    resolv_conf: String,
}

#[cfg(target_os = "linux")]
struct DnsConfig {
    resolv_guard: Option<TempFileGuard>,
    upstream: Option<IpAddr>,
}

#[cfg(target_os = "linux")]
struct TempFileGuard {
    path: PathBuf,
}

#[cfg(target_os = "linux")]
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn build_inherited_dns_config_rewrites_nameserver_and_preserves_options() {
        let host_resolv = "\
# Generated by test
nameserver 8.8.8.8
search example.internal
options edns0 trust-ad
";

        let config = build_inherited_dns_config(
            host_resolv,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv6Addr::new(0xfd42, 0, 0, 0, 0, 0, 0, 2),
        )
        .unwrap();

        assert_eq!(config.upstream, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            config.resolv_conf,
            "search example.internal\noptions edns0 trust-ad\nnameserver 10.0.0.2\nnameserver fd42::2\n"
        );
    }

    #[test]
    fn build_inherited_dns_config_adds_default_options_when_missing() {
        let host_resolv = "\
nameserver 2001:4860:4860::8888
domain example.internal
nameserver 1.1.1.1
";

        let config = build_inherited_dns_config(
            host_resolv,
            Ipv4Addr::new(172, 16, 0, 10),
            Ipv6Addr::new(0xfd42, 0x1234, 0x5678, 0, 0, 0, 0, 10),
        )
        .unwrap();

        assert_eq!(
            config.upstream,
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap())
        );
        assert_eq!(
            config.resolv_conf,
            "domain example.internal\nnameserver 172.16.0.10\nnameserver fd42:1234:5678::a\noptions timeout:1 attempts:1\n"
        );
    }

    #[test]
    fn build_inherited_dns_config_rejects_missing_nameserver() {
        let host_resolv = "search example.internal\n";

        let err = build_inherited_dns_config(
            host_resolv,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv6Addr::new(0xfd42, 0, 0, 0, 0, 0, 0, 2),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no usable nameserver found"));
    }
}
