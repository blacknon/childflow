use anyhow::{Context, Result};
use nix::sys::wait::WaitStatus;

use crate::capture::CaptureHandle;
use crate::cgroup::CgroupManager;
use crate::cli::Cli;
use crate::dns::DnsPlan;
use crate::network::{self, NetworkBackend};
use crate::proxy::{ProxyPlan, TproxyHandle};
use crate::sandbox;

pub(crate) struct ParentRuntime {
    capture: Option<CaptureHandle>,
    dns: Option<crate::dns::DnsHandle>,
    network: network::NetworkContext,
    proxy: Option<TproxyHandle>,
    cgroup: Option<CgroupManager>,
}

impl ParentRuntime {
    pub(crate) fn start(
        run_id: &str,
        child: nix::unistd::Pid,
        cli: &Cli,
        network_plan: &network::NetworkPlan,
        dns_plan: &DnsPlan,
        proxy_plan: Option<&ProxyPlan>,
        child_bootstrap: &mut network::ChildBootstrap,
    ) -> Result<Self> {
        let cgroup = match cli.selected_backend() {
            NetworkBackend::Rootful => Some(
                CgroupManager::create(run_id, child)
                    .with_context(|| format!("failed to create cgroup for pid {child}"))?,
            ),
            NetworkBackend::RootlessInternal => match CgroupManager::create(run_id, child) {
                Ok(manager) => Some(manager),
                Err(err) => {
                    crate::util::debug(format!(
                        "failed to create a dedicated cgroup for the `rootless-internal` backend: {err:#}. Continuing without cgroup-based cleanup for this phase"
                    ));
                    None
                }
            },
        };

        let proxy = proxy_plan
            .and_then(ProxyPlan::transparent_rootful)
            .map(|plan| {
                plan.start().context(
                    "failed to start transparent proxy listener. Check CAP_NET_ADMIN/CAP_NET_RAW, Linux TPROXY support, and whether `IP_TRANSPARENT` is permitted on this host",
                )
            })
            .transpose()?;

        let network = network::setup(network::NetworkSetupParams {
            plan: network_plan,
            run_id,
            child_pid: child,
            cli,
            dns_plan,
            tproxy_port: proxy.as_ref().map(TproxyHandle::listen_port),
            child_bootstrap,
            proxy_plan,
        })
        .context("failed to prepare the selected network backend. Check backend preflight output, kernel namespace support, and whether the requested backend phase is implemented on this host")?;

        let sandbox_policy = sandbox::SandboxPolicy::from_cli(cli);
        let dns = match network.dns_bind_addrs() {
            Some((bind_ipv4, bind_ipv6)) => dns_plan
                .start_forwarder(bind_ipv4, bind_ipv6, sandbox_policy.offline)
                .context("failed to start DNS forwarder on port 53 inside the host namespace. Check whether another service already owns that bind address/port, and whether local firewall policy permits the listener")?,
            None => None,
        };

        let capture = match cli.output.as_ref() {
            Some(output_path) => network
                .capture_plan(output_path, cli.output_view)?
                .map(|plan| {
                    CaptureHandle::start(plan).with_context(|| {
                        "failed to start packet capture. Check CAP_NET_RAW/CAP_NET_ADMIN, AF_PACKET availability, and that the backend created the expected capture path for the selected backend".to_string()
                    })
                })
                .transpose()?,
            None => None,
        };

        Ok(Self {
            capture,
            dns,
            network,
            proxy,
            cgroup,
        })
    }

    pub(crate) fn shutdown(self) -> Result<()> {
        let Self {
            capture,
            dns,
            network,
            proxy,
            cgroup,
        } = self;
        let mut failures = Vec::new();

        if let Some(capture) = capture {
            if let Err(err) = capture.shutdown() {
                failures.push(format!("{err:#}"));
            }
        }

        if let Some(dns) = dns {
            if let Err(err) = dns.shutdown() {
                failures.push(format!("{err:#}"));
            }
        }

        if let Some(proxy) = proxy {
            if let Err(err) = proxy.shutdown() {
                failures.push(format!("{err:#}"));
            }
        }

        if let Err(err) = match network {
            network::NetworkContext::Rootful(ctx) => {
                drop(ctx);
                Ok(())
            }
            network::NetworkContext::RootlessInternal(ctx) => ctx.shutdown(),
        } {
            failures.push(format!("{err:#}"));
        }

        drop(cgroup);

        if failures.is_empty() {
            return Ok(());
        }

        anyhow::bail!(
            "one or more runtime components failed during shutdown:\n{}",
            failures
                .iter()
                .map(|failure| format!("- {failure}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    pub(crate) fn sandbox_violation_observed(&self) -> bool {
        self.network.sandbox_violation_observed()
    }
}

pub(crate) fn wait_status_to_exit_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
        _ => 1,
    }
}
