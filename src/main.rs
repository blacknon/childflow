// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

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
mod doctor;
#[cfg(target_os = "linux")]
mod flow_log;
#[cfg(target_os = "linux")]
mod hosts;
#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod observability;
#[cfg(target_os = "linux")]
mod preflight;
#[cfg(target_os = "linux")]
mod profile;
#[cfg(target_os = "linux")]
mod proxy;
#[cfg(target_os = "linux")]
mod report;
#[cfg(target_os = "linux")]
mod runtime_failure;
#[cfg(target_os = "linux")]
mod sandbox;
#[cfg(target_os = "linux")]
mod summary;
#[cfg(target_os = "linux")]
mod tproxy;
#[cfg(target_os = "linux")]
mod util;

#[cfg(target_os = "linux")]
use anyhow::{Context, Error, Result};
#[cfg(target_os = "linux")]
use nix::sys::wait::{waitpid, WaitStatus};
#[cfg(target_os = "linux")]
use nix::unistd::{fork, pipe, ForkResult};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::process;

#[cfg(target_os = "linux")]
use capture::CaptureHandle;
#[cfg(target_os = "linux")]
use cgroup::CgroupManager;
#[cfg(target_os = "linux")]
use cli::Cli;
#[cfg(target_os = "linux")]
use dns::DnsPlan;
#[cfg(target_os = "linux")]
use hosts::HostsPlan;
#[cfg(target_os = "linux")]
use network::NetworkBackend;
#[cfg(target_os = "linux")]
use profile::Profile;
#[cfg(target_os = "linux")]
use proxy::{ProxyPlan, TproxyHandle};

#[cfg(target_os = "linux")]
fn main() {
    let exit_code = match real_main() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("childflow: {err:#}");
            if let Some(code) = runtime_failure::classify_error(&err) {
                eprintln!("childflow: reason_code: {}", code.as_str());
            }
            1
        }
    };

    process::exit(exit_code);
}

#[cfg(target_os = "linux")]
fn real_main() -> Result<i32> {
    let cli = Cli::parse_effective()?;
    if cli.dump_profile {
        print!("{}", Profile::from_cli(&cli).render_toml()?);
        return Ok(0);
    }

    if cli.doctor {
        return doctor::run(&cli);
    }

    if cli.report.is_some() {
        return report::run(&cli);
    }

    if let Err(err) = cli.validate() {
        log_runtime_failure_event(&cli, "cli_validate", &err);
        return Err(err);
    }
    if let Err(err) = preflight::run(&cli) {
        log_runtime_failure_event(&cli, "preflight", &err);
        return Err(err);
    }
    match run_command_tree(&cli) {
        Ok(code) => Ok(code),
        Err(err) => {
            log_runtime_failure_event(&cli, "run", &err);
            Err(err)
        }
    }
}

fn run_command_tree(cli: &Cli) -> Result<i32> {
    let backend = cli.selected_backend();

    let namespace_mode = network::namespace_mode(backend);
    let run_id = util::unique_run_id();
    let network_plan = network::NetworkPlan::new();
    let child_bootstrap = network::prepare_child_bootstrap(&cli, &network_plan)?;
    let dns_plan = DnsPlan::prepare(
        &run_id,
        backend,
        cli.dns,
        network_plan.host_ipv4(),
        network_plan.host_ipv6(),
    )?;
    let hosts_plan = HostsPlan::prepare(&run_id, cli.hosts_file.as_deref())?;
    let proxy_plan = ProxyPlan::from_cli(&cli)?;
    let child_proxy_env = proxy_plan
        .as_ref()
        .map(ProxyPlan::child_env)
        .unwrap_or_default();

    let (read_fd, write_fd) = pipe().context("failed to create bootstrap pipe")?;
    let (namespace_ready_read_fd, namespace_ready_write_fd) =
        pipe().context("failed to create child namespace ready pipe")?;
    let (ready_read_fd, ready_write_fd) =
        pipe().context("failed to create child bootstrap ready pipe")?;
    let (tap_parent, tap_child) =
        UnixStream::pair().context("failed to create rootless tap transfer socket pair")?;

    match unsafe { fork().context("fork failed")? } {
        ForkResult::Child => {
            drop(write_fd);
            drop(namespace_ready_read_fd);
            drop(ready_read_fd);
            drop(tap_parent);
            let read_file = File::from(read_fd);
            let namespace_ready_file = File::from(namespace_ready_write_fd);
            let ready_file = File::from(ready_write_fd);
            let child_network_bootstrap = child_bootstrap.namespace_bootstrap();
            if let Err(err) = namespace::child_enter_and_exec(namespace::ChildExecParams {
                mode: namespace_mode,
                release_pipe: read_file,
                namespace_ready_pipe: Some(namespace_ready_file),
                ready_pipe: child_network_bootstrap.as_ref().map(|_| ready_file),
                tap_transfer: child_network_bootstrap.as_ref().map(|_| tap_child),
                resolv_conf: dns_plan.resolv_conf_path(),
                resolv_conf_required: dns_plan.resolv_conf_required(),
                hosts_file: hosts_plan.hosts_path(),
                network_bootstrap: child_network_bootstrap.as_ref(),
                extra_env: &child_proxy_env,
                command: &cli.command,
            }) {
                log_runtime_failure_event(&cli, "child_bootstrap", &err);
                eprintln!("childflow: child bootstrap failed: {err:#}");
                if let Some(code) = runtime_failure::classify_error(&err) {
                    eprintln!("childflow: child bootstrap reason_code: {}", code.as_str());
                }
                process::exit(127);
            }

            unreachable!("execvp must not return on success");
        }
        ForkResult::Parent { child } => {
            drop(read_fd);
            drop(namespace_ready_write_fd);
            drop(ready_write_fd);
            drop(tap_child);
            let mut release_file = File::from(write_fd);
            let mut namespace_ready_file = File::from(namespace_ready_read_fd);
            let mut ready_file = File::from(ready_read_fd);
            let mut child_bootstrap = child_bootstrap;

            let runtime = match backend {
                NetworkBackend::Rootful => {
                    drop(namespace_ready_file);
                    let runtime = ParentRuntime::start(
                        &run_id,
                        child,
                        &cli,
                        &network_plan,
                        &dns_plan,
                        proxy_plan.as_ref(),
                        &mut child_bootstrap,
                    )?;

                    release_file
                        .write_all(&[1])
                        .context("failed to release child after namespace bootstrap")?;
                    drop(ready_file);
                    drop(release_file);
                    runtime
                }
                NetworkBackend::RootlessInternal => {
                    let mut namespace_ready = [0_u8; 1];
                    namespace_ready_file
                        .read_exact(&mut namespace_ready)
                        .context("failed to wait for the child to finish unsharing the rootless user namespace")?;
                    drop(namespace_ready_file);

                    namespace::configure_user_namespace(child).context(
                        "failed to configure the child user namespace for the `rootless-internal` backend",
                    )?;

                    release_file
                        .write_all(&[1])
                        .context("failed to release child for rootless tap bootstrap")?;

                    let mut ready = [0_u8; 1];
                    ready_file
                        .read_exact(&mut ready)
                        .context("failed to wait for the child to finish rootless tap bootstrap")?;
                    drop(ready_file);

                    match &mut child_bootstrap {
                        network::ChildBootstrap::RootlessInternal(bootstrap) => {
                            let tap =
                                network::rootless_internal::tap::TapHandle::receive_from_stream(
                                    &tap_parent,
                                )
                            .context("failed to receive the rootless tap fd from the child")?;
                            bootstrap.set_tap(tap);
                        }
                        network::ChildBootstrap::Rootful => unreachable!(
                            "rootless-internal backend must not be paired with rootful child bootstrap"
                        ),
                    }

                    let runtime = ParentRuntime::start(
                        &run_id,
                        child,
                        &cli,
                        &network_plan,
                        &dns_plan,
                        proxy_plan.as_ref(),
                        &mut child_bootstrap,
                    )?;

                    release_file
                        .write_all(&[1])
                        .context("failed to release child after starting the rootless userspace networking engine")?;
                    drop(release_file);
                    runtime
                }
            };

            let status = waitpid(child, None).context("waitpid failed")?;
            let mut exit_code = wait_status_to_exit_code(status);
            let leak_detected = runtime.sandbox_violation_observed();

            runtime.shutdown()?;
            if cli.fail_on_leak && leak_detected && exit_code == 0 {
                util::warn(
                    "sandbox policy blocked outbound traffic; returning exit code 1 because `--fail-on-leak` is enabled",
                );
                exit_code = 1;
            }
            if cli.summary {
                summary::print_run_summary(&cli, exit_code);
            }

            Ok(exit_code)
        }
    }
}

fn log_runtime_failure_event(cli: &Cli, phase: &str, err: &Error) {
    let Some(path) = cli.flow_log.as_deref() else {
        return;
    };

    let reason_code = runtime_failure::classify_or_unknown(err);
    let detail = format!("{err:#}");
    if let Err(log_err) = flow_log::append_runtime_failure(
        path,
        flow_log::RuntimeFailureEvent {
            phase,
            reason_code: reason_code.as_str(),
            detail: &detail,
        },
    ) {
        util::debug(format!(
            "failed to append runtime failure event to {}: {log_err:#}",
            path.display()
        ));
    }
}

#[cfg(target_os = "linux")]
struct ParentRuntime {
    capture: Option<CaptureHandle>,
    dns: Option<dns::DnsHandle>,
    network: network::NetworkContext,
    proxy: Option<TproxyHandle>,
    cgroup: Option<CgroupManager>,
}

#[cfg(target_os = "linux")]
impl ParentRuntime {
    fn start(
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

    fn shutdown(self) -> Result<()> {
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

    fn sandbox_violation_observed(&self) -> bool {
        self.network.sandbox_violation_observed()
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
