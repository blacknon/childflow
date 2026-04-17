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
mod network;
#[cfg(target_os = "linux")]
mod preflight;
#[cfg(target_os = "linux")]
mod tproxy;
#[cfg(target_os = "linux")]
mod util;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
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
use cli::Cli;
#[cfg(target_os = "linux")]
use dns::DnsPlan;
#[cfg(target_os = "linux")]
use network::NetworkBackend;
#[cfg(target_os = "linux")]
use tproxy::{TproxyHandle, TransparentProxyPlan};

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
    preflight::run(&cli)?;

    let namespace_mode = network::namespace_mode(cli.network_backend);
    let run_id = util::unique_run_id();
    let network_plan = network::NetworkPlan::new();
    let child_bootstrap = network::prepare_child_bootstrap(&cli, &network_plan)?;
    let dns_plan = DnsPlan::prepare(
        &run_id,
        cli.network_backend,
        cli.dns,
        network_plan.host_ipv4(),
        network_plan.host_ipv6(),
    )?;
    let proxy_plan = TransparentProxyPlan::from_cli(&cli);

    let (read_fd, write_fd) = pipe().context("failed to create bootstrap pipe")?;
    let (ready_read_fd, ready_write_fd) =
        pipe().context("failed to create child bootstrap ready pipe")?;
    let (tap_parent, tap_child) =
        UnixStream::pair().context("failed to create rootless tap transfer socket pair")?;

    match unsafe { fork().context("fork failed")? } {
        ForkResult::Child => {
            drop(write_fd);
            drop(ready_read_fd);
            drop(tap_parent);
            let read_file = File::from(read_fd);
            let ready_file = File::from(ready_write_fd);
            let child_network_bootstrap = child_bootstrap.namespace_bootstrap();
            if let Err(err) = namespace::child_enter_and_exec(
                namespace_mode,
                read_file,
                child_network_bootstrap.as_ref().map(|_| ready_file),
                child_network_bootstrap.as_ref().map(|_| tap_child),
                dns_plan.resolv_conf_path(),
                child_network_bootstrap.as_ref(),
                &cli.command,
            ) {
                eprintln!("childflow: child bootstrap failed: {err:#}");
                process::exit(127);
            }

            unreachable!("execvp must not return on success");
        }
        ForkResult::Parent { child } => {
            drop(read_fd);
            drop(ready_write_fd);
            drop(tap_child);
            let mut release_file = File::from(write_fd);
            let mut ready_file = File::from(ready_read_fd);
            let mut child_bootstrap = child_bootstrap;

            let runtime = match cli.network_backend {
                NetworkBackend::Rootful => {
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
                            let tap = network::rootless_internal::tap::TapHandle::receive_from_stream(
                                &tap_parent,
                                bootstrap.tap_name(),
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

            // Give the AF_PACKET capture loop a moment to drain the final frames.
            thread::sleep(Duration::from_millis(250));
            drop(runtime);

            Ok(wait_status_to_exit_code(status))
        }
    }
}

#[cfg(target_os = "linux")]
struct ParentRuntime {
    _capture: Option<CaptureHandle>,
    _dns: Option<dns::DnsHandle>,
    _network: network::NetworkContext,
    _proxy: Option<TproxyHandle>,
    _cgroup: Option<CgroupManager>,
}

#[cfg(target_os = "linux")]
impl ParentRuntime {
    fn start(
        run_id: &str,
        child: nix::unistd::Pid,
        cli: &Cli,
        network_plan: &network::NetworkPlan,
        dns_plan: &DnsPlan,
        proxy_plan: Option<&TransparentProxyPlan>,
        child_bootstrap: &mut network::ChildBootstrap,
    ) -> Result<Self> {
        let cgroup = match cli.network_backend {
            NetworkBackend::Rootful => Some(
                CgroupManager::create(run_id, child)
                    .with_context(|| format!("failed to create cgroup for pid {child}"))?,
            ),
            NetworkBackend::RootlessInternal => match CgroupManager::create(run_id, child) {
                Ok(manager) => Some(manager),
                Err(err) => {
                    crate::util::warn(format!(
                        "failed to create a dedicated cgroup for the `rootless-internal` backend: {err:#}. Continuing without cgroup-based cleanup for this phase"
                    ));
                    None
                }
            },
        };

        let proxy = proxy_plan
            .map(|plan| {
                plan.start().context(
                    "failed to start transparent proxy listener. Check CAP_NET_ADMIN/CAP_NET_RAW, Linux TPROXY support, and whether `IP_TRANSPARENT` is permitted on this host",
                )
            })
            .transpose()?;

        let network = network::setup(
            network_plan,
            run_id,
            child,
            cli,
            dns_plan,
            proxy.as_ref().map(TproxyHandle::listen_port),
            child_bootstrap,
        )
        .context("failed to prepare the selected network backend. Check backend preflight output, kernel namespace support, and whether the requested backend phase is implemented on this host")?;

        let dns = match network.dns_bind_addrs() {
            Some((bind_ipv4, bind_ipv6)) => dns_plan
                .start_forwarder(bind_ipv4, bind_ipv6)
                .context("failed to start DNS forwarder on port 53 inside the host namespace. Check whether another service already owns that bind address/port, and whether local firewall policy permits the listener")?,
            None => None,
        };

        let capture = match (network.capture_interface(), cli.output.as_ref()) {
            (Some(interface_name), Some(output_path)) => {
                Some(CaptureHandle::start(interface_name, output_path).with_context(|| {
                    format!(
                        "failed to start packet capture on {}. Check CAP_NET_RAW/CAP_NET_ADMIN, AF_PACKET availability, and that the backend created the expected host-side capture interface",
                        interface_name
                    )
                })?)
            }
            _ => None,
        };

        Ok(Self {
            _capture: capture,
            _dns: dns,
            _network: network,
            _proxy: proxy,
            _cgroup: cgroup,
        })
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
