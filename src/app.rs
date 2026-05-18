use anyhow::{Error, Result};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, pipe, ForkResult};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process;

use crate::cli::Cli;
use crate::dns::DnsPlan;
use crate::flow_log;
use crate::hosts::HostsPlan;
use crate::namespace;
use crate::network::{self, NetworkBackend};
use crate::parent_runtime::{wait_status_to_exit_code, ParentRuntime};
use crate::profile::Profile;
use crate::proxy::ProxyPlan;
use crate::runtime_failure;
use crate::summary;
use crate::util;

pub(crate) fn real_main() -> Result<i32> {
    let cli = Cli::parse_effective()?;
    if cli.dump_profile {
        print!("{}", Profile::from_cli(&cli).render_toml()?);
        return Ok(0);
    }

    if cli.doctor {
        return crate::doctor::run(&cli);
    }

    if cli.report.is_some() {
        return crate::report::run(&cli);
    }

    if let Err(err) = cli.validate() {
        log_runtime_failure_event(&cli, "cli_validate", &err);
        return Err(err);
    }
    if let Err(err) = crate::preflight::run(&cli) {
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
    let child_bootstrap = network::prepare_child_bootstrap(cli, &network_plan)?;
    let dns_plan = DnsPlan::prepare(
        &run_id,
        backend,
        cli.dns,
        network_plan.host_ipv4(),
        network_plan.host_ipv6(),
    )?;
    let hosts_plan = HostsPlan::prepare(&run_id, cli.hosts_file.as_deref())?;
    let proxy_plan = ProxyPlan::from_cli(cli)?;
    let child_proxy_env = proxy_plan
        .as_ref()
        .map(ProxyPlan::child_env)
        .unwrap_or_default();

    let (read_fd, write_fd) = pipe()?;
    let (namespace_ready_read_fd, namespace_ready_write_fd) = pipe()?;
    let (ready_read_fd, ready_write_fd) = pipe()?;
    let (tap_parent, tap_child) = UnixStream::pair()?;

    match unsafe { fork()? } {
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
                log_runtime_failure_event(cli, "child_bootstrap", &err);
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
                        cli,
                        &network_plan,
                        &dns_plan,
                        proxy_plan.as_ref(),
                        &mut child_bootstrap,
                    )?;

                    release_file.write_all(&[1])?;
                    drop(ready_file);
                    drop(release_file);
                    runtime
                }
                NetworkBackend::RootlessInternal => {
                    let mut namespace_ready = [0_u8; 1];
                    namespace_ready_file.read_exact(&mut namespace_ready)?;
                    drop(namespace_ready_file);

                    namespace::configure_user_namespace(child)?;

                    release_file.write_all(&[1])?;

                    let mut ready = [0_u8; 1];
                    ready_file.read_exact(&mut ready)?;
                    drop(ready_file);

                    match &mut child_bootstrap {
                        network::ChildBootstrap::RootlessInternal(bootstrap) => {
                            let tap =
                                network::rootless_internal::tap::TapHandle::receive_from_stream(
                                    &tap_parent,
                                )?;
                            bootstrap.set_tap(tap);
                        }
                        network::ChildBootstrap::Rootful => unreachable!(),
                    }

                    let runtime = ParentRuntime::start(
                        &run_id,
                        child,
                        cli,
                        &network_plan,
                        &dns_plan,
                        proxy_plan.as_ref(),
                        &mut child_bootstrap,
                    )?;

                    release_file.write_all(&[1])?;
                    drop(release_file);
                    runtime
                }
            };

            let status = waitpid(child, None)?;
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
                summary::print_run_summary(cli, exit_code);
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
