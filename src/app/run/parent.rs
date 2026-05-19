use anyhow::Result;
use nix::sys::wait::waitpid;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use crate::cli::Cli;
use crate::dns::DnsPlan;
use crate::network::{self, NetworkBackend};
use crate::parent_runtime::{wait_status_to_exit_code, ParentRuntime};
use crate::proxy::ProxyPlan;
use crate::summary;
use crate::util;

#[allow(clippy::too_many_arguments)]
pub(super) fn run_parent_process(
    cli: &Cli,
    run_id: &str,
    backend: NetworkBackend,
    child: nix::unistd::Pid,
    network_plan: crate::network::NetworkPlan,
    dns_plan: DnsPlan,
    proxy_plan: Option<ProxyPlan>,
    child_bootstrap: network::ChildBootstrap,
    read_fd: std::os::fd::OwnedFd,
    write_fd: std::os::fd::OwnedFd,
    namespace_ready_read_fd: std::os::fd::OwnedFd,
    namespace_ready_write_fd: std::os::fd::OwnedFd,
    ready_read_fd: std::os::fd::OwnedFd,
    ready_write_fd: std::os::fd::OwnedFd,
    tap_parent: UnixStream,
    tap_child: UnixStream,
) -> Result<i32> {
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
                run_id,
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

            crate::namespace::configure_user_namespace(child)?;

            release_file.write_all(&[1])?;

            let mut ready = [0_u8; 1];
            ready_file.read_exact(&mut ready)?;
            drop(ready_file);

            match &mut child_bootstrap {
                network::ChildBootstrap::RootlessInternal(bootstrap) => {
                    let tap = network::rootless_internal::tap::TapHandle::receive_from_stream(
                        &tap_parent,
                    )?;
                    bootstrap.set_tap(tap);
                }
                network::ChildBootstrap::Rootful => unreachable!(),
            }

            let runtime = ParentRuntime::start(
                run_id,
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
