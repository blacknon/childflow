use anyhow::Result;
use std::fs::File;
use std::os::unix::net::UnixStream;
use std::process;

use crate::cli::Cli;
use crate::namespace;
use crate::runtime_failure;

use super::super::log_runtime_failure_event;

#[allow(clippy::too_many_arguments)]
pub(super) fn run_child_process(
    cli: &Cli,
    namespace_mode: crate::namespace::NamespaceMode,
    child_network_bootstrap: Option<crate::namespace::ChildNetworkBootstrap>,
    resolv_conf: Option<&std::path::Path>,
    resolv_conf_required: bool,
    hosts_file: Option<&std::path::Path>,
    child_proxy_env: Vec<(String, String)>,
    read_fd: std::os::fd::OwnedFd,
    namespace_ready_write_fd: std::os::fd::OwnedFd,
    ready_write_fd: std::os::fd::OwnedFd,
    ready_read_fd: std::os::fd::OwnedFd,
    namespace_ready_read_fd: std::os::fd::OwnedFd,
    write_fd: std::os::fd::OwnedFd,
    tap_child: UnixStream,
    tap_parent: UnixStream,
) -> Result<i32> {
    drop(write_fd);
    drop(namespace_ready_read_fd);
    drop(ready_read_fd);
    drop(tap_parent);
    let read_file = File::from(read_fd);
    let namespace_ready_file = File::from(namespace_ready_write_fd);
    let ready_file = File::from(ready_write_fd);
    if let Err(err) = namespace::child_enter_and_exec(namespace::ChildExecParams {
        mode: namespace_mode,
        release_pipe: read_file,
        namespace_ready_pipe: Some(namespace_ready_file),
        ready_pipe: child_network_bootstrap.as_ref().map(|_| ready_file),
        tap_transfer: child_network_bootstrap.as_ref().map(|_| tap_child),
        resolv_conf,
        resolv_conf_required,
        hosts_file,
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
