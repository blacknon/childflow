// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

#[cfg(not(target_os = "linux"))]
compile_error!("childflow is Linux-only. On macOS, use the Docker-based workflow in README.md.");

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
mod app;
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
mod domain;
#[cfg(target_os = "linux")]
mod flow_log;
#[cfg(target_os = "linux")]
mod hosts;
#[cfg(target_os = "linux")]
mod linux_net;
#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod observability;
#[cfg(target_os = "linux")]
mod parent_runtime;
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
use std::process;

#[cfg(target_os = "linux")]
fn main() {
    let exit_code = match app::real_main() {
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
