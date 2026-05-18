// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::env;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::path::Path;

use anyhow::{bail, Result};

pub(super) fn check_tun_device(path: &str) -> Result<()> {
    let device = Path::new(path);
    if !device.exists() {
        bail!("`{path}` is missing");
    }

    OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .map(|_| ())
        .map_err(|err| anyhow::anyhow!("failed to open `{path}` ({err})"))
}

pub(super) fn find_unwritable_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| {
            OpenOptions::new()
                .write(true)
                .open(path)
                .err()
                .map(|err| format!("{path} ({err})"))
        })
        .collect()
}

pub(super) fn find_missing_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter(|path| !Path::new(path).exists())
        .map(|path| path.to_string())
        .collect()
}

pub fn parse_proc_u64(path: &str) -> Result<Option<u64>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents.trim().parse::<u64>()?)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn find_missing_commands(commands: &[&str], path_env: &OsStr) -> Vec<String> {
    let path_dirs = env::split_paths(path_env).collect::<Vec<_>>();
    commands
        .iter()
        .filter(|command| {
            !path_dirs
                .iter()
                .any(|dir| command_exists_in_dir(dir, command))
        })
        .map(|command| command.to_string())
        .collect()
}

fn command_exists_in_dir(dir: &Path, command: &str) -> bool {
    dir.join(command).exists()
}

pub(super) fn current_euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and does not dereference user pointers.
    unsafe { nix::libc::geteuid() }
}
