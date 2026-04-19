// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

pub struct CgroupManager {
    path: PathBuf,
}

impl CgroupManager {
    pub fn create(run_id: &str, child_pid: Pid) -> Result<Self> {
        let parent = current_cgroup_dir()?;
        let base = parent.join("childflow");
        let path = base.join(run_id);

        fs::create_dir_all(&path)
            .with_context(|| format!("failed to create cgroup directory {}", path.display()))?;
        fs::write(
            path.join("cgroup.procs"),
            format!("{}\n", child_pid.as_raw()),
        )
        .with_context(|| format!("failed to move pid {} into cgroup", child_pid))?;

        Ok(Self { path })
    }

    fn cleanup_best_effort(&self) {
        let cgroup_kill = self.path.join("cgroup.kill");
        if cgroup_kill.exists() {
            let _ = fs::write(&cgroup_kill, "1\n");
        } else {
            let pids = self.path.join("cgroup.procs");
            if let Ok(contents) = fs::read_to_string(&pids) {
                for line in contents.lines() {
                    if let Ok(raw) = line.trim().parse::<i32>() {
                        let _ = kill(Pid::from_raw(raw), Signal::SIGTERM);
                    }
                }
                for line in contents.lines() {
                    if let Ok(raw) = line.trim().parse::<i32>() {
                        let _ = kill(Pid::from_raw(raw), Signal::SIGKILL);
                    }
                }
            }
        }

        let _ = fs::remove_dir(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        self.cleanup_best_effort();
    }
}

fn current_cgroup_dir() -> Result<PathBuf> {
    let contents =
        fs::read_to_string("/proc/self/cgroup").context("failed to read /proc/self/cgroup")?;
    let relative = contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or("/")
        .trim();

    let relative = relative.trim_start_matches('/');
    if relative.is_empty() {
        Ok(PathBuf::from("/sys/fs/cgroup"))
    } else {
        Ok(Path::new("/sys/fs/cgroup").join(relative))
    }
}