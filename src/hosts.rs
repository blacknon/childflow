// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub struct HostsPlan {
    hosts_guard: Option<TempFileGuard>,
}

impl HostsPlan {
    pub fn prepare(run_id: &str, hosts_file: Option<&Path>) -> Result<Self> {
        let hosts_guard = match hosts_file {
            Some(path) => Some(copy_hosts_file(run_id, path)?),
            None => None,
        };

        Ok(Self { hosts_guard })
    }

    pub fn hosts_path(&self) -> Option<&Path> {
        self.hosts_guard.as_ref().map(|guard| guard.path.as_path())
    }
}

fn copy_hosts_file(run_id: &str, hosts_file: &Path) -> Result<TempFileGuard> {
    let source = hosts_file.canonicalize().with_context(|| {
        format!(
            "failed to resolve hosts override file {}",
            hosts_file.display()
        )
    })?;
    let override_content = std::fs::read_to_string(&source)
        .with_context(|| format!("failed to read hosts override file {}", source.display()))?;
    let base_content = std::fs::read_to_string("/etc/hosts")
        .context("failed to read /etc/hosts while preparing the child hosts override")?;
    let content = merge_hosts_content(&base_content, &override_content);
    let path = PathBuf::from(format!("/tmp/childflow-hosts-{run_id}.hosts"));
    std::fs::write(&path, content).with_context(|| {
        format!(
            "failed to write temporary hosts override at {}",
            path.display()
        )
    })?;
    Ok(TempFileGuard { path })
}

struct TempFileGuard {
    path: PathBuf,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn merge_hosts_content(base_content: &str, override_content: &str) -> String {
    let overridden_hostnames = collect_hostnames(override_content);
    let mut merged = String::new();

    merged.push_str(override_content);
    if !override_content.ends_with('\n') {
        merged.push('\n');
    }

    for line in base_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            merged.push_str(line);
            merged.push('\n');
            continue;
        }

        let line_hostnames = extract_hostnames(line);
        if line_hostnames
            .iter()
            .any(|hostname| overridden_hostnames.contains(hostname))
        {
            continue;
        }

        merged.push_str(line);
        merged.push('\n');
    }

    merged
}

fn collect_hostnames(content: &str) -> std::collections::HashSet<String> {
    content
        .lines()
        .flat_map(extract_hostnames)
        .collect::<std::collections::HashSet<_>>()
}

fn extract_hostnames(line: &str) -> Vec<String> {
    let without_comment = line.split('#').next().unwrap_or("").trim();
    if without_comment.is_empty() {
        return Vec::new();
    }

    let mut fields = without_comment.split_whitespace();
    let _addr = fields.next();
    fields.map(|field| field.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_hosts_plan_merges_the_requested_hosts_file() {
        let input_path = std::env::temp_dir().join(format!(
            "childflow-hosts-input-{}.hosts",
            std::process::id()
        ));
        std::fs::write(&input_path, "10.0.0.7 demo.internal demo\n").unwrap();

        let run_id = format!("unit-test-{}", std::process::id());
        let plan = HostsPlan::prepare(&run_id, Some(&input_path)).unwrap();
        let path = plan.hosts_path().unwrap();
        let content = std::fs::read_to_string(path).unwrap();

        assert!(content.starts_with("10.0.0.7 demo.internal demo\n"));
        assert!(content.contains("127.0.0.1"));
        assert!(!content.contains("demo.internal localhost"));

        drop(plan);
        let _ = std::fs::remove_file(input_path);
    }

    #[test]
    fn merge_hosts_content_prefers_override_entries_and_keeps_unrelated_base_lines() {
        let base = "\
127.0.0.1 localhost
10.0.0.2 demo.internal old-demo
10.0.0.3 untouched.internal
";
        let override_content = "\
10.0.0.7 demo.internal new-demo
";

        let merged = merge_hosts_content(base, override_content);

        assert!(merged.starts_with("10.0.0.7 demo.internal new-demo\n"));
        assert!(merged.contains("127.0.0.1 localhost\n"));
        assert!(merged.contains("10.0.0.3 untouched.internal\n"));
        assert!(!merged.contains("10.0.0.2 demo.internal old-demo\n"));
    }
}