use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::path::{normalize_profile_path, resolve_relative_path};
use super::Profile;

impl Profile {
    pub(super) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.capture = self
            .capture
            .take()
            .map(|path| resolve_relative_path(base_dir, path));
        self.hosts_file = self
            .hosts_file
            .take()
            .map(|path| resolve_relative_path(base_dir, path));
        self.flow_log = self
            .flow_log
            .take()
            .map(|path| resolve_relative_path(base_dir, path));
    }

    pub(super) fn merge(self, child: Self) -> Self {
        Self {
            extends: None,
            capture: child.capture.or(self.capture),
            capture_point: child.capture_point.or(self.capture_point),
            backend: child.backend.or(self.backend),
            dns: child.dns.or(self.dns),
            hosts_file: child.hosts_file.or(self.hosts_file),
            proxy: child.proxy.or(self.proxy),
            proxy_user: child.proxy_user.or(self.proxy_user),
            proxy_password: child.proxy_password.or(self.proxy_password),
            proxy_insecure: child.proxy_insecure.or(self.proxy_insecure),
            summary: child.summary.or(self.summary),
            doctor_format: child.doctor_format.or(self.doctor_format),
            report_format: child.report_format.or(self.report_format),
            summary_format: child.summary_format.or(self.summary_format),
            flow_log: child.flow_log.or(self.flow_log),
            offline: child.offline.or(self.offline),
            block_private: child.block_private.or(self.block_private),
            block_metadata: child.block_metadata.or(self.block_metadata),
            default_policy: child.default_policy.or(self.default_policy),
            allow_cidrs: child.allow_cidrs.or(self.allow_cidrs),
            deny_cidrs: child.deny_cidrs.or(self.deny_cidrs),
            allow_domains_exact: child.allow_domains_exact.or(self.allow_domains_exact),
            allow_domains: child.allow_domains.or(self.allow_domains),
            deny_domains_exact: child.deny_domains_exact.or(self.deny_domains_exact),
            deny_domains: child.deny_domains.or(self.deny_domains),
            proxy_only: child.proxy_only.or(self.proxy_only),
            fail_on_leak: child.fail_on_leak.or(self.fail_on_leak),
            iface: child.iface.or(self.iface),
            command: child.command.or(self.command),
        }
    }

    pub(super) fn load_inner(path: &Path, stack: &mut Vec<PathBuf>) -> Result<Self> {
        if stack.iter().any(|entry| entry == path) {
            let mut chain = stack
                .iter()
                .map(|entry| entry.display().to_string())
                .collect::<Vec<_>>();
            chain.push(path.display().to_string());
            bail!("profile inheritance cycle detected: {}", chain.join(" -> "));
        }

        stack.push(path.to_path_buf());

        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read profile file `{}`", path.display()))?;
        let mut profile: Self = toml::from_str(&contents)
            .with_context(|| format!("failed to parse profile file `{}`", path.display()))?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));

        let merged = if let Some(parent) = profile.extends.take() {
            let parent_path = normalize_profile_path(&resolve_relative_path(base_dir, parent))?;
            let base_profile = Self::load_inner(&parent_path, stack)?;
            profile.resolve_relative_paths(base_dir);
            base_profile.merge(profile)
        } else {
            profile.resolve_relative_paths(base_dir);
            profile
        };

        stack.pop();
        Ok(merged)
    }
}
