// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::cli::{Cli, DefaultPolicy, OutputView, ProxySpec};
use crate::network::NetworkBackend;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_point: Option<OutputView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<NetworkBackend>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts_file: Option<PathBuf>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_proxy_spec",
        serialize_with = "serialize_optional_proxy_spec",
        skip_serializing_if = "Option::is_none"
    )]
    pub proxy: Option<ProxySpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_insecure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_log: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_private: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_metadata: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_policy: Option<DefaultPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_cidrs: Option<Vec<IpNetwork>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_cidrs: Option<Vec<IpNetwork>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_on_leak: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

impl Profile {
    pub fn load(path: &Path) -> Result<Self> {
        let resolved = normalize_profile_path(path)?;
        Self::load_inner(&resolved, &mut Vec::new())
    }

    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            extends: None,
            capture: cli.output.clone(),
            capture_point: Some(cli.output_view),
            backend: Some(cli.selected_backend()),
            dns: cli.dns,
            hosts_file: cli.hosts_file.clone(),
            proxy: cli.proxy.clone(),
            proxy_user: cli.proxy_user.clone(),
            proxy_password: cli.proxy_password.clone(),
            proxy_insecure: cli.proxy_insecure.then_some(true),
            summary: cli.summary.then_some(true),
            flow_log: cli.flow_log.clone(),
            offline: cli.offline.then_some(true),
            block_private: cli.block_private.then_some(true),
            block_metadata: cli.block_metadata.then_some(true),
            default_policy: Some(cli.default_policy),
            allow_cidrs: (!cli.allow_cidrs.is_empty()).then_some(cli.allow_cidrs.clone()),
            deny_cidrs: (!cli.deny_cidrs.is_empty()).then_some(cli.deny_cidrs.clone()),
            proxy_only: cli.proxy_only.then_some(true),
            fail_on_leak: cli.fail_on_leak.then_some(true),
            iface: cli.iface.clone(),
            command: (!cli.command.is_empty()).then_some(cli.command.clone()),
        }
    }

    pub fn render_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("failed to render effective profile as TOML")
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
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

    fn merge(self, child: Self) -> Self {
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
            flow_log: child.flow_log.or(self.flow_log),
            offline: child.offline.or(self.offline),
            block_private: child.block_private.or(self.block_private),
            block_metadata: child.block_metadata.or(self.block_metadata),
            default_policy: child.default_policy.or(self.default_policy),
            allow_cidrs: child.allow_cidrs.or(self.allow_cidrs),
            deny_cidrs: child.deny_cidrs.or(self.deny_cidrs),
            proxy_only: child.proxy_only.or(self.proxy_only),
            fail_on_leak: child.fail_on_leak.or(self.fail_on_leak),
            iface: child.iface.or(self.iface),
            command: child.command.or(self.command),
        }
    }

    fn load_inner(path: &Path, stack: &mut Vec<PathBuf>) -> Result<Self> {
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

fn resolve_relative_path(base_dir: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn normalize_profile_path(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("failed to resolve profile path `{}`", path.display()))
}

fn deserialize_optional_proxy_spec<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<ProxySpec>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|raw| raw.parse::<ProxySpec>().map_err(serde::de::Error::custom))
        .transpose()
}

fn serialize_optional_proxy_spec<S>(
    value: &Option<ProxySpec>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(spec) => serializer.serialize_some(&spec.to_string()),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_profile_resolves_relative_paths_from_profile_directory() {
        let base_dir = std::env::temp_dir().join("childflow-profile-tests");
        let profile_dir = base_dir.join("nested");
        std::fs::create_dir_all(&profile_dir).unwrap();
        let profile_path = profile_dir.join("sandbox.toml");

        std::fs::write(
            &profile_path,
            r#"
capture = "captures/run.pcapng"
hosts_file = "fixtures/hosts.override"
flow_log = "logs/flow.jsonl"
"#,
        )
        .unwrap();

        let profile = Profile::load(&profile_path).unwrap();

        assert_eq!(
            profile.capture,
            Some(profile_dir.join("captures").join("run.pcapng"))
        );
        assert_eq!(
            profile.hosts_file,
            Some(profile_dir.join("fixtures").join("hosts.override"))
        );
        assert_eq!(
            profile.flow_log,
            Some(profile_dir.join("logs").join("flow.jsonl"))
        );

        let _ = std::fs::remove_file(&profile_path);
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn load_profile_rejects_unknown_keys() {
        let base_dir = std::env::temp_dir().join("childflow-profile-tests-unknown");
        std::fs::create_dir_all(&base_dir).unwrap();
        let profile_path = base_dir.join("sandbox.toml");

        std::fs::write(&profile_path, "unexpected = true\n").unwrap();

        let err = Profile::load(&profile_path).unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("unexpected"));
        assert!(rendered.contains("unknown field"));

        let _ = std::fs::remove_file(&profile_path);
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn load_profile_supports_extends_with_child_override() {
        let base_dir = std::env::temp_dir().join("childflow-profile-tests-extends");
        let child_dir = base_dir.join("child");
        std::fs::create_dir_all(&child_dir).unwrap();
        let base_profile_path = base_dir.join("base.toml");
        let child_profile_path = child_dir.join("sandbox.toml");

        std::fs::write(
            &base_profile_path,
            r#"
summary = true
default_policy = "deny"
allow_cidrs = ["203.0.113.10/32"]
command = ["curl", "https://example.com"]
"#,
        )
        .unwrap();
        std::fs::write(
            &child_profile_path,
            r#"
extends = "../base.toml"
deny_cidrs = ["198.51.100.0/24"]
command = ["ping", "-c", "1", "1.1.1.1"]
"#,
        )
        .unwrap();

        let profile = Profile::load(&child_profile_path).unwrap();

        assert_eq!(profile.extends, None);
        assert_eq!(profile.summary, Some(true));
        assert_eq!(profile.default_policy, Some(DefaultPolicy::Deny));
        assert_eq!(
            profile.allow_cidrs,
            Some(vec!["203.0.113.10/32".parse().unwrap()])
        );
        assert_eq!(
            profile.deny_cidrs,
            Some(vec!["198.51.100.0/24".parse().unwrap()])
        );
        assert_eq!(
            profile.command,
            Some(vec![
                "ping".into(),
                "-c".into(),
                "1".into(),
                "1.1.1.1".into()
            ])
        );

        let _ = std::fs::remove_file(&base_profile_path);
        let _ = std::fs::remove_file(&child_profile_path);
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn load_profile_rejects_extends_cycle() {
        let base_dir = std::env::temp_dir().join("childflow-profile-tests-cycle");
        std::fs::create_dir_all(&base_dir).unwrap();
        let a_profile_path = base_dir.join("a.toml");
        let b_profile_path = base_dir.join("b.toml");

        std::fs::write(&a_profile_path, "extends = \"./b.toml\"\nsummary = true\n").unwrap();
        std::fs::write(&b_profile_path, "extends = \"./a.toml\"\nsummary = true\n").unwrap();

        let err = Profile::load(&a_profile_path).unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("profile inheritance cycle detected"));

        let _ = std::fs::remove_file(&a_profile_path);
        let _ = std::fs::remove_file(&b_profile_path);
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn render_profile_as_toml_uses_stable_proxy_and_backend_values() {
        let cli = Cli {
            dump_profile: false,
            output: Some(PathBuf::from("/tmp/run.pcapng")),
            output_view: OutputView::Both,
            root: false,
            doctor: false,
            network_backend: NetworkBackend::RootlessInternal,
            dns: Some("1.1.1.1".parse().unwrap()),
            hosts_file: Some(PathBuf::from("/tmp/hosts.override")),
            proxy: Some("https://proxy.example.com:443".parse().unwrap()),
            proxy_user: Some("alice".into()),
            proxy_password: Some("secret".into()),
            proxy_insecure: true,
            summary: true,
            flow_log: Some(PathBuf::from("/tmp/flow.jsonl")),
            offline: false,
            block_private: true,
            block_metadata: true,
            default_policy: DefaultPolicy::Deny,
            allow_cidrs: vec!["203.0.113.10/32".parse().unwrap()],
            deny_cidrs: vec!["198.51.100.0/24".parse().unwrap()],
            proxy_only: true,
            fail_on_leak: true,
            iface: None,
            command: vec!["curl".into(), "https://example.com".into()],
        };

        let rendered = Profile::from_cli(&cli).render_toml().unwrap();

        assert!(rendered.contains("capture_point = \"both\""));
        assert!(rendered.contains("backend = \"rootless-internal\""));
        assert!(rendered.contains("proxy = \"https://proxy.example.com:443\""));
        assert!(rendered.contains("default_policy = \"deny\""));
        assert!(rendered.contains("command = ["));
        assert!(rendered.contains("\"curl\""));
        assert!(rendered.contains("\"https://example.com\""));
    }
}
