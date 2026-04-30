// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};

use crate::network::NetworkBackend;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "childflow",
    version,
    about = "Launch a child process tree inside its own netns and capture only its packets",
    trailing_var_arg = true
)]
pub struct Cli {
    /// Write only the target command tree's traffic as pcapng.
    #[arg(short = 'c', long = "capture")]
    pub output: Option<PathBuf>,

    /// Select which capture point or view `--capture` should write. `child` is the current stable view.
    #[arg(short = 'C', long = "capture-point", value_enum, default_value_t = OutputView::Child)]
    pub output_view: OutputView,

    /// Use the rootful backend. Without this flag, childflow uses the default rootless backend.
    #[arg(long = "root")]
    pub root: bool,

    /// Diagnose whether the current host is ready for the selected backend.
    #[arg(long = "doctor")]
    pub doctor: bool,

    /// Select the networking backend. This is kept as a hidden compatibility escape hatch; use `--root` for the public CLI.
    #[arg(
        long = "network-backend",
        value_enum,
        default_value_t = NetworkBackend::RootlessInternal,
        hide = true
    )]
    pub network_backend: NetworkBackend,

    /// Force DNS traffic for the child tree to this IPv4 or IPv6 resolver.
    #[arg(short = 'd', long = "dns")]
    pub dns: Option<IpAddr>,

    /// Bind-mount an `/etc/hosts`-format file over the child's `/etc/hosts` so those entries are consulted first during name resolution.
    #[arg(long = "hosts-file")]
    pub hosts_file: Option<PathBuf>,

    /// Configure an upstream proxy URI, for example http://127.0.0.1:8080, https://proxy.example.com:443, or socks5://host.docker.internal:10080. `--root` uses transparent interception, while the default rootless backend relays outbound TCP through the selected proxy from the parent-side engine.
    #[arg(short = 'p', long = "proxy")]
    pub proxy: Option<ProxySpec>,

    /// Username for upstream proxy authentication.
    #[arg(short = 'U', long = "proxy-user")]
    pub proxy_user: Option<String>,

    /// Password for upstream proxy authentication.
    #[arg(short = 'P', long = "proxy-password")]
    pub proxy_password: Option<String>,

    /// Ignore certificate trust errors for https:// upstream proxies while still validating the hostname.
    #[arg(long = "proxy-insecure")]
    pub proxy_insecure: bool,

    /// Force the host-side egress interface for the child's direct traffic.
    #[arg(short = 'i', long = "iface")]
    pub iface: Option<String>,

    /// Command to execute.
    #[arg(required_unless_present = "doctor")]
    pub command: Vec<String>,
}

impl Cli {
    pub fn selected_backend(&self) -> NetworkBackend {
        if self.root {
            NetworkBackend::Rootful
        } else {
            self.network_backend
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.doctor {
            return Ok(());
        }

        if self.command.is_empty() {
            bail!("missing command to execute");
        }

        if matches!(self.selected_backend(), NetworkBackend::RootlessInternal)
            && self.iface.is_some()
        {
            bail!("`--iface` is not supported by the `rootless-internal` backend");
        }

        if let Some(path) = &self.hosts_file {
            if !path.exists() {
                bail!("`--hosts-file` path does not exist: {}", path.display());
            }
        }

        if self.output_view != OutputView::Child && self.output.is_none() {
            bail!("`--capture-point` requires `--capture`");
        }

        if self.proxy_user.is_some() != self.proxy_password.is_some() {
            bail!("`--proxy-user` and `--proxy-password` must be provided together");
        }

        if (self.proxy_user.is_some() || self.proxy_insecure) && self.proxy.is_none() {
            bail!("proxy authentication and TLS options require `--proxy`");
        }

        if self.proxy_insecure
            && !matches!(
                self.proxy.as_ref().map(|proxy| proxy.scheme),
                Some(ProxyScheme::Https)
            )
        {
            bail!("`--proxy-insecure` is only valid with an `https://` upstream proxy");
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxySpec {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
}

impl FromStr for ProxySpec {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (scheme, rest) = value.split_once("://").ok_or_else(|| {
            "proxy must be a URI like http://host:port or socks5://host:port".to_string()
        })?;

        if rest.is_empty() {
            return Err("proxy URI is missing host:port".to_string());
        }

        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err("proxy URI must not contain a path, query, or fragment".to_string());
        }

        let scheme = match scheme {
            "http" => ProxyScheme::Http,
            "https" => ProxyScheme::Https,
            "socks5" => ProxyScheme::Socks5,
            other => {
                return Err(format!(
                    "unsupported proxy scheme `{other}`; expected `http`, `https`, or `socks5`"
                ))
            }
        };

        let (host, port) = parse_host_port(rest)?;

        Ok(Self { scheme, host, port })
    }
}

fn parse_host_port(input: &str) -> std::result::Result<(String, u16), String> {
    if let Some(rest) = input.strip_prefix('[') {
        let (host, remainder) = rest
            .split_once(']')
            .ok_or_else(|| "invalid proxy URI host".to_string())?;
        let port = remainder
            .strip_prefix(':')
            .ok_or_else(|| "proxy URI must include a port".to_string())?
            .parse::<u16>()
            .map_err(|_| "proxy URI has an invalid port".to_string())?;
        return Ok((host.to_string(), port));
    }

    if input.matches(':').count() > 1 {
        return Err("IPv6 proxy hosts must be enclosed in `[` and `]`".to_string());
    }

    let (host, port) = input
        .rsplit_once(':')
        .ok_or_else(|| "proxy URI must include a port".to_string())?;

    if host.is_empty() {
        return Err("proxy URI is missing a host".to_string());
    }

    let port = port
        .parse::<u16>()
        .map_err(|_| "proxy URI has an invalid port".to_string())?;

    Ok((host.to_string(), port))
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProxyType {
    Http,
    Socks5,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProxyScheme {
    Http,
    Https,
    Socks5,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputView {
    Child,
    Egress,
    WireEgress,
    Both,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cli() -> Cli {
        Cli {
            output: None,
            output_view: OutputView::Child,
            root: false,
            doctor: false,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            hosts_file: None,
            proxy: None,
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            iface: None,
            command: vec!["curl".into()],
        }
    }

    #[test]
    fn parse_proxy_spec_accepts_bracketed_ipv6_hosts() {
        let parsed: ProxySpec = "socks5://[2001:db8::1]:1080".parse().unwrap();

        assert_eq!(parsed.scheme, ProxyScheme::Socks5);
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 1080);
    }

    #[test]
    fn parse_proxy_spec_rejects_ipv6_without_brackets() {
        let err = "http://2001:db8::1:8080".parse::<ProxySpec>().unwrap_err();
        assert!(err.contains("must be enclosed in `[` and `]`"));
    }

    #[test]
    fn parse_proxy_spec_accepts_https_scheme() {
        let parsed: ProxySpec = "https://proxy.example.com:443".parse().unwrap();
        assert_eq!(parsed.scheme, ProxyScheme::Https);
        assert_eq!(parsed.host, "proxy.example.com");
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn validate_requires_complete_proxy_credentials() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            network_backend: NetworkBackend::Rootful,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            proxy_user: Some("alice".into()),
            ..make_cli()
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn validate_rejects_proxy_insecure_for_non_https_proxy() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            network_backend: NetworkBackend::Rootful,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            proxy_insecure: true,
            ..make_cli()
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn validate_allows_rootful_backend_without_output() {
        let cli = Cli {
            network_backend: NetworkBackend::Rootful,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_rejects_rootless_internal_iface() {
        let cli = Cli {
            iface: Some("eth0".into()),
            ..make_cli()
        };

        let err = cli.validate().unwrap_err();
        assert!(err.to_string().contains("rootless-internal"));
        assert!(err.to_string().contains("`--iface`"));
    }

    #[test]
    fn validate_allows_rootless_internal_relay_proxy() {
        let cli = Cli {
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootless_internal_proxy_insecure_for_https_proxy() {
        let cli = Cli {
            proxy: Some("https://proxy.example.com:443".parse().unwrap()),
            proxy_insecure: true,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootless_internal_output() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_rejects_missing_hosts_file() {
        let cli = Cli {
            hosts_file: Some(PathBuf::from("/definitely/missing/childflow.hosts")),
            ..make_cli()
        };

        let err = cli.validate().unwrap_err();
        assert!(err.to_string().contains("`--hosts-file`"));
    }

    #[test]
    fn validate_rejects_output_view_without_output_path() {
        let cli = Cli {
            output_view: OutputView::Egress,
            ..make_cli()
        };

        let err = cli.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("`--capture-point` requires `--capture`"));
    }

    #[test]
    fn validate_allows_rootless_egress_output_view() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            output_view: OutputView::Both,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootful_egress_output_view() {
        let cli = Cli {
            root: true,
            output: Some(PathBuf::from("out.pcapng")),
            output_view: OutputView::Egress,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootless_wire_egress_output_view() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            output_view: OutputView::WireEgress,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn selected_backend_uses_root_flag() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            root: true,
            ..make_cli()
        };

        assert_eq!(cli.selected_backend(), NetworkBackend::Rootful);
    }

    #[test]
    fn validate_root_flag_overrides_hidden_backend_and_allows_rootful_without_output() {
        let cli = Cli {
            root: true,
            network_backend: NetworkBackend::RootlessInternal,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_root_flag_allows_iface_without_output() {
        let cli = Cli {
            root: true,
            iface: Some("eth0".into()),
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_hidden_rootful_backend_allows_iface_without_output() {
        let cli = Cli {
            network_backend: NetworkBackend::Rootful,
            iface: Some("eth0".into()),
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_rootful_backend_allows_https_proxy_insecure_when_output_is_present() {
        let cli = Cli {
            network_backend: NetworkBackend::Rootful,
            output: Some(PathBuf::from("out.pcapng")),
            proxy: Some("https://proxy.example.com:443".parse().unwrap()),
            proxy_insecure: true,
            ..make_cli()
        };

        cli.validate().unwrap();
    }

    #[test]
    fn doctor_flag_allows_empty_command() {
        let cli = Cli {
            doctor: true,
            command: Vec::new(),
            ..make_cli()
        };

        cli.validate().unwrap();
        assert_eq!(cli.selected_backend(), NetworkBackend::RootlessInternal);
    }
}
