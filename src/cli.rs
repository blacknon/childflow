use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Result};
use clap::Parser;

use crate::network::NetworkBackend;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "childflow",
    version,
    about = "Launch a child process tree inside its own netns and capture only its packets",
    trailing_var_arg = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Write only the target command tree's traffic as pcapng.
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Use the rootful backend. Without this flag, childflow uses the default rootless backend.
    #[arg(long = "root")]
    pub root: bool,

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
    #[arg(long = "proxy-user")]
    pub proxy_user: Option<String>,

    /// Password for upstream proxy authentication.
    #[arg(long = "proxy-password")]
    pub proxy_password: Option<String>,

    /// Ignore certificate trust errors for https:// upstream proxies while still validating the hostname.
    #[arg(long = "proxy-insecure")]
    pub proxy_insecure: bool,

    /// Force the host-side egress interface for the child's direct traffic.
    #[arg(short = 'i', long = "iface")]
    pub iface: Option<String>,

    /// Command to execute.
    #[arg(required = true)]
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

        match self.selected_backend() {
            NetworkBackend::Rootful => {
                if self.output.is_none() {
                    bail!(
                        "`--output` is required with the `rootful` backend because packet capture currently depends on the host-side veth capture path"
                    );
                }
            }
            NetworkBackend::RootlessInternal => {}
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

#[cfg(test)]
mod tests {
    use super::*;

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
            root: false,
            network_backend: NetworkBackend::Rootful,
            dns: None,
            hosts_file: None,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            proxy_user: Some("alice".into()),
            proxy_password: None,
            proxy_insecure: false,
            iface: None,
            command: vec!["curl".into()],
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn validate_rejects_proxy_insecure_for_non_https_proxy() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            root: false,
            network_backend: NetworkBackend::Rootful,
            dns: None,
            hosts_file: None,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: true,
            iface: None,
            command: vec!["curl".into()],
        };

        assert!(cli.validate().is_err());
    }

    #[test]
    fn validate_requires_output_for_rootful_backend() {
        let cli = Cli {
            output: None,
            root: false,
            network_backend: NetworkBackend::Rootful,
            dns: None,
            hosts_file: None,
            proxy: None,
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            iface: None,
            command: vec!["curl".into()],
        };

        let err = cli.validate().unwrap_err();
        assert!(err.to_string().contains("`--output` is required"));
    }

    #[test]
    fn validate_rejects_rootless_internal_iface() {
        let cli = Cli {
            output: None,
            root: false,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            hosts_file: None,
            proxy: None,
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            iface: Some("eth0".into()),
            command: vec!["curl".into()],
        };

        let err = cli.validate().unwrap_err();
        assert!(err.to_string().contains("rootless-internal"));
        assert!(err.to_string().contains("`--iface`"));
    }

    #[test]
    fn validate_allows_rootless_internal_relay_proxy() {
        let cli = Cli {
            output: None,
            root: false,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            hosts_file: None,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            iface: None,
            command: vec!["curl".into()],
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootless_internal_proxy_insecure_for_https_proxy() {
        let cli = Cli {
            output: None,
            root: false,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            hosts_file: None,
            proxy: Some("https://proxy.example.com:443".parse().unwrap()),
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: true,
            iface: None,
            command: vec!["curl".into()],
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_allows_rootless_internal_output() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            root: false,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            hosts_file: None,
            proxy: None,
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            iface: None,
            command: vec!["curl".into()],
        };

        cli.validate().unwrap();
    }

    #[test]
    fn validate_rejects_missing_hosts_file() {
        let cli = Cli {
            output: None,
            root: false,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            hosts_file: Some(PathBuf::from("/definitely/missing/childflow.hosts")),
            proxy: None,
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            iface: None,
            command: vec!["curl".into()],
        };

        let err = cli.validate().unwrap_err();
        assert!(err.to_string().contains("`--hosts-file`"));
    }

    #[test]
    fn selected_backend_uses_root_flag() {
        let cli = Cli {
            output: Some(PathBuf::from("out.pcapng")),
            root: true,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            hosts_file: None,
            proxy: None,
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            iface: None,
            command: vec!["curl".into()],
        };

        assert_eq!(cli.selected_backend(), NetworkBackend::Rootful);
    }
}
