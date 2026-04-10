use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Result};
use clap::Parser;

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
    pub output: PathBuf,

    /// Force DNS traffic for the child tree to this IPv4 or IPv6 resolver.
    #[arg(short = 'd', long = "dns")]
    pub dns: Option<IpAddr>,

    /// Force TCP traffic through this upstream proxy URI, for example http://127.0.0.1:8080, https://proxy.example.com:443, or socks5://host.docker.internal:10080.
    #[arg(short = 'p', long = "proxy")]
    pub proxy: Option<ProxySpec>,

    /// Username for upstream proxy authentication.
    #[arg(long = "proxy-user")]
    pub proxy_user: Option<String>,

    /// Password for upstream proxy authentication.
    #[arg(long = "proxy-password")]
    pub proxy_password: Option<String>,

    /// Ignore TLS certificate and hostname validation for https:// upstream proxies.
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
    pub fn validate(&self) -> Result<()> {
        if self.command.is_empty() {
            bail!("missing command to execute");
        }

        if self.proxy_user.is_some() != self.proxy_password.is_some() {
            bail!("`--proxy-user` and `--proxy-password` must be provided together");
        }

        if (self.proxy_user.is_some() || self.proxy_insecure) && self.proxy.is_none() {
            bail!("proxy authentication and TLS options require `--proxy`");
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
        assert!(err.contains("invalid port") || err.contains("must include a port"));
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
            output: PathBuf::from("out.pcapng"),
            dns: None,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            proxy_user: Some("alice".into()),
            proxy_password: None,
            proxy_insecure: false,
            iface: None,
            command: vec!["curl".into()],
        };

        assert!(cli.validate().is_err());
    }
}
