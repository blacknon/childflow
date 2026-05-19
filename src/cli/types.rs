use std::str::FromStr;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::domain::normalize_domain_rule;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxySpec {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for ProxySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let scheme = match self.scheme {
            ProxyScheme::Http => "http",
            ProxyScheme::Https => "https",
            ProxyScheme::Socks5 => "socks5",
        };
        write!(f, "{scheme}://{host}:{}", self.port)
    }
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

pub(super) fn parse_domain_rule(input: &str) -> std::result::Result<String, String> {
    normalize_domain_rule(input)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProxyType {
    Http,
    Socks5,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyScheme {
    Http,
    Https,
    Socks5,
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum OutputView {
    Child,
    Egress,
    WireEgress,
    Both,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    #[default]
    Allow,
    Deny,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    #[default]
    Text,
    Markdown,
    Json,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DoctorFormat {
    #[default]
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum SummaryFormat {
    #[default]
    Text,
    Json,
}
