use std::net::Ipv4Addr;
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

    /// Force DNS traffic for the child tree to this IPv4 resolver.
    #[arg(short = 'd', long = "dns")]
    pub dns: Option<Ipv4Addr>,

    /// Force TCP traffic through this upstream proxy URI, for example http://127.0.0.1:8080 or socks5://host.docker.internal:10080.
    #[arg(short = 'p', long = "proxy")]
    pub proxy: Option<ProxySpec>,

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

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxySpec {
    pub kind: ProxyType,
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

        let kind = match scheme {
            "http" => ProxyType::Http,
            "socks5" => ProxyType::Socks5,
            other => {
                return Err(format!(
                    "unsupported proxy scheme `{other}`; expected `http` or `socks5`"
                ))
            }
        };

        let (host, port) = parse_host_port(rest)?;

        Ok(Self { kind, host, port })
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
