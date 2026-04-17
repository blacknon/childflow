use anyhow::{bail, Result};

use crate::cli::{Cli, ProxyScheme, ProxySpec};

use super::types::ProxyEnvVar;

pub fn render_proxy_uri(cli: &Cli) -> Result<Option<String>> {
    let Some(proxy) = cli.proxy.as_ref() else {
        return Ok(None);
    };

    let auth = match (&cli.proxy_user, &cli.proxy_password) {
        (Some(user), Some(password)) => Some(format!("{user}:{password}@")),
        (None, None) => None,
        _ => bail!("`--proxy-user` and `--proxy-password` must be provided together"),
    };

    let host = render_proxy_host(proxy);
    Ok(Some(format!(
        "{}://{}{host}:{}",
        render_scheme(proxy.scheme),
        auth.as_deref().unwrap_or(""),
        proxy.port
    )))
}

pub fn build_explicit_proxy_env(spec: &ProxySpec, uri: &str) -> Vec<ProxyEnvVar> {
    let mut vars = vec![
        ProxyEnvVar::new("ALL_PROXY", uri),
        ProxyEnvVar::new("all_proxy", uri),
    ];

    if matches!(spec.scheme, ProxyScheme::Http | ProxyScheme::Https) {
        vars.push(ProxyEnvVar::new("HTTP_PROXY", uri));
        vars.push(ProxyEnvVar::new("http_proxy", uri));
        vars.push(ProxyEnvVar::new("HTTPS_PROXY", uri));
        vars.push(ProxyEnvVar::new("https_proxy", uri));
    }

    vars
}

fn render_proxy_host(proxy: &ProxySpec) -> String {
    if proxy.host.contains(':') && !proxy.host.starts_with('[') {
        format!("[{}]", proxy.host)
    } else {
        proxy.host.clone()
    }
}

fn render_scheme(scheme: ProxyScheme) -> &'static str {
    match scheme {
        ProxyScheme::Http => "http",
        ProxyScheme::Https => "https",
        ProxyScheme::Socks5 => "socks5",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::network::NetworkBackend;

    fn base_cli() -> Cli {
        Cli {
            output: None,
            network_backend: NetworkBackend::RootlessInternal,
            dns: None,
            proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
            proxy_user: None,
            proxy_password: None,
            proxy_insecure: false,
            iface: None,
            command: vec!["curl".into()],
        }
    }

    #[test]
    fn render_proxy_uri_embeds_credentials() {
        let mut cli = base_cli();
        cli.proxy = Some("https://proxy.example.com:443".parse().unwrap());
        cli.proxy_user = Some("alice".into());
        cli.proxy_password = Some("secret".into());

        assert_eq!(
            render_proxy_uri(&cli).unwrap(),
            Some("https://alice:secret@proxy.example.com:443".into())
        );
    }

    #[test]
    fn build_explicit_proxy_env_sets_expected_http_vars() {
        let spec: ProxySpec = "http://127.0.0.1:8080".parse().unwrap();
        let vars = build_explicit_proxy_env(&spec, "http://127.0.0.1:8080");
        let keys: Vec<_> = vars.iter().map(|var| var.key.as_str()).collect();

        assert!(keys.contains(&"HTTP_PROXY"));
        assert!(keys.contains(&"HTTPS_PROXY"));
        assert!(keys.contains(&"ALL_PROXY"));
    }
}
