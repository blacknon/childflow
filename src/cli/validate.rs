use anyhow::{bail, Result};

use crate::network::NetworkBackend;

use super::{Cli, OutputView, ProxyScheme};

pub(super) fn validate_cli(cli: &Cli) -> Result<()> {
    if cli.doctor {
        return Ok(());
    }

    if cli.report.is_some() {
        if !cli.command.is_empty() {
            bail!("`--report` does not accept a command to execute");
        }
        return Ok(());
    }

    if cli.command.is_empty() {
        bail!("missing command to execute");
    }

    if matches!(cli.selected_backend(), NetworkBackend::RootlessInternal) && cli.iface.is_some() {
        bail!("`--iface` is not supported by the `rootless-internal` backend");
    }

    if let Some(path) = &cli.hosts_file {
        if !path.exists() {
            bail!("`--hosts-file` path does not exist: {}", path.display());
        }
    }

    if cli.output_view != OutputView::Child && cli.output.is_none() {
        bail!("`--capture-point` requires `--capture`");
    }

    if cli.proxy_user.is_some() != cli.proxy_password.is_some() {
        bail!("`--proxy-user` and `--proxy-password` must be provided together");
    }

    if (cli.proxy_user.is_some() || cli.proxy_insecure) && cli.proxy.is_none() {
        bail!("proxy authentication and TLS options require `--proxy`");
    }

    if cli.proxy_only && cli.proxy.is_none() {
        bail!("`--proxy-only` requires `--proxy`");
    }

    if cli.proxy_insecure
        && !matches!(
            cli.proxy.as_ref().map(|proxy| proxy.scheme),
            Some(ProxyScheme::Https)
        )
    {
        bail!("`--proxy-insecure` is only valid with an `https://` upstream proxy");
    }

    if cli.fail_on_leak && matches!(cli.selected_backend(), NetworkBackend::Rootful) {
        bail!("`--fail-on-leak` is currently supported only by the `rootless-internal` backend");
    }

    if cli.flow_log.is_some() && matches!(cli.selected_backend(), NetworkBackend::Rootful) {
        bail!("`--flow-log` is currently supported only by the `rootless-internal` backend");
    }

    if (!cli.allow_domains.is_empty()
        || !cli.deny_domains.is_empty()
        || !cli.allow_domains_exact.is_empty()
        || !cli.deny_domains_exact.is_empty())
        && matches!(cli.selected_backend(), NetworkBackend::Rootful)
    {
        bail!(
            "`--allow-domain`, `--allow-domain-exact`, `--deny-domain`, and `--deny-domain-exact` are currently supported only by the `rootless-internal` backend"
        );
    }

    Ok(())
}
