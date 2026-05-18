use std::path::PathBuf;

use crate::network::NetworkBackend;

use super::super::*;
use super::fixtures::make_cli;

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
fn validate_rejects_proxy_only_without_proxy() {
    let cli = Cli {
        proxy_only: true,
        ..make_cli()
    };

    assert!(cli.validate().is_err());
}

#[test]
fn validate_rejects_fail_on_leak_for_rootful_backend() {
    let cli = Cli {
        root: true,
        proxy: Some("http://127.0.0.1:8080".parse().unwrap()),
        fail_on_leak: true,
        ..make_cli()
    };

    assert!(cli.validate().is_err());
}

#[test]
fn validate_rejects_flow_log_for_rootful_backend() {
    let cli = Cli {
        root: true,
        flow_log: Some(PathBuf::from("/tmp/childflow-flow.jsonl")),
        ..make_cli()
    };

    assert!(cli.validate().is_err());
}

#[test]
fn validate_rejects_domain_policy_for_rootful_backend() {
    let cli = Cli {
        root: true,
        allow_domains: vec!["example.com".into()],
        ..make_cli()
    };

    assert!(cli.validate().is_err());
}

#[test]
fn validate_rejects_exact_domain_policy_for_rootful_backend() {
    let cli = Cli {
        root: true,
        deny_domains_exact: vec!["auth.example.com".into()],
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

#[test]
fn report_flag_allows_empty_command() {
    let cli = Cli {
        report: Some(PathBuf::from("/tmp/childflow-flow.jsonl")),
        command: Vec::new(),
        ..make_cli()
    };

    cli.validate().unwrap();
}

#[test]
fn report_flag_rejects_command() {
    let cli = Cli {
        report: Some(PathBuf::from("/tmp/childflow-flow.jsonl")),
        ..make_cli()
    };

    assert!(cli.validate().is_err());
}
