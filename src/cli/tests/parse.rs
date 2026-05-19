use std::fs;
use std::path::PathBuf;

use crate::network::NetworkBackend;

use super::super::*;
use super::fixtures::unique_temp_profile_dir;

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
fn selected_backend_uses_root_flag() {
    let cli = Cli {
        output: Some(PathBuf::from("out.pcapng")),
        root: true,
        ..super::fixtures::make_cli()
    };

    assert_eq!(cli.selected_backend(), NetworkBackend::Rootful);
}

#[test]
fn parse_accepts_baseline_sandbox_flags() {
    let cli = Cli::parse_from([
        "childflow",
        "--offline",
        "--summary",
        "--block-private",
        "--block-metadata",
        "--",
        "curl",
        "https://example.com",
    ]);

    assert!(cli.summary);
    assert!(cli.offline);
    assert!(cli.block_private);
    assert!(cli.block_metadata);
    assert_eq!(cli.command, vec!["curl", "https://example.com"]);
}

#[test]
fn parse_accepts_dump_profile_flag() {
    let cli = Cli::parse_from(["childflow", "--dump-profile"]);

    assert!(cli.dump_profile);
    assert!(cli.command.is_empty());
}

#[test]
fn parse_accepts_report_flag() {
    let cli = Cli::parse_from(["childflow", "--report", "/tmp/childflow-flow.jsonl"]);

    assert_eq!(cli.report, Some(PathBuf::from("/tmp/childflow-flow.jsonl")));
    assert_eq!(cli.report_format, ReportFormat::Text);
    assert!(cli.command.is_empty());
}

#[test]
fn parse_accepts_report_format_flag() {
    let cli = Cli::parse_from([
        "childflow",
        "--report",
        "/tmp/childflow-flow.jsonl",
        "--report-format",
        "markdown",
    ]);

    assert_eq!(cli.report, Some(PathBuf::from("/tmp/childflow-flow.jsonl")));
    assert_eq!(cli.report_format, ReportFormat::Markdown);
}

#[test]
fn parse_accepts_report_json_format_flag() {
    let cli = Cli::parse_from([
        "childflow",
        "--report",
        "/tmp/childflow-flow.jsonl",
        "--report-format",
        "json",
    ]);

    assert_eq!(cli.report, Some(PathBuf::from("/tmp/childflow-flow.jsonl")));
    assert_eq!(cli.report_format, ReportFormat::Json);
}

#[test]
fn parse_accepts_summary_format_flag() {
    let cli = Cli::parse_from([
        "childflow",
        "--summary",
        "--summary-format",
        "json",
        "--",
        "curl",
        "https://example.com",
    ]);

    assert!(cli.summary);
    assert_eq!(cli.summary_format, SummaryFormat::Json);
}

#[test]
fn parse_accepts_cidr_policy_flags() {
    let cli = Cli::parse_from([
        "childflow",
        "--default-policy",
        "deny",
        "--allow-cidr",
        "192.0.2.0/24",
        "--allow-cidr",
        "2001:db8::/32",
        "--deny-cidr",
        "198.51.100.0/24",
        "--",
        "curl",
    ]);

    assert_eq!(cli.default_policy, DefaultPolicy::Deny);
    assert_eq!(cli.allow_cidrs.len(), 2);
    assert_eq!(cli.deny_cidrs.len(), 1);
}

#[test]
fn parse_accepts_domain_policy_flags() {
    let cli = Cli::parse_from([
        "childflow",
        "--allow-domain-exact",
        "Auth.Example.com.",
        "--allow-domain",
        "Example.com.",
        "--deny-domain-exact",
        "login.blocked.example.com",
        "--deny-domain",
        "blocked.example.com",
        "--",
        "curl",
    ]);

    assert_eq!(cli.allow_domains_exact, vec!["auth.example.com"]);
    assert_eq!(cli.allow_domains, vec!["example.com"]);
    assert_eq!(cli.deny_domains_exact, vec!["login.blocked.example.com"]);
    assert_eq!(cli.deny_domains, vec!["blocked.example.com"]);
}

#[test]
fn parse_profile_supplies_command_and_relative_paths() {
    let temp_dir = unique_temp_profile_dir("cli-profile-relative");
    let profile_path = temp_dir.join("sandbox.toml");

    fs::write(
        &profile_path,
        r#"
capture = "captures/run.pcapng"
capture_point = "both"
hosts_file = "fixtures/hosts.override"
flow_log = "logs/flow.jsonl"
summary = true
doctor_format = "json"
report_format = "markdown"
summary_format = "json"
command = ["curl", "https://example.com"]
"#,
    )
    .unwrap();

    let cli = Cli::parse_from(["childflow", "--profile", profile_path.to_str().unwrap()]);

    assert_eq!(
        cli.output,
        Some(temp_dir.join("captures").join("run.pcapng"))
    );
    assert_eq!(cli.output_view, OutputView::Both);
    assert_eq!(
        cli.hosts_file,
        Some(temp_dir.join("fixtures").join("hosts.override"))
    );
    assert_eq!(cli.flow_log, Some(temp_dir.join("logs").join("flow.jsonl")));
    assert!(cli.summary);
    assert_eq!(cli.doctor_format, DoctorFormat::Json);
    assert_eq!(cli.report_format, ReportFormat::Markdown);
    assert_eq!(cli.summary_format, SummaryFormat::Json);
    assert_eq!(cli.command, vec!["curl", "https://example.com"]);

    let _ = fs::remove_file(&profile_path);
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn parse_cli_overrides_profile_values() {
    let temp_dir = unique_temp_profile_dir("cli-profile-override");
    let profile_path = temp_dir.join("sandbox.toml");

    fs::write(
        &profile_path,
        r#"
summary = true
doctor_format = "json"
report_format = "markdown"
summary_format = "json"
default_policy = "deny"
allow_cidrs = ["203.0.113.10/32"]
allow_domains_exact = ["auth.example.com"]
allow_domains = ["example.com"]
command = ["curl", "https://example.com"]
"#,
    )
    .unwrap();

    let cli = Cli::parse_from([
        "childflow",
        "--profile",
        profile_path.to_str().unwrap(),
        "--default-policy",
        "allow",
        "--summary-format",
        "text",
        "--deny-cidr",
        "198.51.100.0/24",
        "--",
        "ping",
        "-c",
        "1",
        "1.1.1.1",
    ]);

    assert!(cli.summary);
    assert_eq!(cli.doctor_format, DoctorFormat::Json);
    assert_eq!(cli.report_format, ReportFormat::Markdown);
    assert_eq!(cli.summary_format, SummaryFormat::Text);
    assert_eq!(cli.default_policy, DefaultPolicy::Allow);
    assert_eq!(cli.allow_cidrs.len(), 1);
    assert_eq!(cli.deny_cidrs.len(), 1);
    assert_eq!(cli.allow_domains_exact, vec!["auth.example.com"]);
    assert_eq!(cli.allow_domains, vec!["example.com"]);
    assert_eq!(cli.command, vec!["ping", "-c", "1", "1.1.1.1"]);

    let _ = fs::remove_file(&profile_path);
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn parse_accepts_doctor_format_flag() {
    let cli = Cli::parse_from(["childflow", "--doctor", "--doctor-format", "json"]);

    assert!(cli.doctor);
    assert_eq!(cli.doctor_format, DoctorFormat::Json);
    assert!(cli.command.is_empty());
}

#[test]
fn parse_profile_supplies_doctor_and_report_formats() {
    let temp_dir = unique_temp_profile_dir("cli-profile-observability-formats");
    let profile_path = temp_dir.join("sandbox.toml");

    fs::write(
        &profile_path,
        r#"
doctor_format = "json"
report_format = "markdown"
command = ["curl", "https://example.com"]
"#,
    )
    .unwrap();

    let doctor_cli = Cli::parse_from([
        "childflow",
        "--profile",
        profile_path.to_str().unwrap(),
        "--doctor",
    ]);
    assert!(doctor_cli.doctor);
    assert_eq!(doctor_cli.doctor_format, DoctorFormat::Json);

    let report_cli = Cli::parse_from([
        "childflow",
        "--profile",
        profile_path.to_str().unwrap(),
        "--report",
        "/tmp/childflow-flow.jsonl",
    ]);
    assert_eq!(report_cli.report_format, ReportFormat::Markdown);

    let override_cli = Cli::parse_from([
        "childflow",
        "--profile",
        profile_path.to_str().unwrap(),
        "--report",
        "/tmp/childflow-flow.jsonl",
        "--report-format",
        "json",
    ]);
    assert_eq!(override_cli.report_format, ReportFormat::Json);

    let _ = fs::remove_file(&profile_path);
    let _ = fs::remove_dir_all(&temp_dir);
}
