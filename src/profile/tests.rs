use std::path::PathBuf;

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
capture = "./captures/run.pcapng"
hosts_file = "./fixtures/hosts.override"
flow_log = "./logs/flow.jsonl"
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
doctor_format = "json"
report_format = "json"
summary_format = "json"
default_policy = "deny"
allow_cidrs = ["203.0.113.10/32"]
allow_domains_exact = ["auth.example.com"]
allow_domains = ["example.com"]
command = ["curl", "https://example.com"]
"#,
    )
    .unwrap();
    std::fs::write(
        &child_profile_path,
        r#"
extends = "../base.toml"
deny_cidrs = ["198.51.100.0/24"]
deny_domains_exact = ["login.blocked.example.com"]
deny_domains = ["blocked.example.com"]
command = ["ping", "-c", "1", "1.1.1.1"]
"#,
    )
    .unwrap();

    let profile = Profile::load(&child_profile_path).unwrap();

    assert_eq!(profile.extends, None);
    assert_eq!(profile.summary, Some(true));
    assert_eq!(profile.doctor_format, Some(DoctorFormat::Json));
    assert_eq!(profile.report_format, Some(ReportFormat::Json));
    assert_eq!(profile.summary_format, Some(SummaryFormat::Json));
    assert_eq!(profile.default_policy, Some(DefaultPolicy::Deny));
    assert_eq!(
        profile.allow_cidrs,
        Some(vec!["203.0.113.10/32".parse().unwrap()])
    );
    assert_eq!(
        profile.allow_domains_exact,
        Some(vec!["auth.example.com".into()])
    );
    assert_eq!(profile.allow_domains, Some(vec!["example.com".into()]));
    assert_eq!(
        profile.deny_cidrs,
        Some(vec!["198.51.100.0/24".parse().unwrap()])
    );
    assert_eq!(
        profile.deny_domains_exact,
        Some(vec!["login.blocked.example.com".into()])
    );
    assert_eq!(
        profile.deny_domains,
        Some(vec!["blocked.example.com".into()])
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
        doctor_format: crate::cli::DoctorFormat::Text,
        report: None,
        report_format: crate::cli::ReportFormat::Text,
        network_backend: NetworkBackend::RootlessInternal,
        dns: Some("1.1.1.1".parse().unwrap()),
        hosts_file: Some(PathBuf::from("/tmp/hosts.override")),
        proxy: Some("https://proxy.example.com:443".parse().unwrap()),
        proxy_user: Some("alice".into()),
        proxy_password: Some("secret".into()),
        proxy_insecure: true,
        summary: true,
        summary_format: crate::cli::SummaryFormat::Text,
        flow_log: Some(PathBuf::from("/tmp/flow.jsonl")),
        offline: false,
        block_private: true,
        block_metadata: true,
        default_policy: DefaultPolicy::Deny,
        allow_cidrs: vec!["203.0.113.10/32".parse().unwrap()],
        deny_cidrs: vec!["198.51.100.0/24".parse().unwrap()],
        allow_domains_exact: vec!["auth.example.com".into()],
        allow_domains: vec!["example.com".into()],
        deny_domains_exact: vec!["login.blocked.example.com".into()],
        deny_domains: vec!["blocked.example.com".into()],
        proxy_only: true,
        fail_on_leak: true,
        iface: None,
        command: vec!["curl".into(), "https://example.com".into()],
    };

    let rendered = Profile::from_cli(&cli).render_toml().unwrap();

    assert!(rendered.contains("capture_point = \"both\""));
    assert!(rendered.contains("backend = \"rootless-internal\""));
    assert!(rendered.contains("proxy = \"https://proxy.example.com:443\""));
    assert!(rendered.contains("summary_format = \"text\""));
    assert!(rendered.contains("default_policy = \"deny\""));
    assert!(rendered.contains("allow_domains_exact = [\"auth.example.com\"]"));
    assert!(rendered.contains("allow_domains = [\"example.com\"]"));
    assert!(rendered.contains("deny_domains_exact = [\"login.blocked.example.com\"]"));
    assert!(rendered.contains("deny_domains = [\"blocked.example.com\"]"));
    assert!(rendered.contains("command = ["));
    assert!(rendered.contains("\"curl\""));
    assert!(rendered.contains("\"https://example.com\""));
}

#[test]
fn render_profile_as_toml_includes_doctor_and_report_formats_when_active() {
    let cli = Cli {
        dump_profile: false,
        output: None,
        output_view: OutputView::Child,
        root: false,
        doctor: true,
        doctor_format: crate::cli::DoctorFormat::Json,
        report: Some(PathBuf::from("/tmp/flow.jsonl")),
        report_format: crate::cli::ReportFormat::Markdown,
        network_backend: NetworkBackend::RootlessInternal,
        dns: None,
        hosts_file: None,
        proxy: None,
        proxy_user: None,
        proxy_password: None,
        proxy_insecure: false,
        summary: false,
        summary_format: crate::cli::SummaryFormat::Text,
        flow_log: None,
        offline: false,
        block_private: false,
        block_metadata: false,
        default_policy: DefaultPolicy::Allow,
        allow_cidrs: Vec::new(),
        deny_cidrs: Vec::new(),
        allow_domains_exact: Vec::new(),
        allow_domains: Vec::new(),
        deny_domains_exact: Vec::new(),
        deny_domains: Vec::new(),
        proxy_only: false,
        fail_on_leak: false,
        iface: None,
        command: Vec::new(),
    };

    let rendered = Profile::from_cli(&cli).render_toml().unwrap();

    assert!(rendered.contains("doctor_format = \"json\""));
    assert!(rendered.contains("report_format = \"markdown\""));
}
