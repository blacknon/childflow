use std::env;
use std::path::PathBuf;

use crate::network::NetworkBackend;

use super::inspect::parse_proc_u64;
use super::CheckStatus;
use super::*;

#[test]
fn find_missing_commands_reports_only_missing_entries() {
    let base = PathBuf::from("/tmp/childflow-preflight-tests");
    let path_env = env::join_paths([base.join("bin-a"), base.join("bin-b")]).unwrap();

    assert_eq!(
        find_missing_commands(&["ip", "iptables"], &path_env),
        vec!["ip".to_string(), "iptables".to_string()]
    );
}

#[test]
fn render_issue_list_formats_each_entry() {
    let rendered = render_issue_list(&["first".into(), "second".into()]);
    assert_eq!(rendered, "- first\n- second");
}

#[test]
fn parse_proc_u64_returns_none_when_file_is_missing() {
    assert_eq!(
        parse_proc_u64("/tmp/childflow-preflight/definitely-missing").unwrap(),
        None
    );
}

#[test]
fn inspect_rootless_report_contains_backend_name() {
    let report = inspect(NetworkBackend::RootlessInternal, false);
    assert_eq!(report.backend_name(), "rootless-internal");
    assert!(!report.checks().is_empty());
}

#[test]
fn inspect_rootless_report_marks_external_commands_as_ip_free() {
    let report = inspect(NetworkBackend::RootlessInternal, false);
    let check = report
        .checks()
        .iter()
        .find(|check| check.label == "external commands")
        .expect("rootless preflight should report external commands");

    assert_eq!(check.status, CheckStatus::Ok);
    assert!(check.detail.contains("no longer requires `ip`"));
}

#[test]
fn inspect_rootful_report_requires_only_iptables_userspace() {
    let report = inspect(NetworkBackend::Rootful, false);
    let check = report
        .checks()
        .iter()
        .find(|check| check.label == "external commands")
        .expect("rootful preflight should report external commands");

    assert!(!check.detail.contains("`ip`"));
    match &check.status {
        CheckStatus::Ok | CheckStatus::Fatal => {
            assert!(
                check.detail.contains("iptables") || check.detail.contains("ip6tables"),
                "unexpected rootful external-command detail: {}",
                check.detail
            );
        }
        other => panic!("unexpected rootful external-command status: {:?}", other),
    }
}

#[test]
fn preflight_report_finish_succeeds_with_only_warnings() {
    let mut report = PreflightReport::new("rootless-internal");
    report.push_warning("heads up", "warning detail", "warning hint");

    report.finish().unwrap();
}
