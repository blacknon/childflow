use super::capabilities::{
    inspect_apparmor_userns_capability, render_apparmor_userns_detail, render_capability_status,
    CapabilityReport, CapabilityStatus,
};
use super::json::DoctorJsonReport;
use crate::preflight::{self, CheckStatus};

#[test]
fn render_capability_status_uses_stable_labels() {
    assert_eq!(
        render_capability_status(&CapabilityStatus::Available),
        "AVAILABLE"
    );
    assert_eq!(
        render_capability_status(&CapabilityStatus::Limited),
        "LIMITED"
    );
    assert_eq!(
        render_capability_status(&CapabilityStatus::Unavailable),
        "UNAVAILABLE"
    );
}

#[test]
fn apparmor_userns_restriction_reports_limited_for_non_root() {
    let detail = render_apparmor_userns_detail(1000);
    assert!(!detail.is_empty());
    let _ = inspect_apparmor_userns_capability(1000);
}

#[test]
fn doctor_json_report_uses_stable_status_strings() {
    let mut capabilities = CapabilityReport::default();
    capabilities.push(
        "tun_tap_device",
        "TUN/TAP device",
        CapabilityStatus::Limited,
        "not available in test",
    );
    let preflight = vec![preflight::PreflightCheck {
        label: "external commands".to_string(),
        status: CheckStatus::Warning,
        detail: "missing helper".to_string(),
        hint: Some("install it".to_string()),
    }];

    let report = DoctorJsonReport::from_reports(
        "rootless-internal".to_string(),
        "ready with warnings".to_string(),
        1000,
        1000,
        &capabilities,
        &preflight,
    );

    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["status"], "ready with warnings");
    assert_eq!(value["capabilities"][0]["key"], "tun_tap_device");
    assert_eq!(value["capabilities"][0]["status"], "limited");
    assert_eq!(value["preflight"][0]["status"], "warning");
}
