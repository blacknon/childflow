use std::fs;

use anyhow::{Context, Result};

use super::super::support::{run_childflow_command, unique_temp_profile_dir};

#[test]
fn dump_profile_prints_effective_merged_toml_without_running_command() -> Result<()> {
    let profile_dir = unique_temp_profile_dir("rootless-profile-dump");
    let profile_path = profile_dir.join("sandbox.toml");

    fs::write(
        &profile_path,
        r#"
summary = true
default_policy = "deny"
allow_cidrs = ["203.0.113.10/32"]
command = ["curl", "https://example.com"]
"#,
    )
    .context("failed to write childflow profile for dump-profile")?;

    let output = run_childflow_command(&[
        "--profile",
        profile_path.to_str().unwrap(),
        "--deny-cidr",
        "198.51.100.0/24",
        "--dump-profile",
    ])
    .context("failed to run childflow dump-profile command")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("summary = true"));
    assert!(stdout.contains("default_policy = \"deny\""));
    assert!(stdout.contains("deny_cidrs = [\"198.51.100.0/24\"]"));
    assert!(stdout.contains("command = ["));
    assert!(stdout.contains("\"curl\""));
    assert!(stdout.contains("\"https://example.com\""));
    assert!(String::from_utf8_lossy(&output.stderr).is_empty());

    let _ = fs::remove_file(&profile_path);
    let _ = fs::remove_dir_all(&profile_dir);
    Ok(())
}

#[test]
fn dump_profile_resolves_extended_paths_and_replaces_inherited_lists() -> Result<()> {
    let profile_root = unique_temp_profile_dir("rootless-profile-dump-extends");
    let child_dir = profile_root.join("child");
    fs::create_dir_all(child_dir.join("captures"))
        .context("failed to create child capture directory")?;
    fs::create_dir_all(child_dir.join("logs")).context("failed to create child log directory")?;
    let base_profile_path = profile_root.join("base.toml");
    let child_profile_path = child_dir.join("sandbox.toml");
    let expected_capture = child_dir.join("captures").join("run.pcapng");
    let expected_flow_log = child_dir.join("logs").join("flow.jsonl");

    fs::write(
        &base_profile_path,
        r#"
default_policy = "deny"
allow_cidrs = ["10.0.0.0/8"]
deny_cidrs = ["192.168.0.0/16"]
command = ["curl", "https://example.com"]
"#,
    )
    .context("failed to write base childflow profile for dump-profile extends test")?;
    fs::write(
        &child_profile_path,
        r#"
extends = "../base.toml"
capture = "./captures/run.pcapng"
flow_log = "./logs/flow.jsonl"
summary = true
"#,
    )
    .context("failed to write child childflow profile for dump-profile extends test")?;

    let output = run_childflow_command(&[
        "--profile",
        child_profile_path.to_str().unwrap(),
        "--allow-cidr",
        "198.51.100.0/24",
        "--deny-cidr",
        "203.0.113.0/24",
        "--dump-profile",
    ])
    .context("failed to run childflow dump-profile command for extended profile")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let dumped: toml::Value =
        toml::from_str(&stdout).context("failed to parse dumped extended profile TOML")?;
    let dumped_table = dumped
        .as_table()
        .context("dumped extended profile was not a TOML table")?;

    assert_eq!(
        dumped_table
            .get("summary")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dumped_table
            .get("default_policy")
            .and_then(|value| value.as_str()),
        Some("deny")
    );
    assert_eq!(
        dumped_table.get("capture").and_then(|value| value.as_str()),
        Some(expected_capture.to_string_lossy().as_ref())
    );
    assert_eq!(
        dumped_table
            .get("flow_log")
            .and_then(|value| value.as_str()),
        Some(expected_flow_log.to_string_lossy().as_ref())
    );
    assert_eq!(
        dumped_table
            .get("allow_cidrs")
            .and_then(|value| value.as_array()),
        Some(&vec![toml::Value::String("198.51.100.0/24".to_string())])
    );
    assert_eq!(
        dumped_table
            .get("deny_cidrs")
            .and_then(|value| value.as_array()),
        Some(&vec![toml::Value::String("203.0.113.0/24".to_string())])
    );
    assert_eq!(
        dumped_table
            .get("command")
            .and_then(|value| value.as_array()),
        Some(&vec![
            toml::Value::String("curl".to_string()),
            toml::Value::String("https://example.com".to_string()),
        ])
    );
    assert!(String::from_utf8_lossy(&output.stderr).is_empty());

    let _ = fs::remove_file(&base_profile_path);
    let _ = fs::remove_file(&child_profile_path);
    let _ = fs::remove_dir_all(&profile_root);
    Ok(())
}
