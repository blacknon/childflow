use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};

use super::super::support::{
    discover_reachable_host_ipv4, run_childflow_command, spawn_local_http_server,
    unique_temp_profile_dir,
};

#[test]
fn rootless_internal_runs_from_profile_toml() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-profile-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let profile_dir = unique_temp_profile_dir("rootless-profile");
    let profile_path = profile_dir.join("sandbox.toml");

    fs::write(
        &profile_path,
        format!(
            concat!(
                "default_policy = \"deny\"\n",
                "allow_cidrs = [\"{host_ip}/32\"]\n",
                "command = [\n",
                "  \"python3\",\n",
                "  \"-c\",\n",
                "  \"import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())\",\n",
                "  \"http://{host_ip}:{port}/hello\",\n",
                "]\n"
            ),
            host_ip = host_ip,
            port = server_addr.port()
        ),
    )
    .context("failed to write childflow profile")?;

    let output = run_childflow_command(&["--profile", profile_path.to_str().unwrap()])
        .context("failed to run childflow from a profile")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-profile-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(Duration::from_secs(5))
            .context("profile-driven local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    let _ = fs::remove_file(&profile_path);
    let _ = fs::remove_dir_all(&profile_dir);
    Ok(())
}

#[test]
fn rootless_internal_runs_from_extended_profile_toml() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-profile-extends-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let profile_root = unique_temp_profile_dir("rootless-profile-extends");
    let child_dir = profile_root.join("child");
    fs::create_dir_all(&child_dir).context("failed to create child profile directory")?;
    let base_profile_path = profile_root.join("base.toml");
    let child_profile_path = child_dir.join("sandbox.toml");

    fs::write(
        &base_profile_path,
        format!(
            concat!(
                "default_policy = \"deny\"\n",
                "allow_cidrs = [\"{host_ip}/32\"]\n"
            ),
            host_ip = host_ip
        ),
    )
    .context("failed to write base childflow profile")?;
    fs::write(
        &child_profile_path,
        format!(
            concat!(
                "extends = \"../base.toml\"\n",
                "command = [\n",
                "  \"python3\",\n",
                "  \"-c\",\n",
                "  \"import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())\",\n",
                "  \"http://{host_ip}:{port}/hello\",\n",
                "]\n"
            ),
            host_ip = host_ip,
            port = server_addr.port()
        ),
    )
    .context("failed to write child childflow profile")?;

    let output = run_childflow_command(&["--profile", child_profile_path.to_str().unwrap()])
        .context("failed to run childflow from an extended profile")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-profile-extends-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(Duration::from_secs(5))
            .context("extended-profile local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    let _ = fs::remove_file(&base_profile_path);
    let _ = fs::remove_file(&child_profile_path);
    let _ = fs::remove_dir_all(&profile_root);
    Ok(())
}

#[test]
fn rootless_internal_extended_profile_supports_cli_command_override() -> Result<()> {
    let (server_addr, requests) = spawn_local_http_server("childflow-profile-cli-override-ok")?;
    let host_ip = discover_reachable_host_ipv4()?;
    let profile_root = unique_temp_profile_dir("rootless-profile-cli-override");
    let child_dir = profile_root.join("child");
    fs::create_dir_all(&child_dir).context("failed to create child profile directory")?;
    let base_profile_path = profile_root.join("base.toml");
    let child_profile_path = child_dir.join("sandbox.toml");

    fs::write(
        &base_profile_path,
        format!(
            concat!(
                "default_policy = \"deny\"\n",
                "allow_cidrs = [\"{host_ip}/32\"]\n",
                "command = [\"curl\", \"https://example.com\"]\n"
            ),
            host_ip = host_ip
        ),
    )
    .context("failed to write base childflow profile for CLI override test")?;
    fs::write(
        &child_profile_path,
        "extends = \"../base.toml\"\nsummary = true\n",
    )
    .context("failed to write child childflow profile for CLI override test")?;

    let output = run_childflow_command(&[
        "--profile",
        child_profile_path.to_str().unwrap(),
        "--",
        "python3",
        "-c",
        "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())",
        &format!("http://{host_ip}:{}/hello", server_addr.port()),
    ])
    .context("failed to run childflow from an extended profile with CLI command override")?;

    assert!(
        output.status.success(),
        "childflow failed:\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "childflow-profile-cli-override-ok"
    );
    assert_eq!(
        requests
            .recv_timeout(Duration::from_secs(5))
            .context("CLI-overridden profile local HTTP server did not receive a request")?,
        "GET /hello HTTP/1.1"
    );

    let _ = fs::remove_file(&base_profile_path);
    let _ = fs::remove_file(&child_profile_path);
    let _ = fs::remove_dir_all(&profile_root);
    Ok(())
}
