use std::env;
use std::ffi::{CStr, OsString};
use std::fs::OpenOptions;
use std::path::Path;

use crate::preflight;

use super::CapabilityStatus;

pub(super) fn inspect_tun_capability() -> (CapabilityStatus, String) {
    let path = "/dev/net/tun";
    if !Path::new(path).exists() {
        return (
            CapabilityStatus::Unavailable,
            format!("`{path}` is missing"),
        );
    }

    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => (
            CapabilityStatus::Available,
            "`/dev/net/tun` is present and can be opened".to_string(),
        ),
        Err(err) => (
            CapabilityStatus::Unavailable,
            format!("failed to open `{path}` ({err})"),
        ),
    }
}

pub(super) fn inspect_af_packet_capability() -> (CapabilityStatus, String) {
    let protocol = u16::to_be(nix::libc::ETH_P_ALL as u16) as i32;
    // SAFETY: `socket` is called with constant arguments and returns an owned fd on success.
    let fd = unsafe { nix::libc::socket(nix::libc::AF_PACKET, nix::libc::SOCK_RAW, protocol) };
    if fd >= 0 {
        // SAFETY: `fd` was returned by `socket` above and is still owned here.
        unsafe {
            nix::libc::close(fd);
        }
        return (
            CapabilityStatus::Available,
            "raw AF_PACKET sockets can be opened for capture".to_string(),
        );
    }

    let err = std::io::Error::last_os_error();
    (
        CapabilityStatus::Limited,
        format!("raw AF_PACKET sockets are blocked for the current user ({err})"),
    )
}

pub(super) fn inspect_apparmor_userns_capability(euid: u32) -> CapabilityStatus {
    if euid == 0 {
        return CapabilityStatus::Available;
    }

    match read_trimmed_file("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() {
        Some("1") => CapabilityStatus::Limited,
        Some("0") => CapabilityStatus::Available,
        Some(_) | None => CapabilityStatus::Limited,
    }
}

pub(super) fn render_apparmor_userns_detail(euid: u32) -> String {
    let restriction = read_trimmed_file("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .unwrap_or_else(|| "unavailable".to_string());
    let profile =
        read_trimmed_file("/proc/self/attr/current").unwrap_or_else(|| "<unavailable>".to_string());

    if euid == 0 {
        return format!(
            "current AppArmor profile: {profile}; root bypasses the unprivileged userns gate"
        );
    }

    match restriction.as_str() {
        "1" => format!(
            "AppArmor unprivileged user-namespace restriction is enabled; current profile: {profile}"
        ),
        "0" => format!(
            "AppArmor unprivileged user-namespace restriction is disabled; current profile: {profile}"
        ),
        _ => format!(
            "AppArmor user-namespace restriction state is unavailable; current profile: {profile}"
        ),
    }
}

pub(super) fn missing_commands(commands: &[&str]) -> Vec<String> {
    let path_env = env::var_os("PATH").unwrap_or_else(|| OsString::from(""));
    preflight::find_missing_commands(commands, &path_env)
}

pub(super) fn unwritable_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| {
            OpenOptions::new()
                .write(true)
                .open(path)
                .err()
                .map(|err| format!("{path} ({err})"))
        })
        .collect()
}

pub(super) fn missing_paths(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter(|path| !Path::new(path).exists())
        .map(|path| path.to_string())
        .collect()
}

pub(super) fn read_trimmed_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) fn read_proc_u64(path: &str) -> Option<u64> {
    read_trimmed_file(path).and_then(|value| value.parse::<u64>().ok())
}

pub(super) fn current_username() -> Option<String> {
    env::var("USER")
        .ok()
        .filter(|user| !user.trim().is_empty())
        .or_else(|| {
            let uid = current_euid();
            // SAFETY: `getpwuid` accepts any uid value and returns either null or a valid pointer
            // owned by libc for the duration of this call.
            let passwd = unsafe { nix::libc::getpwuid(uid) };
            if passwd.is_null() {
                return None;
            }
            // SAFETY: `passwd` was checked for null and `pw_name` is a valid NUL-terminated C string.
            let name = unsafe { CStr::from_ptr((*passwd).pw_name) };
            name.to_str().ok().map(|value| value.to_string())
        })
}

pub(super) fn subid_entry_exists(path: &str, username: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .map(|contents| {
            contents
                .lines()
                .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
                .filter_map(|line| line.split(':').next())
                .any(|entry| entry == username)
        })
        .unwrap_or(false)
}

pub(super) fn render_capability_status(status: &CapabilityStatus) -> &'static str {
    match status {
        CapabilityStatus::Available => "AVAILABLE",
        CapabilityStatus::Limited => "LIMITED",
        CapabilityStatus::Unavailable => "UNAVAILABLE",
    }
}

pub(super) fn current_euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and reads no caller-provided memory.
    unsafe { nix::libc::geteuid() }
}
