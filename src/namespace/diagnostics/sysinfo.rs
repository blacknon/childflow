pub(super) fn read_trimmed_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().replace('\n', " | "))
        .filter(|value| !value.is_empty())
}

pub(super) fn read_root_mountinfo_line() -> Option<String> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find(|line| line.contains(" / / "))
                .map(str::to_string)
        })
}

pub(super) fn current_apparmor_profile() -> Option<String> {
    read_trimmed_file("/proc/self/attr/current")
}

pub(super) fn root_mount_propagates_outward() -> Option<bool> {
    let line = read_root_mountinfo_line()?;
    Some(super::parse_mountinfo_propagates_outward(&line))
}

pub(super) fn format_optional_value(value: Option<String>) -> String {
    value.unwrap_or_else(|| "<unavailable>".to_string())
}

pub(super) fn command_in_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let candidate = dir.join(program);
                candidate.exists() && candidate.is_file()
            })
        })
        .unwrap_or(false)
}

pub(super) fn read_proc_u64(path: &str) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

pub(super) fn current_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|user| !user.trim().is_empty())
        .or_else(|| {
            // SAFETY: `geteuid` has no preconditions and reads no caller-provided memory.
            let uid = unsafe { nix::libc::geteuid() };
            // SAFETY: `getpwuid` accepts any uid value and returns either null or a valid libc-owned pointer.
            let passwd = unsafe { nix::libc::getpwuid(uid) };
            if passwd.is_null() {
                return None;
            }
            // SAFETY: `passwd` was checked for null and `pw_name` is a valid NUL-terminated C string.
            let name = unsafe { std::ffi::CStr::from_ptr((*passwd).pw_name) };
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

pub(super) fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

pub(super) fn format_proc_value(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_string())
}
