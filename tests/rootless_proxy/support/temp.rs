use std::fs;
use std::path::PathBuf;

pub(crate) fn unique_temp_profile_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{nanos}"));
    let _ = fs::create_dir_all(&path);
    path
}
