use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

pub(super) fn resolve_relative_path(base_dir: &Path, path: PathBuf) -> PathBuf {
    let joined = if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    };
    normalize_lexical_path(&joined)
}

pub(super) fn normalize_profile_path(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("failed to resolve profile path `{}`", path.display()))
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    let mut has_root = false;

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => {
                normalized.push(component.as_os_str());
                has_root = true;
            }
            Component::CurDir => {}
            Component::ParentDir => match normalized.components().next_back() {
                Some(Component::Normal(_)) => {
                    normalized.pop();
                }
                Some(Component::ParentDir) | None if !has_root => normalized.push(".."),
                _ => {}
            },
            Component::Normal(segment) => normalized.push(segment),
        }
    }

    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}
