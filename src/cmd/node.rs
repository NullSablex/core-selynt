use std::path::{Path, PathBuf};

/// Minimum supported Node.js version. `node --import` requires 20.6+.
pub const NODE_MIN_MAJOR: u32 = 20;
pub const NODE_MIN_MINOR: u32 = 6;

/// Parses `v20.15.1` into `(20, 15, 1)`. Returns `None` when the input does not
/// start with `v` or any of the version components fails to parse.
pub fn parse_node_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let s = ver.strip_prefix('v')?;
    let mut parts = s.splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

pub fn node_version_ok(ver: &str) -> bool {
    parse_node_semver(ver).is_some_and(|(major, minor, _)| {
        major > NODE_MIN_MAJOR || (major == NODE_MIN_MAJOR && minor >= NODE_MIN_MINOR)
    })
}

/// Runs `{path} --version` and returns the raw output (e.g. `v20.15.1`),
/// without checking against the minimum supported version.
pub fn get_node_version_raw(path: &Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
    ver.starts_with('v').then_some(ver)
}

/// Same as `get_node_version_raw` but filters out runtimes that don't meet the
/// minimum supported version.
pub fn get_node_version(path: &Path) -> Option<String> {
    let ver = get_node_version_raw(path)?;
    node_version_ok(&ver).then_some(ver)
}

/// Single-`*` glob expansion. Returns matches whose final component is a file.
pub fn glob_paths(pattern: &str) -> Vec<PathBuf> {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() != 2 {
        return Vec::new();
    }
    let (prefix, suffix) = (parts[0], parts[1]);
    let parent = Path::new(prefix.trim_end_matches('/'));
    if !parent.is_dir() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for entry in entries.flatten() {
        let candidate = entry.path().join(suffix.trim_start_matches('/'));
        if candidate.is_file() {
            results.push(candidate);
        }
    }
    results
}
