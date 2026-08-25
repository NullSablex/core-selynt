use std::path::{Path, PathBuf};

/// Minimum supported Node.js version. `node --import` requires 20.6+.
pub const NODE_MIN_MAJOR: u32 = 20;
pub const NODE_MIN_MINOR: u32 = 6;

/// Parses `v20.15.1` into `(20, 15, 1)`. Returns `None` when the input does not
/// start with `v` or any of the version components fails to parse.
pub(crate) fn parse_node_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let s = ver.strip_prefix('v')?;
    let mut parts = s.splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

pub(crate) fn node_version_ok(ver: &str) -> bool {
    parse_node_semver(ver).is_some_and(|(major, minor, _)| {
        major > NODE_MIN_MAJOR || (major == NODE_MIN_MAJOR && minor >= NODE_MIN_MINOR)
    })
}

/// Runs `{path} --version` and returns the raw output (e.g. `v20.15.1`),
/// without checking against the minimum supported version.
pub(crate) fn get_node_version_raw(path: &Path) -> Option<String> {
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
pub(crate) fn get_node_version(path: &Path) -> Option<String> {
    let ver = get_node_version_raw(path)?;
    node_version_ok(&ver).then_some(ver)
}

/// Single-`*` glob expansion. Returns matches whose final component is a file.
///
/// The `*` matches within one path component, so it may carry literal text on
/// either side of it — `/opt/alt/alt-nodejs*/root/usr/bin/node` scans `/opt/alt`
/// for entries starting with `alt-nodejs`. Matching only whole components would
/// miss CloudLinux's alt-nodejs layout entirely.
pub(crate) fn glob_paths(pattern: &str) -> Vec<PathBuf> {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() != 2 {
        return Vec::new();
    }
    let (prefix, suffix) = (parts[0], parts[1]);

    // Split the prefix at the last `/`: everything before it is the directory to
    // scan, everything after is the literal an entry name must start with.
    let (dir, name_prefix) = match prefix.rfind('/') {
        Some(i) => (&prefix[..=i], &prefix[i + 1..]),
        None => return Vec::new(),
    };
    // Likewise for the suffix: up to the first `/` the entry name must end with
    // that literal; the rest is the path to descend into.
    let (name_suffix, rest) = match suffix.find('/') {
        Some(i) => (&suffix[..i], &suffix[i..]),
        None => (suffix, ""),
    };

    let parent = Path::new(dir.trim_end_matches('/'));
    if !parent.is_dir() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // The `*` must match at least nothing, but the two literals may not
        // overlap — `ab*c` must not match `abc` twice over.
        if !name.starts_with(name_prefix)
            || !name.ends_with(name_suffix)
            || name.len() < name_prefix.len() + name_suffix.len()
        {
            continue;
        }
        let candidate = entry.path().join(rest.trim_start_matches('/'));
        if candidate.is_file() {
            results.push(candidate);
        }
    }
    results
}

#[cfg(test)]
mod glob_tests {
    use super::glob_paths;
    use std::fs;

    /// Builds a throwaway tree and returns its root.
    fn tree(tag: &str, files: &[&str]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("selynt-glob-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for f in files {
            let p = root.join(f.trim_start_matches('/'));
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"").unwrap();
        }
        root
    }

    #[test]
    fn matches_whole_component() {
        let root = tree("whole", &["usr/local/nvm/versions/node/v22.1.0/bin/node"]);
        let pat = format!("{}/usr/local/nvm/versions/node/*/bin/node", root.display());
        assert_eq!(glob_paths(&pat).len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    /// CloudLinux's layout: the `*` sits inside a component, after a literal.
    #[test]
    fn matches_partial_component() {
        let root = tree(
            "partial",
            &[
                "opt/alt/alt-nodejs20/root/usr/bin/node",
                "opt/alt/alt-nodejs22/root/usr/bin/node",
                "opt/alt/alt-php81/root/usr/bin/node",
            ],
        );
        let pat = format!("{}/opt/alt/alt-nodejs*/root/usr/bin/node", root.display());
        let mut got: Vec<String> = glob_paths(&pat)
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        got.sort();
        assert_eq!(got.len(), 2, "alt-php81 must not match: {got:?}");
        assert!(got.iter().all(|p| p.contains("alt-nodejs")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_multiple_stars_and_missing_dir() {
        assert!(glob_paths("/opt/*/x/*/node").is_empty());
        assert!(glob_paths("/nonexistent-selynt/*/node").is_empty());
    }
}
