use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::output::success;
use crate::state::PLUGIN_PATH;

use super::node::{get_node_version, glob_paths};
use super::{admin_get_status, with_debug};

const NODE_FIXED_PATHS: [&str; 2] = ["/usr/local/bin/node", "/usr/bin/node"];
/// Roots a detected runtime may ultimately live under, checked *after* symlinks
/// are resolved. A candidate found in a trusted directory can still be a symlink
/// pointing somewhere a customer controls, and detection executes it.
const NODE_TRUSTED_ROOTS: [&str; 3] = ["/usr/bin/", "/usr/local/", "/opt/"];
const NODE_GLOBS: [&str; 3] = [
    "/usr/local/nvm/versions/node/*/bin/node",
    "/opt/alt/alt-nodejs*/root/usr/bin/node",
    // Where the official tarball is conventionally unpacked. Reached only via
    // the /usr/local/bin/node symlink otherwise, so a second version installed
    // here alongside the first would go undetected.
    "/usr/local/lib/nodejs/*/bin/node",
];

pub fn cmd_admin_list(apps: &[Value], dbg: Option<&Value>) -> ! {
    success(with_debug(json!({ "apps": apps }), dbg))
}

pub fn cmd_admin_detect_nodes(dbg: Option<&Value>) -> ! {
    let versions: Vec<Value> = detect_node_versions()
        .into_iter()
        .map(|(path, ver)| json!({"version": ver, "path": path}))
        .collect();
    success(with_debug(json!({ "versions": versions }), dbg))
}

/// Collects every user's app metadata. Must run as root (before the privilege
/// drop), because per-user state dirs are owned by their respective users.
pub fn collect_admin_list() -> Vec<Value> {
    let mut apps = Vec::new();

    for (user_home, user) in crate::state::list_accounts() {
        let run_dir = user_home.join(".run");
        let Ok(run_entries) = std::fs::read_dir(&run_dir) else {
            continue;
        };

        for entry in run_entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("app") {
                continue;
            }

            let Some(name) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string)
            else {
                continue;
            };

            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let kv = crate::state::parse_kv(&content);

            let app_type = kv.get("type").cloned().unwrap_or_default();
            let host = kv.get("host").cloned().unwrap_or_default();
            let cwd = kv.get("cwd").cloned().unwrap_or_default();
            let entry_file = kv.get("entry").cloned().unwrap_or_default();
            let created_at: Option<u64> = kv.get("created_at").and_then(|v| v.parse().ok());

            let pid_file = run_dir.join(format!("{name}.pid"));
            let meta_file = run_dir.join(format!("{name}.meta"));
            let (status, pid, started_at) = admin_get_status(&pid_file, &meta_file);
            let pid_val = pid.map_or(json!(null), |p| json!(p));

            // Resource usage comes from the app's own cgroup. Folded into this
            // sweep on purpose: the overview refreshes every 15s across every
            // account, and one `stats` call per app would multiply that load.
            let usage = if status == "RUNNING" {
                super::stats::read_scope_usage(&user, &name)
            } else {
                None
            };

            apps.push(json!({
                "user":       user,
                "name":       name,
                "type":       app_type,
                "host":       host,
                "cwd":        cwd,
                "entry":      entry_file,
                "status":     status,
                "pid":        pid_val,
                "created_at": created_at,
                "started_at": started_at,
                "memory":     usage.map(|u| u.memory_bytes),
                "cpu_usec":   usage.map(|u| u.cpu_usec),
            }));
        }
    }

    apps.sort_by(|a, b| {
        let ua = a["user"].as_str().unwrap_or("");
        let ub = b["user"].as_str().unwrap_or("");
        let na = a["name"].as_str().unwrap_or("");
        let nb = b["name"].as_str().unwrap_or("");
        ua.cmp(ub).then(na.cmp(nb))
    });

    apps
}

/// Every path the detector will look at, before any safety judgement.
///
/// Detection *executes* each candidate to read its `--version`, so whatever
/// directory is accepted here is a directory whose contents get run. Allowing
/// `/home/` meant any customer on a shared box could plant a binary there and
/// have it executed — as root, when reached through `save-node-versions` in the
/// root prelude. Being listed here is not trust: see `is_safe_to_execute`.
fn node_candidates() -> Vec<PathBuf> {
    let nvm_dir_glob = std::env::var("NVM_DIR")
        .ok()
        .filter(|d| {
            let safe = d.starts_with("/opt/") || d.starts_with("/usr/local/");
            safe && !d.contains("..")
        })
        .map(|d| format!("{d}/versions/node/*/bin/node"));

    let mut candidates: Vec<PathBuf> = NODE_FIXED_PATHS.iter().map(PathBuf::from).collect();
    for pattern in NODE_GLOBS
        .iter()
        .map(|s| (*s).to_string())
        .chain(nvm_dir_glob)
    {
        candidates.extend(glob_paths(&pattern));
    }
    candidates
}

/// Detects Node.js runtimes installed on the system. Returns
/// `Vec<(path, version)>` — e.g. `("/usr/bin/node", "v22.22.0")`.
pub(super) fn detect_node_versions() -> Vec<(String, String)> {
    let candidates = node_candidates();

    let mut versions = Vec::new();
    let mut seen = HashSet::new();
    for path in &candidates {
        if !path.is_file() {
            continue;
        }
        // Resolve before trusting: `is_file` follows symlinks, so a link planted
        // in a trusted directory would otherwise have its target executed below.
        let Ok(canonical) = std::fs::canonicalize(path) else {
            continue;
        };
        if !is_safe_to_execute(&canonical) {
            continue;
        }
        if !seen.insert(canonical) {
            continue;
        }
        if let Some(ver) = get_node_version(path) {
            versions.push((path.to_string_lossy().to_string(), ver));
        }
    }
    versions
}

/// Whether a *resolved* runtime path lies under a root reserved for
/// system-wide software.
fn is_trusted_runtime_path(canonical: &Path) -> bool {
    NODE_TRUSTED_ROOTS
        .iter()
        .any(|root| canonical.starts_with(root))
}

/// Runtime binaries that exist in a searched location but were refused, paired
/// with why. Detection skips these silently — it must, since executing them is
/// the risk — so the diagnostic reports them instead: "installed it and the
/// panel does not list it" is otherwise indistinguishable from a broken glob.
pub(super) fn rejected_node_runtimes() -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for path in node_candidates() {
        if !path.is_file() {
            continue;
        }
        let Ok(canonical) = std::fs::canonicalize(&path) else {
            continue;
        };
        if !seen.insert(canonical.clone()) {
            continue;
        }
        if is_safe_to_execute(&canonical) {
            continue;
        }
        let reason = if !is_trusted_runtime_path(&canonical) {
            "untrusted_path"
        } else {
            "unsafe_ownership"
        };
        out.push((path.to_string_lossy().to_string(), reason));
    }
    out
}

/// Whether a runtime binary is safe for the detector to execute as root.
///
/// Location alone is not enough. Runtime trees are routinely left owned by the
/// account that unpacked them (a tarball extracted with its original uid, or
/// nvm preserving the owner of `$NVM_DIR`), and `npm install -g` writes into
/// that same tree as that account. Anyone who can write the file — or any
/// directory leading to it — can choose what runs as root here.
fn is_safe_to_execute(canonical: &Path) -> bool {
    if !is_trusted_runtime_path(canonical) {
        return false;
    }
    // The file itself, plus every directory above it: a writable parent means
    // the binary can simply be replaced.
    let mut current = Some(canonical);
    while let Some(p) = current {
        if !is_root_owned_and_unwritable(p) {
            return false;
        }
        if p.parent().is_none_or(|parent| parent == p) {
            break;
        }
        current = p.parent();
    }
    true
}

/// Root-owned and writable by nobody but root.
fn is_root_owned_and_unwritable(path: &Path) -> bool {
    let Ok(md) = std::fs::metadata(path) else {
        return false;
    };
    md.uid() == 0 && md.mode() & 0o022 == 0
}

/// Persists the server-wide default for whether new apps start isolated.
pub fn save_default_isolated(isolated: bool) -> Result<Value, (String, String)> {
    let etc_dir = Path::new(PLUGIN_PATH).join("etc");
    if !etc_dir.is_dir() {
        std::fs::create_dir_all(&etc_dir).map_err(|e| {
            (
                "write_failed".into(),
                format!("failed to create {}: {e}", etc_dir.display()),
            )
        })?;
        let _ = std::fs::set_permissions(&etc_dir, std::fs::Permissions::from_mode(0o755));
    }

    let file = etc_dir.join("default_isolated");
    let value = if isolated { "1\n" } else { "0\n" };
    std::fs::write(&file, value).map_err(|e| {
        (
            "write_failed".into(),
            format!("failed to write {}: {e}", file.display()),
        )
    })?;
    // World-readable: the check runs after the privilege drop, as the account.
    let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644));

    Ok(json!({ "isolated": isolated }))
}

/// Persists the user-selected Node.js runtimes (by detection index) into
/// `{plugin}/etc/node_versions`. Runs as root before the privilege drop.
pub fn save_node_versions(indices: &[usize]) -> Result<Value, (String, String)> {
    let all = detect_node_versions();
    if all.is_empty() {
        return Err(("no_versions".into(), "No Node.js versions detected.".into()));
    }

    let mut selected = Vec::new();
    // Version -> path it was first claimed by, so a clash can name both sides.
    let mut seen_ver: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut dupes = Vec::new();

    for &idx in indices {
        if idx >= all.len() {
            return Err((
                "invalid_index".into(),
                format!("Index {idx} out of range (max: {}).", all.len() - 1),
            ));
        }
        let (ref path, ref ver) = all[idx];
        if let Some(first) = seen_ver.get(ver) {
            dupes.push(format!("{ver} ({first} and {path})"));
            continue;
        }
        seen_ver.insert(ver.clone(), path.clone());
        selected.push(format!("{path} {ver}"));
    }

    if !dupes.is_empty() {
        let list = dupes.join(", ");
        return Err((
            "duplicate_versions".into(),
            format!("Same version installed twice: {list}. Pick one."),
        ));
    }

    if selected.is_empty() {
        return Err(("no_selection".into(), "No valid version selected.".into()));
    }

    let etc_dir = Path::new(PLUGIN_PATH).join("etc");
    if !etc_dir.is_dir() {
        std::fs::create_dir_all(&etc_dir).map_err(|e| {
            (
                "write_failed".into(),
                format!("failed to create {}: {e}", etc_dir.display()),
            )
        })?;
    }
    // The admin CGI runs as the logged-in admin (not as `diradmin`), so the
    // directory needs world-readable traverse.
    let _ = std::fs::set_permissions(&etc_dir, std::fs::Permissions::from_mode(0o755));

    let nv_file = etc_dir.join("node_versions");
    let content = selected.join("\n") + "\n";
    std::fs::write(&nv_file, content.as_bytes()).map_err(|e| {
        (
            "write_failed".into(),
            format!("failed to write {}: {e}", nv_file.display()),
        )
    })?;
    let _ = std::fs::set_permissions(&nv_file, std::fs::Permissions::from_mode(0o644));

    Ok(json!({
        "message": "Versions saved.",
        "saved": selected.len(),
        "file": nv_file.to_string_lossy(),
    }))
}

#[cfg(test)]
mod tests {
    use super::is_trusted_runtime_path;
    use std::path::Path;

    #[test]
    fn accepts_root_owned_locations() {
        for p in [
            "/usr/local/bin/node",
            "/usr/bin/node",
            "/usr/local/nvm/versions/node/v22.23.2/bin/node",
            "/usr/local/lib/nodejs/node-v25.9.0/bin/node",
            "/opt/alt/alt-nodejs20/root/usr/bin/node",
        ] {
            assert!(is_trusted_runtime_path(Path::new(p)), "{p} should be trusted");
        }
    }

    /// Files we create in the test are owned by the test user, not root, so
    /// they must be refused however trusted their location looks.
    #[test]
    fn rejects_binaries_not_owned_by_root() {
        use super::is_safe_to_execute;
        let f = std::env::temp_dir().join(format!("selynt-own-{}", std::process::id()));
        std::fs::write(&f, b"").unwrap();
        assert!(!is_safe_to_execute(&f));
        let _ = std::fs::remove_file(&f);
    }

    /// Under a normal system layout the packaged runtimes are root-owned, so
    /// the check must not reject them — otherwise detection returns nothing.
    #[test]
    fn accepts_a_real_root_owned_binary() {
        use super::is_safe_to_execute;
        // /bin/sh is root-owned on every supported distro; skip if the test
        // environment says otherwise rather than failing spuriously.
        let sh = std::path::Path::new("/bin/sh");
        let Ok(canonical) = std::fs::canonicalize(sh) else {
            return;
        };
        if canonical.starts_with("/usr/bin/") {
            assert!(is_safe_to_execute(&canonical), "{} should pass", canonical.display());
        }
    }

    /// A symlink sitting in a trusted directory may resolve into a customer's
    /// home; detection executes what it finds, so the resolved path is what
    /// must be judged.
    #[test]
    fn rejects_targets_outside_trusted_roots() {
        for p in [
            "/home/attacker/fake-node",
            "/tmp/node",
            "/var/tmp/node",
            "/usr/local-evil/node",
        ] {
            assert!(!is_trusted_runtime_path(Path::new(p)), "{p} must be rejected");
        }
    }
}
