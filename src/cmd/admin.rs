use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::output::success;
use crate::state::PLUGIN_PATH;

use super::node::{get_node_version, glob_paths};
use super::{admin_get_status, with_debug};

const STATE_BASE: &str = "/var/lib/selynt_panel";
const NODE_FIXED_PATHS: [&str; 2] = ["/usr/local/bin/node", "/usr/bin/node"];
const NODE_GLOBS: [&str; 2] = [
    "/usr/local/nvm/versions/node/*/bin/node",
    "/opt/alt/alt-nodejs*/root/usr/bin/node",
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

    let Ok(home_entries) = std::fs::read_dir(STATE_BASE) else {
        return apps;
    };

    for home_entry in home_entries.flatten() {
        let user_home = home_entry.path();
        if !user_home.is_dir() {
            continue;
        }
        let Some(user) = user_home
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };

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

/// Detects Node.js runtimes installed on the system. Returns
/// `Vec<(path, version)>` — e.g. `("/usr/bin/node", "v22.22.0")`.
pub(super) fn detect_node_versions() -> Vec<(String, String)> {
    // Detection *executes* each candidate to read its `--version`, so whatever
    // directory is accepted here is a directory whose contents get run. Allowing
    // `/home/` meant any customer on a shared box could plant a binary there and
    // have it executed — as root, when reached through `save-node-versions` in
    // the root prelude. Keep this to root-controlled locations only.
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

    let mut versions = Vec::new();
    let mut seen = HashSet::new();
    for path in &candidates {
        if !path.is_file() {
            continue;
        }
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        if !seen.insert(canonical) {
            continue;
        }
        if let Some(ver) = get_node_version(path) {
            versions.push((path.to_string_lossy().to_string(), ver));
        }
    }
    versions
}

/// Persists the user-selected Node.js runtimes (by detection index) into
/// `{plugin}/etc/node_versions`. Runs as root before the privilege drop.
pub fn save_node_versions(indices: &[usize]) -> Result<Value, (String, String)> {
    let all = detect_node_versions();
    if all.is_empty() {
        return Err(("no_versions".into(), "No Node.js versions detected.".into()));
    }

    let mut selected = Vec::new();
    let mut seen_ver = HashSet::new();
    let mut dupes = Vec::new();

    for &idx in indices {
        if idx >= all.len() {
            return Err((
                "invalid_index".into(),
                format!("Index {idx} out of range (max: {}).", all.len() - 1),
            ));
        }
        let (ref path, ref ver) = all[idx];
        if !seen_ver.insert(ver.clone()) {
            dupes.push(ver.clone());
            continue;
        }
        selected.push(format!("{path} {ver}"));
    }

    if !dupes.is_empty() {
        let list = dupes.join(", ");
        return Err((
            "duplicate_versions".into(),
            format!("Duplicate versions: {list}. Each version must map to a single path."),
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
