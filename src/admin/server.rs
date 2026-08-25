use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{Value, json};

use crate::sys::output::success;
use crate::sys::state::PLUGIN_PATH;

use crate::runtime::detect::detect_node_versions;
use crate::cmd::{admin_get_status, with_debug};


pub(crate) fn cmd_admin_list(apps: &[Value], dbg: Option<&Value>) -> ! {
    success(with_debug(json!({ "apps": apps }), dbg))
}

pub(crate) fn cmd_admin_detect_nodes(dbg: Option<&Value>) -> ! {
    let versions: Vec<Value> = detect_node_versions()
        .into_iter()
        .map(|(path, ver)| json!({"version": ver, "path": path}))
        .collect();
    success(with_debug(json!({ "versions": versions }), dbg))
}

/// Collects every user's app metadata. Must run as root (before the privilege
/// drop), because per-user state dirs are owned by their respective users.
pub(crate) fn collect_admin_list() -> Vec<Value> {
    let mut apps = Vec::new();

    for (user_home, user) in crate::sys::state::list_accounts() {
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
            let kv = crate::sys::fs::parse_kv(&content);

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
                crate::limits::usage::read_scope_usage(&user, &name)
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


/// Persists the server-wide default for whether new apps start isolated.
pub(crate) fn save_default_isolated(isolated: bool) -> Result<Value, (String, String)> {
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
pub(crate) fn save_node_versions(indices: &[usize]) -> Result<Value, (String, String)> {
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
