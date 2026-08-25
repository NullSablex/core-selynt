use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{Value, json};

use crate::sys::output::success;
use crate::sys::state::PLUGIN_PATH;

use crate::app::{admin_get_status, with_debug};
use crate::runtime::detect::detect_node_versions;

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
/// Describes one app from its `.app` file, for the admin overview.
///
/// `None` when the file is not one — a stray name, or unreadable.
fn describe_app(run_dir: &Path, path: &Path, user: &str) -> Option<Value> {
    if path.extension().and_then(|e| e.to_str()) != Some("app") {
        return None;
    }
    let name = path.file_stem().and_then(|s| s.to_str())?.to_string();
    let kv = crate::sys::fs::parse_kv(&std::fs::read_to_string(path).ok()?);

    let (status, pid, started_at) = admin_get_status(
        &run_dir.join(format!("{name}.pid")),
        &run_dir.join(format!("{name}.meta")),
    );

    // Usage comes from the app's own cgroup, folded into this sweep on purpose:
    // the overview refreshes every 15s across every account, and one `stats`
    // call per app would multiply that load.
    let usage = (status == "RUNNING")
        .then(|| crate::limits::usage::read_scope_usage(user, &name))
        .flatten();

    let field = |k: &str| kv.get(k).cloned().unwrap_or_default();
    Some(json!({
        "user":       user,
        "name":       name,
        "type":       field("type"),
        "host":       field("host"),
        "cwd":        field("cwd"),
        "entry":      field("entry"),
        "status":     status,
        "pid":        pid.map_or(json!(null), |p| json!(p)),
        "created_at": kv.get("created_at").and_then(|v| v.parse::<u64>().ok()),
        "started_at": started_at,
        "memory":     usage.map(|u| u.memory_bytes),
        "cpu_usec":   usage.map(|u| u.cpu_usec),
    }))
}

/// Every app on the server, for the administrator's overview.
pub(crate) fn collect_admin_list() -> Vec<Value> {
    let mut apps = Vec::new();

    for (user_home, user) in crate::sys::state::list_accounts() {
        let run_dir = user_home.join(".run");
        let Ok(entries) = std::fs::read_dir(&run_dir) else {
            continue;
        };
        apps.extend(
            entries
                .flatten()
                .filter_map(|e| describe_app(&run_dir, &e.path(), &user)),
        );
    }

    apps.sort_by(|a, b| {
        let key = |v: &Value| {
            (
                v["user"].as_str().unwrap_or("").to_string(),
                v["name"].as_str().unwrap_or("").to_string(),
            )
        };
        key(a).cmp(&key(b))
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
/// Resolves the chosen indices into `<path> <version>` lines.
///
/// Refuses two paths carrying the same version: the panel keys runtimes by
/// version, so a duplicate would make one of them unreachable.
fn resolve_selection(indices: &[usize]) -> Result<Vec<String>, (String, String)> {
    let all = detect_node_versions();
    if all.is_empty() {
        return Err(("no_versions".into(), "No Node.js versions detected.".into()));
    }

    let mut selected = Vec::new();
    let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    let mut dupes = Vec::new();

    for &idx in indices {
        let Some((path, ver)) = all.get(idx) else {
            return Err((
                "invalid_index".into(),
                format!("Index {idx} out of range (max: {}).", all.len() - 1),
            ));
        };
        if let Some(first) = seen.get(ver.as_str()) {
            dupes.push(format!("{ver} ({first} and {path})"));
            continue;
        }
        seen.insert(ver, path);
        selected.push(format!("{path} {ver}"));
    }

    if !dupes.is_empty() {
        return Err((
            "duplicate_versions".into(),
            format!(
                "Same version installed twice: {}. Pick one.",
                dupes.join(", ")
            ),
        ));
    }
    if selected.is_empty() {
        return Err(("no_selection".into(), "No valid version selected.".into()));
    }
    Ok(selected)
}

/// Persists the runtimes the administrator chose.
pub(crate) fn save_node_versions(indices: &[usize]) -> Result<Value, (String, String)> {
    let selected = resolve_selection(indices)?;

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
