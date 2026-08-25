use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde_json::{Value, json};

use crate::sys::output::{success, user_error};
use crate::sys::state::{AppMeta, list_app_names, load_app_meta};
use crate::sys::fs::{atomic_write, set_perm};

use crate::runtime::kind::Runtime;
use super::logs::{read_tail, strip_ansi};
use super::validate::{
    cwd_escapes_home, scaffold_node_entry, validate_add_args, validate_meta_value,
    validate_rust_entry, write_env_file,
};
use super::{get_status, signal_sync, stop_internal, with_debug};

/// Args bundle for `cmd_add` — keeps the public function signature short.
pub struct AddArgs<'a> {
    pub name: &'a str,
    pub app_type: &'a str,
    pub cwd: Option<&'a str>,
    pub entry: &'a str,
    pub host: &'a str,
    pub domain: Option<&'a str>,
    pub subdomain: Option<&'a str>,
    pub node_version: Option<&'a str>,
    pub env_vars: &'a [String],
}

pub(crate) fn cmd_list(state_dir: &Path, dbg: Option<&Value>) -> ! {
    let names = list_app_names(state_dir);
    let mut apps = Vec::new();

    for name in &names {
        let meta = match load_app_meta(state_dir, name) {
            Ok(m) => m,
            Err(e) => {
                crate::sys::output::debug(format!("skipping '{name}': {e}"));
                continue;
            }
        };
        let (status, pid, started_at) = get_status(state_dir, name);
        let pid_val = pid.map_or(json!(null), |p| json!(p));

        let mut app = json!({
            "name":       name,
            "type":       meta.app_type,
            "status":     status,
            "pid":        pid_val,
            "host":       meta.host,
            "cwd":        meta.cwd,
            "entry":      meta.entry,
            "created_at": meta.created_at,
            "started_at": started_at,
        });
        if !meta.node_version.is_empty() {
            app["node_version"] = json!(meta.node_version);
        }
        apps.push(app);
    }

    success(with_debug(json!({ "apps": apps }), dbg))
}

pub(crate) fn cmd_status(state_dir: &Path, name: &str, dbg: Option<&Value>) -> ! {
    if load_app_meta(state_dir, name).is_err() {
        user_error("app_not_found", &format!("app '{name}' not found"));
    }
    let (status, pid, _) = get_status(state_dir, name);
    let pid_val = pid.map_or(json!(null), |p| json!(p));
    success(with_debug(json!({ "status": status, "pid": pid_val }), dbg))
}

pub(crate) fn cmd_stop(state_dir: &Path, name: &str, timeout_secs: u64, dbg: Option<&Value>) -> ! {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    let (status, _, _) = get_status(state_dir, name);
    if status == "STOPPED" {
        success(with_debug(json!({}), dbg));
    }

    stop_internal(state_dir, name, &meta, timeout_secs);

    // Clear boot-recovery intent — user explicitly stopped this app.
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.enabled")));

    signal_sync();
    success(with_debug(json!({}), dbg))
}

/// Restarts an app.
///
/// The stop and the respawn both happen in the root prelude — see there for
/// why. What is left here is the same readiness path `start` takes, so a
/// restart is reported exactly like a start: only once the app is answering.
///
/// `spawned_pid` is `None` when the prelude found nothing to launch (no
/// systemd, or the app's metadata could not be read); `cmd_start` then falls
/// back to spawning it directly.
pub(crate) fn cmd_restart(
    state_dir: &Path,
    name: &str,
    username: &str,
    web_user: &str,
    spawned_pid: Option<u32>,
    dbg: Option<&Value>,
) -> ! {
    if load_app_meta(state_dir, name).is_err() {
        user_error("app_not_found", &format!("app '{name}' not found"));
    }

    super::start::cmd_start(state_dir, name, username, web_user, spawned_pid, dbg)
}

pub(crate) fn cmd_add(state_dir: &Path, args: &AddArgs<'_>, dbg: Option<&Value>) -> ! {
    // The prelude resolved and checked this already, and wrote it into the
    // `.app` file. Reading it back is what keeps the two from disagreeing:
    // duplicating the default here is how the old one drifted into pointing
    // outside the home, where the check would then refuse it.
    let resolved_cwd = crate::sys::state::load_app_meta(state_dir, args.name)
        .map(|m| m.cwd)
        .unwrap_or_else(|_| args.cwd.unwrap_or_default().to_string());
    let cwd = resolved_cwd.as_str();

    validate_add_args(args, cwd);

    // The `.app` file was already written by the root prelude, which owns it:
    // it is the only piece of state that says what to execute, so the account
    // must not be able to forge one. See `app::appfile`.

    let cwd_path = PathBuf::from(cwd);
    if let Err(e) = std::fs::create_dir_all(&cwd_path) {
        user_error(
            "cwd_create_failed",
            &format!("failed to create cwd directory: {e:#}"),
        );
    }

    if !args.env_vars.is_empty() {
        write_env_file(&cwd_path, args.env_vars);
    }

    // Unknown types are rejected before reaching here (clap parses them into
    // AppType), so an unparseable value means metadata written by hand.
    if let Ok(rt) = Runtime::from_str(args.app_type) {
        let entry_path = cwd_path.join(args.entry);
        if rt.scaffolds_entry() {
            scaffold_node_entry(&entry_path, args.name);
        }
        if rt.requires_executable_entry() {
            validate_rust_entry(&entry_path);
        }
    }

    success(with_debug(json!({}), dbg))
}

/// Reports whether this account isolates its apps, and which are running.
pub(crate) fn cmd_status_isolated(state_dir: &Path, dbg: Option<&Value>) -> ! {
    // `supported` is separate from `isolated` on purpose: the first says
    // whether this host can isolate at all, the second whether the account
    // asked for it. Reporting only the preference would let the panel claim
    // isolation on a host that cannot provide it.
    let supported = crate::limits::sandbox::available();

    success(with_debug(
        json!({
            "isolated": crate::sys::state::account_is_isolated(state_dir),
            "supported": supported,
            "reason": (!supported).then(crate::limits::sandbox::unavailable_reason),
            "running": running_app_names(state_dir),
        }),
        dbg,
    ))
}

/// Turns isolation on or off for the whole account.
///
/// It is deliberately not per-app: a namespace confines what the process inside
/// it sees, but does not change its uid, so one non-isolated app could still
/// read an isolated sibling's files and signal its processes. Isolation only
/// means anything when it covers every app of the account.
/// Switches the account's isolation mode and restarts its running apps.
///
/// Runs as root, in the prelude. Isolation is decided when an app is launched
/// and it moves the app's socket, so a running app keeps its old mode until it
/// is restarted — leaving that to the user would make the setting look like it
/// had no effect. Recreating each systemd scope is privileged work, which is
/// why this cannot happen after the drop.
///
/// Returns the apps that came back up, and those that did not.
pub(crate) fn switch_isolation(
    state_dir: &Path,
    username: &str,
    isolated: bool,
) -> Result<IsolationSwitch, (String, String)> {
    // Refuse rather than accept a setting this host cannot honour. Storing it
    // anyway would leave the panel reporting isolation that is not in effect,
    // which is worse than not offering it: the account would believe its apps
    // are separated while they still share everything.
    if isolated && !crate::limits::sandbox::available() {
        return Err((
            "sandbox_unavailable".into(),
            crate::limits::sandbox::unavailable_reason().to_string(),
        ));
    }

    let flag = state_dir.join("isolated");
    let value = if isolated { "1\n" } else { "0\n" };
    atomic_write(&flag, value.as_bytes())
        .and_then(|()| set_perm(&flag, 0o644))
        .map_err(|e| ("write_failed".to_string(), format!("{e:#}")))?;

    // `admin_get_status`, not `get_status`: the latter requires the process uid
    // to match the caller's, and this runs as root, where it never does.
    let run = state_dir.join(".run");
    let running: Vec<String> = list_app_names(state_dir)
        .into_iter()
        .filter(|n| {
            super::admin_get_status(
                &run.join(format!("{n}.pid")),
                &run.join(format!("{n}.meta")),
            )
            .0 == "RUNNING"
        })
        .collect();

    let mut switch = IsolationSwitch::default();
    for name in running {
        let Ok(meta) = load_app_meta(state_dir, &name) else {
            continue;
        };
        crate::limits::netguard::stop_app_tree(state_dir, &name, &meta);

        // Applying the new mode means stopping the app first, so a failed
        // restart leaves it down. Reporting only the successes would have the
        // panel announce the switch worked while the app it just took down
        // never came back — the account would find it stopped with no clue why.
        if super::start_app_detached(username, &name) {
            switch.restarted.push(name);
        } else {
            switch.failed.push(name);
        }
    }

    Ok(switch)
}

/// Outcome of an isolation switch: the apps that came back up, and those that
/// stayed down after being stopped to apply it.
#[derive(Default)]
pub struct IsolationSwitch {
    pub restarted: Vec<String>,
    pub failed: Vec<String>,
}

/// Names of the account's apps that are currently running.
pub(crate) fn running_app_names(state_dir: &Path) -> Vec<String> {
    list_app_names(state_dir)
        .into_iter()
        .filter(|n| get_status(state_dir, n).0 == "RUNNING")
        .collect()
}

/// Reports the new isolation mode and which apps were restarted to apply it.
///
/// The switch itself — writing the flag and restarting the apps — happens in
/// the root prelude: applying it means recreating each app's systemd scope,
/// which needs privileges this side of the drop no longer has.
pub(crate) fn cmd_set_isolated(isolated: bool, switch: IsolationSwitch, dbg: Option<&Value>) -> ! {
    success(with_debug(
        json!({
            "isolated": isolated,
            "restarted": switch.restarted,
            "failed": switch.failed,
        }),
        dbg,
    ))
}

pub(crate) fn cmd_set_node_version(
    state_dir: &Path,
    name: &str,
    node_version: &str,
    dbg: Option<&Value>,
) -> ! {
    if load_app_meta(state_dir, name).is_err() {
        user_error("app_not_found", &format!("app '{name}' not found"));
    }
    if !validate_meta_value(node_version) {
        user_error(
            "invalid_node_version",
            "node_version must not contain newlines or null bytes",
        );
    }

    // Written by the root prelude — the account cannot modify `.app` itself.

    // The running process keeps the old runtime until it is restarted.
    let (status, _, _) = get_status(state_dir, name);
    let restart_required = status == "RUNNING";

    success(with_debug(
        json!({ "restart_required": restart_required }),
        dbg,
    ))
}

/// Sets (or clears) an app's memory cap. Stored in the `.app` file and applied
/// on the next start — the running scope keeps its current limit.
/// Writes the cap into the `.app` file. Separate from `cmd_set_memory_max` so
/// the root prelude can persist it *before* re-resolving every sibling's cap.
pub(crate) fn apply_memory_max(state_dir: &Path, name: &str, megabytes: u64, uid: u32, gid: u32) {
    if megabytes != 0 && megabytes < 16 {
        return;   // validated (and reported) by cmd_set_memory_max
    }
    let app_file = state_dir.join(".run").join(format!("{name}.app"));
    let Ok(current) = std::fs::read_to_string(&app_file) else {
        return;
    };

    let bytes = megabytes.saturating_mul(1024 * 1024);
    let mut out = String::with_capacity(current.len() + 32);
    for line in current.lines() {
        if line.split_once('=').map(|(k, _)| k.trim()) == Some("memory_max") {
            continue;   // rewritten below (or dropped, when clearing)
        }
        out.push_str(line);
        out.push('\n');
    }
    if bytes > 0 {
        out.push_str(&format!("memory_max={bytes}\n"));
    }
    let _ = atomic_write(&app_file, out.as_bytes()).and_then(|()| set_perm(&app_file, 0o600));
    // This runs as root, so the rewritten file would end up owned by root and
    // become unreadable to the user once privileges are dropped — the command
    // would then fail with `app_not_found` on its own file.
    let _ = crate::sys::fs::chown_path(&app_file, uid, gid);
}

pub(crate) fn cmd_set_memory_max(state_dir: &Path, name: &str, megabytes: u64, dbg: Option<&Value>) -> ! {
    if load_app_meta(state_dir, name).is_err() {
        user_error("app_not_found", &format!("app '{name}' not found"));
    }
    // 16 MB is below anything a Node process can start in; accepting less would
    // just produce an app that is OOM-killed on boot.
    if megabytes != 0 && megabytes < 16 {
        user_error("invalid_memory_max", "memory cap must be 0 (auto) or at least 16 MB");
    }

    // The write and the cap re-resolution already happened in the root prelude.
    let bytes = megabytes.saturating_mul(1024 * 1024);
    let (status, _, _) = get_status(state_dir, name);
    success(with_debug(
        json!({
            "memory_max": if bytes > 0 { json!(bytes) } else { json!(null) },
            // The new cap is live already; a restart is only needed for the app
            // to *use* more memory, never for the limit to take effect.
            "running": status == "RUNNING",
        }),
        dbg,
    ))
}

pub(crate) fn cmd_remove(
    state_dir: &Path,
    name: &str,
    delete_dir: bool,
    meta: Option<AppMeta>,
    dbg: Option<&Value>,
) -> ! {
    // The prelude removed the root-owned `.app` and handed the metadata over,
    // since the account cannot delete that file itself.
    let Some(meta) = meta else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    stop_internal(state_dir, name, &meta, 10);

    // Defensive — `stop_internal` already removed the socket, but on failure the
    // app still has to disappear from disk. Read while `.meta` is still around,
    // since that is what records where the socket really is.
    let active_socket = crate::sys::state::active_socket_path(state_dir, &meta);

    let run_dir = state_dir.join(".run");
    for ext in &["pid", "meta", "enabled"] {
        let _ = std::fs::remove_file(run_dir.join(format!("{name}.{ext}")));
    }

    let cwd_path = PathBuf::from(&meta.cwd);

    let _ = std::fs::remove_file(&active_socket);
    // The configured path too: it differs from the active one when the account
    // switched isolation mode while the app was down, and neither may be left
    // behind.
    let _ = std::fs::remove_file(crate::sys::state::socket_path_for(state_dir, &meta));
    let _ = std::fs::remove_dir(state_dir.join(".sockets").join(name));
    let _ = std::fs::remove_file(state_dir.join(".proxy").join(&meta.host));

    if delete_dir {
        // Never delete *through* a link. `remove_dir_all` on a symlinked cwd
        // wipes the target's contents, so an app pointed at a data directory
        // would take it down with it. Re-checked here rather than trusting the
        // stored path, since apps registered before this validation existed can
        // still hold an escaping cwd.
        match std::fs::symlink_metadata(&cwd_path) {
            Ok(md) if md.file_type().is_symlink() => user_error(
                "cwd_is_symlink",
                "refusing to delete a cwd that is a symlink; remove the link manually",
            ),
            Ok(_) => {
                if cwd_escapes_home(&cwd_path) {
                    user_error(
                        "cwd_outside_home",
                        "refusing to delete a cwd outside the user's home directory",
                    );
                }
                let _ = std::fs::remove_dir_all(&cwd_path);
            }
            // Already gone — nothing to delete.
            Err(_) => {}
        }
    } else {
        // Keep user files (.env, logs) when the directory is preserved — only
        // strip files that no longer make sense without the app registration.
        let logs_dir = cwd_path.join("logs");
        let _ = std::fs::remove_file(logs_dir.join(format!("{name}.out.log")));
        let _ = std::fs::remove_file(logs_dir.join(format!("{name}.err.log")));
    }

    signal_sync();
    success(with_debug(json!({}), dbg))
}

/// Receives data pre-loaded as root (before the privilege drop). Each entry is
/// `(domain, subdomain_prefixes)`.
pub(crate) fn cmd_domains(data: Vec<(String, Vec<String>)>, dbg: Option<&Value>) -> ! {
    let domains_json: Vec<Value> = data
        .into_iter()
        .map(|(domain, subs)| {
            let subdomains: Vec<Value> = subs
                .iter()
                .map(|sub| json!({ "host": format!("{sub}.{domain}") }))
                .collect();
            json!({ "host": domain, "subdomains": subdomains })
        })
        .collect();

    success(with_debug(json!({ "domains": domains_json }), dbg))
}

pub(crate) fn cmd_logs(
    state_dir: &Path,
    name: &str,
    lines: usize,
    use_stderr: bool,
    dbg: Option<&Value>,
) -> ! {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    // Logs are live output: a stopped app has nothing to say. Its file still
    // holds the last run's lines, but showing those would present a finished
    // run as if it were current.
    let (status, _, _) = get_status(state_dir, name);
    if status != "RUNNING" {
        success(with_debug(json!({ "lines": Vec::<String>::new() }), dbg));
    }

    let suffix = if use_stderr { "err" } else { "out" };
    let log_file = PathBuf::from(&meta.cwd)
        .join("logs")
        .join(format!("{name}.{suffix}.log"));

    // Apps commonly log through libraries that colourise unconditionally (Rust's
    // tracing-subscriber, chalk, colorette…). Written to a file those escapes
    // are just bytes, and the panel renders them as literal `[2m`/`[0m` noise,
    // so strip them here — the viewer is HTML, not a terminal.
    let log_lines: Vec<String> = read_tail(&log_file, lines)
        .iter()
        .map(|l| strip_ansi(l))
        .collect();
    success(with_debug(json!({ "lines": log_lines }), dbg))
}
