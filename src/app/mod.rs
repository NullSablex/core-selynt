//! An application's life cycle: registering it, launching it, watching it, and
//! taking it down.

pub mod appfile;
pub mod boot;
pub mod commands;
pub mod logs;
pub mod start;
pub mod validate;

use std::path::Path;

use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;

use crate::sys::fs::parse_kv;
use crate::sys::output::debug;
use crate::sys::proc::{is_process_alive, read_proc_starttime, read_proc_uid};
use crate::sys::state::{AppMeta, SYNC_MARKER};

const STOP_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Linux PIDs fit in `i32` (kernel max is `2^22`), so the `as` cast cannot wrap
/// for any real PID; we centralise it here so the `cast_possible_wrap` lint
/// gets one allow instead of dozens.
#[allow(clippy::cast_possible_wrap)]
pub const fn to_nix_pid(pid: u32) -> Pid {
    Pid::from_raw(pid as i32)
}

/// Merges a `_debug` block into a JSON response when debug mode is on.
pub fn with_debug(mut val: Value, debug: Option<&Value>) -> Value {
    if let Some(dbg) = debug {
        val["_debug"] = dbg.clone();
    }
    val
}

/// Starts one app by invoking the installed binary again, as `username`.
///
/// `cmd_start` ends the process when done, so it cannot be called in a loop;
/// running it as a child also keeps one app's failure from ending a sweep over
/// many. The installed path is used rather than `/proc/self/exe` because this
/// binary is setuid and that path is the one the installer owns.
pub fn start_app_detached(username: &str, name: &str) -> bool {
    std::process::Command::new(format!(
        "{}/bin/core-selynt",
        crate::sys::state::PLUGIN_PATH
    ))
    .arg("start")
    .arg(name)
    .env("USERNAME", username)
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .output()
    .map_or_else(
        |e| {
            debug(format!("start '{name}': could not spawn: {e}"));
            false
        },
        |o| {
            // The child's own message, kept: a failure here used to surface only
            // as the app being down, with nothing saying why.
            if !o.status.success() {
                debug(format!(
                    "start '{name}' failed: {}",
                    String::from_utf8_lossy(&o.stdout).trim()
                ));
            }
            o.status.success()
        },
    )
}

/// Determines `(status, pid, started_at)` for an app, validating the PID
/// against `/proc/{pid}/status` (UID match) and `.meta` (anti-PID-reuse).
pub fn get_status(state_dir: &Path, name: &str) -> (String, Option<u32>, Option<u64>) {
    let pid_file = state_dir.join(".run").join(format!("{name}.pid"));
    let meta_file = state_dir.join(".run").join(format!("{name}.meta"));

    let Ok(pid_str) = std::fs::read_to_string(&pid_file) else {
        return ("STOPPED".to_string(), None, None);
    };
    let Ok(pid) = pid_str.trim().parse::<u32>() else {
        return ("STOPPED".to_string(), None, None);
    };

    let my_uid = nix::unistd::getuid().as_raw();
    if read_proc_uid(pid) != Some(my_uid) {
        return ("STOPPED".to_string(), None, None);
    }

    let meta_content = std::fs::read_to_string(&meta_file).unwrap_or_default();
    let meta_kv = parse_kv(&meta_content);
    if let Some(saved) = meta_kv.get("starttime") {
        let saved_start: u64 = saved.parse().unwrap_or(0);
        if saved_start > 0 && read_proc_starttime(pid) != Some(saved_start) {
            return ("STOPPED".to_string(), None, None);
        }
    }

    let started_at: Option<u64> = meta_kv.get("started_at").and_then(|v| v.parse().ok());
    ("RUNNING".to_string(), Some(pid), started_at)
}

/// Lightweight status check used by the admin command. Skips UID matching
/// because admin reads other users' state dirs as root before the drop.
pub fn admin_get_status(pid_file: &Path, meta_file: &Path) -> (String, Option<u32>, Option<u64>) {
    let Ok(pid_str) = std::fs::read_to_string(pid_file) else {
        return ("STOPPED".to_string(), None, None);
    };
    let Ok(pid) = pid_str.trim().parse::<u32>() else {
        return ("STOPPED".to_string(), None, None);
    };
    if is_process_alive(pid) {
        let started_at: Option<u64> = std::fs::read_to_string(meta_file)
            .ok()
            .and_then(|c| parse_kv(&c).get("started_at").and_then(|v| v.parse().ok()));
        ("RUNNING".to_string(), Some(pid), started_at)
    } else {
        ("STOPPED".to_string(), None, None)
    }
}

/// Touches the sync marker file so the cron sync job knows to re-render the
/// proxy config on its next minute tick.
pub fn signal_sync() {
    // Records that the proxy config no longer matches the live apps.
    //
    // Rewriting it means writing OpenLiteSpeed's config and reloading — both
    // root-only — and this runs after the drop. Re-invoking the setuid binary
    // does not help either: the drop sets `PR_SET_NO_NEW_PRIVS`, which children
    // inherit. A scheduled sweep picks the marker up.
    let _ = std::fs::write(SYNC_MARKER, b"");
}

/// Validates that a value cannot escape its containing directory: no `/`,
/// no `..`, no null bytes, and not empty.
pub fn validate_safe_component(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && !s.contains('\0') && !s.contains("..")
}

/// Stops a process without exiting. Used by `remove` and `restart` to share
/// the SIGTERM→poll→SIGKILL sequence with the user-facing `stop` command.
pub fn stop_internal(state_dir: &Path, name: &str, meta: &AppMeta, timeout_secs: u64) {
    let (status, pid_opt, _) = get_status(state_dir, name);
    if status == "STOPPED" {
        return;
    }
    let Some(pid) = pid_opt else { return };
    let nix_pid = to_nix_pid(pid);

    // An isolated app is launched through bwrap, and the pid the panel tracks
    // is bwrap's. It does not forward signals, so terminating only that pid
    // leaves the real process orphaned — still holding its socket. Collect the
    // descendants up front, while the parent links still exist.
    let descendants = crate::sys::proc::descendants_of(pid);

    // Remove the marker first so the proxy stops routing before we kill.
    let marker = state_dir.join(".proxy").join(&meta.host);
    let _ = std::fs::remove_file(&marker);

    let _ = kill(nix_pid, Signal::SIGTERM);
    for &d in &descendants {
        let _ = kill(to_nix_pid(d), Signal::SIGTERM);
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        std::thread::sleep(STOP_POLL_INTERVAL);
        if !is_process_alive(pid) && descendants.iter().all(|&d| !is_process_alive(d)) {
            break;
        }
        if Instant::now() >= deadline {
            let _ = kill(nix_pid, Signal::SIGKILL);
            for &d in &descendants {
                let _ = kill(to_nix_pid(d), Signal::SIGKILL);
            }
            std::thread::sleep(STOP_POLL_INTERVAL);
            break;
        }
    }

    let _ = std::fs::remove_file(crate::sys::state::active_socket_path(state_dir, meta));
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.pid")));
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.meta")));
}

#[cfg(test)]
mod tests {
    use super::validate_safe_component;

    #[test]
    fn validate_safe_component_blocks_traversal() {
        assert!(validate_safe_component("index.js"));
        assert!(!validate_safe_component("../etc/passwd"));
        assert!(!validate_safe_component("a/b"));
        assert!(!validate_safe_component(""));
        assert!(!validate_safe_component("a\0b"));
    }
}
