mod admin;
mod locale;
mod manage;
mod node;
mod start;

pub use admin::{cmd_admin_detect_nodes, cmd_admin_list, collect_admin_list, save_node_versions};
pub use locale::{set_locale_global, set_locale_user};
pub use manage::{
    AddArgs, cmd_add, cmd_domains, cmd_list, cmd_logs, cmd_remove, cmd_restart,
    cmd_set_node_version, cmd_status, cmd_stop,
};
pub use start::cmd_start;

use std::path::Path;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;

use crate::proc::{is_process_alive, read_proc_starttime, read_proc_uid};
use crate::state::{AppMeta, parse_kv};

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
    let _ = std::fs::write("/var/lib/selynt_panel/.sync_needed", b"");
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

    // Remove the marker first so the proxy stops routing before we kill.
    let marker = state_dir.join(".proxy").join(&meta.host);
    let _ = std::fs::remove_file(&marker);

    let _ = kill(nix_pid, Signal::SIGTERM);

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        std::thread::sleep(STOP_POLL_INTERVAL);
        if !is_process_alive(pid) {
            break;
        }
        if Instant::now() >= deadline {
            let _ = kill(nix_pid, Signal::SIGKILL);
            std::thread::sleep(STOP_POLL_INTERVAL);
            break;
        }
    }

    let _ = std::fs::remove_file(state_dir.join(".sockets").join(&meta.host));
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.pid")));
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.meta")));
}
