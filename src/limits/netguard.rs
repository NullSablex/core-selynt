//! Enforces the no-external-port rule for apps that are already running.
//!
//! `cmd_start` checks this once, while the app is starting. That is not enough:
//! the `node-loader` hook it relies on only covers the app's own process, so a
//! child spawned without it — or any app that is not Node — can bind a port at
//! any moment afterwards. This sweep closes that window by looking at every
//! process in the app's cgroup, whenever it is invoked.
//!
//! Loopback is deliberately allowed. An app talking to itself (a local cache,
//! IPC between its own workers) harms nobody; what the panel forbids is a port
//! reachable from off the host, which bypasses its proxy entirely.

use std::path::Path;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use serde_json::{Value, json};

use crate::sys::output::debug;
use crate::sys::proc::{has_external_listen, is_process_alive};
use crate::sys::state::{AppMeta, list_app_names, load_app_meta};

use crate::app::to_nix_pid;

/// Grace period for the app to shut down before it is killed.
const STOP_TIMEOUT_SECS: u64 = 5;

/// Checks every app of an account and stops those bound to an external port.
///
/// Returns the names that were stopped. Runs as root, so it can act on the
/// account's processes.
pub(crate) fn sweep_account(state_dir: &Path, username: &str) -> Vec<String> {
    let mut stopped = Vec::new();

    for name in list_app_names(state_dir) {
        let Ok(meta) = load_app_meta(state_dir, &name) else {
            continue;
        };
        let pids = super::usage::scope_pids(username, &name);
        if pids.is_empty() {
            continue;
        }
        if !has_external_listen(&pids) {
            continue;
        }

        debug(format!(
            "netguard: '{name}' bound an externally reachable port — stopping"
        ));
        stop_offending_app(state_dir, &name, &meta, &pids, true);
        stopped.push(name);
    }

    stopped
}

/// Stops an app and its whole process tree, as root.
///
/// Used when the panel itself has to bring an app down from the prelude —
/// `stop_internal` cannot, because it resolves the process through
/// `get_status`, which requires the caller's uid to match the app's.
pub(crate) fn stop_app_tree(state_dir: &Path, name: &str, meta: &AppMeta) {
    let pids: Vec<u32> = std::fs::read_to_string(
        state_dir.join(".run").join(format!("{name}.pid")),
    )
    .ok()
    .and_then(|p| p.trim().parse::<u32>().ok())
    .map(|pid| {
        let mut all = vec![pid];
        all.extend(crate::sys::proc::descendants_of(pid));
        all
    })
    .unwrap_or_default();

    if !pids.is_empty() {
        // Keeps `.enabled`: the app is coming straight back up.
        stop_offending_app(state_dir, name, meta, &pids, false);
    }
}

/// Stops an offending app and everything it spawned.
///
/// `stop_internal` is not usable here: it resolves the app through
/// `get_status`, which only accepts a PID whose uid matches the caller's. This
/// runs as root in the prelude, so the account's app reads as STOPPED and
/// nothing would be killed. Signalling the cgroup's PIDs directly also catches
/// the child that opened the port, which `stop_internal` would leave running
/// even if it did stop the main process.
fn stop_offending_app(
    state_dir: &Path,
    name: &str,
    meta: &AppMeta,
    pids: &[u32],
    drop_enabled: bool,
) {
    // Stop routing before killing, so no request lands on a dying process.
    let _ = std::fs::remove_file(state_dir.join(".proxy").join(&meta.host));

    for &pid in pids {
        let _ = kill(to_nix_pid(pid), Signal::SIGTERM);
    }

    let deadline = Instant::now() + Duration::from_secs(STOP_TIMEOUT_SECS);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if pids.iter().all(|&p| !is_process_alive(p)) {
            break;
        }
    }
    for &pid in pids {
        if is_process_alive(pid) {
            let _ = kill(to_nix_pid(pid), Signal::SIGKILL);
        }
    }

    let run = state_dir.join(".run");

    let _ = std::fs::remove_file(crate::sys::state::active_socket_path(state_dir, meta));

    // Clear the run state so the panel reports STOPPED instead of a stale PID.
    for suffix in ["pid", "meta"] {
        let _ = std::fs::remove_file(run.join(format!("{name}.{suffix}")));
    }
    if drop_enabled {
        // Only when the app is being taken down for good: `.enabled` is what
        // brings it back after a reboot, and a restart must not clear it.
        let _ = std::fs::remove_file(run.join(format!("{name}.enabled")));
    }

    crate::app::signal_sync();
}

/// Sweeps every account on the server.
///
/// Runs as root from the timer. Returns each stopped app as `user/name`.
pub(crate) fn sweep_all_accounts() -> Vec<String> {
    let mut stopped = Vec::new();
    for (state_dir, username) in crate::sys::state::list_accounts() {
        for name in sweep_account(&state_dir, &username) {
            stopped.push(format!("{username}/{name}"));
        }
    }
    stopped
}

/// Reports what the root-prelude sweep stopped.
///
/// The sweep itself must run as root, so it happens in the prelude and only its
/// outcome reaches here.
pub(crate) fn report(stopped: Option<Vec<String>>, dbg: Option<&Value>) -> ! {
    let stopped = stopped.unwrap_or_default();
    crate::sys::output::success(crate::app::with_debug(
        json!({
            "stopped": stopped.len(),
            "apps": stopped,
        }),
        dbg,
    ))
}
