//! Restores apps that were running before the last reboot.
//!
//! Invoked by `selynt-panel.service` at boot. An app carries a `.enabled`
//! marker while it is meant to be running; one the user stopped has none and
//! stays stopped.
//!
//! Implemented here rather than as a shell script for the same reason as the
//! diagnostic: this binary is setuid root, and a root-run script is a file
//! whose contents become root execution. Keeping it in the binary means there
//! is nothing extra on disk to write to.

use std::path::Path;

use serde_json::{Value, json};

use crate::sys::output::success;
use crate::sys::proc::is_process_alive;
use crate::sys::state::{PLUGIN_PATH, STATE_BASE, list_app_names};

use super::with_debug;

/// Appends a line to the boot-recovery log, best effort.
///
/// A boot that cannot write its log should still restore the apps, so failures
/// here are ignored deliberately.
fn log(line: &str) {
    use std::io::Write;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(format!("{PLUGIN_PATH}/etc/boot-recover.log"))
    {
        let _ = writeln!(f, "[{now}] {line}");
    }
}

/// Whether an app is still alive, judged from its recorded pid.
///
/// Runs as root, so the pid cannot be checked against the caller's uid the way
/// `get_status` does; after a reboot the recorded pid is stale anyway, which is
/// exactly what this has to detect.
fn already_running(run_dir: &Path, name: &str) -> bool {
    let pid_file = run_dir.join(format!("{name}.pid"));
    let alive = std::fs::read_to_string(&pid_file)
        .ok()
        .and_then(|p| p.trim().parse::<u32>().ok())
        .is_some_and(is_process_alive);

    if !alive {
        // A pid file pointing at nothing would otherwise keep the panel
        // reporting a process that died with the reboot.
        let _ = std::fs::remove_file(&pid_file);
    }
    alive
}

/// Restarts every enabled app of every account.
///
/// Returns the apps it started, as `user/name`.
pub fn recover_all() -> Vec<String> {
    log(&format!("boot-recover: scanning {STATE_BASE}"));
    let mut started = Vec::new();

    for (user_dir, username) in crate::sys::state::list_accounts() {
        let run_dir = user_dir.join(".run");

        for name in list_app_names(&user_dir) {
            if !run_dir.join(format!("{name}.enabled")).is_file() {
                continue;
            }
            if already_running(&run_dir, &name) {
                log(&format!("skip: {username}/{name} already running"));
                continue;
            }

            log(&format!("start: {username}/{name}"));
            if super::start_app_detached(&username, &name) {
                log(&format!("ok: {username}/{name}"));
                started.push(format!("{username}/{name}"));
            } else {
                log(&format!("fail: {username}/{name}"));
            }
        }
    }

    log("boot-recover: done");
    started
}

/// CLI entry point.
pub fn cmd_boot_recover(started: Vec<String>, dbg: Option<&Value>) -> ! {
    success(with_debug(
        json!({ "started": started.len(), "apps": started }),
        dbg,
    ))
}
