//! Undoes what `setup` put in place.
//!
//! The mirror of `cmd::setup` and `cmd::ols`: the same files, the same markers,
//! the same web server. Keeping both halves in one language means the block a
//! template gained is removed by code that knows how it was written, rather
//! than by a second implementation that has to guess.

use std::path::Path;

use serde_json::{Value, json};

use crate::output::success;
use crate::state::{DA_TEMPLATES, STATE_BASE};

use super::with_debug;

/// Stops every app of every account, and everything each one spawned.
///
/// Signals the whole process tree rather than a process group: a sandboxed app
/// sits under bubblewrap, which does not pass signals on, so the group leader
/// dying would leave the real process behind holding its socket.
fn stop_all_apps() -> usize {
    let mut stopped = 0;
    for (state_dir, _username) in crate::state::list_accounts() {
        for name in crate::state::list_app_names(&state_dir) {
            let Ok(meta) = crate::state::load_app_meta(&state_dir, &name) else {
                continue;
            };
            super::netguard::stop_app_tree(&state_dir, &name, &meta);
            stopped += 1;
        }
    }
    stopped
}

/// Removes the panel's block from a template, deleting the file if nothing else
/// was in it.
///
/// A template can hold customisations that are not ours, and those have to
/// outlive the uninstall.
fn strip_block(path: &Path) -> Option<&'static str> {
    let content = std::fs::read_to_string(path).ok()?;

    let mut kept = String::new();
    let mut inside = false;
    for line in content.lines() {
        if line.trim_end() == super::ols::BEGIN_MARK {
            inside = true;
            continue;
        }
        if line.trim_end() == super::ols::END_MARK {
            inside = false;
            continue;
        }
        if !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }

    if kept.trim().is_empty() {
        let _ = std::fs::remove_file(path);
        Some("removed")
    } else {
        let _ = crate::state::atomic_write(path, kept.as_bytes());
        Some("stripped")
    }
}

/// Drops the panel's include line and its generated handler file.
fn clean_web_server_config() {
    for dir in ["/etc/openlitespeed", "/usr/local/lsws/conf"] {
        let dir = Path::new(dir);

        // The include line points at a file that is about to be gone; leaving it
        // behind would make the web server complain on every start.
        let main = dir.join("httpd_config.conf");
        if let Ok(content) = std::fs::read_to_string(&main)
            && content.contains("selynt_extprocessors")
        {
            let cleaned: String = content
                .lines()
                .filter(|l| !l.contains("selynt_extprocessors"))
                .filter(|l| !l.contains("selynt_panel extProcessors include"))
                .map(|l| format!("{l}\n"))
                .collect();
            let _ = crate::state::atomic_write(&main, cleaned.as_bytes());
        }

        let conf = dir.join("selynt_extprocessors.conf");
        let _ = std::fs::remove_file(&conf);
        let _ = std::fs::remove_file(conf.with_extension("conf.tmp"));
    }
}

/// Removes everything the panel installed, leaving the server as it was.
fn run() -> Value {
    // First: the timers invoke this binary, and one firing mid-teardown would
    // recreate what is being removed.
    let units = super::units::remove();

    let stopped = stop_all_apps();

    // After the apps are down: the state directory is where their sockets and
    // metadata live, and stopping reads from it.
    let _ = std::fs::remove_dir_all(STATE_BASE);

    let custom = Path::new(DA_TEMPLATES).join("custom");
    let templates: Vec<String> = ["5", "7"]
        .iter()
        .filter_map(|n| {
            let path = custom.join(format!("openlitespeed_vhost.conf.CUSTOM.{n}.pre"));
            strip_block(&path).map(|what| format!("CUSTOM.{n}: {what}"))
        })
        .collect();

    clean_web_server_config();

    // The vhosts still carry the proxy blocks until DirectAdmin regenerates
    // them from the templates it no longer has.
    let vhosts_rebuilt = super::ols::rebuild_vhosts();
    let reloaded = super::proxysync::reload_web_server();

    json!({
        "units_removed": units.len(),
        "apps_stopped": stopped,
        "templates": templates,
        "vhosts_rebuilt": vhosts_rebuilt,
        "web_server_reloaded": reloaded,
    })
}

/// CLI entry point.
pub fn cmd_teardown(dbg: Option<&Value>) -> ! {
    success(with_debug(run(), dbg))
}
