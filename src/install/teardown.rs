//! Undoes what `setup` put in place.
//!
//! The mirror of `app::setup` and `app::ols`: the same files, the same markers,
//! the same web server. Keeping both halves in one language means the block a
//! template gained is removed by code that knows how it was written, rather
//! than by a second implementation that has to guess.

use std::path::Path;

use serde_json::{Value, json};

use crate::sys::output::success;
use crate::sys::state::{DA_TEMPLATES, STATE_BASE};

use crate::app::with_debug;

/// Stops every app of every account, and everything each one spawned.
///
/// Signals the whole process tree rather than a process group: a sandboxed app
/// sits under bubblewrap, which does not pass signals on, so the group leader
/// dying would leave the real process behind holding its socket.
fn stop_all_apps() -> usize {
    let mut stopped = 0;
    for (state_dir, _username) in crate::sys::state::list_accounts() {
        for name in crate::sys::state::list_app_names(&state_dir) {
            let Ok(meta) = crate::sys::state::load_app_meta(&state_dir, &name) else {
                continue;
            };
            crate::limits::netguard::stop_app_tree(&state_dir, &name, &meta);
            stopped += 1;
        }
    }
    stopped
}

/// Drops the panel's include line and its generated handler file.
///
/// Returns whatever could not be cleaned. The include line points at a file
/// this also deletes, so a failure here leaves the web server referring to
/// something that is gone — the admin has to hear about it rather than read a
/// teardown that claims success.
fn clean_web_server_config() -> Vec<String> {
    let mut failures = Vec::new();
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
                .fold(String::new(), |mut acc, l| {
                    acc.push_str(l);
                    acc.push('\n');
                    acc
                });
            if let Err(e) = crate::sys::fs::atomic_write(&main, cleaned.as_bytes()) {
                failures.push(format!("{}: {e:#}", main.display()));
            }
        }

        // Both layouts: the include-line one and the `conf.d/` drop-in.
        let conf = dir.join(crate::webserver::ols::HANDLERS_FILE);
        let drop_in = dir
            .join("conf.d")
            .join(crate::webserver::ols::HANDLERS_FILE);
        // A file that was never there is not a failure — only one that resisted
        // deletion is.
        for p in [
            conf.clone(),
            conf.with_extension("conf.tmp"),
            drop_in.clone(),
            drop_in.with_extension("conf.tmp"),
        ] {
            if let Err(e) = std::fs::remove_file(&p)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                failures.push(format!("{}: {e}", p.display()));
            }
        }
    }
    failures
}

/// Removes everything the panel installed, leaving the server as it was.
fn run() -> Value {
    // First: the timers invoke this binary, and one firing mid-teardown would
    // recreate what is being removed.
    let units = super::units::remove();

    let stopped = stop_all_apps();

    // Com os apps parados, o gancho de bind não protege mais nada.
    let bindguard_detached = crate::limits::bindguard::detach().is_ok();

    // After the apps are down: the state directory is where their sockets and
    // metadata live, and stopping reads from it.
    let _ = std::fs::remove_dir_all(STATE_BASE);

    let custom = Path::new(DA_TEMPLATES).join("custom");
    let templates: Vec<String> = ["5", "7"]
        .iter()
        .filter_map(|n| {
            let path = custom.join(format!("openlitespeed_vhost.conf.CUSTOM.{n}.pre"));
            crate::webserver::ols::strip_block(&path).map(|what| format!("CUSTOM.{n}: {what}"))
        })
        .collect();

    let config_failures = clean_web_server_config();

    // The vhosts still carry the proxy blocks until DirectAdmin regenerates
    // them from the templates it no longer has.
    let vhosts_rebuilt = crate::webserver::ols::rebuild_vhosts();
    let reloaded = crate::webserver::proxysync::reload_web_server();

    json!({
        "units_removed": units.len(),
        "apps_stopped": stopped,
        "templates": templates,
        "vhosts_rebuilt": vhosts_rebuilt,
        "web_server_reloaded": reloaded,
        "config_cleanup_failures": config_failures,
        "bindguard_detached": bindguard_detached,
    })
}

/// CLI entry point.
pub fn cmd_teardown(dbg: Option<&Value>) -> ! {
    success(with_debug(run(), dbg))
}
