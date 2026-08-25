//! Regenerates the OpenLiteSpeed proxy handlers for every live app.
//!
//! An app serves over a Unix socket, and OpenLiteSpeed only reaches it through
//! an `extProcessor` naming that socket. This rewrites the whole set from the
//! apps that are actually up, then reloads the web server.
//!
//! Runs on a schedule, and only when the panel left a marker saying the app set
//! changed — rewriting on every tick would restart the web server for nothing.
//!
//! It cannot be done inline by the command that changed things: that runs after
//! the privilege drop, which sets `PR_SET_NO_NEW_PRIVS`, and children inherit
//! it — so re-invoking the setuid binary yields an unprivileged process.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::output::success;
use crate::state::SYNC_MARKER;

use super::with_debug;

const LOCK_FILE: &str = "/var/lib/selynt_panel/.sync.lock";

/// The ports the DirectAdmin template generates handlers for.
///
/// The handler name has to match `selynt_proxy-|SDOMAIN|-|VH_PORT|` exactly, or
/// the vhost refers to something that does not exist.
const VHOST_PORTS: [u16; 2] = [80, 443];

/// An app that is up and reachable: its proxy marker and socket both exist.
struct LiveApp {
    host: String,
    socket: PathBuf,
}

/// Whether a host name is safe to write into the config.
///
/// It becomes part of a handler name and of a path, so anything outside this
/// set could break the file or point the handler elsewhere.
fn host_is_safe(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Every app currently serving, across all accounts.
///
/// Driven by the registered apps rather than by the marker files: an isolated
/// app keeps its socket in a subdirectory of its own, and looking for
/// `.sockets/<host>` would find nothing for it — leaving it with no handler and
/// no way to receive traffic.
fn collect_live_apps() -> Vec<LiveApp> {
    let mut apps = Vec::new();

    for (state_dir, _username) in crate::state::list_accounts() {
        for name in crate::state::list_app_names(&state_dir) {
            let Ok(meta) = crate::state::load_app_meta(&state_dir, &name) else {
                continue;
            };
            if !host_is_safe(&meta.host) {
                continue;
            }

            // The marker says the app should be routed; the socket says it can
            // be. A handler pointing at a missing socket makes the web server
            // answer with an error instead of falling through to PHP or static
            // files.
            if !state_dir.join(".proxy").join(&meta.host).exists() {
                continue;
            }
            let socket = crate::state::active_socket_path(&state_dir, &meta);
            if !socket.exists() {
                continue;
            }

            apps.push(LiveApp {
                host: meta.host,
                socket,
            });
        }
    }
    apps
}

/// Renders the handler block for one app on one port.
fn render_handler(app: &LiveApp, port: u16) -> String {
    format!(
        "extProcessor selynt_proxy-{host}-{port} {{\n  \
         type                    proxy\n  \
         address                 uds://{socket}\n  \
         maxConns                35\n  \
         initTimeout             60\n  \
         retryTimeout            0\n  \
         persistConn             1\n  \
         respBuffer              0\n  \
         autoStart               0\n  \
         instances               1\n  \
         priority                0\n}}\n\n",
        host = app.host,
        socket = app.socket.display(),
    )
}

/// The handler blocks, without the generated-at header.
///
/// The header carries a timestamp, so comparing whole files would always report
/// a difference and defeat the point of comparing at all.
fn strip_header(content: &str) -> String {
    content
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Writes the config atomically, so the web server never reads a partial file.
fn write_config(path: &Path, content: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("conf.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640))?;
    // Owned by the web server's config user where it exists, so a reload can
    // read it; root otherwise.
    if let Some((uid, gid)) = crate::state::lookup_user_ids("lsadm") {
        let _ = crate::state::chown_path(&tmp, uid, gid);
    } else {
        let _ = crate::state::chown_path(&tmp, 0, 0);
    }
    std::fs::rename(&tmp, path)
}

/// Asks OpenLiteSpeed to pick up the new configuration.
pub fn reload_web_server() -> bool {
    let restart = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };

    restart("systemctl", &["restart", "lsws"]) || restart("lswsctrl", &["restart"])
}

/// Regenerates the handlers and reloads the web server.
///
/// Returns how many apps were written, or `None` when another run holds the
/// lock — cron fires every minute, and two rewrites at once would race over the
/// same file.
pub fn sync() -> Option<usize> {
    let _lock = Lock::acquire()?;

    // Independent of the routing, and done first so a web server that refuses
    // to reload does not also freeze every account's allowance.
    reapply_account_limits();

    let apps = collect_live_apps();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let mut content = format!(
        "# Selynt Panel extProcessors — generated at {now}\n# DO NOT EDIT — generated automatically\n\n"
    );
    for app in &apps {
        for port in VHOST_PORTS {
            content.push_str(&render_handler(app, port));
        }
    }

    let conf = super::ols::conf_dir()
        .unwrap_or_else(|| Path::new("/etc/openlitespeed"))
        .join("selynt_extprocessors.conf");

    // Only touch the file when the handlers actually differ. The timer runs
    // every few seconds, and rewriting an identical config would reload the web
    // server each time — dropping nothing, but restarting it for no reason.
    let unchanged = std::fs::read_to_string(&conf)
        .is_ok_and(|current| strip_header(&current) == strip_header(&content));

    if !unchanged {
        if write_config(&conf, &content).is_err() {
            return None;
        }
        // A config the web server never read is a config that does not apply.
        // Leaving the marker makes the next sweep try again, instead of the
        // routing staying stale until something else happens to change.
        if !reload_web_server() {
            return None;
        }
    }

    // Cleared only once the config is in place *and* live.
    let _ = std::fs::remove_file(SYNC_MARKER);

    Some(apps.len())
}

/// Re-reads every account's allowance from DirectAdmin and applies it.
///
/// The allowance lives in DirectAdmin, where an admin can change it without the
/// panel being involved — so a raised quota reaches an account that never opens
/// the panel, and a lowered one takes effect without waiting for the customer
/// to restart something.
///
/// Cheap enough to do on each sweep: one file read and one `systemctl
/// set-property` per account, and only when the value actually changed.
fn reapply_account_limits() {
    for (state_dir, username) in crate::state::list_accounts() {
        let limits = super::read_da_limits(&username);
        super::ensure_slice_cap(&username, limits.memory_max);
        super::reapply_app_limits(&state_dir, &username);
    }
}

/// An advisory lock held for as long as the value lives.
///
/// The file is never read from; holding it open is the whole point, since the
/// kernel releases the lock when the last descriptor closes.
struct Lock(#[allow(dead_code)] std::fs::File);

impl Lock {
    /// Returns `None` when another process already holds it.
    fn acquire() -> Option<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(LOCK_FILE)
            .ok()?;

        // SAFETY: `flock` only needs a valid descriptor, which the file owns
        // for as long as this value lives.
        let locked = unsafe {
            libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX | libc::LOCK_NB)
        } == 0;

        locked.then_some(Self(file))
    }
}

/// CLI entry point.
pub fn cmd_sync_proxy(dbg: Option<&Value>) -> ! {
    match sync() {
        Some(count) => success(with_debug(json!({ "apps": count }), dbg)),
        // Another run holds the lock and is about to write the same thing, or
        // the config could not be written at all. Neither is worth failing the
        // command that triggered it: the app is already up either way, and the
        // next change re-runs this.
        None => success(with_debug(json!({ "apps": 0, "skipped": true }), dbg)),
    }
}

#[cfg(test)]
mod tests {
    use super::{host_is_safe, strip_header};

    /// The header carries a timestamp, so it must not count as a difference —
    /// otherwise every sweep would rewrite the file and reload the web server.
    #[test]
    fn header_is_not_part_of_the_comparison() {
        let a = "# generated at 1\nextProcessor x {\n}\n";
        let b = "# generated at 2\nextProcessor x {\n}\n";
        assert_eq!(strip_header(a), strip_header(b));
    }

    #[test]
    fn a_changed_handler_is_a_difference() {
        let a = "# h\nextProcessor one {\n}\n";
        let b = "# h\nextProcessor two {\n}\n";
        assert_ne!(strip_header(a), strip_header(b));
    }

    /// The host becomes part of a handler name and of a path in the config.
    #[test]
    fn rejects_hosts_that_could_break_the_config() {
        assert!(host_is_safe("app.example.com"));
        assert!(host_is_safe("sub-domain_1.example.com"));

        assert!(!host_is_safe(""));
        assert!(!host_is_safe("../escape"));
        assert!(!host_is_safe("has space"));
        assert!(!host_is_safe("brace{}"));
    }
}
