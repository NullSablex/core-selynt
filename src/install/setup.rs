//! Everything the plugin has to put in place before it can work.
//!
//! The three accounts recorded here decide who may act on whose apps: too
//! narrow and every panel action is refused, too broad and an account the panel
//! does not control is trusted.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::sys::auth::user_exists;
use crate::sys::fs::{atomic_write, set_perm};
use crate::sys::output::success;
use crate::sys::state::{PLUGIN_PATH, STATE_BASE};

use crate::app::with_debug;

/// Accounts the panel needs to know about, resolved from the running system.
struct Identities {
    /// The account `DirectAdmin` itself runs as.
    da_user: String,
    da_uid: Option<u32>,
    /// The account `DirectAdmin` executes plugin CGI as. Not the web server user:
    /// plugin pages are served by DA's `legacy-handler`, which drops to
    /// `nobody` on a stock install.
    cgi_user: Option<String>,
}

/// Finds the account `DirectAdmin` runs as.
///
/// `diradmin` on a normal install; the fallbacks cover setups that renamed it.
fn detect_da_user() -> String {
    if user_exists("diradmin") {
        return "diradmin".to_string();
    }

    // Owner of the binary, which is what DirectAdmin installs as itself.
    if let Ok(md) = std::fs::metadata("/usr/local/directadmin/directadmin") {
        use std::os::unix::fs::MetadataExt;
        if let Some(name) = crate::sys::auth::lookup_uid(md.uid()) {
            return name;
        }
    }

    "diradmin".to_string()
}

/// Finds the account plugin CGI runs as, by looking at the handler process.
///
/// Guessing is worse than looking: the binary checks the calling uid against
/// this, and a wrong value makes every panel action fail with `admin_required`.
fn detect_cgi_user() -> Option<String> {
    let entries = std::fs::read_dir("/proc").ok()?;

    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(cmdline) = std::fs::read_to_string(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        // Arguments are NUL-separated in cmdline.
        let cmdline = cmdline.replace('\0', " ");
        if !cmdline.contains("directadmin") || !cmdline.contains("legacy-handler") {
            continue;
        }

        if let Some(uid) = crate::sys::proc::read_proc_uid(pid)
            && uid != 0
            && let Some(name) = crate::sys::auth::lookup_uid(uid)
        {
            return Some(name);
        }
    }

    user_exists("nobody").then(|| "nobody".to_string())
}

fn detect_identities() -> Identities {
    let da_user = detect_da_user();
    Identities {
        da_uid: crate::sys::auth::lookup_user_ids(&da_user).map(|(uid, _)| uid),
        da_user,
        cgi_user: detect_cgi_user(),
    }
}

/// Writes one of the `etc/` files the binary reads back at runtime.
fn write_etc(name: &str, value: &str) -> Result<(), String> {
    let etc = Path::new(PLUGIN_PATH).join("etc");
    std::fs::create_dir_all(&etc).map_err(|e| format!("{e:#}"))?;

    let path = etc.join(name);
    atomic_write(&path, format!("{value}\n").as_bytes())
        .and_then(|()| set_perm(&path, 0o644))
        .map_err(|e| format!("{e:#}"))
}

/// Creates the state directory the accounts' apps live under.
///
/// `0711` on purpose: the web server has to traverse it to reach each account's
/// socket, but must not be able to list who exists.
fn prepare_state_dir(owner_uid: Option<u32>) -> Result<(), String> {
    let base = PathBuf::from(STATE_BASE);
    std::fs::create_dir_all(&base).map_err(|e| format!("{e:#}"))?;

    if let Some(uid) = owner_uid {
        let _ = crate::sys::fs::chown_path(&base, uid, uid);
    }
    set_perm(&base, 0o711).map_err(|e| format!("{e:#}"))
}

/// Reclaims ownership of the plugin tree and applies the expected modes.
///
/// `DirectAdmin`'s Plugin Manager extracts the tarball as whatever account it
/// runs the upload as, leaving the tree owned by an unprivileged user on stock
/// images — one that could then rewrite the CGI endpoints, and the installer
/// itself. The modes come from the same function the diagnostic checks against.
fn apply_ownership() -> Result<(), String> {
    let root = Path::new(PLUGIN_PATH);

    chown_tree(root).map_err(|e| format!("{e:#}"))?;

    // Count what could not be set instead of ignoring it: a tree left with the
    // wrong modes is a working-looking install whose CGI endpoints may not be
    // executable, or whose dictionaries are.
    let mut failed = 0usize;

    // Directories need the execute bit to be traversable at all.
    super::tree::walk_dirs(root, &mut |dir| {
        if set_perm(dir, 0o755).is_err() {
            failed += 1;
        }
    });
    super::tree::walk(root, &mut |file| {
        if set_perm(file, super::tree::expected_mode(file)).is_err() {
            failed += 1;
        }
    });

    if failed > 0 {
        return Err(format!(
            "{failed} path(s) could not be set to their expected mode"
        ));
    }

    // Last, and separately: `chown` clears the setuid bit, so the order matters.
    // Without it every privileged action fails at runtime with `root_required`.
    let bin = root.join("bin/core-selynt");
    if bin.is_file() {
        crate::sys::fs::chown_path(&bin, 0, 0).map_err(|e| format!("{e:#}"))?;
        set_perm(&bin, 0o4755).map_err(|e| format!("{e:#}"))?;
    }

    Ok(())
}

/// Gives every file and directory under `root` to root.
fn chown_tree(root: &Path) -> std::io::Result<()> {
    crate::sys::fs::chown_path(root, 0, 0).map_err(std::io::Error::other)?;

    let Ok(entries) = std::fs::read_dir(root) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Never follow a symlink: `chown` through one lands on its target,
        // which may be anywhere on the system.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            chown_tree(&path)?;
        } else if meta.is_file() {
            crate::sys::fs::chown_path(&path, 0, 0).map_err(std::io::Error::other)?;
        }
    }
    Ok(())
}

/// Records the accounts and prepares the state directory.
pub fn run() -> Result<Value, (String, String)> {
    let ids = detect_identities();

    write_etc("da_user", &ids.da_user).map_err(|e| ("write_failed".to_string(), e))?;
    write_etc(
        "da_uid",
        &ids.da_uid.map_or_else(String::new, |u| u.to_string()),
    )
    .map_err(|e| ("write_failed".to_string(), e))?;

    if let Some(cgi) = &ids.cgi_user {
        write_etc("da_cgi_user", cgi).map_err(|e| ("write_failed".to_string(), e))?;
    }

    prepare_state_dir(ids.da_uid).map_err(|e| ("state_dir_failed".to_string(), e))?;
    apply_ownership().map_err(|e| ("ownership_failed".to_string(), e))?;

    // Wiring the web server is the other half of the same job, and it needs the
    // state directory to exist first. Reported separately so a server without
    // OpenLiteSpeed still records its accounts instead of failing outright.
    let ols = crate::webserver::ols::run().map_or_else(
        |(code, msg)| json!({ "ok": false, "error": code, "message": msg }),
        |o| json!({ "ok": true, "web_user": o.web_user, "vhosts_rebuilt": o.vhosts_rebuilt }),
    );

    // Last: the units name the binary, and it has to be in place with the
    // right permissions before systemd is told to run it.
    let units = super::units::install();

    Ok(json!({
        "da_user": ids.da_user,
        "da_uid": ids.da_uid,
        "cgi_user": ids.cgi_user,
        "ols": ols,
        "units": units.len(),
    }))
}

/// CLI entry point.
pub fn cmd_setup(dbg: Option<&Value>) -> ! {
    match run() {
        Ok(v) => success(with_debug(v, dbg)),
        Err((code, msg)) => crate::sys::output::system_error(&code, &msg),
    }
}
