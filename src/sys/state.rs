use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::auth::user_exists;
use super::fs::{chown_path, chown_recursive, parse_kv};

pub const PLUGIN_PATH: &str = "/usr/local/directadmin/plugins/selynt_panel";
pub const DA_USERS_BASE: &str = "/usr/local/directadmin/data/users";
/// Where `DirectAdmin` keeps the vhost templates it generates configs from.
pub const DA_TEMPLATES: &str = "/usr/local/directadmin/data/templates";
/// Root of the panel's per-account state.
pub const STATE_BASE: &str = "/var/lib/selynt_panel";
/// Set when the proxy config no longer matches the live apps.
pub const SYNC_MARKER: &str = "/var/lib/selynt_panel/.sync_needed";

const STATE_SUBDIRS: [&str; 3] = [".run", ".sockets", ".proxy"];

#[derive(Debug, Clone)]
pub struct AppMeta {
    pub name: String,
    pub app_type: String,
    pub cwd: String,
    pub entry: String,
    pub host: String,
    /// The domain and subdomain the app was created under.
    ///
    /// Persisted and parsed back but never read — the panel derives an app's
    /// address from `host`. Kept because they record what the app was
    /// registered as, and scoped rather than allowed struct-wide so a field
    /// that really falls out of use still gets flagged.
    #[allow(dead_code)]
    pub domain: String,
    #[allow(dead_code)]
    pub subdomain: String,
    pub node_version: String,
    pub created_at: Option<u64>,
    /// Per-app memory cap in bytes. `None` means "auto": the app shares
    /// whatever is left of the account's allowance with the other auto apps.
    pub memory_max: Option<u64>,
}

/// Creates the state dir and operational subdirs as root, then recursively
/// chowns the whole tree to the target user. The recursive chown is required
/// because a previous run with different ownership could otherwise leave
/// stale entries the user can't touch.
pub fn init_state_dir(state_dir: &Path, uid: u32, gid: u32) -> Result<()> {
    for dir in std::iter::once(state_dir.to_path_buf())
        .chain(STATE_SUBDIRS.iter().map(|s| state_dir.join(s)))
    {
        if !dir.is_dir() {
            std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 700 {}", dir.display()))?;
        }
    }

    // The parent dir (`/var/lib/selynt_panel/`) needs world-traverse so the
    // web server can reach into per-user state dirs.
    if let Some(parent) = state_dir.parent() {
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o711));
    }

    chown_recursive(state_dir, uid, gid)
        .with_context(|| format!("chown -R {uid}:{gid} {}", state_dir.display()))?;

    // `.run` is handed back to root, with the sticky bit and group write. The
    // account still creates its own `.pid`/`.meta`/`.enabled` there, but the
    // sticky bit stops it removing or replacing entries it does not own — and
    // `.app`, the only file that says what to execute, is written as root.
    // Without this an app could delete a neighbour's `.app`, or drop in one of
    // its own for the panel to launch.
    let run_dir = state_dir.join(".run");
    if run_dir.is_dir() {
        chown_path(&run_dir, 0, gid)
            .with_context(|| format!("chown root:{gid} {}", run_dir.display()))?;
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o1770))
            .with_context(|| format!("chmod 1770 {}", run_dir.display()))?;
    }

    Ok(())
}

/// Creates `{cwd}/logs/` owned by the target user. Called as root before the
/// privilege drop so the app can write logs after dropping.
pub fn init_app_logs_dir(cwd: &Path, uid: u32, gid: u32) -> Result<()> {
    let logs_dir = cwd.join("logs");
    if !logs_dir.is_dir() {
        std::fs::create_dir_all(&logs_dir)
            .with_context(|| format!("mkdir {}", logs_dir.display()))?;
    }
    let logs_str = logs_dir
        .to_str()
        .with_context(|| format!("non-UTF8 path {}", logs_dir.display()))?;
    let cpath = std::ffi::CString::new(logs_str)
        .with_context(|| format!("invalid path {}", logs_dir.display()))?;
    if unsafe { libc::chown(cpath.as_ptr(), uid, gid) } != 0 {
        anyhow::bail!(
            "chown {} to {uid}:{gid}: {}",
            logs_dir.display(),
            std::io::Error::last_os_error()
        );
    }
    std::fs::set_permissions(&logs_dir, std::fs::Permissions::from_mode(0o750))
        .with_context(|| format!("chmod 750 {}", logs_dir.display()))?;

    // The log files themselves, not just the directory: they are created while
    // still root, in the prelude, so they would be left root-owned and the app
    // could not reopen them on the next start.
    if let Ok(entries) = std::fs::read_dir(&logs_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                let _ = chown_path(&p, uid, gid);
            }
        }
    }
    Ok(())
}

/// Every account with panel state, as `(state_dir, username)`.
///
/// One place to decide what counts as an account. The state base also holds
/// dotfiles, and a directory can outlive the account it belonged to — filtering
/// that in each caller is how the checks stopped agreeing with each other.
pub fn list_accounts() -> Vec<(PathBuf, String)> {
    let Ok(entries) = std::fs::read_dir(STATE_BASE) else {
        return Vec::new();
    };

    let mut accounts: Vec<(PathBuf, String)> = entries
        .flatten()
        .filter_map(|entry| {
            let dir = entry.path();
            let name = dir.file_name()?.to_str()?.to_string();
            if name.starts_with('.') || !dir.join(".run").is_dir() || !user_exists(&name) {
                return None;
            }
            Some((dir, name))
        })
        .collect();

    // Stable order, so output does not shuffle between runs.
    accounts.sort_by(|a, b| a.1.cmp(&b.1));
    accounts
}

/// Whether this account runs its apps isolated from each other.
///
/// Isolation is a property of the **account**, not of a single app. A namespace
/// confines what the process inside it can see; it does not change the uid, so
/// a non-isolated sibling — same uid, ordinary view of the host — could still
/// read an isolated app's files and signal its processes. Protecting one app
/// therefore only works if every app of the account is isolated.
pub fn account_is_isolated(state_dir: &Path) -> bool {
    std::fs::read_to_string(state_dir.join("isolated")).map_or_else(
        // No choice recorded for this account: fall back to the server-wide
        // default the admin set, so accounts that predate the setting behave as
        // decided without being touched one by one.
        |_| {
            std::fs::read_to_string(format!("{PLUGIN_PATH}/etc/default_isolated"))
                .is_ok_and(|v| v.trim() == "1")
        },
        |v| v.trim() == "1",
    )
}

/// The socket path a running app actually has, recorded when it started.
///
/// Not the same as `socket_path_for` once the isolation mode changes: the path
/// moves, but a running app keeps the one it launched with. Stops and cleanups
/// must act on this, or they strand the real file and delete one that was never
/// there. Falls back to the configured path when nothing was recorded.
pub fn active_socket_path(state_dir: &Path, meta: &AppMeta) -> PathBuf {
    let meta_file = state_dir.join(".run").join(format!("{}.meta", meta.name));

    std::fs::read_to_string(meta_file)
        .ok()
        .and_then(|c| parse_kv(&c).get("socket").cloned())
        .map_or_else(|| socket_path_for(state_dir, meta), PathBuf::from)
}

/// Where an app's Unix socket lives.
///
/// Isolated, each app gets a subdirectory of its own: the sandbox binds only
/// that one into the mount namespace, so a sibling's socket is absent rather
/// than merely unreadable. It stays a real file on the host either way — the
/// proxy has to reach it.
pub fn socket_path_for(state_dir: &Path, meta: &AppMeta) -> PathBuf {
    let sockets = state_dir.join(".sockets");
    if account_is_isolated(state_dir) {
        sockets.join(&meta.name).join(&meta.host)
    } else {
        sockets.join(&meta.host)
    }
}

pub fn load_app_meta(state_dir: &Path, name: &str) -> Result<AppMeta> {
    let app_file = state_dir.join(".run").join(format!("{name}.app"));

    // `.run` has to stay writable for the account's own `.pid`/`.meta`, so an
    // app can still drop a file in it. Only root writes `.app`, so anything
    // with another owner was forged — refuse it rather than launch whatever it
    // describes.
    let owner = std::fs::metadata(&app_file)
        .with_context(|| format!("app '{name}' not found"))?
        .uid();
    if owner != 0 {
        anyhow::bail!("app '{name}' has untrusted metadata (owner uid {owner}, expected root)");
    }

    let content =
        std::fs::read_to_string(&app_file).with_context(|| format!("app '{name}' not found"))?;
    let kv = parse_kv(&content);

    Ok(AppMeta {
        name: name.to_string(),
        app_type: kv.get("type").cloned().unwrap_or_default(),
        cwd: kv.get("cwd").cloned().unwrap_or_default(),
        entry: kv.get("entry").cloned().unwrap_or_default(),
        host: kv.get("host").cloned().unwrap_or_default(),
        domain: kv.get("domain").cloned().unwrap_or_default(),
        subdomain: kv.get("subdomain").cloned().unwrap_or_default(),
        node_version: kv.get("node_version").cloned().unwrap_or_default(),
        memory_max: kv
            .get("memory_max")
            .and_then(|v| v.parse().ok())
            .filter(|&n| n > 0),
        created_at: kv.get("created_at").and_then(|v| v.parse().ok()),
    })
}

pub fn list_app_names(state_dir: &Path) -> Vec<String> {
    let run_dir = state_dir.join(".run");
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&run_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            // Same reasoning as `load_app_meta`: a `.app` not owned by root was
            // planted by the account, so it is not an app the panel knows.
            if path.extension().and_then(|e| e.to_str()) == Some("app")
                && std::fs::metadata(&path).is_ok_and(|m| m.uid() == 0)
                && let Some(name) = path.file_stem().and_then(|s| s.to_str())
            {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    names
}

/// Validates an app name against `^[A-Za-z0-9._-]{1,64}$`.
pub fn validate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Reads the web user used for ACLs from `etc/ols_web_user`, or an empty string
/// when unset, in which case `apply_acl` skips ACL configuration.
///
/// `SELYNT_WEB_USER` is honoured only for root, as a debugging escape hatch:
/// this decides which account ACLs are granted to, so an unprivileged caller
/// setting it could open up another user's app directories.
pub fn get_web_user() -> String {
    if unsafe { libc::getuid() } == 0
        && let Ok(u) = std::env::var("SELYNT_WEB_USER")
    {
        return u;
    }
    std::fs::read_to_string(format!("{PLUGIN_PATH}/etc/ols_web_user"))
        .unwrap_or_default()
        .trim()
        .to_string()
}
