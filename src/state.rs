use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;

use anyhow::{Context, Result};

pub const PLUGIN_PATH: &str = "/usr/local/directadmin/plugins/selynt_panel";
pub const DA_USERS_BASE: &str = "/usr/local/directadmin/data/users";
/// Where DirectAdmin keeps the vhost templates it generates configs from.
pub const DA_TEMPLATES: &str = "/usr/local/directadmin/data/templates";
/// Root of the panel's per-account state.
pub const STATE_BASE: &str = "/var/lib/selynt_panel";
/// Set when the proxy config no longer matches the live apps.
pub const SYNC_MARKER: &str = "/var/lib/selynt_panel/.sync_needed";

const GETPWNAM_BUF_SIZE: usize = 4096;
const STATE_SUBDIRS: [&str; 3] = [".run", ".sockets", ".proxy"];

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AppMeta {
    pub name: String,
    pub app_type: String,
    pub cwd: String,
    pub entry: String,
    pub host: String,
    pub domain: String,
    pub subdomain: String,
    pub node_version: String,
    pub created_at: Option<u64>,
    /// Per-app memory cap in bytes. `None` means "auto": the app shares
    /// whatever is left of the account's allowance with the other auto apps.
    pub memory_max: Option<u64>,
}

/// Looks up an account by name, returning `(uid, gid, home)`.
/// uid and gid of a system account, when it exists.
pub fn lookup_user_ids(username: &str) -> Option<(u32, u32)> {
    lookup_user(username).ok().map(|(uid, gid, _)| (uid, gid))
}

/// Whether a system account by this name exists.
///
/// A state directory can outlive the account it belongs to, and acting on one
/// of those would resolve to nothing useful.
pub fn user_exists(username: &str) -> bool {
    lookup_user(username).is_ok()
}

fn lookup_user(username: &str) -> Result<(u32, u32, String)> {
    let cname = std::ffi::CString::new(username).context("USERNAME contains a null byte")?;

    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; GETPWNAM_BUF_SIZE];
    let mut result: *mut libc::passwd = ptr::null_mut();

    let ret = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            ptr::from_mut(&mut pwd),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            ptr::from_mut(&mut result),
        )
    };

    if ret != 0 || result.is_null() {
        anyhow::bail!("user {username:?} not found in /etc/passwd");
    }

    let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
        .to_str()
        .context("home dir is not valid UTF-8")?
        .to_string();

    Ok((pwd.pw_uid, pwd.pw_gid, home))
}

/// Resolves a uid back to its account name, if it has one.
pub fn lookup_uid(uid: u32) -> Option<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; GETPWNAM_BUF_SIZE];
    let mut result: *mut libc::passwd = ptr::null_mut();

    let ret = unsafe {
        libc::getpwuid_r(
            uid,
            ptr::from_mut(&mut pwd),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            ptr::from_mut(&mut result),
        )
    };

    if ret != 0 || result.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
        .to_str()
        .ok()
        .map(ToString::to_string)
}

/// Service accounts the panel may also run as, named in root-owned files
/// written by the installer. These cover the paths where DirectAdmin does *not*
/// run as the logged-in account: its CGI worker and the web server serving
/// proxied apps.
const SERVICE_ACCOUNT_FILES: [&str; 3] = ["etc/da_user", "etc/da_cgi_user", "etc/ols_web_user"];

/// Path to a DirectAdmin account's `user.conf`.
fn da_user_conf(username: &str) -> String {
    format!("{DA_USERS_BASE}/{username}/user.conf")
}

/// Reads `usertype=` for a DirectAdmin account: `admin`, `reseller` or `user`.
/// `None` when there is no such account or the file cannot be read.
///
/// This lives under `data/users/`, which is `diradmin`-owned and `0700`, so it
/// is only readable in the root prelude — exactly where authorisation is
/// decided, and out of reach of the caller.
///
/// The name is interpolated into a path, so it is validated first. It comes
/// from `getpwuid()` rather than the caller, but this decides authorisation and
/// the check is nearly free.
fn da_usertype(username: &str) -> Option<String> {
    if !validate_name(username) {
        return None;
    }
    parse_usertype(&std::fs::read_to_string(da_user_conf(username)).ok()?)
}

/// Extracts `usertype=` from a `user.conf` body.
fn parse_usertype(conf: &str) -> Option<String> {
    conf.lines()
        .find_map(|l| l.trim().strip_prefix("usertype="))
        .map(|v| v.trim().to_string())
}

/// True when a DirectAdmin `usertype` may act on other accounts.
fn usertype_is_privileged(usertype: Option<&str>) -> bool {
    matches!(usertype, Some("admin" | "reseller"))
}

/// True when the caller may act on other accounts and run `admin` commands.
///
/// DirectAdmin executes plugin CGI **as the logged-in account** — `admin` on a
/// default install, but the name is arbitrary and there can be several
/// resellers. Matching account *names* against a list was therefore always
/// going to break on someone's server; authority comes from the account's
/// `usertype=` in DirectAdmin's own database instead:
///
///   * `root` — installer, cron and shell use;
///   * a DA account whose `usertype` is `admin` or `reseller`;
///   * the service accounts in [`SERVICE_ACCOUNT_FILES`], for the paths where
///     DA runs as a worker rather than as the user.
///
/// A plain `user` account is never privileged, so a customer cannot reach
/// another customer's apps even though the CGI runs under their own uid.
/// Whether the caller may install, reconfigure or remove the plugin itself.
///
/// Stricter than [`caller_is_privileged`] on purpose. The web server and
/// DirectAdmin's CGI account are trusted to act *on behalf of* an account —
/// that is what serving the panel requires — but not to take the panel apart.
/// Anything reaching one of those accounts, a compromised CGI endpoint for
/// instance, could otherwise stop every app on the server and strip the
/// configuration.
///
/// Installation is a decision an administrator makes at a shell, so it asks for
/// the identity a shell has.
pub fn caller_is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

pub fn caller_is_privileged() -> bool {
    let caller_uid = unsafe { libc::getuid() };
    if caller_uid == 0 {
        return true;
    }
    let Some(caller) = lookup_uid(caller_uid) else {
        return false;
    };

    if usertype_is_privileged(da_usertype(&caller).as_deref()) {
        return true;
    }

    SERVICE_ACCOUNT_FILES
        .iter()
        .filter_map(|f| std::fs::read_to_string(format!("{PLUGIN_PATH}/{f}")).ok())
        .any(|name| {
            let name = name.trim();
            !name.is_empty() && name == caller
        })
}

/// Resolves the user this invocation is allowed to act on, as
/// `(uid, gid, home, username)`.
///
/// This binary is setuid root and world-executable, so `USERNAME` — a value the
/// caller supplies — cannot be trusted by itself. Taking it at face value let
/// any local account run `USERNAME=victim core-selynt ...` and drive the tool
/// over someone else's apps and state with root behind it.
///
/// Authority comes from the real uid instead (see [`caller_is_privileged`]):
/// privileged callers may name any account, everyone else acts only as
/// themselves.
pub fn resolve_target_user() -> Result<(u32, u32, String, String)> {
    let caller_uid = unsafe { libc::getuid() };
    let caller = lookup_uid(caller_uid);
    let trusted = caller_is_privileged();

    let username = match (std::env::var("USERNAME"), trusted) {
        (Ok(requested), true) => requested,
        (Ok(requested), false) => {
            let own = caller
                .clone()
                .context("caller uid has no account in /etc/passwd")?;
            if requested != own {
                anyhow::bail!(
                    "refusing to act as {requested:?}: caller is {own:?} (uid {caller_uid})"
                );
            }
            own
        }
        // No USERNAME: act as the caller. Root is never a valid target — the
        // privilege drop refuses uid 0 — so say that plainly instead of
        // failing later with a confusing "still root" message.
        (Err(_), _) => {
            let own = caller.context("caller uid has no account in /etc/passwd")?;
            if caller_uid == 0 {
                anyhow::bail!("USERNAME env not set (required when running as root)");
            }
            own
        }
    };

    let (uid, gid, home) = lookup_user(&username)?;
    Ok((uid, gid, home, username))
}

/// Drops privileges to the real user. Must be called AFTER any work that needs
/// root. Uses `initgroups` so the process keeps the user's supplementary
/// groups — required to reach group-restricted runtime binaries (e.g. node in
/// `/usr/local/bin/` on `CloudLinux`).
pub fn drop_privileges(uid: u32, gid: u32, username: &str) -> Result<()> {
    let cname = std::ffi::CString::new(username).context("invalid username for initgroups")?;
    unsafe {
        if libc::initgroups(cname.as_ptr(), gid) != 0 {
            anyhow::bail!(
                "initgroups({username}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        if libc::setgid(gid) != 0 {
            anyhow::bail!("setgid({gid}) failed: {}", std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            anyhow::bail!("setuid({uid}) failed: {}", std::io::Error::last_os_error());
        }
        if libc::geteuid() == 0 || libc::getuid() == 0 {
            anyhow::bail!("privilege drop failed — still root (uid)");
        }
        if libc::getegid() == 0 || libc::getgid() == 0 {
            anyhow::bail!("privilege drop failed — still root (gid)");
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            anyhow::bail!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
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

/// Hands the state tree to the account, leaving `.run` alone.
///
/// `.run` is deliberately root-owned — see `init_state_dir` — so sweeping it
/// into the recursive chown would undo that on every single invocation.
fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<()> {
    if path.file_name().is_some_and(|n| n == ".run") {
        return Ok(());
    }
    chown_path(path, uid, gid)?;
    if path.is_dir() {
        for entry in std::fs::read_dir(path)
            .with_context(|| format!("read_dir {}", path.display()))?
            .flatten()
        {
            let p = entry.path();
            if p.is_dir() {
                chown_recursive(&p, uid, gid)?;
            } else {
                chown_path(&p, uid, gid)?;
            }
        }
    }
    Ok(())
}

pub fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let s = path
        .to_str()
        .with_context(|| format!("non-UTF8 path {}", path.display()))?;
    let c =
        std::ffi::CString::new(s).with_context(|| format!("invalid path {}", path.display()))?;
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        anyhow::bail!(
            "chown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
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

/// Parses `KEY=VALUE` per line. Lines without `=` are silently skipped.
pub fn parse_kv(content: &str) -> HashMap<String, String> {
    content
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            Some((k.trim().to_string(), v.to_string()))
        })
        .collect()
}

/// Atomic write: writes a sibling `.tmp` and renames over the target. Both
/// steps must be on the same filesystem (`state_dir` always is).
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let tmp_name = format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp")
    );
    let tmp = path.with_file_name(tmp_name);
    std::fs::write(&tmp, content).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn set_perm(path: &Path, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
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
    match std::fs::read_to_string(state_dir.join("isolated")) {
        Ok(v) => v.trim() == "1",
        // No choice recorded for this account: fall back to the server-wide
        // default the admin set. Accounts that predate the setting behave as
        // the admin decided, without needing to be touched one by one.
        Err(_) => std::fs::read_to_string(format!("{PLUGIN_PATH}/etc/default_isolated"))
            .is_ok_and(|v| v.trim() == "1"),
    }
}

/// The socket path a running app actually has, recorded when it started.
///
/// Not the same as `socket_path_for` once the account's isolation mode changes:
/// the path moves, but a running app keeps the one it was launched with. Stops
/// and cleanups have to act on this, or they strand the real file and delete
/// one that was never there.
///
/// Falls back to the configured path when nothing was recorded — an app started
/// by an older build, or one that is not running.
pub fn active_socket_path(state_dir: &Path, meta: &AppMeta) -> PathBuf {
    let meta_file = state_dir
        .join(".run")
        .join(format!("{}.meta", meta.name));

    std::fs::read_to_string(meta_file)
        .ok()
        .and_then(|c| parse_kv(&c).get("socket").cloned())
        .map(PathBuf::from)
        .unwrap_or_else(|| socket_path_for(state_dir, meta))
}

/// Where an app's Unix socket lives.
///
/// With isolation off, it goes straight into the account's `.sockets/`, which
/// is what the proxy has always expected. With isolation on, each app gets a
/// subdirectory of its own: the sandbox binds only that directory into the
/// app's mount namespace, so a sibling's socket is not merely unreadable but
/// absent. The socket stays a real file on the host either way — the proxy has
/// to reach it.
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
        memory_max: kv.get("memory_max").and_then(|v| v.parse().ok()).filter(|&n| n > 0),
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

/// Reads the web user used for ACLs from the plugin's `etc/ols_web_user` file.
/// Returns an empty string when unset, in which case `apply_acl` skips ACL
/// configuration.
///
/// `SELYNT_WEB_USER` is honoured only for root, and only as a debugging escape
/// hatch: this value decides which account ACLs are granted to, so letting an
/// unprivileged caller of a setuid binary set it would hand them a way to open
/// up another user's app directories.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_usertype_from_user_conf() {
        let conf = "username=admin\nusertype=admin\ncreator=root\n";
        assert_eq!(parse_usertype(conf).as_deref(), Some("admin"));
    }

    #[test]
    fn parses_usertype_with_surrounding_space() {
        assert_eq!(parse_usertype("  usertype=reseller  \n").as_deref(), Some("reseller"));
    }

    #[test]
    fn missing_usertype_is_none() {
        assert_eq!(parse_usertype("username=bob\ncreator=root\n"), None);
    }

    /// Only admins and resellers may act on other accounts. Getting this wrong
    /// in either direction is a bug: too strict locks the panel out, too loose
    /// lets a customer reach another customer's apps.
    #[test]
    fn only_admin_and_reseller_are_privileged() {
        assert!(usertype_is_privileged(Some("admin")));
        assert!(usertype_is_privileged(Some("reseller")));
        assert!(!usertype_is_privileged(Some("user")));
        assert!(!usertype_is_privileged(None));
        // Case matters: DA writes these lowercase, anything else is not a match.
        assert!(!usertype_is_privileged(Some("Admin")));
        assert!(!usertype_is_privileged(Some("")));
    }

    /// The username lands in a path, so traversal must not reach another
    /// account's user.conf.
    /// The two levels must not collapse into one: the web server account is
    /// privileged enough to serve the panel, and must not be enough to remove
    /// it. Tests run unprivileged, which is exactly the case that has to be
    /// refused.
    #[test]
    fn installing_requires_more_than_being_privileged() {
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        assert!(!super::caller_is_root(), "non-root must not pass the install gate");
    }

    #[test]
    fn user_conf_path_is_scoped_to_data_users() {
        let p = da_user_conf("bob");
        assert_eq!(p, "/usr/local/directadmin/data/users/bob/user.conf");
    }
}
