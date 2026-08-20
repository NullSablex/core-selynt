use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::ptr;

use anyhow::{Context, Result};

pub const PLUGIN_PATH: &str = "/usr/local/directadmin/plugins/selynt_panel";

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
}

/// Resolves the real target user from the `USERNAME` env var via `getpwnam_r`.
/// Returns `(uid, gid, home, username)`.
pub fn resolve_target_user() -> Result<(u32, u32, String, String)> {
    let username = std::env::var("USERNAME").context("USERNAME env not set")?;
    let cname =
        std::ffi::CString::new(username.as_str()).context("USERNAME contains a null byte")?;

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

    Ok((pwd.pw_uid, pwd.pw_gid, home, username))
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

    Ok(())
}

fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<()> {
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

pub fn load_app_meta(state_dir: &Path, name: &str) -> Result<AppMeta> {
    let app_file = state_dir.join(".run").join(format!("{name}.app"));
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
        created_at: kv.get("created_at").and_then(|v| v.parse().ok()),
    })
}

pub fn list_app_names(state_dir: &Path) -> Vec<String> {
    let run_dir = state_dir.join(".run");
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&run_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("app")
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

/// Reads the web user used for ACLs, from `SELYNT_WEB_USER` or the plugin's
/// `etc/ols_web_user` file. Returns an empty string if neither is set, in
/// which case `apply_acl` skips ACL configuration.
pub fn get_web_user() -> String {
    if let Ok(u) = std::env::var("SELYNT_WEB_USER") {
        return u;
    }
    std::fs::read_to_string(format!("{PLUGIN_PATH}/etc/ols_web_user"))
        .unwrap_or_default()
        .trim()
        .to_string()
}
