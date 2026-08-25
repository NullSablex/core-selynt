//! Filesystem primitives shared across the panel.
//!
//! [`atomic_write`] is the reason this module exists: the panel writes files
//! that other processes read concurrently — the proxy configuration the web
//! server reloads, an app's `.app` metadata — and a partially written file
//! there is worse than no file at all. Writing to a temporary and renaming it
//! makes the swap atomic, so a reader sees either the old contents or the new
//! ones, never half of each.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};

/// Hands the state tree to the account, leaving `.run` alone.
///
/// `.run` is deliberately root-owned — see `init_state_dir` — so sweeping it
/// into the recursive chown would undo that on every single invocation.
pub(super) fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<()> {
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

pub(crate) fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
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

/// Parses `KEY=VALUE` per line. Lines without `=` are silently skipped.
pub(crate) fn parse_kv(content: &str) -> HashMap<String, String> {
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
pub(crate) fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
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

pub(crate) fn set_perm(path: &Path, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}
