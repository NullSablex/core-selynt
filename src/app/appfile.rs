//! Writes to an app's `.app` metadata, performed while still root.
//!
//! The `.app` is the only state that says *what to execute*; everything else
//! under `.run` is observable state the account may write. So it is written
//! here and left owned by root: an app shares its account's uid and could
//! otherwise forge one and have the panel launch it — not an escalation, but a
//! way to sabotage a neighbour.

use std::path::{Path, PathBuf};

use crate::sys::fs::{atomic_write, chown_path, set_perm};

/// Owner and mode for `.app` files: readable by the account, writable only by
/// root. The panel reads this after the privilege drop, so it cannot be 0600.
const APP_FILE_MODE: u32 = 0o640;

/// Path of an app's metadata file.
pub(crate) fn app_file_path(state_dir: &Path, name: &str) -> PathBuf {
    state_dir.join(".run").join(format!("{name}.app"))
}

/// Writes an app's metadata as root, leaving it unwritable by the account.
///
/// `gid` is the account's group, so the panel can still read the file after
/// dropping privileges.
pub(crate) fn write_as_root(path: &Path, content: &str, gid: u32) -> Result<(), String> {
    atomic_write(path, content.as_bytes()).map_err(|e| format!("{e:#}"))?;
    // Root owns it; the account's group only reads.
    chown_path(path, 0, gid).map_err(|e| format!("{e:#}"))?;
    set_perm(path, APP_FILE_MODE).map_err(|e| format!("{e:#}"))?;
    Ok(())
}

/// Rewrites one `key=value` in an existing `.app`, appending it when absent.
///
/// Returns the new contents, or `None` when the file cannot be read.
pub(crate) fn rewrite_key(path: &Path, key: &str, value: &str) -> Option<String> {
    let current = std::fs::read_to_string(path).ok()?;
    let mut found = false;
    let mut out = String::with_capacity(current.len() + value.len());
    for line in current.lines() {
        if let Some((k, _)) = line.split_once('=')
            && k.trim() == key
        {
            out.push_str(&format!("{key}={value}\n"));
            found = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !found {
        out.push_str(&format!("{key}={value}\n"));
    }
    Some(out)
}

/// Creates an app's `.app` from the arguments of `add`, as root.
///
/// Fails if the app already exists — the exclusive create is what makes two
/// concurrent `add` calls for the same name safe.
pub(crate) fn create_for_add(
    state_dir: &Path,
    args: &super::commands::AddArgs<'_>,
    username: &str,
    gid: u32,
) -> Result<(), (String, String)> {
    let path = app_file_path(state_dir, args.name);

    if path.exists() {
        return Err((
            "app_exists".into(),
            format!("app '{}' already exists", args.name),
        ));
    }

    // Check the working directory *before* writing anything.
    //
    // `cmd_add` validates too, but only after the drop — by then this has
    // already created the file. A rejected `cwd` used to leave a root-owned
    // `.app` behind: the command answered `cwd_outside_home`, and the app still
    // listed and still started, running code from wherever the caller pointed.
    let home = super::super::sys::auth::lookup_home(username).ok_or_else(|| {
        (
            "invalid_cwd".to_string(),
            format!("could not resolve home directory for '{username}'"),
        )
    })?;
    let cwd = args
        .cwd
        .map_or_else(|| super::validate::default_cwd(&home, args.name), str::to_string);

    if let Some(err) = super::validate::cwd_refusal(&cwd, Path::new(&home)) {
        return Err(err);
    }

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let content = format!(
        "type={t}\ncwd={cwd}\nentry={entry}\nhost={host}\ndomain={d}\nsubdomain={s}\nnode_version={nv}\ncreated_at={created_at}\n",
        t = args.app_type,
        entry = args.entry,
        host = args.host,
        d = args.domain.unwrap_or(""),
        s = args.subdomain.unwrap_or(""),
        nv = args.node_version.unwrap_or(""),
    );

    write_as_root(&path, &content, gid).map_err(|e| ("write_failed".into(), e))
}

/// Updates one key of an existing `.app`, as root.
pub(crate) fn update_key(
    state_dir: &Path,
    name: &str,
    key: &str,
    value: &str,
    gid: u32,
) -> Result<(), (String, String)> {
    let path = app_file_path(state_dir, name);
    let Some(content) = rewrite_key(&path, key, value) else {
        return Err(("app_not_found".into(), format!("app '{name}' not found")));
    };
    write_as_root(&path, &content, gid).map_err(|e| ("write_failed".into(), e))
}

/// Deletes an app's `.app`, as root. Only root can, now that it owns the file.
///
/// Called from the prelude *before* the account's own cleanup: removal is the
/// one operation where losing the metadata early is harmless, since `cmd_remove`
/// has already loaded it. Anything that reads it afterwards is looking at an app
/// that is being deleted.
pub(crate) fn remove(state_dir: &Path, name: &str) {
    let _ = std::fs::remove_file(app_file_path(state_dir, name));
}

#[cfg(test)]
mod tests {
    use super::rewrite_key;
    use std::io::Write;

    /// Tagged per test: they run in parallel and would otherwise share a path.
    fn tmp_with(tag: &str, content: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir()
            .join(format!("selynt-appfile-{tag}-{}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    #[test]
    fn replaces_an_existing_key_in_place() {
        let p = tmp_with("replace", "type=node\nnode_version=/old\nentry=i.js\n");
        let out = rewrite_key(&p, "node_version", "/new").unwrap();
        assert_eq!(out, "type=node\nnode_version=/new\nentry=i.js\n");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn appends_a_key_that_is_not_there() {
        let p = tmp_with("append", "type=node\nentry=i.js\n");
        let out = rewrite_key(&p, "node_version", "/n").unwrap();
        assert!(out.ends_with("node_version=/n\n"));
        assert!(out.starts_with("type=node\n"));
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn missing_file_yields_none() {
        assert!(rewrite_key(std::path::Path::new("/nonexistent-selynt"), "k", "v").is_none());
    }
}
