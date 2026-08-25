//! Checks applied before an application is registered.
//!
//! These decide what the panel will later execute as the account, so each one
//! closes a way of pointing it somewhere it should not go:
//!
//! * a `cwd` outside the account's home — including one reached through a
//!   symlink, which `remove --delete-dir` would follow when deleting;
//! * a value carrying a newline, which would forge extra keys in the
//!   line-oriented `.app` file;
//! * an entry file for a compiled runtime that is not actually an executable.
//!
//! Kept apart from the commands so the rules can be read as a set, and tested
//! without going through a command.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use std::io::Read;

use crate::sys::fs::{atomic_write, set_perm};
use crate::sys::output::{system_error, user_error};
use crate::sys::state::validate_name;

use super::commands::AddArgs;
use super::validate_safe_component;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CwdError {
    NotAbsolute,
    Unresolvable,
    Outside { resolved: String, home: String },
}


pub(super) fn validate_add_args(args: &AddArgs<'_>, cwd: &str) {
    if !validate_name(args.name) {
        user_error("invalid_name", "name must match ^[A-Za-z0-9._-]{1,64}$");
    }
    if !validate_safe_component(args.entry) {
        user_error(
            "invalid_entry",
            "entry must not contain '/', '..' or null bytes",
        );
    }
    if !validate_safe_component(args.host) {
        user_error(
            "invalid_host",
            "host must not contain '/', '..' or null bytes",
        );
    }
    // These land verbatim in the line-oriented `.app` file — a newline would
    // let a value forge extra metadata keys.
    for (field, value) in [
        ("cwd", cwd),
        ("domain", args.domain.unwrap_or("")),
        ("subdomain", args.subdomain.unwrap_or("")),
        ("node_version", args.node_version.unwrap_or("")),
    ] {
        if !validate_meta_value(value) {
            user_error(
                &format!("invalid_{field}"),
                &format!("{field} must not contain newlines or null bytes"),
            );
        }
    }
    validate_cwd_within_home(cwd);
}

/// True when `path` resolves outside `$HOME` (or cannot be resolved at all).
/// Used on the delete path, where failing closed is the safe default.
pub(super) fn cwd_escapes_home(path: &Path) -> bool {
    let Ok(home) = std::env::var("HOME") else {
        return true;
    };
    let (Ok(home_real), Ok(target)) = (
        std::fs::canonicalize(&home),
        std::fs::canonicalize(path),
    ) else {
        return true;
    };
    !target.starts_with(&home_real)
}

/// Rejects a `cwd` that escapes the user's home directory.
///
/// Two ways out existed. A plain path elsewhere (`/tmp/app`) put the code in a
/// world-writable place, where any other account could swap the entry file that
/// then runs as this user. And a symlink under the home pointing outside it was
/// followed by both `add` (writing `.env` and the entry through it) and by
/// `remove --delete-dir`, whose `remove_dir_all` deletes the *target's*
/// contents — a confirmed way to destroy files the app never owned.
///
/// So the check resolves symlinks on every existing ancestor and demands the
/// result stay under `$HOME`.
fn validate_cwd_within_home(cwd: &str) {
    let home = match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => h,
        _ => user_error("cwd_outside_home", "HOME is not set; cannot validate cwd"),
    };
    match check_cwd_within_home(cwd, Path::new(&home)) {
        Ok(()) => {}
        Err(CwdError::NotAbsolute) => user_error("invalid_cwd", "cwd must be an absolute path"),
        Err(CwdError::Unresolvable) => user_error("invalid_cwd", "cwd could not be resolved"),
        Err(CwdError::Outside { resolved, home }) => user_error(
            "cwd_outside_home",
            &format!("cwd must stay inside {home} (resolved to {resolved})"),
        ),
    }
}

/// Resolves `cwd` (following symlinks on every existing ancestor) and checks it
/// lands inside `home`. Split from `validate_cwd_within_home` so the decision is
/// testable without the process-exiting error path.
pub(super) fn check_cwd_within_home(cwd: &str, home: &Path) -> Result<(), CwdError> {
    let home_real = std::fs::canonicalize(home).map_err(|_| CwdError::Unresolvable)?;

    let path = PathBuf::from(cwd);
    if !path.is_absolute() {
        return Err(CwdError::NotAbsolute);
    }

    // The leaf usually doesn't exist yet (add creates it), so canonicalize the
    // deepest existing ancestor and re-append the remainder. Any symlink along
    // the way is resolved by that call.
    let mut existing = path.as_path();
    let mut rest = Vec::new();
    let resolved = loop {
        if let Ok(c) = std::fs::canonicalize(existing) {
            break c.join(rest.iter().rev().collect::<PathBuf>());
        }
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name.to_os_string());
                existing = parent;
            }
            _ => return Err(CwdError::Unresolvable),
        }
    };

    if resolved.starts_with(&home_real) {
        Ok(())
    } else {
        Err(CwdError::Outside {
            resolved: resolved.display().to_string(),
            home: home_real.display().to_string(),
        })
    }
}

/// Values written into the `key=value` `.app` file must stay on one line.
pub(super) fn validate_meta_value(value: &str) -> bool {
    !value.contains('\n') && !value.contains('\r') && !value.contains('\0')
}

pub(super) fn write_env_file(cwd_path: &Path, env_vars: &[String]) {
    let env_file = cwd_path.join(".env");
    let env_content = env_vars.join("\n") + "\n";
    if let Err(e) =
        atomic_write(&env_file, env_content.as_bytes()).and_then(|()| set_perm(&env_file, 0o600))
    {
        system_error("write_failed", &format!("{e:#}"));
    }
}

/// Skipped silently when the file does not exist yet — callers may register an
/// app before placing the binary.
pub(super) fn validate_rust_entry(entry_path: &Path) {
    if !entry_path.exists() {
        return;
    }
    if !is_executable_file(entry_path) {
        user_error(
            "entry_not_executable",
            &format!("file '{}' is not executable", entry_path.display()),
        );
    }
    if !is_elf(entry_path) {
        user_error(
            "entry_not_elf",
            &format!("file '{}' is not a valid ELF binary", entry_path.display()),
        );
    }
}

/// Drops a Node.js scaffold template at `entry_path` when the file is missing
/// and the plugin ships a template at `{plugin}/templates/node/index.js`.
pub(super) fn scaffold_node_entry(entry_path: &Path, name: &str) {
    if entry_path.exists() {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Some(plugin_dir) = exe.parent().and_then(Path::parent) else {
        return;
    };
    let template = plugin_dir.join("templates/node/index.js");
    if let Ok(tpl) = std::fs::read_to_string(&template) {
        let rendered = tpl.replace("{{APP_NAME}}", name);
        let _ = std::fs::write(entry_path, rendered.as_bytes());
    }
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
}

/// Checks the ELF magic number (`\x7fELF`) on the first 4 bytes of the file.
fn is_elf(path: &Path) -> bool {
    let mut buf = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok_and(|()| buf == [0x7f, b'E', b'L', b'F'])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an isolated home under the OS temp dir: `<tmp>/selynt-test-<n>/home`
    /// plus a sibling `outside/` to point escapes at.
    fn sandbox(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("selynt-test-{tag}-{}", std::process::id()));
        let home = base.join("home");
        let outside = base.join("outside");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(home.join("apps")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        (home, outside)
    }

    #[test]
    fn accepts_cwd_inside_home() {
        let (home, _) = sandbox("inside");
        let cwd = home.join("apps/myapp");
        assert_eq!(check_cwd_within_home(cwd.to_str().unwrap(), &home), Ok(()));
    }

    #[test]
    fn accepts_cwd_that_does_not_exist_yet() {
        // `add` creates the directory afterwards, so a missing leaf is normal.
        let (home, _) = sandbox("missing");
        let cwd = home.join("apps/deep/not/created/yet");
        assert_eq!(check_cwd_within_home(cwd.to_str().unwrap(), &home), Ok(()));
    }

    #[test]
    fn rejects_cwd_outside_home() {
        let (home, outside) = sandbox("outside");
        let cwd = outside.join("app");
        assert!(matches!(
            check_cwd_within_home(cwd.to_str().unwrap(), &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn rejects_dotdot_traversal_out_of_home() {
        let (home, _) = sandbox("dotdot");
        let cwd = format!("{}/apps/../../outside/app", home.display());
        assert!(matches!(
            check_cwd_within_home(&cwd, &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn keeps_dotdot_that_stays_inside_home() {
        let (home, _) = sandbox("dotdot-ok");
        let cwd = format!("{}/apps/../apps/myapp", home.display());
        assert_eq!(check_cwd_within_home(&cwd, &home), Ok(()));
    }

    /// The vector that destroyed data: a link under the home whose target is
    /// elsewhere. `remove --delete-dir` would wipe the target's contents.
    #[test]
    fn rejects_symlink_pointing_outside_home() {
        let (home, outside) = sandbox("symlink");
        let link = home.join("apps/escape");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(matches!(
            check_cwd_within_home(link.to_str().unwrap(), &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn rejects_symlinked_ancestor_pointing_outside_home() {
        // The link is mid-path, not the leaf — canonicalize must still catch it.
        let (home, outside) = sandbox("symlink-mid");
        let link = home.join("apps/bridge");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let cwd = link.join("nested/app");
        assert!(matches!(
            check_cwd_within_home(cwd.to_str().unwrap(), &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn accepts_symlink_that_stays_within_home() {
        let (home, _) = sandbox("symlink-in");
        let target = home.join("apps/real");
        std::fs::create_dir_all(&target).unwrap();
        let link = home.join("apps/alias");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(check_cwd_within_home(link.to_str().unwrap(), &home), Ok(()));
    }

    #[test]
    fn rejects_relative_cwd() {
        let (home, _) = sandbox("relative");
        assert_eq!(
            check_cwd_within_home("apps/myapp", &home),
            Err(CwdError::NotAbsolute)
        );
    }

    /// `/home/user2` must not pass just because it shares a textual prefix with
    /// `/home/user` — starts_with on components, not on the raw string.
    #[test]
    fn rejects_sibling_home_with_shared_prefix() {
        let base = std::env::temp_dir().join(format!("selynt-test-prefix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("user");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(base.join("user2")).unwrap();
        let cwd = base.join("user2/app");
        assert!(matches!(
            check_cwd_within_home(cwd.to_str().unwrap(), &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn validate_meta_value_blocks_forged_keys() {
        assert!(validate_meta_value("/home/user/apps/x"));
        assert!(!validate_meta_value("x\nhost=evil"));
        assert!(!validate_meta_value("x\rhost=evil"));
        assert!(!validate_meta_value("x\0y"));
    }
}
