//! Checks applied before an application is registered.
//!
//! These decide what the panel later executes as the account: a `cwd` outside
//! the home (including through a symlink, which `remove --delete-dir` would
//! follow), a value with a newline that would forge keys in the `.app` file, or
//! an entry file that is not executable.

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

/// Where an app's code lives when the caller does not say: `<home>/apps/<name>`.
///
/// The home comes from DirectAdmin, which is what makes this pass
/// [`check_cwd_within_home`]. Using the *name* and not the host is deliberate:
/// the name is the app's identity, while a host can be repointed without the
/// code moving.
pub(crate) fn default_cwd(home: &str, name: &str) -> String {
    format!("{home}/apps/{name}")
}

/// [`check_cwd_within_home`] as an error the caller can report, rather than one
/// that ends the process.
///
/// The root prelude needs this shape: it writes the `.app` file, and a refusal
/// there has to stop the write and travel back as JSON — not exit, and above
/// all not leave the file behind.
pub(crate) fn cwd_refusal(cwd: &str, home: &Path) -> Option<(String, String)> {
    match check_cwd_within_home(cwd, home) {
        Ok(()) => None,
        Err(CwdError::NotAbsolute) => {
            Some(("invalid_cwd".into(), "cwd must be an absolute path".into()))
        }
        Err(CwdError::Unresolvable) => {
            Some(("invalid_cwd".into(), "cwd could not be resolved".into()))
        }
        Err(CwdError::Outside { resolved, home }) => Some((
            "cwd_outside_home".into(),
            format!("cwd must stay inside {home} (resolved to {resolved})"),
        )),
    }
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
    let (Ok(home_real), Ok(target)) = (std::fs::canonicalize(&home), std::fs::canonicalize(path))
    else {
        return true;
    };
    !target.starts_with(&home_real)
}

/// Rejects a `cwd` that escapes the account's home.
///
/// Two ways out existed: a path somewhere world-writable, where another account
/// could swap the entry file that then runs as this user, and a symlink under
/// the home pointing outside it — followed by `add` when writing the entry, and
/// by `remove --delete-dir`, which deletes the *target's* contents. So the
/// check resolves symlinks on every existing ancestor.
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

    /// The default has to survive the check that runs right after it.
    ///
    /// It once did not: the default pointed under the state directory, the home
    /// check refused it, and `add` without `--cwd` could not succeed at all.
    #[test]
    fn the_default_cwd_passes_the_home_check() {
        let home = tmp_home();
        let home_str = home.to_string_lossy().to_string();

        let cwd = default_cwd(&home_str, "minha-app");
        assert_eq!(cwd, format!("{home_str}/apps/minha-app"));
        assert!(
            cwd_refusal(&cwd, &home).is_none(),
            "the default must not be refused: {cwd}"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// A refused `cwd` must be refused through the same rule the command uses,
    /// so the prelude and the command cannot disagree about what is allowed.
    #[test]
    fn cwd_refusal_reports_what_the_command_reports() {
        let home = tmp_home();

        let (code, _) = cwd_refusal("/tmp/fora-do-home", &home).expect("must be refused");
        assert_eq!(code, "cwd_outside_home");

        let (code, _) = cwd_refusal("relativo/nao-serve", &home).expect("must be refused");
        assert_eq!(code, "invalid_cwd");

        std::fs::remove_dir_all(&home).ok();
    }

    /// A home that exists, so `canonicalize` inside the check has something to
    /// resolve.
    fn tmp_home() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("selynt-home-{}", std::process::id()));
        std::fs::create_dir_all(p.join("apps")).unwrap();
        p
    }
}
