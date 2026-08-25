//! Per-account isolation, built on mount and PID namespaces.
//!
//! An account's apps run as the same user, so by default they can read each
//! other's files and signal each other's processes. Isolated, each runs where
//! the neighbours do not exist — still as the account, since a system user per
//! app would fill `/etc/passwd` with entries DirectAdmin knows nothing about.
//!
//! The sandbox goes *inside* the systemd scope: the app must stay in its own
//! cgroup for the memory limits and the netguard sweep to keep working.

use std::path::Path;
use std::process::Command;

/// Read-only system paths an app needs to run at all: the interpreter, shared
/// libraries and the resolver's configuration.
const SYSTEM_PATHS: [&str; 6] = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"];

/// Whether this host can isolate apps.
///
/// Bubblewrap is packaged on the distributions the panel targets but is not
/// universally installed, and unprivileged namespaces can be disabled outright.
/// Callers fall back to running the app unisolated.
pub(crate) fn available() -> bool {
    bwrap_path().is_some() && user_namespaces_enabled()
}

/// Why isolation is unavailable, for a message the account will actually read.
///
/// Returns an i18n key rather than prose: the panel translates it, and the CLI
/// prints it as-is.
pub(crate) fn unavailable_reason() -> &'static str {
    if bwrap_path().is_none() {
        "errors.sandbox_no_bwrap"
    } else if !user_namespaces_enabled() {
        "errors.sandbox_no_userns"
    } else {
        "errors.sandbox_unavailable"
    }
}

fn bwrap_path() -> Option<&'static str> {
    ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
}

/// `user.max_user_namespaces` at 0 means the kernel refuses to create one.
fn user_namespaces_enabled() -> bool {
    std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|n| n > 0)
}

/// Wraps `cmd` so it runs seeing only its own directory and processes.
///
/// The app's working directory and its socket directory are bound read-write;
/// the rest of the account's home is left out of the mount namespace. A tmpfs
/// would hide the neighbours too, but the socket created on it would exist only
/// inside the namespace and the proxy could never reach it.
pub(crate) fn wrap(cmd: Command, app_dir: &Path, socket_dir: &Path) -> Command {
    let Some(bwrap) = bwrap_path() else {
        return cmd;
    };

    let mut run = Command::new(bwrap);

    for p in SYSTEM_PATHS {
        if Path::new(p).exists() {
            run.arg("--ro-bind").arg(p).arg(p);
        }
    }

    run.arg("--bind").arg(app_dir).arg(app_dir);
    run.arg("--bind").arg(socket_dir).arg(socket_dir);

    run.arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        // A private /tmp keeps one app's temporary files away from the others.
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--unshare-pid");
    // Deliberately no `--die-with-parent`: the app is detached with `setsid`
    // and outlives whatever started it, so tying it to its immediate parent
    // kills it the moment the spawn returns. The systemd scope is what bounds
    // its lifetime.

    run.arg(cmd.get_program());
    for a in cmd.get_args() {
        run.arg(a);
    }
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => {
                run.env(k, v);
            }
            None => {
                run.env_remove(k);
            }
        }
    }

    run
}

#[cfg(test)]
mod tests {
    use super::wrap;
    use std::path::Path;
    use std::process::Command;

    /// The wrapper must not lose the program it was asked to run.
    #[test]
    fn keeps_program_and_args() {
        if super::bwrap_path().is_none() {
            return;
        }
        let mut inner = Command::new("/usr/local/bin/node");
        inner.arg("--import").arg("/x/loader.js").arg("/app/i.js");

        let wrapped = wrap(inner, Path::new("/app"), Path::new("/sock"));
        let args: Vec<String> = wrapped
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert!(args.contains(&"/usr/local/bin/node".to_string()));
        assert!(args.contains(&"/app/i.js".to_string()));
        assert!(args.windows(3).any(|w| w == ["--bind", "/app", "/app"]));
    }

    /// Environment is what carries SELYNT_SOCKET to the app.
    #[test]
    fn carries_environment_over() {
        if super::bwrap_path().is_none() {
            return;
        }
        let mut inner = Command::new("/bin/true");
        inner.env("SELYNT_SOCKET", "/sock/app.sock");

        let wrapped = wrap(inner, Path::new("/app"), Path::new("/sock"));
        let found = wrapped
            .get_envs()
            .any(|(k, v)| k == "SELYNT_SOCKET" && v == Some("/sock/app.sock".as_ref()));
        assert!(found);
    }

    /// Sibling apps must not be reachable, so only the app's own directory is
    /// ever bound read-write.
    #[test]
    fn binds_only_the_apps_own_directory() {
        if super::bwrap_path().is_none() {
            return;
        }
        let wrapped = wrap(
            Command::new("/bin/true"),
            Path::new("/home/bob/apps/api"),
            Path::new("/state/bob/.sockets/api"),
        );
        let args: Vec<String> = wrapped
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        let rw_binds: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && args[i - 1] == "--bind")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(rw_binds.len(), 2, "only app dir and socket dir: {rw_binds:?}");
        assert!(!args.iter().any(|a| a == "/home/bob/apps"));
    }

    /// The reason is only asked for when isolation is unavailable, so with
    /// bwrap present the cause is that namespaces are off. The branches were
    /// once inverted — the arm meaning "namespaces are disabled" tested that
    /// they were *enabled* — so the panel gave a generic message in the one
    /// case it could actually explain, and named a missing feature that was
    /// present in the other.
    fn reason_for(bwrap: bool, userns: bool) -> &'static str {
        if !bwrap {
            "errors.sandbox_no_bwrap"
        } else if !userns {
            "errors.sandbox_no_userns"
        } else {
            "errors.sandbox_unavailable"
        }
    }

    #[test]
    fn unavailable_reason_names_the_actual_cause() {
        assert_eq!(reason_for(false, true), "errors.sandbox_no_bwrap");
        assert_eq!(reason_for(false, false), "errors.sandbox_no_bwrap");
        // bwrap is installed, so what is missing is namespace support.
        assert_eq!(reason_for(true, false), "errors.sandbox_no_userns");
        // Both present: unavailability has some other cause.
        assert_eq!(reason_for(true, true), "errors.sandbox_unavailable");
    }
}
