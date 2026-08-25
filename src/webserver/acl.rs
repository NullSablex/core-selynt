use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crate::sys::output::debug;

/// Grants the web user the minimum access required to reach an app's Unix
/// socket and proxy marker. Tries `setfacl` first; if it is unavailable or
/// fails, falls back to `chmod` with permissive-but-still-restricted modes.
pub(crate) fn apply_acl(state_dir: &Path, socket_path: &Path, marker_path: &Path, web_user: &str) {
    if web_user.is_empty() {
        debug("no web_user configured — skipping ACL");
        return;
    }

    let sockets_dir = state_dir.join(".sockets");
    let proxy_dir = state_dir.join(".proxy");

    if !try_setfacl(
        state_dir,
        &sockets_dir,
        &proxy_dir,
        socket_path,
        marker_path,
        web_user,
    ) {
        // Worth stating plainly: the fallback cannot name the web user, so it
        // opens directory traverse to every account instead of just one. An
        // operator seeing this should install `acl` rather than accept it.
        debug(
            "setfacl failed — falling back to chmod: directory traverse will be \
             granted to all accounts, not only the web user. Install the 'acl' \
             package to restore per-account isolation.",
        );
        fallback_chmod(
            state_dir,
            &sockets_dir,
            &proxy_dir,
            socket_path,
            marker_path,
        );
    }
}

/// `setfacl` strategy:
///   - `--x` on the three directories (traverse only)
///   - `rw-` on the socket (web server reads/writes it)
///   - `r--` on the marker (web server only checks for existence)
fn try_setfacl(
    state_dir: &Path,
    sockets_dir: &Path,
    proxy_dir: &Path,
    socket_path: &Path,
    marker_path: &Path,
    web_user: &str,
) -> bool {
    let traverse = format!("u:{web_user}:--x");
    let read_write = format!("u:{web_user}:rw-");
    let read_only = format!("u:{web_user}:r--");

    let setfacl = |target: &Path, acl: &str| -> bool {
        Command::new("setfacl")
            .args(["-m", acl, target.to_str().unwrap_or("")])
            .status()
            .is_ok_and(|s| s.success())
    };

    // An isolated app's socket sits one level deeper, in a directory of its
    // own; the web server needs to traverse that too.
    let app_socket_dir = socket_path
        .parent()
        .filter(|p| *p != sockets_dir)
        .map(Path::to_path_buf);

    setfacl(state_dir, &traverse)
        && setfacl(sockets_dir, &traverse)
        && setfacl(proxy_dir, &traverse)
        && app_socket_dir
            .as_deref()
            .is_none_or(|d| setfacl(d, &traverse))
        && setfacl(socket_path, &read_write)
        && setfacl(marker_path, &read_only)
}

/// `chmod` fallback when `setfacl` is unavailable — weaker, and deliberately
/// noisy about it.
///
/// An ACL names one account; a mode bit cannot, so `711` grants traverse to
/// *every* account on the server. The socket stays `600`, so a neighbour still
/// cannot read it; what is lost is the directory-level opacity. A warning
/// rather than a refusal: leaving every app unreachable would be worse.
fn fallback_chmod(
    state_dir: &Path,
    sockets_dir: &Path,
    proxy_dir: &Path,
    socket_path: &Path,
    marker_path: &Path,
) {
    for dir in &[state_dir, sockets_dir, proxy_dir] {
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711));
    }
    if let Some(d) = socket_path.parent().filter(|p| *p != sockets_dir) {
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o711));
    }
    let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::set_permissions(marker_path, std::fs::Permissions::from_mode(0o604));
}
