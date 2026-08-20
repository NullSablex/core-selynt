use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crate::output::debug;

/// Grants the web user the minimum access required to reach an app's Unix
/// socket and proxy marker. Tries `setfacl` first; if it is unavailable or
/// fails, falls back to `chmod` with permissive-but-still-restricted modes.
pub fn apply_acl(state_dir: &Path, socket_path: &Path, marker_path: &Path, web_user: &str) {
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
        debug("setfacl failed — falling back to chmod");
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

    setfacl(state_dir, &traverse)
        && setfacl(sockets_dir, &traverse)
        && setfacl(proxy_dir, &traverse)
        && setfacl(socket_path, &read_write)
        && setfacl(marker_path, &read_only)
}

/// `chmod` fallback when `setfacl` is unavailable: `711` on the directories
/// (other-traverse only), `600` on the socket, `604` on the marker.
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
    let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::set_permissions(marker_path, std::fs::Permissions::from_mode(0o604));
}
