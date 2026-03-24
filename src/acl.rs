use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crate::output::debug;

/// Aplica ACL para o usuário web no socket e no marker.
///
/// Tenta setfacl primeiro; em caso de falha faz fallback para chmod.
pub fn apply_acl(state_dir: &Path, socket_path: &Path, marker_path: &Path, web_user: &str) {
    if web_user.is_empty() {
        debug("nenhum web_user configurado — ACL ignorada");
        return;
    }

    let s_dir = state_dir.join(".sockets");
    let p_dir = state_dir.join(".proxy");

    if !try_setfacl(
        state_dir,
        &s_dir,
        &p_dir,
        socket_path,
        marker_path,
        web_user,
    ) {
        debug("setfacl falhou — fallback para chmod");
        fallback_chmod(state_dir, &s_dir, &p_dir, socket_path, marker_path);
    }
}

/// Aplica setfacl:
///   --x em state_dir, s/, p/
///   rw- no socket
///   r-- no marker
fn try_setfacl(
    state_dir: &Path,
    s_dir: &Path,
    p_dir: &Path,
    socket_path: &Path,
    marker_path: &Path,
    web_user: &str,
) -> bool {
    let x_entry = format!("u:{web_user}:--x");
    let rw_entry = format!("u:{web_user}:rw-");
    let r_entry = format!("u:{web_user}:r--");

    let setfacl_dir = |dir: &Path, acl: &str| -> bool {
        Command::new("setfacl")
            .args(["-m", acl, dir.to_str().unwrap_or("")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    setfacl_dir(state_dir, &x_entry)
        && setfacl_dir(s_dir, &x_entry)
        && setfacl_dir(p_dir, &x_entry)
        && setfacl_dir(socket_path, &rw_entry)
        && setfacl_dir(marker_path, &r_entry)
}

/// Fallback chmod quando setfacl não está disponível:
///   711 nos dirs, 600 no socket, 604 no marker
fn fallback_chmod(
    state_dir: &Path,
    s_dir: &Path,
    p_dir: &Path,
    socket_path: &Path,
    marker_path: &Path,
) {
    for dir in &[state_dir, s_dir, p_dir] {
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711));
    }
    let _ =
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));
    let _ =
        std::fs::set_permissions(marker_path, std::fs::Permissions::from_mode(0o604));
}
