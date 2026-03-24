use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};

pub const PLUGIN_PATH: &str = "/usr/local/directadmin/plugins/selynt_panel";

/// Metadados de um app, lidos do arquivo `.app`
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

// ─── Resolução de usuário e privilégio ───────────────────────────────────────

/// Resolve o user real a partir de USERNAME env → getpwnam.
/// Retorna (uid, gid, home, username).
pub fn resolve_target_user() -> Result<(u32, u32, String, String)> {
    let username = std::env::var("USERNAME").context("USERNAME env não definido")?;
    let cname =
        std::ffi::CString::new(username.as_str()).context("USERNAME inválido (contém nulo)")?;

    // Usar getpwnam_r (reentrant) em vez de getpwnam
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let ret = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };

    if ret != 0 || result.is_null() {
        anyhow::bail!("user {:?} não encontrado em /etc/passwd", username);
    }

    let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
        .to_str()
        .context("home dir não é UTF-8")?
        .to_string();

    Ok((pwd.pw_uid, pwd.pw_gid, home, username))
}

/// Drop de privilégio para o user real.
/// DEVE ser chamado APÓS criar dirs que precisam de root.
/// Usa initgroups() para preservar supplementary groups do user (necessário
/// para acessar binários em paths com restrição de grupo, ex: /usr/local/bin/node).
pub fn drop_privileges(uid: u32, gid: u32, username: &str) -> Result<()> {
    let cname = std::ffi::CString::new(username)
        .context("username inválido para initgroups")?;
    unsafe {
        if libc::initgroups(cname.as_ptr(), gid) != 0 {
            anyhow::bail!("initgroups({}) falhou: {}", username, std::io::Error::last_os_error());
        }
        if libc::setgid(gid) != 0 {
            anyhow::bail!("setgid({}) falhou: {}", gid, std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            anyhow::bail!("setuid({}) falhou: {}", uid, std::io::Error::last_os_error());
        }
        // Verificação completa: uid, gid, euid, egid
        if libc::geteuid() == 0 || libc::getuid() == 0 {
            anyhow::bail!("drop de privilégio falhou — ainda root (uid)");
        }
        if libc::getegid() == 0 || libc::getgid() == 0 {
            anyhow::bail!("drop de privilégio falhou — ainda root (gid)");
        }
        // Impedir re-escalação de privilégio via execve em binários setuid
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            anyhow::bail!("prctl(PR_SET_NO_NEW_PRIVS) falhou: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

// ─── Inicialização de diretórios ─────────────────────────────────────────────

/// Cria o state dir e subdirs operacionais como root, chown recursivo para o user real.
/// Garante que TODOS os arquivos e dirs dentro do state_dir pertençam ao user,
/// mesmo que tenham sido criados por uma execução anterior com ownership diferente.
pub fn init_state_dir(state_dir: &Path, uid: u32, gid: u32) -> Result<()> {
    let subdirs = [".run", ".sockets", ".proxy"];

    // Criar dirs se não existem (só chmod em dirs novos para não desfazer ACLs)
    for dir in std::iter::once(state_dir.to_path_buf())
        .chain(subdirs.iter().map(|s| state_dir.join(s)))
    {
        if !dir.is_dir() {
            std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {:?}", dir))?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 700 {:?}", dir))?;
        }
    }

    // Dir pai (/var/lib/selynt_panel/) precisa de traverse para o web server
    if let Some(parent) = state_dir.parent() {
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o711));
    }

    // chown recursivo: state_dir e tudo dentro
    chown_recursive(state_dir, uid, gid)
        .with_context(|| format!("chown -R {}:{} {:?}", uid, gid, state_dir))?;

    Ok(())
}

/// chown recursivo em um diretório e todo seu conteúdo.
fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<()> {
    chown_path(path, uid, gid)?;
    if path.is_dir() {
        for entry in std::fs::read_dir(path)
            .with_context(|| format!("read_dir {:?}", path))?
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
    let s = path.to_str().with_context(|| format!("path não-UTF8 {:?}", path))?;
    let c = std::ffi::CString::new(s).with_context(|| format!("path inválido {:?}", path))?;
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        anyhow::bail!("chown {:?}: {}", path, std::io::Error::last_os_error());
    }
    Ok(())
}

/// Cria {cwd}/logs/ com ownership do user real.
/// Chamado como root, antes do drop de privilégio.
pub fn init_app_logs_dir(cwd: &Path, uid: u32, gid: u32) -> Result<()> {
    let logs_dir = cwd.join("logs");
    if !logs_dir.is_dir() {
        std::fs::create_dir_all(&logs_dir)
            .with_context(|| format!("mkdir {:?}", logs_dir))?;
    }
    let logs_str = logs_dir.to_str()
        .with_context(|| format!("caminho não-UTF8 {:?}", logs_dir))?;
    let cpath = std::ffi::CString::new(logs_str)
        .with_context(|| format!("caminho inválido {:?}", logs_dir))?;
    if unsafe { libc::chown(cpath.as_ptr(), uid, gid) } != 0 {
        anyhow::bail!(
            "chown {:?} para {}:{}: {}",
            logs_dir, uid, gid, std::io::Error::last_os_error()
        );
    }
    std::fs::set_permissions(&logs_dir, std::fs::Permissions::from_mode(0o750))
        .with_context(|| format!("chmod 750 {:?}", logs_dir))?;
    Ok(())
}

// ─── Utilitários de estado ────────────────────────────────────────────────────

/// Parse de arquivo `KEY=VALUE` por linha
pub fn parse_kv(content: &str) -> HashMap<String, String> {
    content
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            Some((k.trim().to_string(), v.to_string()))
        })
        .collect()
}

/// Escrita atômica: escreve em `.tmp` e depois rename
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let tmp_name = format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp")
    );
    let tmp = path.with_file_name(tmp_name);
    std::fs::write(&tmp, content).with_context(|| format!("write {:?}", tmp))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename {:?} → {:?}", tmp, path))?;
    Ok(())
}

/// Aplica permissões Unix a um path
pub fn set_perm(path: &Path, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {:o} {:?}", mode, path))
}

/// Carrega metadados de um app a partir do arquivo `.app`
pub fn load_app_meta(state_dir: &Path, name: &str) -> Result<AppMeta> {
    let app_file = state_dir.join(".run").join(format!("{name}.app"));
    let content = std::fs::read_to_string(&app_file)
        .with_context(|| format!("app '{name}' não encontrado"))?;
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

/// Lista todos os nomes de apps registrados (por arquivos `.app`)
pub fn list_app_names(state_dir: &Path) -> Vec<String> {
    let run_dir = state_dir.join(".run");
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&run_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("app") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    names
}

/// Valida nome de app: ^[A-Za-z0-9._-]{1,64}$
pub fn validate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Lê o usuário web para ACL (env SELYNT_WEB_USER ou arquivo no plugin)
pub fn get_web_user() -> String {
    if let Ok(u) = std::env::var("SELYNT_WEB_USER") {
        return u;
    }
    std::fs::read_to_string(format!("{PLUGIN_PATH}/etc/ols_web_user"))
        .unwrap_or_default()
        .trim()
        .to_string()
}
