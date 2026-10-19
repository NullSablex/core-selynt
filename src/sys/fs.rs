//! Filesystem primitives shared across the panel.
//!
//! [`atomic_write`] is why this exists: the panel writes files other processes
//! read concurrently, and a half-written one there is worse than none. Writing
//! to a temporary and renaming makes the swap atomic.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};

/// Hands the state tree to the account, leaving `.run` alone.
///
/// `.run` is deliberately root-owned — see `init_state_dir` — so sweeping it
/// into the recursive chown would undo that on every single invocation.
///
/// Roda como root numa árvore onde a conta escreve, então o tipo de cada
/// entrada é lido sem seguir symlink: só se desce em diretório de verdade, só
/// se troca dono de arquivo comum e diretório. Socket, link e FIFO ficam como
/// estão — os sockets já são da conta, criados pelo próprio app.
pub(super) fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<()> {
    if path.file_name().is_some_and(|n| n == ".run") {
        return Ok(());
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    let ty = meta.file_type();
    if !(ty.is_dir() || ty.is_file()) {
        return Ok(());
    }
    chown_path(path, uid, gid)?;
    if ty.is_dir() {
        for entry in std::fs::read_dir(path)
            .with_context(|| format!("read_dir {}", path.display()))?
            .flatten()
        {
            chown_recursive(&entry.path(), uid, gid)?;
        }
    }
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

/// Abre um caminho existente sem seguir symlink, para alterar o próprio objeto.
///
/// O binário roda como root e grava em pastas onde a conta também escreve;
/// seguir um link ali deixaria a conta escolher o que o root altera. Com o
/// descritor em mãos, `fchmod`/`fchown` agem sobre o que foi aberto — não há
/// janela entre conferir e alterar. `O_NONBLOCK` evita travar num FIFO
/// plantado no lugar do arquivo.
fn open_nofollow(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {} (no symlinks)", path.display()))?;
    let ty = f.metadata()?.file_type();
    if !(ty.is_file() || ty.is_dir()) {
        anyhow::bail!("{} is neither a file nor a directory", path.display());
    }
    Ok(f)
}

/// Se o caminho é um arquivo comum, sem seguir symlink.
pub fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Se o caminho é um diretório de verdade, sem seguir symlink.
pub fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

/// Abre para acrescentar, criando se faltar e esvaziando antes, sem seguir
/// symlink. Para os logs que o lado root abre em nome da aplicação.
pub fn open_log_nofollow(path: &Path, truncate: bool) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    if truncate {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("truncate {}", path.display()))?;
    }
    let f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    if !f.metadata()?.file_type().is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    Ok(f)
}

/// Troca dono e grupo do arquivo ou diretório, recusando symlink.
pub fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::fd::AsRawFd;
    let f = open_nofollow(path)?;
    // SAFETY: o descritor é válido enquanto `f` vive.
    if unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } != 0 {
        anyhow::bail!(
            "chown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Troca o modo do arquivo ou diretório, recusando symlink.
pub fn set_perm(path: &Path, mode: u32) -> Result<()> {
    open_nofollow(path)?
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}

/// Grava o arquivo inteiro de uma vez: temporário ao lado e `rename` por cima.
///
/// O temporário tem nome imprevisível e nasce com `O_EXCL | O_NOFOLLOW`: se
/// qualquer coisa já ocupar o nome, a abertura falha em vez de seguir um link.
/// O nome fixo de antes (`.<arquivo>.tmp`) deixava a conta, que escreve nas
/// mesmas pastas, apontá-lo para um arquivo do sistema e fazer o root gravar
/// lá. O `rename` substitui o próprio caminho final, mesmo que seja um link,
/// sem segui-lo.
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = path.with_file_name(format!(".{base}.{}.{nonce:x}.tmp", std::process::id()));

    let result = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(content)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all().ok();
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod safe_write_tests {
    use super::{atomic_write, chown_path, set_perm};
    use std::os::unix::fs::PermissionsExt;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("selynt-fs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Um link no lugar do arquivo final é substituído, não seguido: o alvo
    /// fica intacto.
    #[test]
    fn writing_over_a_symlink_replaces_the_link() {
        let d = dir("link");
        let alvo = d.join("alvo");
        std::fs::write(&alvo, "INTACTO").unwrap();
        let final_ = d.join("estado");
        std::os::unix::fs::symlink(&alvo, &final_).unwrap();

        atomic_write(&final_, b"novo").unwrap();

        assert_eq!(std::fs::read_to_string(&alvo).unwrap(), "INTACTO");
        assert!(
            !std::fs::symlink_metadata(&final_)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&final_).unwrap(), "novo");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Nenhum temporário fica para trás, nem com sucesso nem com falha.
    #[test]
    fn no_temporary_file_is_left_behind() {
        let d = dir("tmp");
        atomic_write(&d.join("a"), b"x").unwrap();
        assert!(atomic_write(&d.join("sem-pasta").join("b"), b"x").is_err());
        let sobras: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(sobras.is_empty(), "{sobras:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// O chown recursivo do diretório de estado atravessa sockets e links sem
    /// abortar e sem seguir link para fora da árvore. Faltou no primeiro teste:
    /// o diretório real tem os sockets dos apps, e o comando inteiro falhava.
    #[test]
    fn recursive_chown_skips_sockets_and_links() {
        let d = dir("rec");
        let fora = dir("rec-fora");
        std::fs::create_dir_all(d.join(".sockets").join("abc")).unwrap();
        let _sock =
            std::os::unix::net::UnixListener::bind(d.join(".sockets/abc/app.sock")).unwrap();
        std::fs::write(fora.join("alheio"), "x").unwrap();
        std::os::unix::fs::symlink(&fora, d.join("link-dir")).unwrap();
        std::fs::write(d.join("locale"), "pt-br").unwrap();

        // Para o próprio dono, o chown é permitido mesmo sem root.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        super::chown_recursive(&d, uid, gid).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&fora);
    }

    /// Modo e dono recusam link em vez de alterar o que ele aponta.
    #[test]
    fn mode_and_owner_refuse_symlinks() {
        let d = dir("perm");
        let alvo = d.join("alvo");
        std::fs::write(&alvo, "x").unwrap();
        std::fs::set_permissions(&alvo, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&alvo, &link).unwrap();

        assert!(set_perm(&link, 0o777).is_err());
        assert!(chown_path(&link, 0, 0).is_err());
        let modo = std::fs::metadata(&alvo).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o600, "o alvo do link foi alterado");

        // No próprio arquivo, funciona.
        set_perm(&alvo, 0o640).unwrap();
        let modo = std::fs::metadata(&alvo).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o640);
        let _ = std::fs::remove_dir_all(&d);
    }
}
