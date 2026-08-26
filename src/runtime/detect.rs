//! Finding the Node.js runtimes on this server, and deciding which are safe to
//! run.
//!
//! Detection is not a passive scan: reading a version means *executing* the
//! binary, and `save-node-versions` does so as root. A runtime a customer can
//! write is therefore one they can have run as root, so each candidate must
//! resolve inside a trusted root *and* be root-owned and unwritable by others,
//! parents included.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::node::{get_node_version, glob_paths};

const NODE_FIXED_PATHS: [&str; 2] = ["/usr/local/bin/node", "/usr/bin/node"];
/// Roots a detected runtime may ultimately live under, checked *after* symlinks
/// are resolved. A candidate found in a trusted directory can still be a symlink
/// pointing somewhere a customer controls, and detection executes it.
const NODE_TRUSTED_ROOTS: [&str; 3] = ["/usr/bin/", "/usr/local/", "/opt/"];
const NODE_GLOBS: [&str; 3] = [
    "/usr/local/nvm/versions/node/*/bin/node",
    "/opt/alt/alt-nodejs*/root/usr/bin/node",
    // Where the official tarball is conventionally unpacked. Reached only via
    // the /usr/local/bin/node symlink otherwise, so a second version installed
    // here alongside the first would go undetected.
    "/usr/local/lib/nodejs/*/bin/node",
];

/// Every path the detector will look at, before any safety judgement.
///
/// Detection *executes* each candidate to read its `--version`, so whatever
/// directory is accepted here is a directory whose contents get run. Allowing
/// `/home/` meant any customer on a shared box could plant a binary there and
/// have it executed — as root, when reached through `save-node-versions` in the
/// root prelude. Being listed here is not trust: see `is_safe_to_execute`.
fn node_candidates() -> Vec<PathBuf> {
    let nvm_dir_glob = std::env::var("NVM_DIR")
        .ok()
        .filter(|d| {
            let safe = d.starts_with("/opt/") || d.starts_with("/usr/local/");
            safe && !d.contains("..")
        })
        .map(|d| format!("{d}/versions/node/*/bin/node"));

    let mut candidates: Vec<PathBuf> = NODE_FIXED_PATHS.iter().map(PathBuf::from).collect();
    for pattern in NODE_GLOBS
        .iter()
        .map(|s| (*s).to_string())
        .chain(nvm_dir_glob)
    {
        candidates.extend(glob_paths(&pattern));
    }
    candidates
}

/// Detects Node.js runtimes installed on the system. Returns
/// `Vec<(path, version)>` — e.g. `("/usr/bin/node", "v22.22.0")`.
/// The interpreter to execute when an app names no version of its own.
///
/// Returns an absolute path, never the bare name: the app is launched with the
/// environment of whoever invoked the panel, and the CGI's `PATH` does not
/// carry `/usr/local/bin`. Relying on `PATH` made a Node app start from a shell
/// and fail from the panel — inside the sandbox, as `execvp node: No such file
/// or directory`.
pub fn default_node_path() -> Option<String> {
    NODE_FIXED_PATHS
        .iter()
        .find(|p| Path::new(p).is_file())
        .map(|p| (*p).to_string())
}

pub fn detect_node_versions() -> Vec<(String, String)> {
    let candidates = node_candidates();

    let mut versions = Vec::new();
    let mut seen = HashSet::new();
    for path in &candidates {
        if !path.is_file() {
            continue;
        }
        // Resolve before trusting: `is_file` follows symlinks, so a link planted
        // in a trusted directory would otherwise have its target executed below.
        let Ok(canonical) = std::fs::canonicalize(path) else {
            continue;
        };
        if !is_safe_to_execute(&canonical) {
            continue;
        }
        if !seen.insert(canonical) {
            continue;
        }
        if let Some(ver) = get_node_version(path) {
            versions.push((path.to_string_lossy().to_string(), ver));
        }
    }

    // Da mais nova para a mais antiga. Sem isto a ordem é a da varredura — os
    // caminhos fixos antes dos globs, e cada glob na ordem que o diretório
    // devolve —, então a lista saía como v25, v20, v22, v24.
    versions.sort_by(|(_, a), (_, b)| {
        super::node::parse_node_semver(b)
            .cmp(&super::node::parse_node_semver(a))
            .then_with(|| a.cmp(b))
    });
    versions
}

/// Whether a *resolved* runtime path lies under a root reserved for
/// system-wide software.
fn is_trusted_runtime_path(canonical: &Path) -> bool {
    NODE_TRUSTED_ROOTS
        .iter()
        .any(|root| canonical.starts_with(root))
}

/// Runtime binaries that exist in a searched location but were refused, paired
/// with why. Detection skips these silently — it must, since executing them is
/// the risk — so the diagnostic reports them instead: "installed it and the
/// panel does not list it" is otherwise indistinguishable from a broken glob.
pub fn rejected_node_runtimes() -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for path in node_candidates() {
        if !path.is_file() {
            continue;
        }
        let Ok(canonical) = std::fs::canonicalize(&path) else {
            continue;
        };
        if !seen.insert(canonical.clone()) {
            continue;
        }
        if is_safe_to_execute(&canonical) {
            continue;
        }
        let reason = if is_trusted_runtime_path(&canonical) {
            "unsafe_ownership"
        } else {
            "untrusted_path"
        };
        out.push((path.to_string_lossy().to_string(), reason));
    }
    out
}

/// Whether a runtime binary is safe for the detector to execute as root.
///
/// Location alone is not enough. Runtime trees are routinely left owned by the
/// account that unpacked them (a tarball extracted with its original uid, or
/// nvm preserving the owner of `$NVM_DIR`), and `npm install -g` writes into
/// that same tree as that account. Anyone who can write the file — or any
/// directory leading to it — can choose what runs as root here.
fn is_safe_to_execute(canonical: &Path) -> bool {
    if !is_trusted_runtime_path(canonical) {
        return false;
    }
    // The file itself, plus every directory above it: a writable parent means
    // the binary can simply be replaced.
    let mut current = Some(canonical);
    while let Some(p) = current {
        if !is_root_owned_and_unwritable(p) {
            return false;
        }
        if p.parent().is_none_or(|parent| parent == p) {
            break;
        }
        current = p.parent();
    }
    true
}

/// Root-owned and writable by nobody but root.
fn is_root_owned_and_unwritable(path: &Path) -> bool {
    let Ok(md) = std::fs::metadata(path) else {
        return false;
    };
    md.uid() == 0 && md.mode() & 0o022 == 0
}
#[cfg(test)]
mod tests {
    use super::{NODE_FIXED_PATHS, default_node_path, is_trusted_runtime_path};
    use std::path::Path;

    #[test]
    fn accepts_root_owned_locations() {
        for p in [
            "/usr/local/bin/node",
            "/usr/bin/node",
            "/usr/local/nvm/versions/node/v22.23.2/bin/node",
            "/usr/local/lib/nodejs/node-v25.9.0/bin/node",
            "/opt/alt/alt-nodejs20/root/usr/bin/node",
        ] {
            assert!(
                is_trusted_runtime_path(Path::new(p)),
                "{p} should be trusted"
            );
        }
    }

    /// Files we create in the test are owned by the test user, not root, so
    /// they must be refused however trusted their location looks.
    #[test]
    fn rejects_binaries_not_owned_by_root() {
        use super::is_safe_to_execute;
        let f = std::env::temp_dir().join(format!("selynt-own-{}", std::process::id()));
        std::fs::write(&f, b"").unwrap();
        assert!(!is_safe_to_execute(&f));
        let _ = std::fs::remove_file(&f);
    }

    /// Under a normal system layout the packaged runtimes are root-owned, so
    /// the check must not reject them — otherwise detection returns nothing.
    #[test]
    fn accepts_a_real_root_owned_binary() {
        use super::is_safe_to_execute;
        // /bin/sh is root-owned on every supported distro; skip if the test
        // environment says otherwise rather than failing spuriously.
        let sh = std::path::Path::new("/bin/sh");
        let Ok(canonical) = std::fs::canonicalize(sh) else {
            return;
        };
        if canonical.starts_with("/usr/bin/") {
            assert!(
                is_safe_to_execute(&canonical),
                "{} should pass",
                canonical.display()
            );
        }
    }

    /// A symlink sitting in a trusted directory may resolve into a customer's
    /// home; detection executes what it finds, so the resolved path is what
    /// must be judged.
    #[test]
    fn rejects_targets_outside_trusted_roots() {
        for p in [
            "/home/attacker/fake-node",
            "/tmp/node",
            "/var/tmp/node",
            "/usr/local-evil/node",
        ] {
            assert!(
                !is_trusted_runtime_path(Path::new(p)),
                "{p} must be rejected"
            );
        }
    }

    /// The default interpreter must be an absolute path.
    ///
    /// It used to be the bare name `node`, resolved through `PATH`. The app
    /// inherits the environment of whoever invoked the panel, and the CGI's
    /// `PATH` has no `/usr/local/bin` — so an app that started fine from a
    /// shell died from the panel with `execvp node: No such file or directory`,
    /// and switching isolation left it down.
    #[test]
    fn default_node_path_is_absolute_or_none() {
        if let Some(p) = default_node_path() {
            assert!(
                std::path::Path::new(&p).is_absolute(),
                "{p} must not depend on PATH"
            );
        }
        for p in NODE_FIXED_PATHS {
            assert!(p.starts_with('/'), "{p} must be absolute");
        }
    }

    /// A lista sai da versão mais nova para a mais antiga.
    ///
    /// Sem ordenar, ela seguia a varredura: os caminhos fixos primeiro, depois
    /// cada glob na ordem que o diretório devolvesse — o que no servidor
    /// resultava em v25, v20, v22, v24, sem lógica visível para quem escolhe.
    #[test]
    fn versions_are_listed_newest_first() {
        let mut v = vec![
            ("/usr/local/bin/node".to_string(), "v25.9.0".to_string()),
            ("/nvm/20/node".to_string(), "v20.20.2".to_string()),
            ("/nvm/22/node".to_string(), "v22.23.2".to_string()),
            ("/nvm/24/node".to_string(), "v24.19.0".to_string()),
        ];
        v.sort_by(|(_, a), (_, b)| {
            super::super::node::parse_node_semver(b)
                .cmp(&super::super::node::parse_node_semver(a))
                .then_with(|| a.cmp(b))
        });
        let ordem: Vec<&str> = v.iter().map(|(_, ver)| ver.as_str()).collect();
        assert_eq!(ordem, ["v25.9.0", "v24.19.0", "v22.23.2", "v20.20.2"]);
    }
}
