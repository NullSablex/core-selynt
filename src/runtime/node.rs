use std::path::{Path, PathBuf};

/// Minimum supported Node.js version. `node --import` requires 20.6+.
pub const NODE_MIN_MAJOR: u32 = 20;
pub const NODE_MIN_MINOR: u32 = 6;

/// Parses `v20.15.1` into `(20, 15, 1)`. Returns `None` when the input does not
/// start with `v` or any of the version components fails to parse.
pub fn parse_node_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let s = ver.strip_prefix('v')?;
    let mut parts = s.splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Se a entrada é TypeScript, que o Node executa removendo os tipos.
pub fn is_typescript_entry(entry: &str) -> bool {
    Path::new(entry)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e, "ts" | "mts" | "cts"))
}

/// Se o Node desta versão executa TypeScript sem flag nenhuma.
///
/// A remoção de tipos ficou ligada por padrão no 22.18.0 e no 23.6.0; antes
/// disso o Node recusa o `.ts` com um erro que não diz o motivo. `None` quando
/// a versão não é legível — sem saber, não há o que afirmar.
pub fn strips_types_by_default(ver: &str) -> Option<bool> {
    let (major, minor, _) = parse_node_semver(ver)?;
    Some(match major {
        0..=21 => false,
        22 => minor >= 18,
        23 => minor >= 6,
        _ => true,
    })
}

/// A versão gravada para um runtime em `etc/node_versions` (`<caminho> <versão>`).
///
/// O admin detectou e escolheu esses runtimes; a versão vem dali, sem
/// executar o binário — executar runtime como root é o que a detecção existe
/// para fazer com cuidado (ver `runtime::detect`).
pub fn recorded_version(node_path: &str) -> Option<String> {
    let content = std::fs::read_to_string(format!(
        "{}/etc/node_versions",
        crate::sys::state::PLUGIN_PATH
    ))
    .ok()?;
    recorded_version_in(&content, node_path)
}

fn recorded_version_in(content: &str, node_path: &str) -> Option<String> {
    content.lines().find_map(|l| {
        let mut parts = l.split_whitespace();
        (parts.next()? == node_path).then(|| parts.next().map(str::to_string))?
    })
}

/// Recusa uma aplicação TypeScript num Node que não a executa.
///
/// `Some((versão, motivo))` quando a combinação não sobe. Versão desconhecida
/// não bloqueia: recusar sem saber seria adivinhar.
pub fn typescript_refusal(entry: &str, node_path: &str) -> Option<String> {
    if !is_typescript_entry(entry) {
        return None;
    }
    let ver = recorded_version(node_path)?;
    (strips_types_by_default(&ver) == Some(false)).then(|| {
        format!(
            "Node {ver} does not run TypeScript ({entry}) directly; \
             choose Node 22.18 or later, or compile the entry to JavaScript"
        )
    })
}

pub fn node_version_ok(ver: &str) -> bool {
    parse_node_semver(ver).is_some_and(|(major, minor, _)| {
        major > NODE_MIN_MAJOR || (major == NODE_MIN_MAJOR && minor >= NODE_MIN_MINOR)
    })
}

/// Runs `{path} --version` and returns the raw output (e.g. `v20.15.1`),
/// without checking against the minimum supported version.
pub fn get_node_version_raw(path: &Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
    ver.starts_with('v').then_some(ver)
}

/// Same as `get_node_version_raw` but filters out runtimes that don't meet the
/// minimum supported version.
pub fn get_node_version(path: &Path) -> Option<String> {
    let ver = get_node_version_raw(path)?;
    node_version_ok(&ver).then_some(ver)
}

/// Single-`*` glob expansion. Returns matches whose final component is a file.
///
/// The `*` matches within one path component, so it may carry literal text on
/// either side of it — `/opt/alt/alt-nodejs*/root/usr/bin/node` scans `/opt/alt`
/// for entries starting with `alt-nodejs`. Matching only whole components would
/// miss `CloudLinux`'s alt-nodejs layout entirely.
pub fn glob_paths(pattern: &str) -> Vec<PathBuf> {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() != 2 {
        return Vec::new();
    }
    let (prefix, suffix) = (parts[0], parts[1]);

    // Split the prefix at the last `/`: everything before it is the directory to
    // scan, everything after is the literal an entry name must start with.
    let (dir, name_prefix) = match prefix.rfind('/') {
        Some(i) => (&prefix[..=i], &prefix[i + 1..]),
        None => return Vec::new(),
    };
    // Likewise for the suffix: up to the first `/` the entry name must end with
    // that literal; the rest is the path to descend into.
    let (name_suffix, rest) = suffix
        .find('/')
        .map_or((suffix, ""), |i| (&suffix[..i], &suffix[i..]));

    let parent = Path::new(dir.trim_end_matches('/'));
    if !parent.is_dir() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // The `*` must match at least nothing, but the two literals may not
        // overlap — `ab*c` must not match `abc` twice over.
        if !name.starts_with(name_prefix)
            || !name.ends_with(name_suffix)
            || name.len() < name_prefix.len() + name_suffix.len()
        {
            continue;
        }
        let candidate = entry.path().join(rest.trim_start_matches('/'));
        if candidate.is_file() {
            results.push(candidate);
        }
    }
    results
}

#[cfg(test)]
mod glob_tests {
    use super::glob_paths;
    use std::fs;

    /// Builds a throwaway tree and returns its root.
    fn tree(tag: &str, files: &[&str]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("selynt-glob-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for f in files {
            let p = root.join(f.trim_start_matches('/'));
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"").unwrap();
        }
        root
    }

    #[test]
    fn matches_whole_component() {
        let root = tree("whole", &["usr/local/nvm/versions/node/v22.1.0/bin/node"]);
        let pat = format!("{}/usr/local/nvm/versions/node/*/bin/node", root.display());
        assert_eq!(glob_paths(&pat).len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    /// `CloudLinux`'s layout: the `*` sits inside a component, after a literal.
    #[test]
    fn matches_partial_component() {
        let root = tree(
            "partial",
            &[
                "opt/alt/alt-nodejs20/root/usr/bin/node",
                "opt/alt/alt-nodejs22/root/usr/bin/node",
                "opt/alt/alt-php81/root/usr/bin/node",
            ],
        );
        let pat = format!("{}/opt/alt/alt-nodejs*/root/usr/bin/node", root.display());
        let mut got: Vec<String> = glob_paths(&pat)
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        got.sort();
        assert_eq!(got.len(), 2, "alt-php81 must not match: {got:?}");
        assert!(got.iter().all(|p| p.contains("alt-nodejs")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_multiple_stars_and_missing_dir() {
        assert_eq!(
            glob_paths("/opt/*/x/*/node"),
            Vec::<std::path::PathBuf>::new()
        );
        assert_eq!(
            glob_paths("/nonexistent-selynt/*/node"),
            Vec::<std::path::PathBuf>::new()
        );
    }
}

#[cfg(test)]
mod typescript_tests {
    use super::{is_typescript_entry, recorded_version_in, strips_types_by_default};

    /// Os limites reais: 22.18.0 e 23.6.0 ligaram a remoção de tipos.
    #[test]
    fn type_stripping_follows_the_release_that_enabled_it() {
        for (v, esperado) in [
            ("v20.20.2", Some(false)),
            ("v22.17.1", Some(false)),
            ("v22.18.0", Some(true)),
            ("v22.23.2", Some(true)),
            ("v23.5.0", Some(false)),
            ("v23.6.0", Some(true)),
            ("v24.19.0", Some(true)),
            ("v25.9.0", Some(true)),
            ("lixo", None),
        ] {
            assert_eq!(strips_types_by_default(v), esperado, "{v}");
        }
    }

    #[test]
    fn only_typescript_extensions_count() {
        for e in ["app.ts", "app.mts", "dir.x/app.cts"] {
            assert!(is_typescript_entry(e), "{e}");
        }
        for e in ["app.js", "app.mjs", "app.tsx.js", "ts", "app"] {
            assert!(!is_typescript_entry(e), "{e}");
        }
    }

    #[test]
    fn the_recorded_version_is_matched_by_exact_path() {
        let c = "/opt/node20/bin/node v20.20.2\n/opt/node20/bin/node2 v24.1.0\n";
        assert_eq!(
            recorded_version_in(c, "/opt/node20/bin/node").as_deref(),
            Some("v20.20.2")
        );
        assert_eq!(
            recorded_version_in(c, "/opt/node20/bin/node2").as_deref(),
            Some("v24.1.0")
        );
        assert_eq!(recorded_version_in(c, "/opt/node20/bin"), None);
    }
}
