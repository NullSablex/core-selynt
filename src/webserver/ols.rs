//! Wires the panel into `OpenLiteSpeed` and `DirectAdmin`: the vhost templates
//! carry the proxy blocks, and the web server's user is recorded so the socket
//! ACL can name it.
//!
//! In the binary rather than a shell script because it runs as root and edits
//! the templates every customer's vhost comes from — a file root executes is a
//! file whose contents become root execution.

use std::path::{Path, PathBuf};

use crate::sys::state::{DA_TEMPLATES, PLUGIN_PATH, STATE_BASE};

/// Delimiters of the block the panel owns inside a shared template file.
///
/// `DirectAdmin` templates may hold other people's customisations, so the block
/// is replaced between its markers instead of the file being overwritten.
pub const BEGIN_MARK: &str = "# BEGIN SELYNT_PANEL";
pub const END_MARK: &str = "# END SELYNT_PANEL";

/// Per-vhost proxy handler, pointing at the app's Unix socket.
///
/// `|SDOMAIN|`, `|VH_PORT|` and `|USER|` are `DirectAdmin` template variables,
/// substituted when it generates each vhost.
const TEMPLATE_CUSTOM_7: &str = "\
# BEGIN SELYNT_PANEL
extprocessor selynt_proxy-|SDOMAIN|-|VH_PORT| {
  type                    proxy
  address                 uds:///var/lib/selynt_panel/|USER|/.sockets/|SDOMAIN|
  maxConns                35
  initTimeout             60
  retryTimeout            0
  persistConn             1
  respBuffer              0
  autoStart               0
  instances               1
}
# END SELYNT_PANEL";

/// Routes to the handler above, but only while the app's proxy marker exists.
///
/// Without that condition every request to the domain would be proxied, so a
/// stopped app would break the site instead of falling through to PHP or static
/// files.
const TEMPLATE_CUSTOM_5: &str = "\
# BEGIN SELYNT_PANEL
RewriteCond /var/lib/selynt_panel/|USER|/.proxy/|SDOMAIN| -f
RewriteRule ^(.*)$ http://selynt_proxy-|SDOMAIN|-|VH_PORT|/$1 [P,L,E=PROXY-HOST:|HTTP_HOST|]
# END SELYNT_PANEL";

/// `OpenLiteSpeed`'s configuration directory, whichever layout is in use.
///
/// `DirectAdmin` 1.690+ installs it under `/etc/openlitespeed`; older builds keep
/// it in `/usr/local/lsws/conf`.
pub fn conf_dir() -> Option<&'static Path> {
    ["/etc/openlitespeed", "/usr/local/lsws/conf"]
        .into_iter()
        .map(Path::new)
        .find(|d| d.join("httpd_config.conf").is_file())
}

/// The main configuration file, when `OpenLiteSpeed` is installed.
pub fn main_conf() -> Option<PathBuf> {
    conf_dir().map(|d| d.join("httpd_config.conf"))
}

/// Marker lines around the include, so `teardown` can find and remove it.
const INCLUDE_BEGIN: &str = "# BEGIN SELYNT_PANEL extProcessors include";
const INCLUDE_END: &str = "# END SELYNT_PANEL extProcessors include";

/// Name of the generated handler file, in either location.
pub const HANDLERS_FILE: &str = "selynt_extprocessors.conf";

/// Whether the main config already reads `conf.d/*.conf` on its own.
///
/// `DirectAdmin`'s template for `OpenLiteSpeed` includes that directory under
/// "user configurations not maintained by `DirectAdmin`": a `CustomBuild` update
/// regenerates `httpd_config.conf` but never touches what is dropped there.
fn reads_drop_ins(conf_dir: &Path) -> bool {
    conf_dir.join("conf.d").is_dir()
        && std::fs::read_to_string(conf_dir.join("httpd_config.conf")).is_ok_and(|main| {
            main.lines().any(|l| {
                let l = l.trim();
                l.starts_with("include") && l.ends_with("conf.d/*.conf")
            })
        })
}

/// Where the generated handlers belong.
///
/// In `conf.d/` whenever the main config reads it. Appending an include line to
/// `httpd_config.conf` instead is what used to break: `DirectAdmin` owns that
/// file, a `CustomBuild` update rewrote it, and every proxied app answered 503
/// until someone ran `setup` again. The drop-in needs no line in a file the
/// panel does not own. Older layouts without `conf.d` keep the include.
pub fn handlers_path(conf_dir: &Path) -> PathBuf {
    if reads_drop_ins(conf_dir) {
        conf_dir.join("conf.d").join(HANDLERS_FILE)
    } else {
        conf_dir.join(HANDLERS_FILE)
    }
}

/// Whether the web server reads the generated handlers at all.
pub fn handlers_are_included(conf_dir: &Path) -> bool {
    reads_drop_ins(conf_dir)
        || std::fs::read_to_string(conf_dir.join("httpd_config.conf"))
            .is_ok_and(|main| main.contains(HANDLERS_FILE))
}

/// Removes what the include-line layout left behind, once the drop-in is used.
///
/// Both at once would define every handler twice. Only the panel's own lines
/// leave `httpd_config.conf`, and the file is rewritten only if one was there.
/// Returns whether anything changed — the web server then needs a reload.
pub fn retire_legacy_include(conf_dir: &Path) -> std::io::Result<bool> {
    if !reads_drop_ins(conf_dir) {
        return Ok(false);
    }
    let mut changed = false;
    let main = conf_dir.join("httpd_config.conf");
    let existing = std::fs::read_to_string(&main)?;
    if existing.contains(HANDLERS_FILE) {
        let kept = strip_legacy_include(&existing);
        crate::sys::fs::atomic_write(&main, kept.as_bytes()).map_err(std::io::Error::other)?;
        changed = true;
    }
    match std::fs::remove_file(conf_dir.join(HANDLERS_FILE)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(changed),
        Err(e) => Err(e),
    }
}

/// `httpd_config.conf` without the panel's include block.
fn strip_legacy_include(content: &str) -> String {
    content
        .lines()
        .filter(|l| {
            let l = l.trim_end();
            l != INCLUDE_BEGIN && l != INCLUDE_END && !l.contains(HANDLERS_FILE)
        })
        .fold(String::new(), |mut acc, l| {
            acc.push_str(l);
            acc.push('\n');
            acc
        })
}

/// Makes sure the web server reads the generated handler file.
///
/// Without it the handlers exist on disk and the web server never reads them,
/// so every proxied app answers 503 while looking perfectly healthy: the
/// process runs, the socket accepts, and the marker is in place.
///
/// Where `conf.d/` is read, there is nothing to add — only the old include
/// to retire. Otherwise the include line goes into `httpd_config.conf`.
fn ensure_include(conf_dir: &Path) -> std::io::Result<()> {
    if reads_drop_ins(conf_dir) {
        return retire_legacy_include(conf_dir).map(|_| ());
    }

    let main = conf_dir.join("httpd_config.conf");
    let existing = std::fs::read_to_string(&main)?;
    if existing.contains(HANDLERS_FILE) {
        return Ok(());
    }

    let include = conf_dir.join(HANDLERS_FILE);
    let block = format!(
        "\n{INCLUDE_BEGIN}\ninclude {}\n{INCLUDE_END}\n",
        include.display()
    );
    crate::sys::fs::atomic_write(&main, format!("{existing}{block}").as_bytes())
        .map_err(std::io::Error::other)
}

/// Replaces the panel's block in a template, leaving anything else in place.
fn upsert_block(path: &Path, block: &str) -> std::io::Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();

    // Everything that is not ours, so a customisation someone else added to the
    // same template survives.
    let mut kept = String::new();
    let mut inside = false;
    for line in existing.lines() {
        if line.trim_end() == BEGIN_MARK {
            inside = true;
            continue;
        }
        if line.trim_end() == END_MARK {
            inside = false;
            continue;
        }
        if !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }

    let content = if kept.trim().is_empty() {
        format!("{block}\n")
    } else {
        format!("{block}\n{kept}")
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::sys::fs::atomic_write(path, content.as_bytes()).map_err(std::io::Error::other)?;
    crate::sys::fs::set_perm(path, 0o644).map_err(std::io::Error::other)
}

/// The account `OpenLiteSpeed` runs as, which is what the socket ACL is granted
/// to.
///
/// Read from the server's own configuration first, then from the accounts a web
/// server is normally installed as. `DirectAdmin`'s `OpenLiteSpeed` config carries
/// no `user` directive at all, so the fallback is the usual path, not the
/// exception.
fn detect_web_user() -> Option<String> {
    if let Some(conf) = main_conf()
        && let Ok(content) = std::fs::read_to_string(conf)
    {
        for line in content.lines() {
            let line = line.trim();
            // A commented-out directive is not a setting.
            if line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            if parts.next().is_some_and(|k| k.eq_ignore_ascii_case("user"))
                && let Some(value) = parts.next()
            {
                let user = value.trim_matches('"');
                // The name has to belong to an account that exists: the socket
                // ACL is granted to it, and granting it to nobody at all would
                // leave every app unreachable with no error to point at.
                if !user.is_empty() && crate::sys::auth::user_exists(user) {
                    return Some(user.to_string());
                }
            }
        }
    }

    ["apache", "lsws", "www-data", "nginx", "nobody"]
        .into_iter()
        .find(|u| crate::sys::auth::user_exists(u))
        .map(ToString::to_string)
}

/// Asks `DirectAdmin` to regenerate every vhost from the templates.
///
/// Installing a template changes nothing on its own — the vhosts already on
/// disk were generated from the previous version.
pub fn rebuild_vhosts() -> bool {
    let custombuild = Path::new("/usr/local/directadmin/custombuild");
    if custombuild.join("build").is_file() {
        return std::process::Command::new("./build")
            .arg("rewrite_confs")
            .current_dir(custombuild)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
    }

    std::process::Command::new("da")
        .args(["build", "rewrite_confs"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// What the setup did, so the installer can report it.
pub struct Outcome {
    pub web_user: Option<String>,
    /// Whether `DirectAdmin` regenerated its vhosts from the new templates.
    /// Installing a template changes nothing until that happens.
    pub vhosts_rebuilt: bool,
}

/// Installs the templates and records the web server's user.
pub fn run() -> Result<Outcome, (String, String)> {
    if conf_dir().is_none() {
        return Err((
            "ols_missing".into(),
            "OpenLiteSpeed not found — the panel routes traffic through it".into(),
        ));
    }

    let templates_written = if Path::new(DA_TEMPLATES).is_dir() {
        let custom = Path::new(DA_TEMPLATES).join("custom");
        let seven = custom.join("openlitespeed_vhost.conf.CUSTOM.7.pre");
        let five = custom.join("openlitespeed_vhost.conf.CUSTOM.5.pre");

        upsert_block(&seven, TEMPLATE_CUSTOM_7)
            .and_then(|()| upsert_block(&five, TEMPLATE_CUSTOM_5))
            .map_err(|e| ("template_write_failed".to_string(), format!("{e:#}")))?;
        true
    } else {
        false
    };

    // The web server has to traverse this to reach each account's socket.
    let _ = crate::sys::fs::set_perm(Path::new(STATE_BASE), 0o711);

    let web_user = detect_web_user();
    if let Some(user) = &web_user {
        let etc = Path::new(PLUGIN_PATH).join("etc");
        let _ = std::fs::create_dir_all(&etc);
        let file = etc.join("ols_web_user");
        crate::sys::fs::atomic_write(&file, format!("{user}\n").as_bytes())
            .and_then(|()| crate::sys::fs::set_perm(&file, 0o644))
            .map_err(|e| ("web_user_write_failed".to_string(), format!("{e:#}")))?;
    }

    let vhosts_rebuilt = templates_written && rebuild_vhosts();

    // After the rebuild, never before: `rewrite_confs` regenerates
    // `httpd_config.conf` from DirectAdmin's own templates and drops anything
    // else in it. Writing the include first meant writing it and then watching
    // it be erased in the same run.
    if let Some(dir) = conf_dir()
        && let Err(e) = ensure_include(dir)
    {
        return Err(("include_write_failed".to_string(), format!("{e:#}")));
    }

    Ok(Outcome {
        web_user,
        vhosts_rebuilt,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BEGIN_MARK, END_MARK, HANDLERS_FILE, INCLUDE_BEGIN, INCLUDE_END, handlers_are_included,
        handlers_path, retire_legacy_include, strip_legacy_include, upsert_block,
    };

    /// Uma árvore de configuração do OLS, com ou sem o `conf.d/` incluído.
    fn layout(tag: &str, main: &str, drop_in_dir: bool) -> std::path::PathBuf {
        let d = tmp(tag);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        if drop_in_dir {
            std::fs::create_dir_all(d.join("conf.d")).unwrap();
        }
        std::fs::write(d.join("httpd_config.conf"), main).unwrap();
        d
    }

    const DA_MAIN: &str = "include /etc/openlitespeed/httpd-defaults.conf\n\
                           include /etc/openlitespeed/conf.d/*.conf\n";

    /// Com o `conf.d/` lido pelo próprio `DirectAdmin`, os handlers vão para lá —
    /// e não dependem de linha nenhuma num arquivo que o DA reescreve.
    #[test]
    fn handlers_go_to_the_drop_in_directory_when_it_is_read() {
        let d = layout("dropin", DA_MAIN, true);
        assert_eq!(handlers_path(&d), d.join("conf.d").join(HANDLERS_FILE));
        assert!(handlers_are_included(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// O diretório existir não basta: sem o include dele, o servidor não o lê.
    #[test]
    fn a_drop_in_directory_nobody_includes_does_not_count() {
        let d = layout("dropin-unread", "include /x/httpd-defaults.conf\n", true);
        assert_eq!(handlers_path(&d), d.join(HANDLERS_FILE));
        assert!(!handlers_are_included(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Migrando do layout antigo: sai o bloco do painel e o arquivo velho, e o
    /// resto do `httpd_config.conf` fica intacto.
    #[test]
    fn the_legacy_include_is_retired_once_the_drop_in_is_used() {
        let main = format!(
            "{DA_MAIN}\n{INCLUDE_BEGIN}\ninclude /etc/openlitespeed/{HANDLERS_FILE}\n{INCLUDE_END}\n"
        );
        let d = layout("retire", &main, true);
        std::fs::write(d.join(HANDLERS_FILE), "velho").unwrap();

        assert!(retire_legacy_include(&d).unwrap());
        let depois = std::fs::read_to_string(d.join("httpd_config.conf")).unwrap();
        assert!(!depois.contains(HANDLERS_FILE));
        assert!(!depois.contains(INCLUDE_BEGIN));
        assert!(depois.contains("conf.d/*.conf"));
        assert!(!d.join(HANDLERS_FILE).exists());

        // Já limpo: nada muda, e o servidor não precisa recarregar.
        assert!(!retire_legacy_include(&d).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sem `conf.d/`, a limpeza não pode apagar o include de que o servidor
    /// ainda depende.
    #[test]
    fn the_legacy_include_stays_where_there_is_no_drop_in() {
        let main = format!("{INCLUDE_BEGIN}\ninclude /x/{HANDLERS_FILE}\n{INCLUDE_END}\n");
        let d = layout("keep", &main, false);
        assert!(!retire_legacy_include(&d).unwrap());
        assert!(handlers_are_included(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn stripping_keeps_foreign_lines() {
        let s = format!("a\n{INCLUDE_BEGIN}\ninclude /x/{HANDLERS_FILE}\n{INCLUDE_END}\nb\n");
        assert_eq!(strip_legacy_include(&s), "a\nb\n");
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("selynt-ols-{tag}-{}", std::process::id()))
    }

    /// A template `DirectAdmin` ships, or an admin customised, must survive.
    #[test]
    fn keeps_content_that_is_not_ours() {
        let p = tmp("keep");
        std::fs::write(&p, "SomeoneElsesDirective on\n").unwrap();

        upsert_block(&p, "# BEGIN SELYNT_PANEL\nours\n# END SELYNT_PANEL").unwrap();

        let out = std::fs::read_to_string(&p).unwrap();
        assert!(out.contains("SomeoneElsesDirective on"));
        assert!(out.contains("ours"));
        let _ = std::fs::remove_file(p);
    }

    /// Running the setup twice must not stack two copies of the block.
    #[test]
    fn replaces_its_own_block_instead_of_appending() {
        let p = tmp("replace");
        let block = format!("{BEGIN_MARK}\nfirst\n{END_MARK}");
        upsert_block(&p, &block).unwrap();

        let block2 = format!("{BEGIN_MARK}\nsecond\n{END_MARK}");
        upsert_block(&p, &block2).unwrap();

        let out = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            out.matches(BEGIN_MARK).count(),
            1,
            "block duplicated: {out}"
        );
        assert!(out.contains("second"));
        assert!(!out.contains("first"));
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn creates_the_file_when_absent() {
        let p = tmp("create");
        let _ = std::fs::remove_file(&p);

        upsert_block(&p, "# BEGIN SELYNT_PANEL\nx\n# END SELYNT_PANEL").unwrap();

        assert!(std::fs::read_to_string(&p).unwrap().contains('x'));
        let _ = std::fs::remove_file(p);
    }
}
