//! Wires the panel into OpenLiteSpeed and DirectAdmin.
//!
//! Two things have to be in place for an app to receive traffic:
//!
//! - DirectAdmin's vhost templates carry the proxy blocks, so every generated
//!   vhost knows how to reach an app's socket.
//! - The web server's user is recorded, since the socket is reached through a
//!   POSIX ACL granted to it and nothing else.
//!
//! Done here rather than in a shell script for the same reason as the rest:
//! this runs as root at install time, and it edits the templates every
//! customer's vhost is generated from. A file root executes is a file whose
//! contents become root execution.

use std::path::{Path, PathBuf};

use crate::sys::state::{DA_TEMPLATES, PLUGIN_PATH, STATE_BASE};

/// Delimiters of the block the panel owns inside a shared template file.
///
/// DirectAdmin templates may hold other people's customisations, so the block
/// is replaced between its markers instead of the file being overwritten.
pub const BEGIN_MARK: &str = "# BEGIN SELYNT_PANEL";
pub const END_MARK: &str = "# END SELYNT_PANEL";

/// Per-vhost proxy handler, pointing at the app's Unix socket.
///
/// `|SDOMAIN|`, `|VH_PORT|` and `|USER|` are DirectAdmin template variables,
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

/// OpenLiteSpeed's configuration directory, whichever layout is in use.
///
/// DirectAdmin 1.690+ installs it under `/etc/openlitespeed`; older builds keep
/// it in `/usr/local/lsws/conf`.
pub(crate) fn conf_dir() -> Option<&'static Path> {
    ["/etc/openlitespeed", "/usr/local/lsws/conf"]
        .into_iter()
        .map(Path::new)
        .find(|d| d.join("httpd_config.conf").is_file())
}

/// The main configuration file, when OpenLiteSpeed is installed.
pub(crate) fn main_conf() -> Option<PathBuf> {
    conf_dir().map(|d| d.join("httpd_config.conf"))
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

/// The account OpenLiteSpeed runs as, which is what the socket ACL is granted
/// to.
///
/// Read from the server's own configuration first, then from the accounts a web
/// server is normally installed as. DirectAdmin's OpenLiteSpeed config carries
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

/// Asks DirectAdmin to regenerate every vhost from the templates.
///
/// Installing a template changes nothing on its own — the vhosts already on
/// disk were generated from the previous version.
pub(crate) fn rebuild_vhosts() -> bool {
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
    /// Whether DirectAdmin regenerated its vhosts from the new templates.
    /// Installing a template changes nothing until that happens.
    pub vhosts_rebuilt: bool,
}

/// Installs the templates and records the web server's user.
pub(crate) fn run() -> Result<Outcome, (String, String)> {
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

    Ok(Outcome {
        web_user,
        vhosts_rebuilt,
    })
}

#[cfg(test)]
mod tests {
    use super::{BEGIN_MARK, END_MARK, upsert_block};

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("selynt-ols-{tag}-{}", std::process::id()))
    }

    /// A template DirectAdmin ships, or an admin customised, must survive.
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
        assert_eq!(out.matches(BEGIN_MARK).count(), 1, "block duplicated: {out}");
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
