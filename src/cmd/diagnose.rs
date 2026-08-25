//! Health checks for the plugin's install.
//!
//! Everything here is inspection: reading files, stat'ing paths, listing
//! directories. Nothing is executed and nothing is modified.
//!
//! Deliberately implemented in Rust rather than by shelling out to
//! `scripts/diag-proxy.sh`. This binary is setuid root, so handing it a shell
//! script to run turns any write to that file into root execution — the same
//! class of hole the ownership hardening in the installer exists to close.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde_json::{Value, json};

use crate::state::{DA_TEMPLATES, DA_USERS_BASE, PLUGIN_PATH, STATE_BASE};


/// Outcome of a single check.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Pass,
    Warn,
    Fail,
}

impl Level {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

struct Report {
    items: Vec<Value>,
}

impl Report {
    fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Records one check. `key` names the message in the panel's dictionary,
    /// and `arg` carries the single value it may interpolate.
    ///
    /// The binary reports *state*, never prose: the panel is translated and the
    /// admin reading it should not have to know about setuid bits, template
    /// numbers or which system account serves CGI.
    fn add(&mut self, level: Level, group: &str, key: &str, arg: Option<String>) {
        self.items.push(json!({
            "level": level.as_str(),
            "group": group,
            "key":   key,
            "arg":   arg,
        }));
    }

    fn count(&self, level: Level) -> usize {
        self.items
            .iter()
            .filter(|i| i["level"] == level.as_str())
            .count()
    }
}

/// Reads a file's permission bits as an octal number, e.g. `644`.
fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(std::fs::metadata(path).ok()?.mode() & 0o7777)
}

/// The permissions a file under the plugin tree is expected to have.
pub fn expected_mode(path: &Path) -> u32 {
    let s = path.to_string_lossy();
    if s.ends_with(".service") {
        return 0o644;
    }
    if s.ends_with(".raw")
        || s.ends_with(".html")
        || (s.contains("/scripts/") && s.ends_with(".sh"))
        || s.contains("/hooks/")
    {
        return 0o755;
    }
    0o644
}

/// Walks a directory tree, calling `visit` for every directory found.
pub fn walk_dirs(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    visit(dir);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Same reason as `walk`: a symlinked directory would take the caller
        // outside this tree, and changing permissions through it would land on
        // whatever it points at.
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            walk_dirs(&path, visit);
        }
    }
}

/// Walks a directory tree, calling `visit` for every file found.
pub fn walk(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Do not follow symlinks: a link could point anywhere, and the check
        // is about this tree.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            walk(&path, visit);
        } else if meta.is_file() {
            visit(&path);
        }
    }
}

fn check_binary(r: &mut Report) {
    use std::os::unix::fs::MetadataExt;
    let bin = Path::new(PLUGIN_PATH).join("bin/core-selynt");
    match std::fs::metadata(&bin) {
        Err(_) => r.add(Level::Fail, "install", "binary_missing", None),
        Ok(m) => {
            let mode = m.mode() & 0o7777;
            if mode == 0o4755 && m.uid() == 0 {
                r.add(Level::Pass, "install", "binary_ok", None);
            } else {
                r.add(Level::Fail, "install", "binary_perms", None);
            }
        }
    }
}

fn check_ownership_and_modes(r: &mut Report) {
    use std::os::unix::fs::MetadataExt;
    let root = Path::new(PLUGIN_PATH);
    let bin = root.join("bin/core-selynt");
    // DirectAdmin rewrites plugin.conf and owns it; not ours to judge.
    let conf = root.join("plugin.conf");

    let mut foreign = 0usize;
    let mut wrong_mode = Vec::new();

    walk(root, &mut |p| {
        if p == bin || p == conf {
            return;
        }
        if let Ok(m) = std::fs::symlink_metadata(p)
            && m.uid() != 0
        {
            foreign += 1;
        }
        if let Some(mode) = mode_of(p) {
            let want = expected_mode(p);
            if mode != want {
                wrong_mode.push(format!(
                    "{} ({mode:o}, expected {want:o})",
                    p.strip_prefix(root).unwrap_or(p).display()
                ));
            }
        }
    });

    if foreign == 0 {
        r.add(Level::Pass, "install", "ownership_ok", None);
    } else {
        r.add(Level::Fail, "install", "ownership_bad", Some(foreign.to_string()));
    }

    if wrong_mode.is_empty() {
        r.add(Level::Pass, "install", "permissions_ok", None);
    } else {
        r.add(
            Level::Warn,
            "install",
            "permissions_bad",
            Some(wrong_mode.len().to_string()),
        );
    }
}

fn check_identity_files(r: &mut Report) {
    // Reported as one check: three separate rows naming `diradmin`, `nobody`
    // and `apache` told the admin nothing actionable. What matters is whether
    // the panel can authorise its own requests.
    let missing = ["etc/da_user", "etc/da_cgi_user", "etc/ols_web_user"]
        .iter()
        .filter(|f| {
            std::fs::read_to_string(Path::new(PLUGIN_PATH).join(f))
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
        })
        .count();
    if missing == 0 {
        r.add(Level::Pass, "install", "identity_ok", None);
    } else {
        r.add(Level::Warn, "install", "identity_bad", None);
    }
}

fn check_state_dir(r: &mut Report) {
    let base = Path::new(STATE_BASE);
    if !base.is_dir() {
        r.add(Level::Fail, "state", "state_missing", None);
        return;
    }
    r.add(Level::Pass, "state", "state_ok", None);

    let mut accounts = 0usize;
    let mut apps = 0usize;
    let mut unowned: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(base) {
        for e in entries.flatten() {
            let run = e.path().join(".run");
            if !run.is_dir() {
                continue;
            }
            accounts += 1;
            if let Ok(files) = std::fs::read_dir(&run) {
                for f in files.flatten() {
                    let path = f.path();
                    if path.extension().and_then(|x| x.to_str()) != Some("app") {
                        continue;
                    }
                    apps += 1;
                    // The panel refuses metadata it does not own, so such an
                    // app is invisible in the interface with no other clue as
                    // to why. Either a migration that did not complete — remove
                    // `.run/.adopted` to have it redone — or a file the account
                    // planted, which is exactly what the refusal is for.
                    if !std::fs::metadata(&path).is_ok_and(|m| m.uid() == 0) {
                        unowned.push(path.display().to_string());
                    }
                }
            }
        }
    }
    r.add(Level::Pass, "state", "registered", Some(format!("{apps}|{accounts}")));

    for path in unowned {
        r.add(Level::Warn, "state", "app_not_owned", Some(path));
    }
}

/// Checks that the proxy handlers the panel generates are actually in place.
///
/// Templates being installed is not the same as the config having been rebuilt
/// from them: an app can be running, with its socket ready, and still be
/// unreachable because no vhost routes to it. That failure is invisible from
/// the app's own state, which is why it is checked here.
fn check_proxy_config(r: &mut Report) {
    let Some(conf_dir) = super::ols::conf_dir() else {
        // Nothing to check against — `check_templates` already reports on the
        // DirectAdmin side.
        return;
    };

    let ep_conf = conf_dir.join("selynt_extprocessors.conf");
    match std::fs::read_to_string(&ep_conf) {
        Ok(content) => {
            let count = content
                .lines()
                .filter(|l| l.trim_start().starts_with("extProcessor"))
                .count();
            if count > 0 {
                r.add(Level::Pass, "proxy", "extproc_ok", Some(count.to_string()));
            } else {
                r.add(Level::Warn, "proxy", "extproc_empty", None);
            }
        }
        Err(_) => r.add(Level::Warn, "proxy", "extproc_missing", None),
    }

    // A vhost only routes to the panel once it carries the proxy handler, and
    // that arrives when DirectAdmin rebuilds its configs from the templates.
    //
    // These live under each account in DirectAdmin's data directory, not in
    // OpenLiteSpeed's own tree: DA generates them from its templates and OLS
    // includes them. Looking in the OLS `vhosts/` directory finds nothing on a
    // DA install, which would read as "no vhosts" rather than as a problem.
    let Ok(users) = std::fs::read_dir(DA_USERS_BASE) else {
        return;
    };
    let (mut checked, mut with_proxy) = (0usize, 0usize);
    for entry in users.flatten() {
        let conf = entry.path().join("openlitespeed.conf");
        let Ok(content) = std::fs::read_to_string(&conf) else {
            continue;
        };
        checked += 1;
        if content.contains("selynt_proxy") {
            with_proxy += 1;
        }
    }

    if checked == 0 {
        return;
    }
    if with_proxy > 0 {
        r.add(
            Level::Pass,
            "proxy",
            "vhosts_ok",
            Some(format!("{with_proxy}|{checked}")),
        );
    } else {
        r.add(Level::Warn, "proxy", "vhosts_unpatched", Some(checked.to_string()));
    }
}

fn check_templates(r: &mut Report) {
    let missing = ["5", "7"]
        .iter()
        .filter(|n| {
            !Path::new(&format!(
                "{DA_TEMPLATES}/custom/openlitespeed_vhost.conf.CUSTOM.{n}.pre"
            ))
            .is_file()
        })
        .count();
    if missing == 0 {
        r.add(Level::Pass, "proxy", "templates_ok", None);
    } else {
        r.add(Level::Fail, "proxy", "templates_missing", None);
    }
}

fn check_boot_service(r: &mut Report) {
    let unit = Path::new("/etc/systemd/system/selynt-panel.service");
    if unit.is_file() {
        r.add(Level::Pass, "boot", "service_ok", None);
    } else {
        r.add(Level::Warn, "boot", "service_missing", None);
    }
}

fn check_runtimes(r: &mut Report) {
    let f = Path::new(PLUGIN_PATH).join("etc/node_versions");
    match std::fs::read_to_string(&f) {
        Ok(v) if !v.trim().is_empty() => {
            let n = v.lines().filter(|l| !l.trim().is_empty()).count();
            r.add(Level::Pass, "runtime", "node_ok", Some(n.to_string()));
        }
        _ => r.add(Level::Warn, "runtime", "node_none", None),
    }

    // A runtime that exists but was refused is invisible in the panel, and the
    // admin has no other way to tell that from a path the detector never looks
    // at. Report each one with the reason.
    for (path, reason) in super::admin::rejected_node_runtimes() {
        let key = match reason {
            "unsafe_ownership" => "node_unsafe_owner",
            _ => "node_untrusted_path",
        };
        r.add(Level::Warn, "runtime", key, Some(path));
    }
}

/// Runs every check and returns the report plus a summary.
pub fn run_diagnostic() -> Result<Value, (String, String)> {
    let mut r = Report::new();
    check_binary(&mut r);
    check_ownership_and_modes(&mut r);
    check_identity_files(&mut r);
    check_state_dir(&mut r);
    check_templates(&mut r);
    check_proxy_config(&mut r);
    check_boot_service(&mut r);
    check_runtimes(&mut r);

    Ok(json!({
        "checks": r.items,
        "summary": {
            "pass": r.count(Level::Pass),
            "warn": r.count(Level::Warn),
            "fail": r.count(Level::Fail),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_files_are_not_executable() {
        assert_eq!(expected_mode(Path::new("/x/scripts/selynt-panel.service")), 0o644);
    }

    #[test]
    fn cgi_endpoints_and_pages_are_executable() {
        assert_eq!(expected_mode(Path::new("/x/user/api/apps.raw")), 0o755);
        assert_eq!(expected_mode(Path::new("/x/user/index.html")), 0o755);
        assert_eq!(expected_mode(Path::new("/x/scripts/install.sh")), 0o755);
        assert_eq!(expected_mode(Path::new("/x/hooks/anything")), 0o755);
    }

    #[test]
    fn everything_else_is_read_only() {
        assert_eq!(expected_mode(Path::new("/x/images/menu_user.json")), 0o644);
        assert_eq!(expected_mode(Path::new("/x/lib/common.php")), 0o644);
        assert_eq!(expected_mode(Path::new("/x/LICENSE")), 0o644);
    }
}
