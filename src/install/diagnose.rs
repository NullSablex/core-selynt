//! Health checks for the plugin's install: reading files, stat'ing paths,
//! listing directories. Nothing is executed and nothing is modified.
//!
//! In Rust rather than shelling out to a script because this binary is setuid
//! root — handing it a script turns any write to that file into root execution.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde_json::{Value, json};

use crate::sys::state::{DA_TEMPLATES, DA_USERS_BASE, PLUGIN_PATH, STATE_BASE};

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
    const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Records one check. `key` names the message in the panel's dictionary,
    /// and `arg` carries the single value it may interpolate.
    ///
    /// The binary reports *state*, never prose: the panel is translated and the
    /// admin reading it should not have to know about setuid bits, template
    /// numbers or which system account serves CGI.
    fn add(&mut self, level: Level, group: &str, key: &str, arg: Option<&str>) {
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

    super::tree::walk(root, &mut |p| {
        if p == bin || p == conf {
            return;
        }
        if let Ok(m) = std::fs::symlink_metadata(p)
            && m.uid() != 0
        {
            foreign += 1;
        }
        if let Some(mode) = super::tree::mode_of(p) {
            let want = super::tree::expected_mode(p);
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
        r.add(
            Level::Fail,
            "install",
            "ownership_bad",
            Some(&foreign.to_string()),
        );
    }

    if wrong_mode.is_empty() {
        r.add(Level::Pass, "install", "permissions_ok", None);
    } else {
        r.add(
            Level::Warn,
            "install",
            "permissions_bad",
            Some(&wrong_mode.len().to_string()),
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
                .map_or(true, |v| v.trim().is_empty())
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
    r.add(
        Level::Pass,
        "state",
        "registered",
        Some(&format!("{apps}|{accounts}")),
    );

    for path in unowned {
        r.add(Level::Warn, "state", "app_not_owned", Some(&path));
    }

    check_acl_support(r);
}

/// Checks that the per-account boundary is enforced by ACL, not by mode bits.
///
/// Without `setfacl` the panel falls back to `chmod 711`, and a mode bit cannot
/// name one account — traverse opens to every account on the server. Apps keep
/// working either way, so nothing else surfaces it.
fn check_acl_support(r: &mut Report) {
    let has_setfacl = ["/usr/bin/setfacl", "/bin/setfacl"]
        .iter()
        .any(|p| Path::new(p).exists());

    if !has_setfacl {
        r.add(Level::Warn, "state", "acl_missing", None);
        return;
    }

    // Present is not the same as applied: a filesystem mounted without
    // `acl` accepts the binary but not the attribute, and the panel would have
    // silently fallen back on every start.
    let widened: Vec<String> = crate::sys::state::list_accounts()
        .into_iter()
        .filter(|(dir, _)| std::fs::metadata(dir).is_ok_and(|m| m.mode() & 0o001 != 0))
        .map(|(_, user)| user)
        .collect();

    if widened.is_empty() {
        r.add(Level::Pass, "state", "acl_ok", None);
    } else {
        r.add(
            Level::Warn,
            "state",
            "acl_fallback_used",
            Some(&widened.join(", ")),
        );
    }
}

/// Checks that the proxy handlers the panel generates are actually in place.
///
/// Templates being installed is not the same as the config having been rebuilt
/// from them: an app can be running, with its socket ready, and still be
/// unreachable because no vhost routes to it. That failure is invisible from
/// the app's own state, which is why it is checked here.
fn check_proxy_config(r: &mut Report) {
    let Some(conf_dir) = crate::webserver::ols::conf_dir() else {
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
                r.add(Level::Pass, "proxy", "extproc_ok", Some(&count.to_string()));
            } else {
                r.add(Level::Warn, "proxy", "extproc_empty", None);
            }
        }
        Err(_) => r.add(Level::Warn, "proxy", "extproc_missing", None),
    }

    // The handler file is only read if the main config includes it. Without the
    // line every proxied app answers 503 while looking healthy from every other
    // angle — process up, socket accepting, marker in place — and DirectAdmin
    // drops it whenever it rewrites the file.
    match std::fs::read_to_string(conf_dir.join("httpd_config.conf")) {
        Ok(main) if main.contains("selynt_extprocessors.conf") => {
            r.add(Level::Pass, "proxy", "include_ok", None);
        }
        Ok(_) => r.add(Level::Fail, "proxy", "include_missing", None),
        Err(_) => r.add(Level::Warn, "proxy", "main_conf_unreadable", None),
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
            Some(&format!("{with_proxy}|{checked}")),
        );
    } else {
        r.add(
            Level::Warn,
            "proxy",
            "vhosts_unpatched",
            Some(&checked.to_string()),
        );
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
            r.add(Level::Pass, "runtime", "node_ok", Some(&n.to_string()));
        }
        _ => r.add(Level::Warn, "runtime", "node_none", None),
    }

    // A runtime that exists but was refused is invisible in the panel, and the
    // admin has no other way to tell that from a path the detector never looks
    // at. Report each one with the reason.
    for (path, reason) in crate::runtime::detect::rejected_node_runtimes() {
        let key = match reason {
            "unsafe_ownership" => "node_unsafe_owner",
            _ => "node_untrusted_path",
        };
        r.add(Level::Warn, "runtime", key, Some(&path));
    }
}

/// Runs every check and returns the report plus a summary.
pub fn run_diagnostic() -> Value {
    let mut r = Report::new();
    check_binary(&mut r);
    check_ownership_and_modes(&mut r);
    check_identity_files(&mut r);
    check_state_dir(&mut r);
    check_templates(&mut r);
    check_proxy_config(&mut r);
    check_boot_service(&mut r);
    check_runtimes(&mut r);

    json!({
        "checks": r.items,
        "summary": {
            "pass": r.count(Level::Pass),
            "warn": r.count(Level::Warn),
            "fail": r.count(Level::Fail),
        },
    })
}
