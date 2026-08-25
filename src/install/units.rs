//! The systemd units the panel installs, and their lifecycle.
//!
//! Embedded rather than shipped as files under `scripts/`. Each one names this
//! binary as what root executes, so leaving them on disk as separate files
//! meant a second place where that instruction could be rewritten — the same
//! reason the shell scripts went away.
//!
//! It also removes a whole class of mistake: a unit that exists in the tree but
//! that the installer forgets to copy is a feature silently absent. The list
//! below *is* the installer's list.

use std::path::Path;

use crate::sys::state::PLUGIN_PATH;

/// Where systemd looks for units installed by packages and administrators.
const SYSTEMD_DIR: &str = "/etc/systemd/system";

/// A unit and how it should be enabled.
struct Unit {
    name: &'static str,
    content: &'static str,
    /// Units enabled to run at boot rather than on a timer.
    enable: bool,
    /// Started immediately as well as enabled — timers, which have nothing to
    /// wait for.
    start_now: bool,
}

/// Restores apps that were running before a reboot.
const PANEL_SERVICE: &str = "\
[Unit]
Description=Selynt Panel — restaurar aplicações após reinício
After=network-online.target directadmin.service lsws.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={BIN} boot-recover
RemainAfterExit=no
User=root

# The apps this unit starts must outlive it. systemd kills a oneshot service's
# whole cgroup once it exits, which is why nothing survived a reboot before:
# every app came back up and died moments later. `KillMode=process` limits that
# to the main process.
KillMode=process

[Install]
WantedBy=multi-user.target
";

/// Stops apps that bound a port reachable from outside the host.
const NETGUARD_SERVICE: &str = "\
[Unit]
Description=Selynt Panel — parar aplicações com porta exposta
After=network.target

[Service]
Type=oneshot
ExecStart={BIN} netguard --all-accounts
User=root

# The sweep only reads /proc and signals offending processes; it must never take
# the panel's own apps down with it when it exits.
KillMode=process
";

const NETGUARD_TIMER: &str = "\
[Unit]
Description=Selynt Panel — verificação periódica de portas expostas

[Timer]
# A sweep costs a few milliseconds, so it can run far more often than a cron
# minute would allow.
OnBootSec=60s
OnUnitActiveSec=15s
AccuracySec=1s

[Install]
WantedBy=timers.target
";

/// Rewrites the proxy configuration when the set of live apps changes.
const PROXYSYNC_SERVICE: &str = "\
[Unit]
Description=Selynt Panel — sincronizar rotas do servidor web
After=network.target

[Service]
Type=oneshot
ExecStart={BIN} sync-proxy
User=root

# Rewrites a config file and reloads the web server; it must not take the
# panel's own apps down with it when it exits.
KillMode=process
";

const PROXYSYNC_TIMER: &str = "\
[Unit]
Description=Selynt Panel — verificação de rotas pendentes

[Timer]
# The sync only does work when there is something to sync, so a short interval
# costs a stat(). Anything longer leaves an app unreachable after it starts.
OnBootSec=30s
OnUnitActiveSec=5s
AccuracySec=1s

[Install]
WantedBy=timers.target
";

/// Everything the panel installs. Adding a unit here is all it takes.
const UNITS: [Unit; 5] = [
    Unit {
        name: "selynt-panel.service",
        content: PANEL_SERVICE,
        enable: true,
        start_now: false,
    },
    Unit {
        name: "selynt-netguard.service",
        content: NETGUARD_SERVICE,
        enable: false,
        start_now: false,
    },
    Unit {
        name: "selynt-netguard.timer",
        content: NETGUARD_TIMER,
        enable: true,
        start_now: true,
    },
    Unit {
        name: "selynt-proxysync.service",
        content: PROXYSYNC_SERVICE,
        enable: false,
        start_now: false,
    },
    Unit {
        name: "selynt-proxysync.timer",
        content: PROXYSYNC_TIMER,
        enable: true,
        start_now: true,
    },
];

/// Whether this host can run the units at all.
/// True when units can be written and managed on this host.
///
/// Deliberately not the same question as [`crate::limits::policy::can_run_scopes`]:
/// this one is about the unit directory, that one about the `systemd-run`
/// binary. Both were once called `systemd_available`, which invited importing
/// whichever came to hand and getting a check that passes for the wrong reason.
pub(crate) fn units_supported() -> bool {
    Path::new(SYSTEMD_DIR).is_dir() && Path::new("/run/systemd/system").is_dir()
}

fn systemctl(args: &[&str]) -> bool {
    std::process::Command::new("systemctl")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Writes every unit and enables the ones that should run.
///
/// Returns the units it installed.
pub(crate) fn install() -> Vec<&'static str> {
    if !units_supported() {
        return Vec::new();
    }

    let bin = format!("{PLUGIN_PATH}/bin/core-selynt");
    let mut installed = Vec::new();

    for unit in &UNITS {
        let path = Path::new(SYSTEMD_DIR).join(unit.name);
        let content = unit.content.replace("{BIN}", &bin);

        if crate::sys::fs::atomic_write(&path, content.as_bytes())
            .and_then(|()| crate::sys::fs::set_perm(&path, 0o644))
            .is_err()
        {
            continue;
        }
        installed.push(unit.name);
    }

    // Once, after writing them all: systemd has to re-read the directory before
    // any of them can be enabled.
    systemctl(&["daemon-reload"]);

    for unit in &UNITS {
        if !unit.enable {
            continue;
        }
        if unit.start_now {
            systemctl(&["enable", "--now", unit.name]);
        } else {
            systemctl(&["enable", unit.name]);
        }
    }

    installed
}

/// Disables and removes every unit the panel installed.
pub(crate) fn remove() -> Vec<&'static str> {
    if !units_supported() {
        return Vec::new();
    }

    let mut removed = Vec::new();
    for unit in &UNITS {
        // `--now` also stops it: a timer left running would keep invoking a
        // binary that is being uninstalled.
        systemctl(&["disable", "--now", unit.name]);

        let path = Path::new(SYSTEMD_DIR).join(unit.name);
        if std::fs::remove_file(&path).is_ok() {
            removed.push(unit.name);
        }
    }

    systemctl(&["daemon-reload"]);
    removed
}

#[cfg(test)]
mod tests {
    use super::{PLUGIN_PATH, UNITS};

    /// Every unit has to name the binary, and the placeholder has to be
    /// substituted — a literal `{BIN}` would leave systemd unable to start it.
    #[test]
    fn every_unit_runs_the_installed_binary() {
        let bin = format!("{PLUGIN_PATH}/bin/core-selynt");

        for unit in &UNITS {
            let rendered = unit.content.replace("{BIN}", &bin);
            assert!(!rendered.contains("{BIN}"), "{}: placeholder left", unit.name);

            // Timers carry no ExecStart; services do.
            if unit.name.ends_with(".service") {
                assert!(
                    rendered.contains(&format!("ExecStart={bin}")),
                    "{}: does not run the installed binary",
                    unit.name
                );
            }
        }
    }

    /// A service enabled on its own would run once at boot and never again;
    /// the periodic ones are driven by their timer.
    #[test]
    fn only_timers_and_the_boot_service_are_enabled() {
        for unit in &UNITS {
            if unit.enable {
                assert!(
                    unit.name.ends_with(".timer") || unit.name == "selynt-panel.service",
                    "{} should not be enabled directly",
                    unit.name
                );
            }
            if unit.start_now {
                assert!(unit.name.ends_with(".timer"), "{} started eagerly", unit.name);
            }
        }
    }
}
