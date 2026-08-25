//! Per-app resource usage, read from the app's systemd scope cgroup.

use std::path::Path;

use serde_json::{Value, json};

use crate::sys::output::{success, user_error};
use crate::sys::state::{DA_USERS_BASE, load_app_meta};

use crate::cmd::{get_status, with_debug};

/// cgroup v2 path for an app's scope.
///
/// Apps live under the account's slice, but a binary upgrade can find apps
/// started by the previous version still sitting in `system.slice`. Falling
/// back to the old location keeps those visible — without it they would read as
/// stopped and their stats would come back empty until a restart.
fn scope_cgroup(username: &str, name: &str) -> String {
    let unit = format!("selynt-{username}-{name}.scope");
    let in_slice = format!("{}/{unit}", super::policy::slice_cgroup(username));
    if Path::new(&in_slice).is_dir() {
        return in_slice;
    }
    format!("/sys/fs/cgroup/system.slice/{unit}")
}

/// Every PID in the app's scope — the app itself plus anything it spawned.
///
/// The cgroup is what makes a whole-app check possible: a child process is
/// still in it, however it was started, so callers do not have to walk the
/// process tree themselves. Empty when the app is not running.
pub(crate) fn scope_pids(username: &str, name: &str) -> Vec<u32> {
    let procs = Path::new(&scope_cgroup(username, name)).join("cgroup.procs");
    let Ok(content) = std::fs::read_to_string(procs) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

/// Reads a single integer from a cgroup file. `max` (no limit) yields `None`.
fn read_num(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Anonymous memory of the cgroup, in bytes — the app's own pages.
///
/// `memory.current` also counts the page cache, which the kernel reclaims
/// under pressure and which swings with any file the app reads. `anon` is what
/// the app actually holds, so it is what the panel reports.
fn read_anon_bytes(dir: &Path) -> Option<u64> {
    let stat = std::fs::read_to_string(dir.join("memory.stat")).ok()?;
    stat.lines()
        .find_map(|l| l.strip_prefix("anon "))?
        .trim()
        .parse()
        .ok()
}

/// Cumulative CPU time of the cgroup, in microseconds.
fn read_cpu_usec(dir: &Path) -> Option<u64> {
    let stat = std::fs::read_to_string(dir.join("cpu.stat")).ok()?;
    stat.lines()
        .find_map(|l| l.strip_prefix("usage_usec "))?
        .trim()
        .parse()
        .ok()
}

/// Live resource usage of one app's scope.
#[derive(Clone, Copy)]
pub struct ScopeUsage {
    pub memory_bytes: u64,
    pub cpu_usec: u64,
}

/// Reads an app's cgroup usage, or `None` when the scope is not present (the
/// app is stopped, or systemd is unavailable and it runs outside a scope).
pub(crate) fn read_scope_usage(username: &str, name: &str) -> Option<ScopeUsage> {
    let dir = std::path::PathBuf::from(scope_cgroup(username, name));
    if !dir.is_dir() {
        return None;
    }
    Some(ScopeUsage {
        memory_bytes: read_anon_bytes(&dir)
            .or_else(|| read_num(&dir.join("memory.current")))
            .unwrap_or(0),
        cpu_usec: read_cpu_usec(&dir).unwrap_or(0),
    })
}

/// Account resource limits as configured in DirectAdmin.
#[derive(Default, Clone, Copy)]
pub struct DaLimits {
    pub memory_max: Option<u64>,
    pub cpu_quota_percent: Option<u32>,
}

/// Reads the account's limits from DirectAdmin. **Must run as root**:
/// `data/users/` is `diradmin`-owned and `0700`, so after the privilege drop
/// this silently returns nothing and every app looks unlimited.
pub(crate) fn read_da_limits(username: &str) -> DaLimits {
    DaLimits {
        memory_max: da_limit(username, "MemoryMax")
            .as_deref()
            .and_then(parse_memory_limit),
        cpu_quota_percent: da_limit(username, "CPUQuota")
            .as_deref()
            .and_then(parse_cpu_quota),
    }
}

/// Reads a `key=value` field from a DirectAdmin `user.conf`.
fn da_limit(username: &str, key: &str) -> Option<String> {
    let conf = std::fs::read_to_string(format!("{DA_USERS_BASE}/{username}/user.conf")).ok()?;
    let prefix = format!("{key}=");

    // Filter before taking, not after: DirectAdmin writes the key with an empty
    // value when no limit is set, and a later line may carry the real one.
    // Stopping at the first match found an empty value and concluded there was
    // no limit at all.
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix(&prefix))
        .map(str::trim)
        .find(|v| !v.is_empty())
        .map(ToString::to_string)
}

/// Parses a systemd memory limit (`512M`, `2G`, `infinity`) into bytes.
fn parse_memory_limit(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("infinity") {
        return None;
    }
    let (digits, mult) = match raw.chars().last()? {
        'K' | 'k' => (&raw[..raw.len() - 1], 1024),
        'M' | 'm' => (&raw[..raw.len() - 1], 1024 * 1024),
        'G' | 'g' => (&raw[..raw.len() - 1], 1024 * 1024 * 1024),
        _ => (raw, 1),
    };
    digits.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// Parses a systemd CPU quota (`50%`, `150%`) into a percentage of one core.
fn parse_cpu_quota(raw: &str) -> Option<u32> {
    let raw = raw.trim().trim_end_matches('%').trim();
    raw.parse().ok()
}

/// Reports memory and CPU for one app, alongside the account's limits.
///
/// CPU is a cumulative counter, so a single reading cannot express a rate. The
/// raw value is returned and the caller samples twice — that keeps the CGI from
/// blocking for a second on every request.
pub(crate) fn cmd_stats(
    state_dir: &Path,
    name: &str,
    username: &str,
    limits: DaLimits,
    dbg: Option<&Value>,
) -> ! {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    let (status, _, _) = get_status(state_dir, name);
    let dir = std::path::PathBuf::from(scope_cgroup(username, name));

    // A stopped app has no cgroup: report zeroes rather than an error, so the
    // UI can render the row either way.
    let running = status == "RUNNING" && dir.is_dir();

    let memory_used = if running {
        read_anon_bytes(&dir)
            .or_else(|| read_num(&dir.join("memory.current")))
            .unwrap_or(0)
    } else {
        0
    };
    let cpu_usec = if running {
        read_cpu_usec(&dir).unwrap_or(0)
    } else {
        0
    };
    let pids = if running {
        read_num(&dir.join("pids.current")).unwrap_or(0)
    } else {
        0
    };

    // The limits this app actually runs under.
    let app = app_limits_for(state_dir, username, name, &meta);

    // Fall back to the machine's total RAM so a percentage still means
    // something when the account has no explicit cap.
    // What the app is actually held to, most specific first: the resolved
    // ceiling, then the user's own pin (which applies even when the account has
    // no allowance to divide), then the account, and only as a last resort the
    // machine's RAM — showing "16 MB of 3.6 GB" for an app pinned at 200 MB
    // told the user nothing about the limit they had just set.
    let memory_limit = app
        .map(|l| l.max)
        .or(meta.memory_max)
        .or(limits.memory_max)
        .or_else(|| {
            std::fs::read_to_string("/proc/meminfo").ok().and_then(|m| {
                m.lines()
                    .find_map(|l| l.strip_prefix("MemTotal:"))
                    .and_then(|v| v.trim().trim_end_matches(" kB").trim().parse::<u64>().ok())
                    .map(|kb| kb * 1024)
            })
        });

    let cpu_quota = limits.cpu_quota_percent;

    success(with_debug(
        json!({
            "running": running,
            "memory": {
                "used": memory_used,
                "limit": memory_limit,
                "min": app.map(|l| l.min),
                "high": app.map(|l| l.high),
                "max": app.map(|l| l.max),
                "pinned": meta.memory_max,
                "account": limits.memory_max,
                "slice_cap": limits.memory_max.map(super::policy::slice_cap),
                "slice_used": limits.memory_max.and_then(|_| {
                    read_anon_bytes(Path::new(&super::policy::slice_cgroup(username)))
                }),
            },
            "cpu": { "usage_usec": cpu_usec, "quota_percent": cpu_quota },
            "pids": pids,
        }),
        dbg,
    ))
}


/// True when the app's systemd scope exists — i.e. the app is running.
fn scope_is_live(username: &str, name: &str) -> bool {
    Path::new(&scope_cgroup(username, name)).is_dir()
}

/// Resolves the memory cap for one app, reading the account allowance from
/// DirectAdmin and every sibling app's own setting. Must run as root.
pub(crate) fn app_limits_for(
    state_dir: &Path,
    username: &str,
    name: &str,
    meta: &crate::sys::state::AppMeta,
) -> Option<super::policy::AppLimits> {
    app_limits_for_with(state_dir, username, name, meta, "", "")
}

/// [`app_limits_for`], counting `pending` as running even though its scope does
/// not exist yet.
pub(crate) fn app_limits_for_with(
    state_dir: &Path,
    username: &str,
    name: &str,
    meta: &crate::sys::state::AppMeta,
    pending: &str,
    leaving: &str,
) -> Option<super::policy::AppLimits> {
    let account = read_da_limits(username).memory_max;

    // No account allowance: there is no pool to divide, but a pin the user set
    // is still theirs to enforce — otherwise asking for 200 MB would leave the
    // app running unbounded.
    let Some(account) = account else {
        return meta.memory_max.map(|cap| super::policy::AppLimits {
            min: 0,
            high: cap.saturating_sub(16 * 1024 * 1024).max(1),
            max: cap,
        });
    };

    // Only running siblings share the pool. A pinned app no longer reserves
    // anything from it — a pin just caps that one app — so all that matters
    // here is how many are actually competing.
    let mut running = 1; // this app
    for other in crate::sys::state::list_app_names(state_dir) {
        if other == name {
            continue;
        }
        // Presence of the scope cgroup is the reliable signal here:
        // `get_status` compares the process uid against `getuid()`, which is
        // root inside the prelude, so every app would look stopped.
        if other != leaving && (scope_is_live(username, &other) || other == pending) {
            running += 1;
        }
    }

    Some(super::policy::app_limits(
        super::policy::slice_cap(account),
        running,
        meta.memory_max,
    ))
}


/// Pushes the resolved memory cap onto every *running* app of an account.
///
/// Caps have to be re-resolved whenever any app's setting changes: pinning one
/// app shrinks what the auto apps may take. Waiting for the next start would
/// leave the running apps on their old, larger limits, so for a while the caps
/// would add up to more than the account owns — precisely the overcommit the
/// limits exist to prevent.
///
/// `systemctl set-property --runtime` applies to a live scope, so the new
/// ceiling takes effect at once. `--runtime` keeps it out of /etc: the scope is
/// transient and the source of truth is the `.app` file.
pub(crate) fn reapply_app_limits(state_dir: &Path, username: &str) {
    reapply_app_limits_with(state_dir, username, "", "");
}

/// Same as [`reapply_app_limits`], but treats `leaving` as already gone — used
/// when stopping an app, whose scope outlives the prelude that decides limits.
pub(crate) fn reapply_app_limits_excluding(state_dir: &Path, username: &str, leaving: &str) {
    reapply_app_limits_with(state_dir, username, "", leaving);
}

/// Same as [`reapply_app_limits`], but also counts `pending` — an app that is about
/// to start and therefore has no scope yet.
pub(crate) fn reapply_app_limits_including(state_dir: &Path, username: &str, pending: &str) {
    reapply_app_limits_with(state_dir, username, pending, "");
}

fn reapply_app_limits_with(state_dir: &Path, username: &str, pending: &str, leaving: &str) {
    if !super::policy::can_run_scopes() {
        return;
    }
    for name in crate::sys::state::list_app_names(state_dir) {
        let Ok(meta) = crate::sys::state::load_app_meta(state_dir, &name) else {
            continue;
        };
        // Only touch scopes that exist; a stopped app gets its limits at start.
        if !scope_is_live(username, &name) || name == leaving {
            continue;
        }
        let unit = format!("selynt-{username}-{name}.scope");

        let props = match app_limits_for_with(state_dir, username, &name, &meta, pending, leaving) {
            Some(l) => vec![
                format!("MemoryMin={}", l.min),
                format!("MemoryHigh={}", l.high),
                format!("MemoryMax={}", l.max),
            ],
            // Explicit clearing: omitting a property leaves the old value in
            // place, so an account losing its limit would keep the last cap.
            None => vec![
                "MemoryMin=0".to_string(),
                "MemoryHigh=infinity".to_string(),
                "MemoryMax=infinity".to_string(),
            ],
        };

        let mut cmd = std::process::Command::new("systemctl");
        cmd.args(["set-property", "--runtime", &unit]);
        cmd.args(&props);
        let _ = cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Applies the collective ceiling to the account's slice.
///
/// This is the limit the kernel actually enforces: the per-app maxima are
/// deliberately allowed to add up to more than this, and the slice is what
/// stops them. Called before and after a spawn — before, the slice may not
/// exist yet and the call simply fails; after, it exists and takes effect.
pub(crate) fn ensure_slice_cap(username: &str, cap: Option<u64>) {
    if !super::policy::can_run_scopes() {
        return;
    }
    let unit = super::policy::slice_unit_name(username);
    let value = match cap {
        Some(bytes) => format!("MemoryMax={bytes}"),
        None => "MemoryMax=infinity".to_string(),
    };
    let _ = std::process::Command::new("systemctl")
        .args(["set-property", "--runtime", &unit, &value])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_path_matches_the_unit_created_at_start() {
        assert_eq!(
            scope_cgroup("bob", "api"),
            "/sys/fs/cgroup/system.slice/selynt-bob-api.scope"
        );
    }

    #[test]
    fn parses_systemd_memory_suffixes() {
        assert_eq!(parse_memory_limit("512M"), Some(512 * 1024 * 1024));
        assert_eq!(parse_memory_limit("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_memory_limit("1024"), Some(1024));
        assert_eq!(parse_memory_limit("infinity"), None);
        assert_eq!(parse_memory_limit(""), None);
    }

    #[test]
    fn parses_cpu_quota_with_and_without_sign() {
        assert_eq!(parse_cpu_quota("50%"), Some(50));
        // Above 100% means more than a single core.
        assert_eq!(parse_cpu_quota("150%"), Some(150));
        assert_eq!(parse_cpu_quota("bogus"), None);
    }
}

#[cfg(test)]
mod da_limit_tests {
    /// DirectAdmin writes the key with no value when the account has no limit,
    /// and can carry a second line with the real one. Taking the first match
    /// found the empty one and reported "no limit".
    #[test]
    fn an_empty_key_does_not_hide_a_later_value() {
        let conf = "wordpress=ON\nMemoryMax=\nzoom=100\nMemoryMax=1G\n";
        let found = conf
            .lines()
            .filter_map(|l| l.trim().strip_prefix("MemoryMax="))
            .map(str::trim)
            .find(|v| !v.is_empty());
        assert_eq!(found, Some("1G"));
    }

    #[test]
    fn no_value_anywhere_means_no_limit() {
        let conf = "wordpress=ON\nMemoryMax=\n";
        let found = conf
            .lines()
            .filter_map(|l| l.trim().strip_prefix("MemoryMax="))
            .map(str::trim)
            .find(|v| !v.is_empty());
        assert_eq!(found, None);
    }
}
