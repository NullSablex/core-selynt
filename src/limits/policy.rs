//! How much memory each app may use, and how much the account's apps may use
//! together.
//!
//! The per-app maxima deliberately add up to more than the account's slice
//! allows. That overcommit is what makes usage elastic: one app alone reaches
//! most of the pool, and the kernel reclaims from whoever overran once others
//! compete. A fixed equal share instead reserved memory nobody was using.

use std::path::Path;

/// Smallest guarantee an app gets. Node needs roughly 30–50 MB just to start,
/// so anything below this produces an app that cannot run.
const FLOOR: u64 = 48 * 1024 * 1024;

/// Gap between `MemoryHigh` and `MemoryMax`, so throttling (reclaim, swap) has
/// room to act before the OOM killer does.
const HEADROOM: u64 = 16 * 1024 * 1024;

/// Share of the pool a single app may reach. The remainder is slack for another
/// app to start into; real contention is settled by the slice, not here.
const ELASTIC_RATIO: (u64, u64) = (80, 100);

/// The memory properties applied to one app's systemd scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppLimits {
    /// `MemoryMin` — protected from reclaim.
    pub min: u64,
    /// `MemoryHigh` — throttle point.
    pub high: u64,
    /// `MemoryMax` — hard ceiling.
    pub max: u64,
}

/// Ceiling for all of an account's apps together.
///
/// The whole `DirectAdmin` allowance: that number is already the agreed limit for
/// the account, and the account's other services compete inside it.
pub const fn slice_cap(account_limit: u64) -> u64 {
    account_limit
}

/// systemd unit name of the account's slice.
pub fn slice_unit_name(username: &str) -> String {
    format!("selynt-{username}.slice")
}

/// cgroup path of the account's slice.
pub fn slice_cgroup(username: &str) -> String {
    format!("/sys/fs/cgroup/selynt.slice/{}", slice_unit_name(username))
}

/// Resolves one app's limits.
///
/// `pool` is [`slice_cap`], `running` counts the apps sharing it (including
/// this one), and `pinned` is the ceiling the user chose, if any — a pin only
/// ever narrows what the app may take.
pub fn app_limits(pool: u64, running: usize, pinned: Option<u64>) -> AppLimits {
    let fair = pool / running.max(1) as u64;

    // Reach well past the fair share when there is room. The slice is what
    // actually holds the line, so a generous per-app ceiling costs nothing.
    // Capped below the pool so a second app always has room to start.
    let elastic = pool * ELASTIC_RATIO.0 / ELASTIC_RATIO.1;

    // Guarantee the fair share, never below what a process needs to boot and
    // never above the elastic ceiling — guaranteeing more than the app may use
    // is meaningless, and with a single app it would raise the ceiling to the
    // whole pool. With many apps the guarantees may exceed the slice; the
    // kernel scales them down proportionally under pressure, which beats
    // promising less than an app needs to start.
    let mut min = fair.clamp(FLOOR.min(pool), elastic.max(FLOOR.min(pool)));

    let mut max = elastic.max(min);
    if let Some(cap) = pinned {
        max = max.min(cap);
        min = min.min(max);
    }

    let high = max.saturating_sub(HEADROOM).max(min);

    AppLimits { min, high, max }
}

/// True when this host can place apps in their own systemd scope.
///
/// Requires `systemd-run` and a live system manager — a container without
/// systemd as PID 1 has the binary but no bus to talk to.
pub fn can_run_scopes() -> bool {
    Path::new("/run/systemd/system").is_dir()
        && (Path::new("/usr/bin/systemd-run").exists() || Path::new("/bin/systemd-run").exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;

    #[test]
    fn lone_app_can_reach_most_of_the_pool() {
        let l = app_limits(GB, 1, None);
        assert_eq!(l.max, GB * 80 / 100);
        // The old model capped a lone app at its "fair share" of the whole
        // pool; now it can grow into the spare capacity.
        assert!(l.max > GB / 2);
    }

    /// The defining property of on-demand: with two apps, each may still take
    /// more than half — they only shrink when both actually want it.
    #[test]
    fn two_apps_can_each_exceed_a_fair_half() {
        let l = app_limits(GB, 2, None);
        assert!(l.max > GB / 2, "max {} should exceed half the pool", l.max);
        assert_eq!(l.min, GB / 2, "the guarantee is still the fair share");
    }

    #[test]
    fn guaranteed_minimum_never_below_node_floor() {
        // 10 apps in a 200 MB pool: a fair share would be 20 MB, too little for
        // Node to start.
        let l = app_limits(200 * MB, 10, None);
        assert_eq!(l.min, FLOOR);
    }

    #[test]
    fn pin_only_narrows() {
        let open = app_limits(GB, 1, None);

        // Above the elastic ceiling: no effect, the account still rules.
        let high_pin = app_limits(GB, 1, Some(2 * GB));
        assert_eq!(high_pin.max, open.max);

        // Below it: the app is held to what the user asked for.
        let low_pin = app_limits(GB, 1, Some(100 * MB));
        assert_eq!(low_pin.max, 100 * MB);
        assert!(low_pin.min <= low_pin.max);
    }

    #[test]
    fn high_sits_below_max_and_at_or_above_min() {
        for (pool, running, pin) in [
            (GB, 1, None),
            (GB, 4, None),
            (200 * MB, 10, None),
            (GB, 2, Some(16 * MB)),
            (64 * MB, 1, Some(16 * MB)),
            (16 * MB, 8, None),
        ] {
            let l = app_limits(pool, running, pin);
            assert!(
                l.min <= l.high && l.high <= l.max,
                "invariant broken for pool={pool} running={running} pin={pin:?}: {l:?}"
            );
        }
    }

    #[test]
    fn slice_cap_is_the_whole_account() {
        assert_eq!(slice_cap(GB), GB);
    }

    #[test]
    fn slice_unit_is_namespaced_per_account() {
        assert_eq!(slice_unit_name("bob"), "selynt-bob.slice");
        assert_ne!(slice_unit_name("bob"), slice_unit_name("alice"));
    }
}
