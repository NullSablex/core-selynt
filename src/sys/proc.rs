use std::collections::HashSet;
use std::path::Path;

const TCP_LISTEN_STATE: &str = "0A";
const PROC_NET_INODE_FIELD: usize = 9;
const PROC_NET_LOCAL_ADDR_FIELD: usize = 1;
const PROC_STAT_UTIME_OFFSET: usize = 11;

/// Whether a `/proc/net/*` local address is reachable from outside the host.
///
/// The address is the hex, little-endian form of the bind address. Loopback is
/// the app talking to itself — a local cache, IPC between its own processes —
/// and stays allowed. Anything else (`0.0.0.0`, `::`, or a real interface
/// address) is reachable from off the machine and bypasses the panel's proxy.
///
/// Accepts the `addr:port` field as it appears in the file.
fn is_externally_bound(local_addr: &str) -> bool {
    let Some((addr, _port)) = local_addr.rsplit_once(':') else {
        return false;
    };
    match addr.len() {
        // IPv4: 127.0.0.0/8 is loopback. Little-endian, so the first octet of
        // the address is the *last* byte pair of the hex string.
        8 => !addr.get(6..8).is_some_and(|b| b.eq_ignore_ascii_case("7f")),
        // IPv6: `::1` is loopback, and so is a v4-mapped 127.x address
        // (`::ffff:7f00:0001`), which is how a dual-stack bind to localhost
        // can appear.
        32 => {
            let is_v6_loopback = addr.eq_ignore_ascii_case("00000000000000000000000001000000");
            let is_mapped_v4_loopback = addr
                .get(16..24)
                .is_some_and(|m| m.eq_ignore_ascii_case("ffff0000"))
                && addr
                    .get(30..32)
                    .is_some_and(|b| b.eq_ignore_ascii_case("7f"));
            !(is_v6_loopback || is_mapped_v4_loopback)
        }
        _ => false,
    }
}

pub(crate) fn read_proc_uid(pid: u32) -> Option<u32> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    content
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
}

/// Reads the process start time (field 22) from `/proc/{pid}/stat`.
///
/// The `comm` field can contain spaces and parentheses, so we use `rfind(')')`
/// to locate its end before tokenising the rest of the line.
pub(crate) fn read_proc_starttime(pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_paren = content.rfind(')')?;
    let rest = &content[after_paren + 2..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

pub(crate) fn is_process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Sum of `utime + stime` from `/proc/{pid}/stat` — total CPU ticks consumed.
pub(crate) fn read_proc_cpu_ticks(pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_paren = content.rfind(')')?;
    let rest = &content[after_paren + 2..];
    let mut it = rest.split_whitespace();
    let utime: u64 = it.nth(PROC_STAT_UTIME_OFFSET)?.parse().ok()?;
    let stime: u64 = it.next()?.parse().ok()?;
    Some(utime + stime)
}

/// `VmRSS` in kilobytes from `/proc/{pid}/status`.
pub(crate) fn read_proc_rss_kb(pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    content
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessSnapshot {
    pub cpu_ticks: u64,
    pub rss_kb: u64,
}

pub(crate) fn read_proc_snapshot(pid: u32) -> Option<ProcessSnapshot> {
    let cpu_ticks = read_proc_cpu_ticks(pid)?;
    let rss_kb = read_proc_rss_kb(pid).unwrap_or_default();
    Some(ProcessSnapshot { cpu_ticks, rss_kb })
}

/// Whether any of `socket_inodes` is a listening/bound network socket.
///
/// With `external_only`, loopback binds are ignored: an app is free to talk to
/// itself, and only a port reachable from off the host bypasses the proxy.
fn socket_inodes_are_bound(socket_inodes: &HashSet<u64>, external_only: bool) -> bool {
    let extract_field = |line: &str, n: usize| -> Option<String> {
        line.split_whitespace().nth(n).map(ToString::to_string)
    };
    let extract_inode = |line: &str| -> Option<u64> {
        line.split_whitespace()
            .nth(PROC_NET_INODE_FIELD)?
            .parse()
            .ok()
    };

    // UDP has no LISTEN state, so any bound socket counts.
    for (files, listen_only) in [
        (["/proc/net/tcp", "/proc/net/tcp6"], true),
        (["/proc/net/udp", "/proc/net/udp6"], false),
    ] {
        for f in &files {
            let Ok(content) = std::fs::read_to_string(f) else {
                continue;
            };
            for line in content.lines().skip(1) {
                if listen_only && line.split_whitespace().nth(3) != Some(TCP_LISTEN_STATE) {
                    continue;
                }
                let Some(inode) = extract_inode(line) else {
                    continue;
                };
                if !socket_inodes.contains(&inode) {
                    continue;
                }
                if external_only
                    && !extract_field(line, PROC_NET_LOCAL_ADDR_FIELD)
                        .is_some_and(|a| is_externally_bound(&a))
                {
                    continue;
                }
                return true;
            }
        }
    }

    false
}

/// Socket inodes held by `pid`, or an empty set when the process is gone.
fn socket_inodes_of(pid: u32) -> HashSet<u64> {
    let mut inodes = HashSet::new();
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return inodes;
    };
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let t = target.to_string_lossy();
            if let Some(inner) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                && let Ok(inode) = inner.parse::<u64>()
            {
                inodes.insert(inode);
            }
        }
    }
    inodes
}

/// Every descendant of `pid`, found by walking `/proc/*/stat` parent links.
///
/// A sandboxed app sits under a bwrap process, and bwrap does not pass signals
/// on to it, so stopping the app means signalling the children too.
pub(crate) fn descendants_of(pid: u32) -> Vec<u32> {
    let mut children: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Ok(this) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if let Some(parent) = read_proc_ppid(this) {
            children.entry(parent).or_default().push(this);
        }
    }

    let mut out = Vec::new();
    let mut queue = vec![pid];
    while let Some(p) = queue.pop() {
        for &c in children.get(&p).map(Vec::as_slice).unwrap_or_default() {
            out.push(c);
            queue.push(c);
        }
    }
    out
}

/// Parent pid (field 4) from `/proc/{pid}/stat`.
fn read_proc_ppid(pid: u32) -> Option<u32> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_paren = content.rfind(')')?;
    content[after_paren + 2..]
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Whether any process in `pids` is bound to a port reachable from off the host.
///
/// Checking the whole set matters: the loader that blocks `listen()` only
/// covers the app's own process, so a child spawned without it — or an app that
/// is not Node at all — can bind freely. Passing every PID in the app's cgroup
/// closes that path.
pub(crate) fn has_external_listen(pids: &[u32]) -> bool {
    let mut socket_inodes: HashSet<u64> = HashSet::new();
    for &pid in pids {
        socket_inodes.extend(socket_inodes_of(pid));
    }
    if socket_inodes.is_empty() {
        return false;
    }
    socket_inodes_are_bound(&socket_inodes, true)
}

#[cfg(test)]
mod tests {
    use super::is_externally_bound;

    /// Addresses come from `/proc/net/*` in hex, little-endian. These are the
    /// exact strings the kernel produced on a live server.
    /// Start and the netguard sweep enforce one policy and must agree on it.
    /// Start once checked *every* bind, so an app listening on 127.0.0.1 was
    /// refused at start while the sweep would have left it running — the same
    /// app allowed or forbidden depending on when it opened the socket.
    #[test]
    fn loopback_is_allowed_by_the_same_rule_everywhere() {
        // What start rejects must be exactly what the sweep stops.
        assert!(!is_externally_bound("0100007F:4A57"));
        assert!(is_externally_bound("00000000:1F90"));
    }

    #[test]
    fn ipv4_loopback_is_internal() {
        // 127.0.0.1:19031 — an app talking to itself.
        assert!(!is_externally_bound("0100007F:4A57"));
        // 127.0.0.53 (systemd-resolved) is still loopback.
        assert!(!is_externally_bound("3500007F:0035"));
    }

    #[test]
    fn ipv4_wildcard_and_real_addresses_are_external() {
        // 0.0.0.0:19032 — reachable from anywhere.
        assert!(is_externally_bound("00000000:4A58"));
        // 10.0.0.5 — a real interface address, still off-host reachable.
        assert!(is_externally_bound("0500000A:1F90"));
    }

    #[test]
    fn ipv6_loopback_is_internal() {
        // ::1
        assert!(!is_externally_bound(
            "00000000000000000000000001000000:4A57"
        ));
    }

    #[test]
    fn ipv6_wildcard_is_external() {
        // :: — the dual-stack catch-all, as seen on the server.
        assert!(is_externally_bound(
            "00000000000000000000000000000000:006E"
        ));
    }

    /// A dual-stack bind to localhost can surface as a v4-mapped address; it is
    /// still loopback and must not be treated as exposed.
    #[test]
    fn v4_mapped_loopback_is_internal() {
        assert!(!is_externally_bound(
            "0000000000000000FFFF00000100007F:4A57"
        ));
    }

    /// A v4-mapped *public* address is the real thing and must be caught.
    #[test]
    fn v4_mapped_public_is_external() {
        assert!(is_externally_bound(
            "0000000000000000FFFF00000500000A:1F90"
        ));
    }

    #[test]
    fn malformed_input_is_not_reported_as_external() {
        assert!(!is_externally_bound(""));
        assert!(!is_externally_bound("garbage"));
        assert!(!is_externally_bound("ABC:1"));
    }
}
