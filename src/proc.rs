use std::collections::HashSet;
use std::path::Path;

const TCP_LISTEN_STATE: &str = "0A";
const PROC_NET_INODE_FIELD: usize = 9;
const PROC_STAT_UTIME_OFFSET: usize = 11;

pub fn read_proc_uid(pid: u32) -> Option<u32> {
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
pub fn read_proc_starttime(pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_paren = content.rfind(')')?;
    let rest = &content[after_paren + 2..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

pub fn is_process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Sum of `utime + stime` from `/proc/{pid}/stat` — total CPU ticks consumed.
pub fn read_proc_cpu_ticks(pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_paren = content.rfind(')')?;
    let rest = &content[after_paren + 2..];
    let mut it = rest.split_whitespace();
    let utime: u64 = it.nth(PROC_STAT_UTIME_OFFSET)?.parse().ok()?;
    let stime: u64 = it.next()?.parse().ok()?;
    Some(utime + stime)
}

/// `VmRSS` in kilobytes from `/proc/{pid}/status`.
pub fn read_proc_rss_kb(pid: u32) -> Option<u64> {
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

pub fn read_proc_snapshot(pid: u32) -> Option<ProcessSnapshot> {
    let cpu_ticks = read_proc_cpu_ticks(pid)?;
    let rss_kb = read_proc_rss_kb(pid).unwrap_or_default();
    Some(ProcessSnapshot { cpu_ticks, rss_kb })
}

/// Reports whether the process is listening on any TCP or UDP socket.
///
/// We walk `/proc/{pid}/fd/`, collect the inodes of every socket FD, then scan
/// `/proc/net/{tcp,tcp6,udp,udp6}` and match against those inodes. UDP entries
/// are treated as listening because UDP has no `LISTEN` state — any bound
/// socket counts.
pub fn has_network_listen(pid: u32) -> bool {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };

    let mut socket_inodes: HashSet<u64> = HashSet::new();
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let t = target.to_string_lossy();
            if let Some(inner) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                && let Ok(inode) = inner.parse::<u64>()
            {
                socket_inodes.insert(inode);
            }
        }
    }

    if socket_inodes.is_empty() {
        return false;
    }

    let extract_inode = |line: &str| -> Option<u64> {
        line.split_whitespace()
            .nth(PROC_NET_INODE_FIELD)?
            .parse()
            .ok()
    };

    for f in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = std::fs::read_to_string(f) else {
            continue;
        };
        for line in content.lines().skip(1) {
            if line.split_whitespace().nth(3) != Some(TCP_LISTEN_STATE) {
                continue;
            }
            if let Some(inode) = extract_inode(line)
                && socket_inodes.contains(&inode)
            {
                return true;
            }
        }
    }

    for f in &["/proc/net/udp", "/proc/net/udp6"] {
        let Ok(content) = std::fs::read_to_string(f) else {
            continue;
        };
        for line in content.lines().skip(1) {
            if let Some(inode) = extract_inode(line)
                && socket_inodes.contains(&inode)
            {
                return true;
            }
        }
    }

    false
}
