use std::collections::HashSet;
use std::path::Path;

/// Lê o UID real do processo via /proc/{pid}/status
pub fn read_proc_uid(pid: u32) -> Option<u32> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Lê o starttime do processo via /proc/{pid}/stat (campo 22, índice 19 após comm)
///
/// O campo comm pode conter espaços — usamos rfind(')') para ignorá-lo com segurança.
pub fn read_proc_starttime(pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Localiza o fim de "(comm)" — pode conter espaços
    let after_paren = content.rfind(')')?;
    let rest = &content[after_paren + 2..]; // skip ") "
    // Campos após comm (índice 0-based): state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
    // tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12)
    // cutime(13) cstime(14) priority(15) nice(16) num_threads(17) itrealvalue(18) starttime(19)
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Verifica se o processo existe em /proc
pub fn is_process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Verifica se o processo abriu portas de rede (TCP ou UDP).
///
/// Algoritmo:
///   1. Percorre /proc/{pid}/fd/ e coleta inodes de sockets
///   2. TCP: busca inodes em /proc/net/tcp{,6} com estado LISTEN (0x0A)
///   3. UDP: busca inodes em /proc/net/udp{,6} — qualquer entrada = porta bound
pub fn has_network_listen(pid: u32) -> bool {
    let fd_dir = format!("/proc/{pid}/fd");
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return false,
    };

    let mut socket_inodes: HashSet<u64> = HashSet::new();
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let t = target.to_string_lossy();
            if let Some(inner) = t
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            {
                if let Ok(inode) = inner.parse::<u64>() {
                    socket_inodes.insert(inode);
                }
            }
        }
    }

    if socket_inodes.is_empty() {
        return false;
    }

    // Helper: extrai inode (campo 9) de uma linha /proc/net/*
    let extract_inode = |line: &str| -> Option<u64> {
        let mut fields = line.split_whitespace();
        // 0=sl 1=local 2=rem 3=st 4=tx:rx 5=tr:tm 6=retrnsmt 7=uid 8=timeout 9=inode
        for _ in 0..9 {
            fields.next();
        }
        fields.next()?.parse().ok()
    };

    // TCP: estado LISTEN (0x0A)
    for f in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(f) {
            for line in content.lines().skip(1) {
                let state = line.split_whitespace().nth(3).unwrap_or("");
                if state != "0A" {
                    continue;
                }
                if let Some(inode) = extract_inode(line) {
                    if socket_inodes.contains(&inode) {
                        return true;
                    }
                }
            }
        }
    }

    // UDP: qualquer socket bound (UDP não tem estado LISTEN)
    for f in &["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(content) = std::fs::read_to_string(f) {
            for line in content.lines().skip(1) {
                if let Some(inode) = extract_inode(line) {
                    if socket_inodes.contains(&inode) {
                        return true;
                    }
                }
            }
        }
    }

    false
}
