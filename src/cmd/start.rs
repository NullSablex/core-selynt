use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use serde_json::{Value, json};

use crate::acl::apply_acl;
use crate::output::{debug, success, system_error, user_error};
use crate::proc::{
    ProcessSnapshot, has_network_listen, is_process_alive, read_proc_snapshot, read_proc_starttime,
};
use crate::state::{AppMeta, PLUGIN_PATH, atomic_write, load_app_meta, set_perm};

use super::manage::rotate_log_if_needed;
use super::node::{NODE_MIN_MAJOR, NODE_MIN_MINOR, get_node_version_raw, node_version_ok};
use super::{get_status, signal_sync, to_nix_pid, validate_safe_component, with_debug};

/// Absolute ceiling for socket creation (any app type).
const SOCKET_HARD_TIMEOUT: Duration = Duration::from_secs(120);

/// Time between progress snapshots. 2.5s absorbs scheduling jitter and Node
/// GC pauses without raising false positives.
const PROGRESS_CHECK_INTERVAL: Duration = Duration::from_millis(2500);

/// Consecutive zero-delta checks (both CPU and RSS) to declare the process
/// stuck. `STUCK_THRESHOLD × PROGRESS_CHECK_INTERVAL` = 10s of confirmed
/// inactivity before SIGKILL.
const STUCK_THRESHOLD: u32 = 4;

/// Ceiling for the socket-accept phase (socket exists, waiting for connect).
const SOCKET_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);

const SPAWN_PROC_SETTLE: Duration = Duration::from_millis(50);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(100);
const KILL_GRACE: Duration = Duration::from_millis(500);

const NETWORK_PORT_FORBIDDEN_MSG: &str =
    "process opened a network port (TCP/UDP) — only Unix sockets are allowed";

pub fn cmd_start(state_dir: &Path, name: &str, web_user: &str, dbg: Option<&Value>) -> ! {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    if !validate_safe_component(&meta.entry) {
        user_error(
            "invalid_entry",
            "entry contains path traversal — re-create the app",
        );
    }
    if !validate_safe_component(&meta.host) {
        user_error(
            "invalid_host",
            "host contains path traversal — re-create the app",
        );
    }

    let (status, pid, _) = get_status(state_dir, name);
    if status == "RUNNING" {
        success(with_debug(json!({ "pid": pid }), dbg));
    }

    let socket_path = state_dir.join(".sockets").join(&meta.host);
    let marker_path = state_dir.join(".proxy").join(&meta.host);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&marker_path);

    let pid_file = state_dir.join(".run").join(format!("{name}.pid"));
    let meta_file = state_dir.join(".run").join(format!("{name}.meta"));

    let pid = spawn_app(&meta, name, &socket_path);

    if let Err(e) = persist_state(&pid_file, &meta_file, pid) {
        let _ = kill(to_nix_pid(pid), Signal::SIGKILL);
        system_error("state_write_failed", &format!("{e:#}"));
    }

    let ctx = WaitContext {
        pid,
        socket_path: &socket_path,
        pid_file: &pid_file,
        meta_file: &meta_file,
    };
    wait_for_socket_file(&ctx);
    wait_for_socket_accept(&ctx);

    if has_network_listen(pid) {
        let nix_pid = to_nix_pid(pid);
        let _ = kill(nix_pid, Signal::SIGTERM);
        std::thread::sleep(KILL_GRACE);
        let _ = kill(nix_pid, Signal::SIGKILL);
        cleanup_failed(&pid_file, &meta_file, Some(&socket_path));
        user_error("network_port_forbidden", NETWORK_PORT_FORBIDDEN_MSG);
    }

    if let Err(e) = std::fs::write(&marker_path, b"").and_then(|()| {
        std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o644))
    }) {
        system_error("marker_failed", &format!("{e:#}"));
    }

    apply_acl(state_dir, &socket_path, &marker_path, web_user);

    // Persist intent so boot-recovery can re-start this app after a reboot.
    // Removed by `cmd_stop` and `cmd_remove`; `cmd_restart` re-runs `cmd_start`,
    // which recreates the marker.
    let enabled_path = state_dir.join(".run").join(format!("{name}.enabled"));
    let _ = std::fs::write(&enabled_path, b"")
        .and_then(|()| std::fs::set_permissions(&enabled_path, std::fs::Permissions::from_mode(0o600)));

    signal_sync();

    success(with_debug(json!({ "pid": pid }), dbg))
}

fn spawn_app(meta: &AppMeta, name: &str, socket_path: &Path) -> u32 {
    let cwd_path = PathBuf::from(&meta.cwd);
    let log_out = cwd_path.join("logs").join(format!("{name}.out.log"));
    let log_err = cwd_path.join("logs").join(format!("{name}.err.log"));
    rotate_log_if_needed(&log_out);
    rotate_log_if_needed(&log_err);

    let stdout_file = match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_out)
    {
        Ok(f) => f,
        Err(e) => system_error("log_open_failed", &format!("stdout log: {e:#}")),
    };
    let stderr_file = match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_err)
    {
        Ok(f) => f,
        Err(e) => system_error("log_open_failed", &format!("stderr log: {e:#}")),
    };

    let env_vars = load_env_file(&cwd_path);
    let entry_path = cwd_path.join(&meta.entry);
    let socket_str = socket_path.to_string_lossy().to_string();

    let mut cmd = build_command(meta, &entry_path);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(stdout_file);
    cmd.stderr(stderr_file);
    cmd.current_dir(&meta.cwd);
    cmd.env("SELYNT_SOCKET", &socket_str);
    cmd.env("SELYNT_HOST", &meta.host);
    for (k, v) in &env_vars {
        cmd.env(k, v);
    }

    // `setsid` makes the child a new session leader so signals delivered to
    // the parent (or the controlling terminal) don't leak into the child tree.
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid().map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(())
        });
    }

    let cmd_display = match meta.app_type.as_str() {
        "node" => format!("node {}", entry_path.display()),
        _ => entry_path.display().to_string(),
    };
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => system_error("spawn_failed", &format!("{cmd_display}: {e:#}")),
    };
    let pid = child.id();
    debug(format!("spawned '{name}' PID={pid}"));
    pid
}

fn load_env_file(cwd: &Path) -> Vec<(String, String)> {
    let env_file = cwd.join(".env");
    if !env_file.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(&env_file)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn build_command(meta: &AppMeta, entry_path: &Path) -> Command {
    if meta.app_type.as_str() == "node" {
        let node_bin = if meta.node_version.is_empty() {
            "node".to_string()
        } else {
            meta.node_version.clone()
        };
        if let Some(ver) = get_node_version_raw(Path::new(&node_bin))
            && !node_version_ok(&ver)
        {
            user_error(
                "unsupported_node",
                &format!(
                    "Node.js {ver} is not supported. Minimum: v{NODE_MIN_MAJOR}.{NODE_MIN_MINOR}.0"
                ),
            );
        }
        let mut c = Command::new(&node_bin);
        c.arg("--import");
        c.arg(format!("{PLUGIN_PATH}/lib/node-loader.js"));
        c.arg(entry_path);
        c
    } else {
        Command::new(entry_path)
    }
}

fn persist_state(pid_file: &Path, meta_file: &Path, pid: u32) -> anyhow::Result<()> {
    atomic_write(pid_file, format!("{pid}\n").as_bytes())?;
    set_perm(pid_file, 0o600)?;

    std::thread::sleep(SPAWN_PROC_SETTLE);

    let my_uid = nix::unistd::getuid().as_raw();
    let starttime = read_proc_starttime(pid).unwrap_or(0);
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let meta_content = format!("uid={my_uid}\nstarttime={starttime}\nstarted_at={started_at}\n");

    if let Err(e) =
        atomic_write(meta_file, meta_content.as_bytes()).and_then(|()| set_perm(meta_file, 0o600))
    {
        let _ = std::fs::remove_file(pid_file);
        return Err(e);
    }
    Ok(())
}

struct WaitContext<'a> {
    pid: u32,
    socket_path: &'a Path,
    pid_file: &'a Path,
    meta_file: &'a Path,
}

fn cleanup_failed(pid_file: &Path, meta_file: &Path, socket: Option<&Path>) {
    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(meta_file);
    if let Some(s) = socket {
        let _ = std::fs::remove_file(s);
    }
}

fn check_failure_modes(ctx: &WaitContext<'_>, include_socket_cleanup: bool) {
    if has_network_listen(ctx.pid) {
        let nix_pid = to_nix_pid(ctx.pid);
        let _ = kill(nix_pid, Signal::SIGTERM);
        std::thread::sleep(KILL_GRACE);
        let _ = kill(nix_pid, Signal::SIGKILL);
        cleanup_failed(
            ctx.pid_file,
            ctx.meta_file,
            include_socket_cleanup.then_some(ctx.socket_path),
        );
        user_error("network_port_forbidden", NETWORK_PORT_FORBIDDEN_MSG);
    }
    if !is_process_alive(ctx.pid) {
        cleanup_failed(
            ctx.pid_file,
            ctx.meta_file,
            include_socket_cleanup.then_some(ctx.socket_path),
        );
        system_error(
            "process_exited",
            "process exited before reaching the expected state",
        );
    }
}

fn wait_for_socket_file(ctx: &WaitContext<'_>) {
    let deadline = Instant::now() + SOCKET_HARD_TIMEOUT;
    let mut last_check = Instant::now();
    let mut last_snapshot = read_proc_snapshot(ctx.pid);
    let mut stuck = 0u32;

    loop {
        if ctx.socket_path.exists() {
            return;
        }
        if Instant::now() >= deadline {
            let _ = kill(to_nix_pid(ctx.pid), Signal::SIGKILL);
            cleanup_failed(ctx.pid_file, ctx.meta_file, None);
            system_error(
                "socket_timeout",
                "process did not create the Unix socket within 120s",
            );
        }
        check_failure_modes(ctx, false);

        if last_check.elapsed() >= PROGRESS_CHECK_INTERVAL {
            last_check = Instant::now();
            let current = read_proc_snapshot(ctx.pid);
            stuck = next_stuck_count(stuck, last_snapshot, current);
            last_snapshot = current;
            if stuck >= STUCK_THRESHOLD {
                debug(format!(
                    "pid={} stuck without progress: {stuck}/{STUCK_THRESHOLD}",
                    ctx.pid
                ));
                let _ = kill(to_nix_pid(ctx.pid), Signal::SIGKILL);
                cleanup_failed(ctx.pid_file, ctx.meta_file, None);
                system_error(
                    "socket_stuck",
                    "process stopped making progress before creating the Unix socket",
                );
            }
        }

        std::thread::sleep(READY_POLL_INTERVAL);
    }
}

fn wait_for_socket_accept(ctx: &WaitContext<'_>) {
    let deadline = Instant::now() + SOCKET_ACCEPT_TIMEOUT;
    let mut last_check = Instant::now();
    let mut last_snapshot = read_proc_snapshot(ctx.pid);
    let mut stuck = 0u32;

    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(ctx.socket_path).is_ok() {
            return;
        }
        check_failure_modes(ctx, true);

        if last_check.elapsed() >= PROGRESS_CHECK_INTERVAL {
            last_check = Instant::now();
            let current = read_proc_snapshot(ctx.pid);
            stuck = next_stuck_count(stuck, last_snapshot, current);
            last_snapshot = current;
            if stuck >= STUCK_THRESHOLD {
                let _ = kill(to_nix_pid(ctx.pid), Signal::SIGKILL);
                cleanup_failed(ctx.pid_file, ctx.meta_file, Some(ctx.socket_path));
                system_error(
                    "socket_stuck",
                    "process stopped making progress before accepting connections on the socket",
                );
            }
        }

        std::thread::sleep(READY_POLL_INTERVAL);
    }

    let _ = kill(to_nix_pid(ctx.pid), Signal::SIGKILL);
    cleanup_failed(ctx.pid_file, ctx.meta_file, Some(ctx.socket_path));
    system_error(
        "socket_not_accepting",
        "Unix socket exists but is not accepting connections",
    );
}

const fn next_stuck_count(
    current_stuck: u32,
    prev: Option<ProcessSnapshot>,
    current: Option<ProcessSnapshot>,
) -> u32 {
    let made_progress = match (prev, current) {
        (Some(p), Some(c)) => c.cpu_ticks > p.cpu_ticks || c.rss_kb > p.rss_kb,
        _ => true,
    };
    if made_progress { 0 } else { current_stuck + 1 }
}
