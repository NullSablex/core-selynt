use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use serde_json::{Value, json};

use crate::runtime::kind::Runtime;
use crate::sys::fs::{atomic_write, set_perm};
use crate::sys::output::{debug, success, system_error, user_error};
use crate::sys::proc::{
    ProcessSnapshot, has_external_listen, is_process_alive, read_proc_snapshot, read_proc_starttime,
};
use crate::sys::state::{AppMeta, PLUGIN_PATH, load_app_meta, socket_path_for};
use crate::webserver::acl::apply_acl;

use super::logs::rotate_log_if_needed;
use super::{get_status, signal_sync, to_nix_pid, validate_safe_component, with_debug};
use crate::runtime::node::{NODE_MIN_MAJOR, NODE_MIN_MINOR, get_node_version_raw, node_version_ok};

/// Absolute ceiling for socket creation (any app type).
const SOCKET_HARD_TIMEOUT: Duration = Duration::from_mins(2);

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
    "process opened an externally reachable network port — only Unix sockets are allowed";

/// Whether the app has bound a port reachable from off the host.
///
/// Two things learned from the netguard sweep, which enforces the same rule:
/// loopback is allowed (an app talking to itself bypasses nothing), and the
/// whole cgroup counts — a child spawned without the Node loader can bind
/// anything, so checking only the app's own pid let it through.
fn app_has_external_port(username: &str, name: &str, pid: u32) -> bool {
    let pids = match crate::limits::usage::scope_pids(username, name) {
        // No cgroup (systemd unavailable, or the scope is not up yet): the
        // app's own process is all there is to look at.
        p if p.is_empty() => vec![pid],
        p => p,
    };
    has_external_listen(&pids)
}

/// Kills the app and fails the start if it bound a reachable port.
///
/// Checked once the socket is up: an app can open a port at any point during
/// startup, and the periodic sweep would only notice it later.
fn refuse_external_port(ctx: &WaitContext<'_>, socket_path: &Path) {
    if !app_has_external_port(ctx.username, ctx.name, ctx.pid) {
        return;
    }
    let nix_pid = to_nix_pid(ctx.pid);
    let _ = kill(nix_pid, Signal::SIGTERM);
    std::thread::sleep(KILL_GRACE);
    let _ = kill(nix_pid, Signal::SIGKILL);
    cleanup_failed(ctx.pid_file, ctx.meta_file, Some(socket_path));
    user_error("network_port_forbidden", NETWORK_PORT_FORBIDDEN_MSG);
}

/// Makes the app reachable: the proxy marker, the socket ACL, and the
/// `.enabled` flag boot recovery reads.
fn publish_route(
    state_dir: &Path,
    name: &str,
    socket_path: &Path,
    marker_path: &Path,
    web_user: &str,
) {
    if let Err(e) = std::fs::write(marker_path, b"").and_then(|()| {
        std::fs::set_permissions(marker_path, std::fs::Permissions::from_mode(0o644))
    }) {
        system_error("marker_failed", &format!("{e:#}"));
    }

    apply_acl(state_dir, socket_path, marker_path, web_user);

    // Intent, so boot recovery restarts this app. Removed by `stop` and
    // `remove`; a restart re-runs this and recreates it.
    let enabled = state_dir.join(".run").join(format!("{name}.enabled"));
    let _ = std::fs::write(&enabled, b"")
        .and_then(|()| std::fs::set_permissions(&enabled, std::fs::Permissions::from_mode(0o600)));
}

pub fn cmd_start(
    state_dir: &Path,
    name: &str,
    username: &str,
    web_user: &str,
    spawned_pid: Option<u32>,
    dbg: Option<&Value>,
) -> ! {
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

    let socket_path = socket_path_for(state_dir, &meta);
    let marker_path = state_dir.join(".proxy").join(&meta.host);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&marker_path);

    let pid_file = state_dir.join(".run").join(format!("{name}.pid"));
    let meta_file = state_dir.join(".run").join(format!("{name}.meta"));

    // Normally the app was already spawned into its own systemd scope by the
    // root prelude; fall back to spawning here when that path is unavailable.
    let pid = spawned_pid.unwrap_or_else(|| {
        spawn_app(
            &meta,
            name,
            &socket_path,
            None,
            None,
            crate::sys::state::account_is_isolated(state_dir),
        )
    });

    if let Err(e) = persist_state(&pid_file, &meta_file, pid, &socket_path) {
        let _ = kill(to_nix_pid(pid), Signal::SIGKILL);
        system_error("state_write_failed", &format!("{e:#}"));
    }

    let ctx = WaitContext {
        pid,
        username,
        name,
        socket_path: &socket_path,
        pid_file: &pid_file,
        meta_file: &meta_file,
    };
    wait_for_socket_file(&ctx);
    wait_for_socket_accept(&ctx);

    refuse_external_port(&ctx, &socket_path);
    publish_route(state_dir, name, &socket_path, &marker_path, web_user);

    signal_sync();

    success(with_debug(json!({ "pid": pid }), dbg))
}

/// Spawns an app into its own systemd scope. Must be called as root, before
/// the privilege drop: registering a transient unit needs the system bus, and
/// an unprivileged caller gets "Interactive authentication required".
/// `systemd-run --uid/--gid` drops to the app's account for us.
///
/// Returns `None` when systemd is unavailable, leaving `cmd_start` to spawn the
/// app the ordinary way after the drop.
pub fn spawn_into_scope(
    meta: &AppMeta,
    name: &str,
    state_dir: &Path,
    username: &str,
    uid: u32,
    gid: u32,
) -> Option<u32> {
    if !crate::limits::policy::can_run_scopes() {
        return None;
    }
    let socket_path = socket_path_for(state_dir, meta);
    let _ = std::fs::remove_file(&socket_path);

    // Resolve the cap here, in the root prelude: it needs the account's
    // allowance from DirectAdmin (root-only) plus every sibling app's setting.
    let limits = crate::limits::usage::app_limits_for(state_dir, username, name, meta);

    Some(spawn_app(
        meta,
        name,
        &socket_path,
        Some((username, uid, gid)),
        limits,
        crate::sys::state::account_is_isolated(state_dir),
    ))
}

/// Opens an app's log files, truncating them first.
///
/// Each run starts empty: the panel shows what the app is saying *now*, and
/// keeping the previous run's output made fixed errors look current.
fn open_log_files(cwd: &Path, name: &str) -> (std::fs::File, std::fs::File) {
    let open = |path: &Path, which: &str| {
        rotate_log_if_needed(path);
        let _ = std::fs::write(path, b"");
        match std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
        {
            Ok(f) => f,
            Err(e) => system_error("log_open_failed", &format!("{which} log: {e:#}")),
        }
    };
    let logs = cwd.join("logs");
    (
        open(&logs.join(format!("{name}.out.log")), "stdout"),
        open(&logs.join(format!("{name}.err.log")), "stderr"),
    )
}

/// Creates the directory an isolated app's socket lives in, owned by the
/// account.
///
/// It has to exist before the sandbox can bind it and before the app can
/// `bind(2)`. Created here, while still root, so it would otherwise be left
/// root-owned and the app could not create its socket in it.
fn ensure_socket_dir(socket_path: &Path, scope: Option<(&str, u32, u32)>) {
    let Some(dir) = socket_path.parent() else {
        return;
    };
    if dir.is_dir() {
        return;
    }
    let _ = std::fs::create_dir_all(dir);
    let _ = set_perm(dir, 0o750);
    if let Some((_, uid, gid)) = scope {
        let _ = crate::sys::fs::chown_path(dir, uid, gid);
    }
}

/// Puts the app inside its namespaces, when the account asked for isolation.
///
/// Applied *inside* the scope wrapper: the app has to stay in its own cgroup so
/// the memory limits and the netguard sweep still see it. Refuses to start
/// rather than run shared — isolation was accepted when it was switched on, so
/// losing it means the host changed underneath, and starting anyway would give
/// the account less separation than it is told it has.
fn apply_sandbox(cmd: Command, isolated: bool, cwd: &Path, socket_path: &Path) -> Command {
    if !isolated {
        return cmd;
    }
    let Some(socket_dir) = socket_path.parent() else {
        return cmd;
    };
    if !crate::limits::sandbox::available() {
        user_error(
            "sandbox_unavailable",
            crate::limits::sandbox::unavailable_reason(),
        );
    }
    crate::limits::sandbox::wrap(cmd, cwd, socket_dir)
}

fn spawn_app(
    meta: &AppMeta,
    name: &str,
    socket_path: &Path,
    scope: Option<(&str, u32, u32)>,
    limits: Option<crate::limits::policy::AppLimits>,
    isolated: bool,
) -> u32 {
    let cwd_path = PathBuf::from(&meta.cwd);
    let (stdout_file, stderr_file) = open_log_files(&cwd_path, name);

    let env_vars = load_env_file(&cwd_path);
    let entry_path = cwd_path.join(&meta.entry);
    let socket_str = socket_path.to_string_lossy().to_string();

    ensure_socket_dir(socket_path, scope);

    let cmd = build_command(meta, &entry_path);

    let mut cmd = apply_sandbox(cmd, isolated, &cwd_path, socket_path);
    cmd.env("SELYNT_SOCKET", &socket_str);
    cmd.env("SELYNT_HOST", &meta.host);
    for (k, v) in &env_vars {
        cmd.env(k, v);
    }

    // Give the app its own cgroup where systemd is available, so it does not
    // die with whatever process happened to start it. Falls back to a bare
    // spawn elsewhere.
    if let Some((username, uid, gid)) = scope
        && crate::limits::policy::can_run_scopes()
    {
        cmd = wrap_in_scope(&cmd, username, name, uid, gid, limits.as_ref());
    }

    // Applied after wrapping: these are not readable back off a Command, so
    // they have to land on whichever one is actually spawned.
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(stdout_file);
    cmd.stderr(stderr_file);
    cmd.current_dir(&meta.cwd);

    // `setsid` makes the child a new session leader so signals delivered to
    // the parent (or the controlling terminal) don't leak into the child tree.
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid().map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(())
        });
    }

    let cmd_display = Runtime::from_str(&meta.app_type).map_or_else(
        |()| entry_path.display().to_string(),
        |rt| rt.command_display(&entry_path),
    );
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
    if Runtime::from_str(&meta.app_type).is_ok_and(Runtime::is_interpreted) {
        // Absolute path, never the bare name: the app inherits the environment
        // of whoever invoked the panel, and the CGI's `PATH` lacks
        // `/usr/local/bin`. The same app started from a shell and failed from
        // the panel — inside the sandbox as `execvp node: No such file`.
        let node_bin = if meta.node_version.is_empty() {
            crate::runtime::detect::default_node_path().unwrap_or_else(|| "node".to_string())
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

/// Name of the transient systemd scope backing an app.
fn scope_unit_name(username: &str, name: &str) -> String {
    format!("selynt-{username}-{name}.scope")
}

/// Wraps `cmd` in `systemd-run --scope` so the app lands in a cgroup of its own.
///
/// Without it the app inherits the cgroup of whatever started it and systemd
/// tears it down along with that — which is why apps restored at boot used to
/// die moments later. Registering a scope needs the system bus, so this runs
/// before the drop and lets `--uid`/`--gid` perform it. `--collect` clears the
/// unit on exit, so a crash leaves nothing blocking the next start.
fn wrap_in_scope(
    cmd: &Command,
    username: &str,
    name: &str,
    uid: u32,
    gid: u32,
    limits: Option<&crate::limits::policy::AppLimits>,
) -> Command {
    let mut run = Command::new("systemd-run");
    run.arg("--scope")
        .arg("--quiet")
        .arg("--collect")
        .arg(format!("--unit={}", scope_unit_name(username, name)))
        // The account's slice is the ceiling the kernel enforces over all of
        // its apps together; the per-app maxima below may exceed it on purpose.
        .arg(format!(
            "--slice={}",
            crate::limits::policy::slice_unit_name(username)
        ))
        .arg(format!("--uid={uid}"))
        .arg(format!("--gid={gid}"))
        // Keep the app alive when systemd stops the unit that spawned it.
        // (`--scope` only accepts a subset of unit properties; NoNewPrivileges
        // is not among them — the drop below is handled by --uid/--gid.)
        .arg("--property=KillMode=process");

    // MemoryMin is what the app is guaranteed against reclaim; MemoryHigh
    // throttles it first, giving it a chance to give memory back; MemoryMax is
    // the hard stop where the OOM killer steps in. The slice above is what
    // keeps the account as a whole in bounds.
    if let Some(l) = limits {
        run.arg(format!("--property=MemoryMin={}", l.min));
        run.arg(format!("--property=MemoryHigh={}", l.high));
        run.arg(format!("--property=MemoryMax={}", l.max));
    }

    run.arg(cmd.get_program());
    for a in cmd.get_args() {
        run.arg(a);
    }
    // Command exposes no way to read back stdio/cwd, so the caller reapplies
    // those to the wrapper; env vars are readable and carried over here.
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => {
                run.env(k, v);
            }
            None => {
                run.env_remove(k);
            }
        }
    }
    run
}

fn persist_state(
    pid_file: &Path,
    meta_file: &Path,
    pid: u32,
    socket_path: &Path,
) -> anyhow::Result<()> {
    atomic_write(pid_file, format!("{pid}\n").as_bytes())?;
    set_perm(pid_file, 0o600)?;

    std::thread::sleep(SPAWN_PROC_SETTLE);

    let my_uid = nix::unistd::getuid().as_raw();
    let starttime = read_proc_starttime(pid).unwrap_or(0);
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Record where the socket actually is. Turning account isolation on or off
    // moves it, and a running app keeps the path it was started with — stopping
    // it has to clean up that file, not the one the current setting implies.
    let socket = socket_path.display();
    let meta_content =
        format!("uid={my_uid}\nstarttime={starttime}\nstarted_at={started_at}\nsocket={socket}\n");

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
    /// Needed to resolve the app's cgroup, so the port check covers every
    /// process it spawned and not just its own.
    username: &'a str,
    name: &'a str,
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
    if app_has_external_port(ctx.username, ctx.name, ctx.pid) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_unit_name_is_namespaced_per_user_and_app() {
        assert_eq!(scope_unit_name("bob", "api"), "selynt-bob-api.scope");
        // Two users may run an app under the same name without colliding.
        assert_ne!(
            scope_unit_name("bob", "api"),
            scope_unit_name("alice", "api")
        );
    }

    #[test]
    fn wrap_in_scope_keeps_program_and_args() {
        let mut inner = Command::new("/usr/bin/node");
        inner.arg("--import").arg("/tmp/loader.js").arg("/app/i.js");
        let wrapped = wrap_in_scope(&inner, "bob", "api", 1003, 1003, None);

        assert_eq!(wrapped.get_program(), "systemd-run");
        let args: Vec<String> = wrapped
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--scope".to_string()));
        assert!(args.contains(&"--collect".to_string()));
        assert!(args.contains(&"--unit=selynt-bob-api.scope".to_string()));
        // The real command has to survive the wrapping, in order.
        assert!(args.contains(&"/usr/bin/node".to_string()));
        assert!(args.contains(&"/app/i.js".to_string()));
        let node = args.iter().position(|a| a == "/usr/bin/node").unwrap();
        let entry = args.iter().position(|a| a == "/app/i.js").unwrap();
        assert!(node < entry, "argument order must be preserved");
    }

    /// The scope must carry the privilege drop: this runs as root, so without
    /// --uid/--gid the app would keep running as root.
    #[test]
    fn wrap_in_scope_drops_privileges_via_systemd() {
        let wrapped = wrap_in_scope(&Command::new("/bin/true"), "bob", "api", 1003, 1004, None);
        let args: Vec<String> = wrapped
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--uid=1003".to_string()));
        assert!(args.contains(&"--gid=1004".to_string()));
    }

    /// Apps must land in the account's slice — that is where the collective
    /// ceiling lives, and the per-app maxima intentionally exceed it.
    #[test]
    fn wrap_in_scope_places_app_in_the_user_slice() {
        let limits = crate::limits::policy::AppLimits {
            min: 64 * 1024 * 1024,
            high: 96 * 1024 * 1024,
            max: 128 * 1024 * 1024,
        };
        let wrapped = wrap_in_scope(
            &Command::new("/bin/true"),
            "bob",
            "api",
            1003,
            1003,
            Some(&limits),
        );
        let args: Vec<String> = wrapped
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--slice=selynt-bob.slice".to_string()));
        assert!(args.contains(&"--property=MemoryMin=67108864".to_string()));
        assert!(args.contains(&"--property=MemoryHigh=100663296".to_string()));
        assert!(args.contains(&"--property=MemoryMax=134217728".to_string()));
    }

    /// Without an account allowance there is nothing to divide, so the app runs
    /// unconstrained — the behaviour before limits existed.
    #[test]
    fn wrap_in_scope_omits_properties_without_limits() {
        let wrapped = wrap_in_scope(&Command::new("/bin/true"), "bob", "api", 1003, 1003, None);
        let args: Vec<String> = wrapped
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|a| a.starts_with("--property=Memory")));
    }

    #[test]
    fn wrap_in_scope_carries_environment_over() {
        let mut inner = Command::new("/bin/true");
        inner.env("SELYNT_SOCKET", "/run/app.sock");
        let wrapped = wrap_in_scope(&inner, "bob", "api", 1003, 1003, None);
        let found = wrapped
            .get_envs()
            .any(|(k, v)| k == "SELYNT_SOCKET" && v == Some("/run/app.sock".as_ref()));
        assert!(found, "app env must reach the wrapped command");
    }
}
