use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::output::{success, system_error, user_error};
use crate::state::{atomic_write, list_app_names, load_app_meta, set_perm, validate_name};

use super::{get_status, signal_sync, stop_internal, validate_safe_component, with_debug};

const LOG_TAIL_CHUNK: u64 = 8192;
const LOG_ROTATE_MAX_BYTES: u64 = 50 * 1024 * 1024;
const LOG_ROTATE_KEEP_LINES: usize = 5000;

/// Args bundle for `cmd_add` — keeps the public function signature short.
pub struct AddArgs<'a> {
    pub name: &'a str,
    pub app_type: &'a str,
    pub cwd: Option<&'a str>,
    pub entry: &'a str,
    pub host: &'a str,
    pub domain: Option<&'a str>,
    pub subdomain: Option<&'a str>,
    pub node_version: Option<&'a str>,
    pub env_vars: &'a [String],
}

pub fn cmd_list(state_dir: &Path, dbg: Option<&Value>) -> ! {
    let names = list_app_names(state_dir);
    let mut apps = Vec::new();

    for name in &names {
        let meta = match load_app_meta(state_dir, name) {
            Ok(m) => m,
            Err(e) => {
                crate::output::debug(format!("skipping '{name}': {e}"));
                continue;
            }
        };
        let (status, pid, started_at) = get_status(state_dir, name);
        let pid_val = pid.map_or(json!(null), |p| json!(p));

        let mut app = json!({
            "name":       name,
            "type":       meta.app_type,
            "status":     status,
            "pid":        pid_val,
            "host":       meta.host,
            "cwd":        meta.cwd,
            "entry":      meta.entry,
            "created_at": meta.created_at,
            "started_at": started_at,
        });
        if !meta.node_version.is_empty() {
            app["node_version"] = json!(meta.node_version);
        }
        apps.push(app);
    }

    success(with_debug(json!({ "apps": apps }), dbg))
}

pub fn cmd_status(state_dir: &Path, name: &str, dbg: Option<&Value>) -> ! {
    if load_app_meta(state_dir, name).is_err() {
        user_error("app_not_found", &format!("app '{name}' not found"));
    }
    let (status, pid, _) = get_status(state_dir, name);
    let pid_val = pid.map_or(json!(null), |p| json!(p));
    success(with_debug(json!({ "status": status, "pid": pid_val }), dbg))
}

pub fn cmd_stop(state_dir: &Path, name: &str, timeout_secs: u64, dbg: Option<&Value>) -> ! {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    let (status, _, _) = get_status(state_dir, name);
    if status == "STOPPED" {
        success(with_debug(json!({}), dbg));
    }

    stop_internal(state_dir, name, &meta, timeout_secs);

    // Clear boot-recovery intent — user explicitly stopped this app.
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.enabled")));

    signal_sync();
    success(with_debug(json!({}), dbg))
}

pub fn cmd_restart(state_dir: &Path, name: &str, web_user: &str, dbg: Option<&Value>) -> ! {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    let (status, _, _) = get_status(state_dir, name);
    if status == "RUNNING" {
        stop_internal(state_dir, name, &meta, 10);
    }

    super::cmd_start(state_dir, name, web_user, None, dbg)
}

pub fn cmd_add(state_dir: &Path, args: &AddArgs<'_>, dbg: Option<&Value>) -> ! {
    let resolved_cwd = args.cwd.map_or_else(
        || {
            state_dir
                .join("apps")
                .join("nodejs")
                .join(args.host)
                .to_string_lossy()
                .into_owned()
        },
        str::to_string,
    );
    let cwd = resolved_cwd.as_str();

    validate_add_args(args, cwd);

    let app_file = state_dir.join(".run").join(format!("{}.app", args.name));
    create_app_file(&app_file, args.name);
    write_app_metadata(&app_file, args, cwd);

    let cwd_path = PathBuf::from(cwd);
    if let Err(e) = std::fs::create_dir_all(&cwd_path) {
        user_error(
            "cwd_create_failed",
            &format!("failed to create cwd directory: {e:#}"),
        );
    }

    if !args.env_vars.is_empty() {
        write_env_file(&cwd_path, args.env_vars);
    }

    if args.app_type == "rust" {
        validate_rust_entry(&cwd_path.join(args.entry));
    } else if args.app_type == "node" {
        scaffold_node_entry(&cwd_path.join(args.entry), args.name);
    }

    success(with_debug(json!({}), dbg))
}

pub fn cmd_set_node_version(
    state_dir: &Path,
    name: &str,
    node_version: &str,
    dbg: Option<&Value>,
) -> ! {
    if load_app_meta(state_dir, name).is_err() {
        user_error("app_not_found", &format!("app '{name}' not found"));
    }
    if !validate_meta_value(node_version) {
        user_error(
            "invalid_node_version",
            "node_version must not contain newlines or null bytes",
        );
    }

    let app_file = state_dir.join(".run").join(format!("{name}.app"));
    let Ok(current) = std::fs::read_to_string(&app_file) else {
        system_error("read_failed", &format!("read {}", app_file.display()));
    };

    let mut found = false;
    let mut new_content = String::with_capacity(current.len() + node_version.len());
    for line in current.lines() {
        if let Some((k, _)) = line.split_once('=')
            && k.trim() == "node_version"
        {
            new_content.push_str(&format!("node_version={node_version}\n"));
            found = true;
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }
    if !found {
        new_content.push_str(&format!("node_version={node_version}\n"));
    }

    if let Err(e) =
        atomic_write(&app_file, new_content.as_bytes()).and_then(|()| set_perm(&app_file, 0o600))
    {
        system_error("write_failed", &format!("{e:#}"));
    }

    // The running process keeps the old runtime until it is restarted.
    let (status, _, _) = get_status(state_dir, name);
    let restart_required = status == "RUNNING";

    success(with_debug(
        json!({ "restart_required": restart_required }),
        dbg,
    ))
}

/// Sets (or clears) an app's memory cap. Stored in the `.app` file and applied
/// on the next start — the running scope keeps its current limit.
/// Writes the cap into the `.app` file. Separate from `cmd_set_memory_max` so
/// the root prelude can persist it *before* re-resolving every sibling's cap.
pub fn apply_memory_max(state_dir: &Path, name: &str, megabytes: u64, uid: u32, gid: u32) {
    if megabytes != 0 && megabytes < 16 {
        return;   // validated (and reported) by cmd_set_memory_max
    }
    let app_file = state_dir.join(".run").join(format!("{name}.app"));
    let Ok(current) = std::fs::read_to_string(&app_file) else {
        return;
    };

    let bytes = megabytes.saturating_mul(1024 * 1024);
    let mut out = String::with_capacity(current.len() + 32);
    for line in current.lines() {
        if line.split_once('=').map(|(k, _)| k.trim()) == Some("memory_max") {
            continue;   // rewritten below (or dropped, when clearing)
        }
        out.push_str(line);
        out.push('\n');
    }
    if bytes > 0 {
        out.push_str(&format!("memory_max={bytes}\n"));
    }
    let _ = atomic_write(&app_file, out.as_bytes()).and_then(|()| set_perm(&app_file, 0o600));
    // This runs as root, so the rewritten file would end up owned by root and
    // become unreadable to the user once privileges are dropped — the command
    // would then fail with `app_not_found` on its own file.
    let _ = crate::state::chown_path(&app_file, uid, gid);
}

pub fn cmd_set_memory_max(state_dir: &Path, name: &str, megabytes: u64, dbg: Option<&Value>) -> ! {
    if load_app_meta(state_dir, name).is_err() {
        user_error("app_not_found", &format!("app '{name}' not found"));
    }
    // 16 MB is below anything a Node process can start in; accepting less would
    // just produce an app that is OOM-killed on boot.
    if megabytes != 0 && megabytes < 16 {
        user_error("invalid_memory_max", "memory cap must be 0 (auto) or at least 16 MB");
    }

    // The write and the cap re-resolution already happened in the root prelude.
    let bytes = megabytes.saturating_mul(1024 * 1024);
    let (status, _, _) = get_status(state_dir, name);
    success(with_debug(
        json!({
            "memory_max": if bytes > 0 { json!(bytes) } else { json!(null) },
            // The new cap is live already; a restart is only needed for the app
            // to *use* more memory, never for the limit to take effect.
            "running": status == "RUNNING",
        }),
        dbg,
    ))
}

pub fn cmd_remove(state_dir: &Path, name: &str, delete_dir: bool, dbg: Option<&Value>) -> ! {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    stop_internal(state_dir, name, &meta, 10);

    let run_dir = state_dir.join(".run");
    for ext in &["app", "pid", "meta", "enabled"] {
        let _ = std::fs::remove_file(run_dir.join(format!("{name}.{ext}")));
    }

    let cwd_path = PathBuf::from(&meta.cwd);

    // Defensive — `stop_internal` already removes these, but on failure we
    // still want the app to disappear from disk.
    let _ = std::fs::remove_file(state_dir.join(".sockets").join(&meta.host));
    let _ = std::fs::remove_file(state_dir.join(".proxy").join(&meta.host));

    if delete_dir {
        // Never delete *through* a link. `remove_dir_all` on a symlinked cwd
        // wipes the target's contents, so an app pointed at a data directory
        // would take it down with it. Re-checked here rather than trusting the
        // stored path, since apps registered before this validation existed can
        // still hold an escaping cwd.
        match std::fs::symlink_metadata(&cwd_path) {
            Ok(md) if md.file_type().is_symlink() => user_error(
                "cwd_is_symlink",
                "refusing to delete a cwd that is a symlink; remove the link manually",
            ),
            Ok(_) => {
                if cwd_escapes_home(&cwd_path) {
                    user_error(
                        "cwd_outside_home",
                        "refusing to delete a cwd outside the user's home directory",
                    );
                }
                let _ = std::fs::remove_dir_all(&cwd_path);
            }
            // Already gone — nothing to delete.
            Err(_) => {}
        }
    } else {
        // Keep user files (.env, logs) when the directory is preserved — only
        // strip files that no longer make sense without the app registration.
        let logs_dir = cwd_path.join("logs");
        let _ = std::fs::remove_file(logs_dir.join(format!("{name}.out.log")));
        let _ = std::fs::remove_file(logs_dir.join(format!("{name}.err.log")));
    }

    signal_sync();
    success(with_debug(json!({}), dbg))
}

/// Receives data pre-loaded as root (before the privilege drop). Each entry is
/// `(domain, subdomain_prefixes)`.
pub fn cmd_domains(data: Vec<(String, Vec<String>)>, dbg: Option<&Value>) -> ! {
    let domains_json: Vec<Value> = data
        .into_iter()
        .map(|(domain, subs)| {
            let subdomains: Vec<Value> = subs
                .iter()
                .map(|sub| json!({ "host": format!("{sub}.{domain}") }))
                .collect();
            json!({ "host": domain, "subdomains": subdomains })
        })
        .collect();

    success(with_debug(json!({ "domains": domains_json }), dbg))
}

pub fn cmd_logs(
    state_dir: &Path,
    name: &str,
    lines: usize,
    use_stderr: bool,
    dbg: Option<&Value>,
) -> ! {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    // Logs are live output: a stopped app has nothing to say. Its file still
    // holds the last run's lines, but showing those would present a finished
    // run as if it were current.
    let (status, _, _) = get_status(state_dir, name);
    if status != "RUNNING" {
        success(with_debug(json!({ "lines": Vec::<String>::new() }), dbg));
    }

    let suffix = if use_stderr { "err" } else { "out" };
    let log_file = PathBuf::from(&meta.cwd)
        .join("logs")
        .join(format!("{name}.{suffix}.log"));

    // Apps commonly log through libraries that colourise unconditionally (Rust's
    // tracing-subscriber, chalk, colorette…). Written to a file those escapes
    // are just bytes, and the panel renders them as literal `[2m`/`[0m` noise,
    // so strip them here — the viewer is HTML, not a terminal.
    let log_lines: Vec<String> = read_tail(&log_file, lines)
        .iter()
        .map(|l| strip_ansi(l))
        .collect();
    success(with_debug(json!({ "lines": log_lines }), dbg))
}

/// Removes ANSI escape sequences (CSI/OSC and the shorter two-byte forms) from
/// `s`, leaving the plain text.
pub(super) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // CSI: params/intermediates, then a final byte in @..~
            Some('[') => {
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: runs until BEL or the ST sequence (ESC \).
            Some(']') => {
                let mut prev_esc = false;
                for c in chars.by_ref() {
                    if c == '\x07' || (prev_esc && c == '\\') {
                        break;
                    }
                    prev_esc = c == '\x1b';
                }
            }
            // Two-byte escapes (ESC c, ESC =, …): drop both.
            Some(_) => {}
            None => break,
        }
    }
    out
}

/// Efficient tail: reads back from EOF in `LOG_TAIL_CHUNK`-sized blocks until
/// at least `n` newlines have been seen, then returns the last `n` lines.
pub(super) fn read_tail(path: &Path, n: usize) -> Vec<String> {
    if n == 0 {
        return Vec::new();
    }

    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };

    let Ok(size) = file.seek(SeekFrom::End(0)) else {
        return Vec::new();
    };

    if size == 0 {
        return Vec::new();
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut newlines: usize = 0;
    let mut cursor = size;

    while cursor > 0 && newlines <= n {
        let to_read = LOG_TAIL_CHUNK.min(cursor);
        cursor -= to_read;

        if file.seek(SeekFrom::Start(cursor)).is_err() {
            break;
        }
        let Ok(to_read_usize) = usize::try_from(to_read) else {
            break;
        };
        let mut chunk = vec![0u8; to_read_usize];
        if file.read_exact(&mut chunk).is_err() {
            break;
        }

        #[allow(clippy::naive_bytecount)]
        let chunk_newlines = chunk.iter().filter(|&&b| b == b'\n').count();
        newlines += chunk_newlines;

        chunk.extend_from_slice(&buf);
        buf = chunk;
    }

    let s = String::from_utf8_lossy(&buf);
    let lines: Vec<String> = s.lines().map(str::to_owned).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].to_vec()
}

/// Truncates a log file to the last `LOG_ROTATE_KEEP_LINES` lines when it
/// grows past `LOG_ROTATE_MAX_BYTES`.
pub(super) fn rotate_log_if_needed(path: &Path) {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size <= LOG_ROTATE_MAX_BYTES {
        return;
    }
    crate::output::debug(format!("rotating log {} ({size} bytes)", path.display()));

    let lines = read_tail(path, LOG_ROTATE_KEEP_LINES);
    let content = lines.join("\n") + "\n";
    let _ = atomic_write(path, content.as_bytes());
}

fn validate_add_args(args: &AddArgs<'_>, cwd: &str) {
    if !validate_name(args.name) {
        user_error("invalid_name", "name must match ^[A-Za-z0-9._-]{1,64}$");
    }
    if !validate_safe_component(args.entry) {
        user_error(
            "invalid_entry",
            "entry must not contain '/', '..' or null bytes",
        );
    }
    if !validate_safe_component(args.host) {
        user_error(
            "invalid_host",
            "host must not contain '/', '..' or null bytes",
        );
    }
    // These land verbatim in the line-oriented `.app` file — a newline would
    // let a value forge extra metadata keys.
    for (field, value) in [
        ("cwd", cwd),
        ("domain", args.domain.unwrap_or("")),
        ("subdomain", args.subdomain.unwrap_or("")),
        ("node_version", args.node_version.unwrap_or("")),
    ] {
        if !validate_meta_value(value) {
            user_error(
                &format!("invalid_{field}"),
                &format!("{field} must not contain newlines or null bytes"),
            );
        }
    }
    validate_cwd_within_home(cwd);
}

/// True when `path` resolves outside `$HOME` (or cannot be resolved at all).
/// Used on the delete path, where failing closed is the safe default.
fn cwd_escapes_home(path: &Path) -> bool {
    let Ok(home) = std::env::var("HOME") else {
        return true;
    };
    let (Ok(home_real), Ok(target)) = (
        std::fs::canonicalize(&home),
        std::fs::canonicalize(path),
    ) else {
        return true;
    };
    !target.starts_with(&home_real)
}

/// Rejects a `cwd` that escapes the user's home directory.
///
/// Two ways out existed. A plain path elsewhere (`/tmp/app`) put the code in a
/// world-writable place, where any other account could swap the entry file that
/// then runs as this user. And a symlink under the home pointing outside it was
/// followed by both `add` (writing `.env` and the entry through it) and by
/// `remove --delete-dir`, whose `remove_dir_all` deletes the *target's*
/// contents — a confirmed way to destroy files the app never owned.
///
/// So the check resolves symlinks on every existing ancestor and demands the
/// result stay under `$HOME`.
fn validate_cwd_within_home(cwd: &str) {
    let home = match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => h,
        _ => user_error("cwd_outside_home", "HOME is not set; cannot validate cwd"),
    };
    match check_cwd_within_home(cwd, Path::new(&home)) {
        Ok(()) => {}
        Err(CwdError::NotAbsolute) => user_error("invalid_cwd", "cwd must be an absolute path"),
        Err(CwdError::Unresolvable) => user_error("invalid_cwd", "cwd could not be resolved"),
        Err(CwdError::Outside { resolved, home }) => user_error(
            "cwd_outside_home",
            &format!("cwd must stay inside {home} (resolved to {resolved})"),
        ),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CwdError {
    NotAbsolute,
    Unresolvable,
    Outside { resolved: String, home: String },
}

/// Resolves `cwd` (following symlinks on every existing ancestor) and checks it
/// lands inside `home`. Split from `validate_cwd_within_home` so the decision is
/// testable without the process-exiting error path.
pub(super) fn check_cwd_within_home(cwd: &str, home: &Path) -> Result<(), CwdError> {
    let home_real = std::fs::canonicalize(home).map_err(|_| CwdError::Unresolvable)?;

    let path = PathBuf::from(cwd);
    if !path.is_absolute() {
        return Err(CwdError::NotAbsolute);
    }

    // The leaf usually doesn't exist yet (add creates it), so canonicalize the
    // deepest existing ancestor and re-append the remainder. Any symlink along
    // the way is resolved by that call.
    let mut existing = path.as_path();
    let mut rest = Vec::new();
    let resolved = loop {
        if let Ok(c) = std::fs::canonicalize(existing) {
            break c.join(rest.iter().rev().collect::<PathBuf>());
        }
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name.to_os_string());
                existing = parent;
            }
            _ => return Err(CwdError::Unresolvable),
        }
    };

    if resolved.starts_with(&home_real) {
        Ok(())
    } else {
        Err(CwdError::Outside {
            resolved: resolved.display().to_string(),
            home: home_real.display().to_string(),
        })
    }
}

/// Values written into the `key=value` `.app` file must stay on one line.
fn validate_meta_value(value: &str) -> bool {
    !value.contains('\n') && !value.contains('\r') && !value.contains('\0')
}

/// Creates the `.app` file with `create_new` so a concurrent caller cannot win
/// a TOCTOU race against the existence check + write.
fn create_app_file(app_file: &Path, name: &str) {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(app_file)
    {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            user_error("app_exists", &format!("app '{name}' already exists"));
        }
        Err(e) => {
            system_error(
                "write_failed",
                &format!("create {}: {e:#}", app_file.display()),
            );
        }
    }
}

fn write_app_metadata(app_file: &Path, args: &AddArgs<'_>, cwd: &str) {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let content = format!(
        "type={t}\ncwd={cwd}\nentry={entry}\nhost={host}\ndomain={d}\nsubdomain={s}\nnode_version={nv}\ncreated_at={created_at}\n",
        t = args.app_type,
        entry = args.entry,
        host = args.host,
        d = args.domain.unwrap_or(""),
        s = args.subdomain.unwrap_or(""),
        nv = args.node_version.unwrap_or(""),
    );

    if let Err(e) =
        atomic_write(app_file, content.as_bytes()).and_then(|()| set_perm(app_file, 0o600))
    {
        system_error("write_failed", &format!("{e:#}"));
    }
}

fn write_env_file(cwd_path: &Path, env_vars: &[String]) {
    let env_file = cwd_path.join(".env");
    let env_content = env_vars.join("\n") + "\n";
    if let Err(e) =
        atomic_write(&env_file, env_content.as_bytes()).and_then(|()| set_perm(&env_file, 0o600))
    {
        system_error("write_failed", &format!("{e:#}"));
    }
}

/// Skipped silently when the file does not exist yet — callers may register an
/// app before placing the binary.
fn validate_rust_entry(entry_path: &Path) {
    if !entry_path.exists() {
        return;
    }
    if !is_executable_file(entry_path) {
        user_error(
            "entry_not_executable",
            &format!("file '{}' is not executable", entry_path.display()),
        );
    }
    if !is_elf(entry_path) {
        user_error(
            "entry_not_elf",
            &format!("file '{}' is not a valid ELF binary", entry_path.display()),
        );
    }
}

/// Drops a Node.js scaffold template at `entry_path` when the file is missing
/// and the plugin ships a template at `{plugin}/templates/node/index.js`.
fn scaffold_node_entry(entry_path: &Path, name: &str) {
    if entry_path.exists() {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Some(plugin_dir) = exe.parent().and_then(Path::parent) else {
        return;
    };
    let template = plugin_dir.join("templates/node/index.js");
    if let Ok(tpl) = std::fs::read_to_string(&template) {
        let rendered = tpl.replace("{{APP_NAME}}", name);
        let _ = std::fs::write(entry_path, rendered.as_bytes());
    }
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
}

/// Checks the ELF magic number (`\x7fELF`) on the first 4 bytes of the file.
fn is_elf(path: &Path) -> bool {
    let mut buf = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok_and(|()| buf == [0x7f, b'E', b'L', b'F'])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an isolated home under the OS temp dir: `<tmp>/selynt-test-<n>/home`
    /// plus a sibling `outside/` to point escapes at.
    fn sandbox(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("selynt-test-{tag}-{}", std::process::id()));
        let home = base.join("home");
        let outside = base.join("outside");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(home.join("apps")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        (home, outside)
    }

    #[test]
    fn accepts_cwd_inside_home() {
        let (home, _) = sandbox("inside");
        let cwd = home.join("apps/myapp");
        assert_eq!(check_cwd_within_home(cwd.to_str().unwrap(), &home), Ok(()));
    }

    #[test]
    fn accepts_cwd_that_does_not_exist_yet() {
        // `add` creates the directory afterwards, so a missing leaf is normal.
        let (home, _) = sandbox("missing");
        let cwd = home.join("apps/deep/not/created/yet");
        assert_eq!(check_cwd_within_home(cwd.to_str().unwrap(), &home), Ok(()));
    }

    #[test]
    fn rejects_cwd_outside_home() {
        let (home, outside) = sandbox("outside");
        let cwd = outside.join("app");
        assert!(matches!(
            check_cwd_within_home(cwd.to_str().unwrap(), &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn rejects_dotdot_traversal_out_of_home() {
        let (home, _) = sandbox("dotdot");
        let cwd = format!("{}/apps/../../outside/app", home.display());
        assert!(matches!(
            check_cwd_within_home(&cwd, &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn keeps_dotdot_that_stays_inside_home() {
        let (home, _) = sandbox("dotdot-ok");
        let cwd = format!("{}/apps/../apps/myapp", home.display());
        assert_eq!(check_cwd_within_home(&cwd, &home), Ok(()));
    }

    /// The vector that destroyed data: a link under the home whose target is
    /// elsewhere. `remove --delete-dir` would wipe the target's contents.
    #[test]
    fn rejects_symlink_pointing_outside_home() {
        let (home, outside) = sandbox("symlink");
        let link = home.join("apps/escape");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(matches!(
            check_cwd_within_home(link.to_str().unwrap(), &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn rejects_symlinked_ancestor_pointing_outside_home() {
        // The link is mid-path, not the leaf — canonicalize must still catch it.
        let (home, outside) = sandbox("symlink-mid");
        let link = home.join("apps/bridge");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let cwd = link.join("nested/app");
        assert!(matches!(
            check_cwd_within_home(cwd.to_str().unwrap(), &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn accepts_symlink_that_stays_within_home() {
        let (home, _) = sandbox("symlink-in");
        let target = home.join("apps/real");
        std::fs::create_dir_all(&target).unwrap();
        let link = home.join("apps/alias");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(check_cwd_within_home(link.to_str().unwrap(), &home), Ok(()));
    }

    #[test]
    fn rejects_relative_cwd() {
        let (home, _) = sandbox("relative");
        assert_eq!(
            check_cwd_within_home("apps/myapp", &home),
            Err(CwdError::NotAbsolute)
        );
    }

    /// `/home/user2` must not pass just because it shares a textual prefix with
    /// `/home/user` — starts_with on components, not on the raw string.
    #[test]
    fn rejects_sibling_home_with_shared_prefix() {
        let base = std::env::temp_dir().join(format!("selynt-test-prefix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("user");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(base.join("user2")).unwrap();
        let cwd = base.join("user2/app");
        assert!(matches!(
            check_cwd_within_home(cwd.to_str().unwrap(), &home),
            Err(CwdError::Outside { .. })
        ));
    }

    #[test]
    fn validate_safe_component_blocks_traversal() {
        assert!(super::super::validate_safe_component("index.js"));
        assert!(!super::super::validate_safe_component("../etc/passwd"));
        assert!(!super::super::validate_safe_component("a/b"));
        assert!(!super::super::validate_safe_component(""));
        assert!(!super::super::validate_safe_component("a\0b"));
    }

    #[test]
    fn validate_meta_value_blocks_forged_keys() {
        assert!(validate_meta_value("/home/user/apps/x"));
        assert!(!validate_meta_value("x\nhost=evil"));
        assert!(!validate_meta_value("x\rhost=evil"));
        assert!(!validate_meta_value("x\0y"));
    }
}
