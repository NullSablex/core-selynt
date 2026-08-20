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

    super::cmd_start(state_dir, name, web_user, dbg)
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
        let _ = std::fs::remove_dir_all(&meta.cwd);
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

    let suffix = if use_stderr { "err" } else { "out" };
    let log_file = PathBuf::from(&meta.cwd)
        .join("logs")
        .join(format!("{name}.{suffix}.log"));

    let log_lines = read_tail(&log_file, lines);
    success(with_debug(json!({ "lines": log_lines }), dbg))
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
