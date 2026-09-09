use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde_json::{Value, json};

use crate::sys::fs::{atomic_write, set_perm};
use crate::sys::output::{debug, success, user_error};
use crate::sys::state::{AppMeta, list_app_names, load_app_meta};

use super::logs::{read_tail, strip_ansi};
use super::validate::{
    cwd_escapes_home, scaffold_node_entry, validate_add_args, validate_meta_value,
    validate_rust_entry, write_env_file,
};
use super::{get_status, signal_sync, stop_internal, with_debug};
use crate::runtime::kind::Runtime;

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
                crate::sys::output::debug(format!("skipping '{name}': {e}"));
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

/// Restarts an app.
///
/// The stop and the respawn both happen while still root — see `plan`. What is
/// left here is the readiness path `start` takes, so a restart is reported the
/// same way: only once the app is answering. `spawned_pid` is `None` when there
/// was nothing to launch, and `cmd_start` then spawns it directly.
pub fn cmd_restart(
    state_dir: &Path,
    name: &str,
    username: &str,
    web_user: &str,
    spawned_pid: Option<u32>,
    dbg: Option<&Value>,
) -> ! {
    if load_app_meta(state_dir, name).is_err() {
        user_error("app_not_found", &format!("app '{name}' not found"));
    }

    super::start::cmd_start(state_dir, name, username, web_user, spawned_pid, dbg)
}

pub fn cmd_add(state_dir: &Path, args: &AddArgs<'_>, dbg: Option<&Value>) -> ! {
    // The prelude resolved and checked this already, and wrote it into the
    // `.app` file. Reading it back is what keeps the two from disagreeing:
    // duplicating the default here is how the old one drifted into pointing
    // outside the home, where the check would then refuse it.
    let resolved_cwd = crate::sys::state::load_app_meta(state_dir, args.name)
        .map_or_else(|_| args.cwd.unwrap_or_default().to_string(), |m| m.cwd);
    let cwd = resolved_cwd.as_str();

    validate_add_args(args, cwd);

    // The `.app` file was already written by the root prelude, which owns it:
    // it is the only piece of state that says what to execute, so the account
    // must not be able to forge one. See `app::appfile`.

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

    // Unknown types are rejected before reaching here (clap parses them into
    // AppType), so an unparseable value means metadata written by hand.
    if let Ok(rt) = Runtime::from_str(args.app_type) {
        let entry_path = cwd_path.join(args.entry);
        if rt.scaffolds_entry() {
            scaffold_node_entry(&entry_path, args.name);
        }
        if rt.requires_executable_entry() {
            validate_rust_entry(&entry_path);
        }
    }

    success(with_debug(json!({}), dbg))
}

/// Reports whether this account isolates its apps, and which are running.
pub fn cmd_status_isolated(state_dir: &Path, dbg: Option<&Value>) -> ! {
    // `supported` is separate from `isolated` on purpose: the first says
    // whether this host can isolate at all, the second whether the account
    // asked for it. Reporting only the preference would let the panel claim
    // isolation on a host that cannot provide it.
    let supported = crate::limits::sandbox::available();

    success(with_debug(
        json!({
            "isolated": crate::sys::state::account_is_isolated(state_dir),
            "supported": supported,
            "reason": (!supported).then(crate::limits::sandbox::unavailable_reason),
            "running": running_app_names(state_dir),
        }),
        dbg,
    ))
}

/// Switches the account's isolation mode and restarts its running apps.
///
/// Not per-app on purpose: a namespace confines what the process inside sees
/// but does not change its uid, so a non-isolated sibling could still read an
/// isolated app's files. It only means anything covering the whole account.
///
/// Runs as root — recreating each systemd scope is privileged, and an app keeps
/// the mode it launched with until restarted. Returns the apps that came back
/// up, and those that did not.
pub fn switch_isolation(
    state_dir: &Path,
    username: &str,
    isolated: bool,
) -> Result<IsolationSwitch, (String, String)> {
    // Refuse rather than accept a setting this host cannot honour. Storing it
    // anyway would leave the panel reporting isolation that is not in effect,
    // which is worse than not offering it: the account would believe its apps
    // are separated while they still share everything.
    if isolated && !crate::limits::sandbox::available() {
        return Err((
            "sandbox_unavailable".into(),
            crate::limits::sandbox::unavailable_reason().to_string(),
        ));
    }

    let flag = state_dir.join("isolated");
    let value = if isolated { "1\n" } else { "0\n" };
    atomic_write(&flag, value.as_bytes())
        .and_then(|()| set_perm(&flag, 0o644))
        .map_err(|e| ("write_failed".to_string(), format!("{e:#}")))?;

    // `admin_get_status`, not `get_status`: the latter requires the process uid
    // to match the caller's, and this runs as root, where it never does.
    let run = state_dir.join(".run");
    let running: Vec<String> = list_app_names(state_dir)
        .into_iter()
        .filter(|n| {
            super::admin_get_status(
                &run.join(format!("{n}.pid")),
                &run.join(format!("{n}.meta")),
            )
            .0 == "RUNNING"
        })
        .collect();

    let mut switch = IsolationSwitch::default();
    for name in running {
        let Ok(meta) = load_app_meta(state_dir, &name) else {
            continue;
        };
        crate::limits::netguard::stop_app_tree(state_dir, &name, &meta);

        // Applying the new mode means stopping the app first, so a failed
        // restart leaves it down. Reporting only the successes would have the
        // panel announce the switch worked while the app it just took down
        // never came back — the account would find it stopped with no clue why.
        if super::start_app_detached(username, &name) {
            switch.restarted.push(name);
        } else {
            switch.failed.push(name);
        }
    }

    Ok(switch)
}

/// Outcome of an isolation switch: the apps that came back up, and those that
/// stayed down after being stopped to apply it.
#[derive(Default)]
pub struct IsolationSwitch {
    pub restarted: Vec<String>,
    pub failed: Vec<String>,
}

/// Names of the account's apps that are currently running.
pub fn running_app_names(state_dir: &Path) -> Vec<String> {
    list_app_names(state_dir)
        .into_iter()
        .filter(|n| get_status(state_dir, n).0 == "RUNNING")
        .collect()
}

/// Reports the new isolation mode and which apps were restarted to apply it.
///
/// The switch itself — writing the flag and restarting the apps — happens in
/// the root prelude: applying it means recreating each app's systemd scope,
/// which needs privileges this side of the drop no longer has.
pub fn cmd_set_isolated(isolated: bool, switch: &IsolationSwitch, dbg: Option<&Value>) -> ! {
    success(with_debug(
        json!({
            "isolated": isolated,
            "restarted": switch.restarted,
            "failed": switch.failed,
        }),
        dbg,
    ))
}

/// Por que o `entry` não pode ser aceito, ou `Ok(())`.
///
/// Usada pelo prelúdio root *antes* de gravar o `.app` e pelo comando depois da
/// queda de privilégio: uma regra só, para os dois lados não discordarem sobre
/// o que é aceitável.
pub fn entry_refusal(state_dir: &Path, name: &str, entry: &str) -> Result<(), (String, String)> {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        return Err(("app_not_found".into(), format!("app '{name}' not found")));
    };
    if !super::validate_safe_component(entry) {
        return Err((
            "invalid_entry".into(),
            "entry must not contain '/', '..' or null bytes".into(),
        ));
    }
    // Apontar para um arquivo inexistente deixaria a aplicação sem subir, e o
    // erro só apareceria no próximo start — longe de onde a escolha foi feita.
    if !PathBuf::from(&meta.cwd).join(entry).is_file() {
        return Err((
            "entry_not_found".into(),
            format!("file '{entry}' not found in the application directory"),
        ));
    }
    Ok(())
}

/// Troca o arquivo de entrada da aplicação.
///
/// O `entry` era decidido na criação e ficava assim para sempre: quem escolheu
/// `index.js` e depois migrou para `app.mjs`, ou de JavaScript para TypeScript,
/// não tinha como dizer isso ao painel — só recriando a aplicação.
///
/// Recusa arquivo que não existe. O caminho é resolvido dentro do diretório da
/// aplicação, e a validação é a mesma do `add`: sem `/`, sem `..`, sem bytes
/// nulos — o valor vai para o `.app`, que é lido linha a linha, e uma quebra de
/// linha ali forjaria outras chaves.
pub fn cmd_set_entry(state_dir: &Path, name: &str, entry: &str, dbg: Option<&Value>) -> ! {
    // Já recusado no prelúdio, antes da gravação; repetido aqui porque o comando
    // não pode depender de quem o chamou ter feito a verificação.
    if let Err((code, msg)) = entry_refusal(state_dir, name, entry) {
        user_error(&code, &msg);
    }

    // Escrito pelo prelúdio root — a conta não altera o `.app` por conta própria.

    // O processo em execução continua com o arquivo antigo até reiniciar.
    let (status, _, _) = get_status(state_dir, name);
    let restart_required = status == "RUNNING";

    success(with_debug(
        json!({ "entry": entry, "restart_required": restart_required }),
        dbg,
    ));
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

    // Written by the root prelude — the account cannot modify `.app` itself.

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
pub fn apply_memory_max(state_dir: &Path, name: &str, megabytes: u64, gid: u32) {
    if megabytes != 0 && megabytes < 16 {
        return; // validated (and reported) by cmd_set_memory_max
    }
    let app_file = state_dir.join(".run").join(format!("{name}.app"));
    let Ok(current) = std::fs::read_to_string(&app_file) else {
        return;
    };

    let bytes = megabytes.saturating_mul(1024 * 1024);
    let mut out = String::with_capacity(current.len() + 32);
    for line in current.lines() {
        if line.split_once('=').map(|(k, _)| k.trim()) == Some("memory_max") {
            continue; // rewritten below (or dropped, when clearing)
        }
        out.push_str(line);
        out.push('\n');
    }
    if bytes > 0 {
        let _ = writeln!(out, "memory_max={bytes}");
    }
    // Through `write_as_root`, like every other `.app` write: the file has to
    // stay root-owned or `load_app_meta` refuses it, and the app vanishes from
    // the panel while its process keeps running. Writing it as the account —
    // which this once did, to keep it readable after the drop — is exactly what
    // the ownership check exists to reject.
    if let Err(e) = super::appfile::write_as_root(&app_file, &out, gid) {
        debug(format!("apply_memory_max '{name}': {e}"));
    }
}

pub fn cmd_set_memory_max(state_dir: &Path, name: &str, megabytes: u64, dbg: Option<&Value>) -> ! {
    if load_app_meta(state_dir, name).is_err() {
        user_error("app_not_found", &format!("app '{name}' not found"));
    }
    // 16 MB is below anything a Node process can start in; accepting less would
    // just produce an app that is OOM-killed on boot.
    if megabytes != 0 && megabytes < 16 {
        user_error(
            "invalid_memory_max",
            "memory cap must be 0 (auto) or at least 16 MB",
        );
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

/// Erases everything the panel recorded about an app: run state, sockets and
/// the proxy marker.
///
/// `stop_internal` already removed the live socket, but on failure the app
/// still has to disappear from disk. Both socket paths are cleared: they differ
/// when the account switched isolation mode while the app was down, and neither
/// may be left behind.
fn remove_run_state(state_dir: &Path, name: &str, meta: &AppMeta) {
    // Read while `.meta` is still around — that is what records where the
    // socket really is.
    let active_socket = crate::sys::state::active_socket_path(state_dir, meta);

    let run_dir = state_dir.join(".run");
    // `job` e `job.log` guardam a última execução npm: sem removê-los aqui, um
    // app recriado com o mesmo nome herdaria o resultado do anterior.
    for ext in &["pid", "meta", "enabled", "job", "job.log"] {
        let _ = std::fs::remove_file(run_dir.join(format!("{name}.{ext}")));
    }

    let _ = std::fs::remove_file(&active_socket);
    let _ = std::fs::remove_file(crate::sys::state::socket_path_for(state_dir, meta));
    let _ = std::fs::remove_dir(state_dir.join(".sockets").join(name));
    let _ = std::fs::remove_file(state_dir.join(".proxy").join(&meta.host));
}

pub fn cmd_remove(
    state_dir: &Path,
    name: &str,
    delete_dir: bool,
    meta: Option<AppMeta>,
    dbg: Option<&Value>,
) -> ! {
    // The prelude removed the root-owned `.app` and handed the metadata over,
    // since the account cannot delete that file itself.
    let Some(meta) = meta else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    stop_internal(state_dir, name, &meta, 10);

    remove_run_state(state_dir, name, &meta);

    let cwd_path = PathBuf::from(&meta.cwd);

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

/// Lists the `scripts` entries of the app's `package.json`.
///
/// Read-only, and deliberately narrow. The file belongs to the account and is
/// read after the privilege drop, so this can see exactly what the account can
/// see — a symlink pointing elsewhere resolves with the account's rights, not
/// root's.
///
/// Only the names reach the caller, never the command bodies. A script body is
/// arbitrary shell written by the customer; echoing it into a web page invites
/// the panel to render someone's `rm -rf` as if the panel endorsed it, and the
/// panel has no reason to display it. Names are filtered to what npm can be
/// asked to run without a shell reinterpreting it.
pub fn cmd_scripts(state_dir: &Path, name: &str, dbg: Option<&Value>) -> ! {
    let Ok(meta) = load_app_meta(state_dir, name) else {
        user_error("app_not_found", &format!("app '{name}' not found"));
    };

    if meta.app_type != "node" {
        success(with_debug(
            json!({ "scripts": Vec::<String>::new(), "deps": "unknown", "reason": "not_node" }),
            dbg,
        ));
    }

    let pkg = PathBuf::from(&meta.cwd).join("package.json");
    let Ok(raw) = std::fs::read_to_string(&pkg) else {
        success(with_debug(
            json!({ "scripts": Vec::<String>::new(), "deps": "unknown", "reason": "no_package_json" }),
            dbg,
        ));
    };

    // A malformed package.json is the customer's to fix; say so instead of
    // reporting "no scripts", which would read as if the file were fine.
    let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
        success(with_debug(
            json!({ "scripts": Vec::<String>::new(), "deps": "unknown", "reason": "invalid_package_json" }),
            dbg,
        ));
    };

    let mut names: Vec<String> = parsed
        .get("scripts")
        .and_then(Value::as_object)
        .map(|m| {
            m.keys()
                .filter(|k| is_safe_script_name(k))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    names.sort();

    let deps = dependency_state(Path::new(&meta.cwd), &parsed);
    success(with_debug(json!({ "scripts": names, "deps": deps }), dbg));
}

/// Whether a `package.json` script name is safe to hand to `npm run`.
///
/// npm itself allows almost anything as a key. This is the boundary where a
/// name stops being data and becomes part of a command, so it is kept to what
/// cannot be mistaken for an option, a path or shell syntax: leading `-` would
/// be read as a flag, and the rest keeps quoting and traversal out.
pub(super) fn is_safe_script_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-' | '.'))
}

#[cfg(test)]
mod script_name_tests {
    use super::is_safe_script_name;

    #[test]
    fn accepts_names_npm_projects_actually_use() {
        for n in [
            "start",
            "build",
            "test",
            "dev",
            "lint:fix",
            "build_prod",
            "db.migrate",
            "pre-build",
        ] {
            assert!(is_safe_script_name(n), "{n} should be accepted");
        }
    }

    /// The name is about to become part of a command line. These are the shapes
    /// that stop being data at that point.
    #[test]
    fn refuses_names_that_would_leave_the_argument() {
        for n in [
            "",                 // nothing to run
            "-x",               // reads as an option to npm
            "--prefix",         // same, long form
            "a b",              // splits into two arguments
            "build; rm -rf /",  // command separator
            "build && curl x",  // chaining
            "build | sh",       // pipe
            "$(id)",            // command substitution
            "`id`",             // command substitution, backticks
            "build\nrm",        // newline
            "../../etc/passwd", // traversal
            "a/b",              // path separator
            "build'",           // quote
        ] {
            assert!(!is_safe_script_name(n), "{n:?} should be refused");
        }
    }

    #[test]
    fn refuses_absurdly_long_names() {
        assert!(!is_safe_script_name(&"a".repeat(65)));
        assert!(is_safe_script_name(&"a".repeat(64)));
    }
}

/// State of the app's dependencies, decided without running npm.
///
/// `npm ls` would answer this too, but it needs npm on `PATH` — which under the
/// panel's CGI does not carry `/usr/local/bin` — and costs a second. Comparing
/// files is both faster and immune to the environment.
///
/// Deliberately not resolving semver ranges: whether `^2.1.3` is satisfied by
/// what is on disk is npm's call, and guessing produces confident wrong answers.
fn dependency_state(cwd: &Path, pkg: &Value) -> &'static str {
    let declared: Vec<&String> = ["dependencies", "devDependencies"]
        .iter()
        .filter_map(|k| pkg.get(*k))
        .filter_map(Value::as_object)
        .flat_map(serde_json::Map::keys)
        .collect();

    if declared.is_empty() {
        return "none";
    }
    if !cwd.join("node_modules").is_dir() {
        return "missing";
    }

    // The lockfile names every directory that should exist. Without one there
    // is nothing to compare against, so a present `node_modules` is taken at
    // face value rather than reported as a problem that may not exist.
    let Ok(raw) = std::fs::read_to_string(cwd.join("package-lock.json")) else {
        return "ok";
    };
    let Ok(lock) = serde_json::from_str::<Value>(&raw) else {
        return "ok";
    };
    let Some(entries) = lock.get("packages").and_then(Value::as_object) else {
        return "ok";
    };

    let mut locked = Vec::new();
    for path in entries.keys() {
        let Some(rel) = path.strip_prefix("node_modules/") else {
            continue;
        };
        locked.push(rel);
        if !cwd.join(path).is_dir() {
            return "incomplete";
        }
    }

    if declared.iter().any(|d| !locked.contains(&d.as_str())) {
        return "outdated";
    }

    "ok"
}

/// Why an argument typed in the panel must not reach a command line, or `None`.
///
/// Commands are built with `Command::new` and an argument array, never through
/// a shell, so `;`, `&&` and `$(…)` are already inert — they arrive as literal
/// characters in a single argument. This check is not about that.
///
/// It is about the two things an array cannot prevent:
///
/// - an argument that starts with `-` is read as an *option* by whatever runs,
///   and `npm --prefix /elsewhere` or `node --experimental-…` change what the
///   command does rather than what it operates on;
/// - a path leaving the application, which the sandbox blocks at the mount
///   level but which should never be composed in the first place.
///
/// Everything else is left alone: an argument is data the customer chose, and
/// refusing legitimate values teaches people to work around the panel.
///
/// Written before the execution command that will call it: this is the boundary
/// where a value stops being data, and it should exist — and be tested — before
/// anything is able to run.
#[allow(
    dead_code,
    reason = "boundary for the execution command, added first on purpose"
)]
pub fn argument_refusal(arg: &str) -> Option<String> {
    if arg.is_empty() {
        return None;
    }
    if arg.len() > 256 {
        return Some("argument is too long".to_string());
    }
    if arg.chars().any(char::is_control) {
        return Some("argument contains control characters".to_string());
    }
    if arg.starts_with('-') {
        return Some(format!(
            "argument {arg:?} would be read as an option; the panel only passes values"
        ));
    }
    if arg.contains("..") || arg.starts_with('/') {
        return Some(format!(
            "argument {arg:?} points outside the application directory"
        ));
    }
    None
}

/// Splits the argument string typed in the panel into individual arguments.
///
/// Whitespace-separated, with no quoting rules of its own. Supporting quotes
/// here would mean reimplementing a shell parser — and a half-correct shell
/// parser is exactly how arguments start meaning something the user did not
/// write. Anyone needing that has SSH.
#[allow(
    dead_code,
    reason = "boundary for the execution command, added first on purpose"
)]
pub fn split_arguments(raw: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for a in raw.split_whitespace() {
        if let Some(err) = argument_refusal(a) {
            return Err(err);
        }
        out.push(a.to_string());
    }
    if out.len() > 32 {
        return Err("too many arguments".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod argument_tests {
    use super::{argument_refusal, split_arguments};

    #[test]
    fn accepts_plain_values() {
        for a in ["production", "dist/index.js", "3000", "test.spec.ts"] {
            assert!(argument_refusal(a).is_none(), "{a} should be accepted");
        }
    }

    /// The panel passes values, not options: an argument that turns into a flag
    /// changes what the command does.
    #[test]
    fn refuses_arguments_that_would_be_read_as_options() {
        for a in ["-x", "--prefix", "--experimental-vm-modules", "-C"] {
            assert!(argument_refusal(a).is_some(), "{a} should be refused");
        }
    }

    #[test]
    fn refuses_paths_leaving_the_application() {
        for a in ["../secret", "/etc/passwd", "a/../../b"] {
            assert!(argument_refusal(a).is_some(), "{a} should be refused");
        }
    }

    /// Shell metacharacters are inert because nothing goes through a shell, but
    /// they must not be silently dropped either: they arrive as one argument.
    #[test]
    fn shell_metacharacters_stay_a_single_literal_argument() {
        let args = split_arguments("build;rm").unwrap();
        assert_eq!(args, vec!["build;rm"]);
    }

    #[test]
    fn splits_on_whitespace_and_refuses_the_bad_one() {
        assert_eq!(split_arguments("a b c").unwrap(), vec!["a", "b", "c"]);
        assert!(split_arguments("ok --evil").is_err());
        assert!(split_arguments("").unwrap().is_empty());
    }

    #[test]
    fn refuses_absurd_counts_and_lengths() {
        assert!(split_arguments(&"a ".repeat(33)).is_err());
        assert!(argument_refusal(&"a".repeat(257)).is_some());
    }
}
