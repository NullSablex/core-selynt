mod acl;
mod cmd;
mod output;
mod proc;
mod state;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

use std::path::{Path, PathBuf};

use output::system_error;
use state::{
    drop_privileges, init_app_logs_dir, init_state_dir, load_app_meta, resolve_target_user,
};

const STATE_BASE: &str = "/var/lib/selynt_panel";
const DA_USERS_BASE: &str = "/usr/local/directadmin/data/users";

#[derive(Parser)]
#[command(
    name = "core_selynt",
    version,
    about = "Selynt Panel — process manager"
)]
struct Cli {
    /// Enable debug mode: adds `_debug` to the JSON output.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Lists every registered app.
    List,

    /// Shows status (RUNNING/STOPPED) and PID of an app.
    Status { name: String },

    /// Starts an app.
    Start { name: String },

    /// Stops an app.
    Stop {
        name: String,
        /// Seconds to wait before SIGKILL (default: 10).
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },

    /// Restarts an app (stop + start).
    Restart { name: String },

    /// Registers a new app.
    Add {
        name: String,
        #[arg(long = "type", value_enum)]
        app_type: AppType,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        entry: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        subdomain: Option<String>,
        /// Path to a `node` binary (e.g. `/usr/local/bin/node`). Uses `PATH` if omitted.
        #[arg(long)]
        node_version: Option<String>,
        /// Environment variable, in `KEY=VAL` form (repeatable).
        #[arg(long = "env", value_name = "KEY=VAL")]
        env_vars: Vec<String>,
    },

    /// Removes an app (stops it first if running).
    Remove {
        name: String,
        /// Also delete the app's `cwd` directory.
        #[arg(long)]
        delete_dir: bool,
    },

    /// Updates the Node.js runtime path of an existing app.
    SetNodeVersion {
        name: String,
        /// Path to a `node` binary (e.g. `/usr/local/bin/node`).
        #[arg(long)]
        node_version: String,
    },

    /// Prints the last lines of an app's log.
    Logs {
        name: String,
        /// Number of lines to read (default: 100).
        #[arg(long, default_value_t = 100)]
        lines: usize,
        /// Read stderr instead of stdout.
        #[arg(long)]
        stderr: bool,
    },

    /// Lists the user's domains and subdomains (reads DA data files as root).
    Domains {
        /// Filter by a specific domain.
        #[arg(long)]
        domain: Option<String>,
    },

    /// Persists the current user's own panel-language preference.
    SetLocale {
        /// Locale code (e.g. `pt-br`, `en`). Empty clears the preference.
        locale: String,
    },

    /// Administrative commands (requires `diradmin`).
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// Returns the binary version.
    Version,
    /// Lists apps from every user.
    List,
    /// Detects Node.js runtimes installed on the system.
    DetectNodes,
    /// Persists the Node.js runtimes selected by detection index.
    SaveNodeVersions { indices: Vec<usize> },
    /// Persists the plugin-wide default panel language.
    SetLocale {
        /// Locale code (e.g. `pt-br`, `en`). Empty clears the default.
        locale: String,
    },
}

#[derive(Clone, ValueEnum)]
enum AppType {
    Node,
    Rust,
}

impl AppType {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Rust => "rust",
        }
    }
}

fn main() {
    let cli = Cli::parse();

    if !nix::unistd::geteuid().is_root() {
        system_error("root_required", "core_selynt must be setuid root (euid=0)");
    }

    let (uid, gid, home, username) = match resolve_target_user() {
        Ok(u) => u,
        Err(e) => system_error("user_resolve_failed", &format!("{e:#}")),
    };

    let state_dir = resolve_state_dir(&username);

    if let Err(e) = init_state_dir(&state_dir, uid, gid) {
        system_error(
            "init_failed",
            &format!("{e:#} (uid={uid}, state_dir={})", state_dir.display()),
        );
    }

    let prelude = run_root_prelude(&cli.command, &username, &state_dir, uid, gid);
    let web_user = state::get_web_user();

    if let Err(e) = drop_privileges(uid, gid, &username) {
        system_error("privilege_drop_failed", &format!("{e:#}"));
    }

    output::debug(format!("state_dir={}", state_dir.display()));

    let dbg = build_debug_base(cli.debug, &username, &home, Some(&state_dir));
    dispatch(cli.command, &state_dir, &web_user, prelude, dbg.as_ref())
}

/// Resolves the state dir for `username`. Honours `SELYNT_STATE_DIR` only when
/// it falls under `/var/lib/selynt_panel/` and contains no `..` traversal.
fn resolve_state_dir(username: &str) -> PathBuf {
    PathBuf::from(
        std::env::var("SELYNT_STATE_DIR")
            .ok()
            .filter(|p| p.starts_with(&format!("{STATE_BASE}/")) && !p.contains(".."))
            .unwrap_or_else(|| format!("{STATE_BASE}/{username}")),
    )
}

/// Data that has to be collected as root, before the privilege drop, because
/// the files involved are owned by `diradmin` or live in directories the real
/// user cannot traverse.
struct RootPrelude {
    domains: Vec<(String, Vec<String>)>,
    admin_apps: Vec<serde_json::Value>,
    save_node_versions: Option<Result<serde_json::Value, (String, String)>>,
    set_locale: Option<Result<serde_json::Value, (String, String)>>,
}

fn run_root_prelude(
    command: &Commands,
    username: &str,
    state_dir: &Path,
    uid: u32,
    gid: u32,
) -> RootPrelude {
    let domains = match command {
        Commands::Domains { domain } => read_domains_files(username, domain.as_deref()),
        _ => Vec::new(),
    };

    if let Commands::Start { name } = command
        && let Ok(meta) = load_app_meta(state_dir, name)
    {
        let cwd = PathBuf::from(&meta.cwd);
        if let Err(e) = init_app_logs_dir(&cwd, uid, gid) {
            output::debug(format!("init_app_logs_dir: {e:#}"));
        }
    }

    let admin_apps = if matches!(
        command,
        Commands::Admin {
            command: AdminCommands::List
        }
    ) {
        cmd::collect_admin_list()
    } else {
        Vec::new()
    };

    let save_node_versions = if let Commands::Admin {
        command: AdminCommands::SaveNodeVersions { indices },
    } = command
    {
        Some(cmd::save_node_versions(indices))
    } else {
        None
    };

    // Locale writes must happen as root: the state dir is owned by `diradmin`
    // (711) and the panel CGI runs as the web user, which cannot write there.
    let set_locale = match command {
        Commands::SetLocale { locale } => {
            Some(cmd::set_locale_user(state_dir, locale, uid, gid))
        }
        Commands::Admin {
            command: AdminCommands::SetLocale { locale },
        } => Some(cmd::set_locale_global(locale)),
        _ => None,
    };

    RootPrelude {
        domains,
        admin_apps,
        save_node_versions,
        set_locale,
    }
}

fn dispatch(
    command: Commands,
    state_dir: &Path,
    web_user: &str,
    prelude: RootPrelude,
    dbg: Option<&serde_json::Value>,
) -> ! {
    match command {
        Commands::List => cmd::cmd_list(state_dir, dbg),
        Commands::Status { name } => cmd::cmd_status(state_dir, &name, dbg),
        Commands::Start { name } => cmd::cmd_start(state_dir, &name, web_user, dbg),
        Commands::Stop { name, timeout } => cmd::cmd_stop(state_dir, &name, timeout, dbg),
        Commands::Restart { name } => cmd::cmd_restart(state_dir, &name, web_user, dbg),
        Commands::Add {
            name,
            app_type,
            cwd,
            entry,
            host,
            domain,
            subdomain,
            node_version,
            env_vars,
        } => cmd::cmd_add(
            state_dir,
            &cmd::AddArgs {
                name: &name,
                app_type: app_type.as_str(),
                cwd: cwd.as_deref(),
                entry: &entry,
                host: &host,
                domain: domain.as_deref(),
                subdomain: subdomain.as_deref(),
                node_version: node_version.as_deref(),
                env_vars: &env_vars,
            },
            dbg,
        ),
        Commands::Remove { name, delete_dir } => cmd::cmd_remove(state_dir, &name, delete_dir, dbg),
        Commands::SetNodeVersion { name, node_version } => {
            cmd::cmd_set_node_version(state_dir, &name, &node_version, dbg)
        }
        Commands::Logs {
            name,
            lines,
            stderr,
        } => cmd::cmd_logs(state_dir, &name, lines, stderr, dbg),
        Commands::Domains { .. } => cmd::cmd_domains(prelude.domains, dbg),
        Commands::SetLocale { .. } => emit_prelude_result(
            prelude.set_locale,
            "set_locale result missing for SetLocale",
            dbg,
        ),
        Commands::Admin {
            command: AdminCommands::Version,
        } => {
            println!(
                "{}",
                json!({"ok": true, "version": env!("CARGO_PKG_VERSION")})
            );
            std::process::exit(0);
        }
        Commands::Admin {
            command: AdminCommands::List,
        } => cmd::cmd_admin_list(&prelude.admin_apps, dbg),
        Commands::Admin {
            command: AdminCommands::DetectNodes,
        } => cmd::cmd_admin_detect_nodes(dbg),
        Commands::Admin {
            command: AdminCommands::SaveNodeVersions { .. },
        } => emit_prelude_result(
            prelude.save_node_versions,
            "save_node_versions result missing for SaveNodeVersions",
            dbg,
        ),
        Commands::Admin {
            command: AdminCommands::SetLocale { .. },
        } => emit_prelude_result(
            prelude.set_locale,
            "set_locale result missing for Admin::SetLocale",
            dbg,
        ),
    }
}

/// Emits a JSON result computed in the root prelude. `run_root_prelude`
/// populates `result` for the matching command, so `None` is a programming bug.
fn emit_prelude_result(
    result: Option<Result<serde_json::Value, (String, String)>>,
    missing_msg: &str,
    dbg: Option<&serde_json::Value>,
) -> ! {
    let outcome = result.expect(missing_msg);
    match outcome {
        Ok(val) => {
            let mut obj = serde_json::Map::new();
            obj.insert("ok".into(), json!(true));
            if let serde_json::Value::Object(map) = val {
                obj.extend(map);
            }
            if let Some(d) = dbg {
                obj.insert("_debug".into(), d.clone());
            }
            println!("{}", serde_json::Value::Object(obj));
            std::process::exit(0);
        }
        Err((error, message)) => output::user_error(&error, &message),
    }
}

/// Reads `domains.list` and the per-domain `*.subdomains` files for `username`
/// from the `DirectAdmin` data dir. Must be called as root.
fn read_domains_files(username: &str, filter: Option<&str>) -> Vec<(String, Vec<String>)> {
    let base = format!("{DA_USERS_BASE}/{username}");

    let list_content = std::fs::read_to_string(format!("{base}/domains.list")).unwrap_or_default();

    list_content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|d| filter.is_none_or(|f| *d == f))
        .map(|domain| {
            let sub_path = format!("{base}/domains/{domain}.subdomains");
            let subs: Vec<String> = std::fs::read_to_string(&sub_path)
                .unwrap_or_default()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            (domain.to_string(), subs)
        })
        .collect()
}

fn build_debug_base(
    enabled: bool,
    user: &str,
    home: &str,
    state_dir: Option<&Path>,
) -> Option<serde_json::Value> {
    if !enabled {
        return None;
    }
    let sd = state_dir.and_then(Path::to_str).unwrap_or("").to_string();
    Some(json!({
        "user": user,
        "home": home,
        "state_dir": sd,
    }))
}
