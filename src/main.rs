mod admin;
mod app;
mod plan;
mod install;
mod limits;
mod runtime;
mod sys;
mod webserver;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

use std::path::{Path, PathBuf};

use runtime::kind::Runtime;
use sys::auth::{drop_privileges, resolve_target_user};
use sys::output::system_error;
use sys::state::{
    DA_USERS_BASE, STATE_BASE, init_app_logs_dir, init_state_dir, load_app_meta,
};

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

    /// Reports CPU and memory usage of an app, with the account's limits.
    Stats { name: String },

    /// Restarts every enabled app of every account, after a reboot.
    ///
    /// Runs as root from `selynt-panel.service`; not meant to be called by
    /// hand. Apps the user stopped carry no marker and stay stopped.
    BootRecover,

    /// Removes everything the plugin installed.
    ///
    /// Stops every app, strips the vhost templates and cleans the web server's
    /// configuration. Run by the uninstaller.
    Teardown,

    /// Prepares everything the plugin needs to run.
    ///
    /// Records which accounts DirectAdmin uses, creates the state directory and
    /// wires the panel into OpenLiteSpeed. Run by the installer; safe to re-run.
    Setup,

    /// Regenerates the web server's proxy handlers for every live app.
    ///
    /// Runs as root from cron; not meant to be called by hand.
    SyncProxy,

    /// Reports whether this account isolates its apps.
    StatusIsolated,

    /// Isolates this account's apps from each other, or restores the default.
    ///
    /// Applies to the account as a whole: isolating a single app would not
    /// protect it, since a non-isolated sibling shares its uid. Takes effect as
    /// each app is restarted.
    SetIsolated {
        /// `true` isolates, `false` restores the shared default.
        #[arg(long, action = clap::ArgAction::Set)]
        isolated: bool,
    },

    /// Stops any of the account's apps bound to an externally reachable port.
    ///
    /// The start-time check only sees the app's own process; this covers every
    /// process in the app's cgroup, so a port opened later — or by a child that
    /// never went through the Node loader — is caught too. Loopback is allowed.
    Netguard {
        /// Sweep every account instead of just the caller's. Used by the timer,
        /// and restricted to root and the panel's web user.
        #[arg(long)]
        all_accounts: bool,
    },

    /// Sets the memory cap of an app. `0` (or empty) restores "auto".
    SetMemoryMax {
        name: String,
        /// Cap in megabytes; `0` clears it.
        #[arg(long)]
        megabytes: u64,
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
    /// Sets whether newly created apps start isolated from their siblings.
    SaveDefaultIsolated {
        /// `true` makes isolation the default for new accounts.
        #[arg(long, action = clap::ArgAction::Set)]
        isolated: bool,
    },
    /// Runs the proxy-stack diagnostic and returns its report.
    Diagnose,
    /// Persists the plugin-wide default panel language.
    SetLocale {
        /// Locale code (e.g. `pt-br`, `en`). Empty clears the default.
        locale: String,
    },
}

/// CLI surface for [`Runtime`]. Kept separate so clap's derive stays out of the
/// runtime definition itself; `as_str` is the single source of truth for the
/// identifier that reaches metadata.
#[derive(Clone, ValueEnum)]
enum AppType {
    Node,
    Rust,
}

impl AppType {
    const fn runtime(&self) -> Runtime {
        match self {
            Self::Node => Runtime::Node,
            Self::Rust => Runtime::Rust,
        }
    }

    const fn as_str(&self) -> &'static str {
        self.runtime().as_str()
    }
}

/// Maintenance that covers the whole server rather than one account.
#[derive(Clone, Copy)]
enum ServerWide {
    /// Bring back apps that were running before the last reboot.
    BootRecover,
    /// Stop apps of any account bound to an externally reachable port.
    NetguardAll,
    /// Rewrite the web server's proxy handlers from the live apps.
    SyncProxy,
    /// Record the accounts, prepare the state directory and wire up the proxy.
    Setup,
    /// Stop every app and undo the server-side configuration.
    Teardown,
}

/// Classifies a command as server-wide, if it is one.
const fn server_wide_command(command: &Commands) -> Option<ServerWide> {
    match command {
        Commands::BootRecover => Some(ServerWide::BootRecover),
        Commands::Netguard { all_accounts: true } => Some(ServerWide::NetguardAll),
        Commands::SyncProxy => Some(ServerWide::SyncProxy),
        Commands::Setup => Some(ServerWide::Setup),
        Commands::Teardown => Some(ServerWide::Teardown),
        _ => None,
    }
}

/// Runs server-wide maintenance and exits.
///
/// Stays root throughout: the work spans every account, so there is no single
/// identity to drop to. Each app it starts goes through its own invocation of
/// the binary, which drops to that app's account as usual.
fn run_server_wide(command: ServerWide, debug: bool) -> ! {
    // Not `build_debug_base`: its fields describe the account being acted on,
    // and there is none here. Reporting the scope is the honest equivalent.
    let dbg = debug.then(|| json!({ "scope": "server" }));

    match command {
        ServerWide::BootRecover => {
            app::boot::cmd_boot_recover(app::boot::recover_all(), dbg.as_ref())
        }
        ServerWide::NetguardAll => {
            limits::netguard::report(Some(limits::netguard::sweep_all_accounts()), dbg.as_ref())
        }
        ServerWide::SyncProxy => webserver::proxysync::cmd_sync_proxy(dbg.as_ref()),
        ServerWide::Setup => install::setup::cmd_setup(dbg.as_ref()),
        ServerWide::Teardown => install::teardown::cmd_teardown(dbg.as_ref()),
    }
}

fn main() {
    let cli = Cli::parse();

    if !nix::unistd::geteuid().is_root() {
        system_error("root_required", "core_selynt must be setuid root (euid=0)");
    }

    // Server-wide maintenance has no target account: it sweeps every one of
    // them. Handling it before `resolve_target_user` keeps `USERNAME` out of
    // the picture entirely — there is no account to name, and demanding one
    // would be asking for a value the answer does not depend on.
    if let Some(command) = server_wide_command(&cli.command) {
        // Three levels, not two.
        //
        // `SyncProxy` is how an ordinary command tells the panel that the
        // routing no longer matches the live apps, and it is invoked by the
        // panel itself after the privilege drop. It reads only state the panel
        // wrote and rewrites a file derived entirely from it, so any account may
        // ask for it.
        //
        // `Setup` and `Teardown` change the installation itself — they stop
        // every app, rewrite DirectAdmin's templates and reconfigure the web
        // server. The web server's own account is trusted to act on behalf of a
        // customer, which is what serving the panel needs, but not to take the
        // panel apart: otherwise anything that reached that account could
        // uninstall it.
        //
        // The rest is server-wide maintenance the panel triggers for itself.
        let allowed = match command {
            ServerWide::SyncProxy => true,
            ServerWide::Setup | ServerWide::Teardown => sys::auth::caller_is_root(),
            _ => sys::auth::caller_is_privileged(),
        };
        if !allowed {
            let (code, message) = if matches!(command, ServerWide::Setup | ServerWide::Teardown) {
                (
                    "root_required",
                    "installing or removing the plugin requires root",
                )
            } else {
                (
                    "admin_required",
                    "server-wide maintenance requires root or the panel web user",
                )
            };
            system_error(code, message);
        }
        run_server_wide(command, cli.debug);
    }

    let (uid, gid, home, username) = match resolve_target_user() {
        Ok(u) => u,
        Err(e) => system_error("user_resolve_failed", &format!("{e:#}")),
    };

    // `Admin` subcommands expose every user's apps and run privileged work in
    // the prelude, so they are restricted to the callers the panel itself runs
    // as. Without this any local account could read the whole server's app
    // inventory — and `save-node-versions` would execute a caller-supplied
    // binary as root via NVM_DIR.
    if matches!(cli.command, Commands::Admin { .. }) && !sys::auth::caller_is_privileged() {
        system_error(
            "admin_required",
            "administrative commands require root or the panel web user",
        );
    }

    // Pin HOME to the resolved account's real home. It arrives from the caller,
    // who could otherwise point it anywhere — and the cwd confinement check
    // relies on it. `resolve_target_user` got this from getpwnam, not the
    // environment, so it is the trustworthy value.
    // SAFETY: single-threaded at this point; no other thread can observe env.
    unsafe { std::env::set_var("HOME", &home) };

    let state_dir = resolve_state_dir(&username);

    if let Err(e) = init_state_dir(&state_dir, uid, gid) {
        system_error(
            "init_failed",
            &format!("{e:#} (uid={uid}, state_dir={})", state_dir.display()),
        );
    }

    let web_user = sys::state::get_web_user();
    let ctx = plan::Ctx {
        username: &username,
        state_dir: &state_dir,
        web_user: &web_user,
        uid,
        gid,
        dbg: build_debug_base(cli.debug, &username, &home, Some(&state_dir)),
    };

    // Everything the command needs root for happens inside `plan`; what it
    // returns runs as the account. The drop sits between the two and is the
    // only place it happens.
    let deferred = plan::plan(cli.command, &ctx);

    if let Err(e) = drop_privileges(uid, gid, &username) {
        system_error("privilege_drop_failed", &format!("{e:#}"));
    }

    sys::output::debug(format!("state_dir={}", state_dir.display()));

    deferred();
    // Every command exits from inside; reaching here means one returned.
    system_error("internal", "command returned without producing output")
}

/// Resolves the state dir for `username`.
///
/// `SELYNT_STATE_DIR` is honoured only for privileged callers (root and the
/// panel web user, which is how the CGI passes it). Checking just the prefix
/// was not enough: `/var/lib/selynt_panel/<other-user>` satisfies it, so any
/// local account could point the tool at somebody else's state and list, start,
/// stop or remove their apps.
fn resolve_state_dir(username: &str) -> PathBuf {
    let own = format!("{STATE_BASE}/{username}");
    if !sys::auth::caller_is_privileged() {
        return PathBuf::from(own);
    }
    PathBuf::from(
        std::env::var("SELYNT_STATE_DIR")
            .ok()
            .filter(|p| p.starts_with(&format!("{STATE_BASE}/")) && !p.contains(".."))
            .unwrap_or(own),
    )
}

/// Emits a JSON result produced on the privileged side.
///
/// Takes the value itself rather than an `Option`: with each command's prelude
/// and body in the same arm, a result that was never produced is no longer
/// representable, and the "result missing" branches that used to guard against
/// it are gone with it.
fn emit_prelude_result(
    outcome: Result<serde_json::Value, (String, String)>,
    dbg: Option<&serde_json::Value>,
) -> ! {
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
        Err((code, msg)) => sys::output::user_error(&code, &msg),
    }
}

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
