mod admin;
mod app;
mod install;
mod limits;
mod runtime;
mod sys;
mod webserver;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

use std::path::{Path, PathBuf};

use runtime::kind::Runtime;
use sys::output::system_error;
use sys::state::{AppMeta, STATE_BASE, DA_USERS_BASE, init_app_logs_dir, init_state_dir, load_app_meta};
use sys::auth::{drop_privileges, resolve_target_user};


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
        ServerWide::BootRecover => app::boot::cmd_boot_recover(app::boot::recover_all(), dbg.as_ref()),
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
                ("root_required", "installing or removing the plugin requires root")
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

    let prelude = run_root_prelude(&cli.command, &username, &state_dir, uid, gid);
    let web_user = sys::state::get_web_user();

    if let Err(e) = drop_privileges(uid, gid, &username) {
        system_error("privilege_drop_failed", &format!("{e:#}"));
    }

    sys::output::debug(format!("state_dir={}", state_dir.display()));

    let dbg = build_debug_base(cli.debug, &username, &home, Some(&state_dir));
    dispatch(cli.command, &state_dir, &username, &web_user, prelude, dbg.as_ref())
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

/// Data that has to be collected as root, before the privilege drop, because
/// the files involved are owned by `diradmin` or live in directories the real
/// user cannot traverse.
struct RootPrelude {
    /// Diagnostic report — the script reads DirectAdmin and OpenLiteSpeed
    /// files that only root can reach.
    diagnostic: Option<Result<serde_json::Value, (String, String)>>,
    /// Account resource limits from DirectAdmin's `user.conf`, which lives in a
    /// `diradmin`-owned `0700` directory and is unreadable after the drop.
    da_limits: limits::usage::DaLimits,
    /// PID of an app spawned into its own systemd scope. Registering a scope
    /// needs the system bus, so it happens here while we are still root;
    /// `systemd-run --uid/--gid` performs the privilege drop for the app.
    spawned_pid: Option<u32>,
    domains: Vec<(String, Vec<String>)>,
    admin_apps: Vec<serde_json::Value>,
    save_node_versions: Option<Result<serde_json::Value, (String, String)>>,
    set_locale: Option<Result<serde_json::Value, (String, String)>>,
    /// Apps stopped by the network sweep: it signals the account's processes,
    /// so it has to run before the drop.
    netguard_stopped: Option<Vec<String>>,
    /// Outcome of writing an app's `.app` metadata, which only root may do.
    app_file_result: Option<Result<(), (String, String)>>,
    /// Metadata of an app being removed. The `.app` is root-owned, so the
    /// prelude deletes it and passes what it held to the command.
    removed_meta: Option<AppMeta>,
    /// Apps restarted to apply a change of isolation mode, and those that
    /// failed to come back up.
    isolation_switch: Option<Result<app::commands::IsolationSwitch, (String, String)>>,
}

/// Whether this command needs the account's DirectAdmin allowance read.
///
/// Every command that touches memory limits, not just `Stats`: the allowance is
/// the pool all the per-app limits are derived from, and `user.conf` is only
/// readable here, as root. Reading it also re-applies the account's slice cap,
/// so a quota an admin changed in DirectAdmin reaches the account without
/// waiting for it to start or stop something.
const fn wants_da_limits(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Stats { .. }
            | Commands::Start { .. }
            | Commands::Stop { .. }
            | Commands::Remove { .. }
            | Commands::SetMemoryMax { .. }
            | Commands::List
            | Commands::Status { .. }
            | Commands::Restart { .. }
    )
}

/// Whether this command launches an app into its own systemd scope.
///
/// `Restart` belongs here alongside `Start`, and the two must not drift: an app
/// spawned outside the prelude lands outside systemd, with no cgroup of its
/// own — no memory cap, and invisible to the netguard sweep.
const fn spawns_into_scope(command: &Commands) -> bool {
    matches!(command, Commands::Start { .. } | Commands::Restart { .. })
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

    let da_limits = if wants_da_limits(command) {
        let limits = limits::usage::read_da_limits(username);

        // Re-apply on every command that reads them, not only on the ones that
        // change an app. The account's allowance lives in DirectAdmin and an
        // admin can raise or lower it at any time; without this the account
        // stays on whatever ceiling was in force the last time it happened to
        // start or stop something — a raised quota never arriving, and a
        // lowered one never taking effect.
        limits::usage::ensure_slice_cap(username, limits.memory_max);
        limits
    } else {
        limits::usage::DaLimits::default()
    };

    // A pin takes effect on the live scope immediately — waiting for a restart
    // would leave the app on its old, larger ceiling. `systemctl set-property`
    // needs root, hence here.
    if let Commands::SetMemoryMax { name, megabytes } = command {
        app::commands::apply_memory_max(state_dir, name, *megabytes, uid, gid);
        limits::usage::ensure_slice_cap(username, da_limits.memory_max);
        limits::usage::reapply_app_limits(state_dir, username);
    }

    // Stopping or removing an app frees its share, so the survivors' guarantees
    // go back up. The scope is still alive at this point — the process is only
    // killed after the privilege drop — so it is excluded explicitly, or the
    // others would be sized as if it were still competing.
    if let Commands::Stop { name, .. } | Commands::Remove { name, .. } = command {
        limits::usage::ensure_slice_cap(username, da_limits.memory_max);
        limits::usage::reapply_app_limits_excluding(state_dir, username, name);
    }

    // Switching isolation moves each app's socket and changes how it is
    // launched, so the running apps are restarted here to make the setting take
    // effect immediately — recreating their systemd scopes needs root.
    let isolation_switch = if let Commands::SetIsolated { isolated } = command {
        Some(app::commands::switch_isolation(state_dir, username, *isolated))
    } else {
        None
    };

    // Removal needs root as well: the account cannot delete a root-owned file.
    // The metadata is read first and handed over, since the command still needs
    // it to stop the app and clean up.
    let removed_meta = if let Commands::Remove { name, .. } = command {
        let meta = load_app_meta(state_dir, name).ok();
        if meta.is_some() {
            app::appfile::remove(state_dir, name);
        }
        meta
    } else {
        None
    };

    // The `.app` file is the only state that says what to execute, so it is
    // written here and left owned by root: an app sharing its account's uid
    // must not be able to forge one and have the panel launch it. Everything
    // else under `.run` is observable state the account may write.
    let app_file_result = match command {
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
        } => Some(app::appfile::create_for_add(
            state_dir,
            &app::commands::AddArgs {
                name,
                app_type: app_type.as_str(),
                cwd: cwd.as_deref(),
                entry,
                host,
                domain: domain.as_deref(),
                subdomain: subdomain.as_deref(),
                node_version: node_version.as_deref(),
                env_vars,
            },
            gid,
        )),
        Commands::SetNodeVersion { name, node_version } => Some(app::appfile::update_key(
            state_dir,
            name,
            "node_version",
            node_version,
            gid,
        )),
        _ => None,
    };

    // Stopping an offending app means signalling processes owned by the
    // account, so the sweep runs here, before the drop. The result is reported
    // by the dispatcher below, which is where the debug payload lives.
    let netguard_stopped = if matches!(command, Commands::Netguard { .. }) {
        Some(limits::netguard::sweep_account(state_dir, username))
    } else {
        None
    };

    // `Restart` stops the app here, as root, rather than letting `cmd_restart`
    // do it after the drop. `stop_internal` resolves the process through
    // `get_status`, which requires the process uid to match the caller's — true
    // after the drop, never in this prelude. Stopping here is what lets the
    // restart go on to spawn into a fresh systemd scope below: spawned after
    // the drop instead, the app would land outside systemd altogether, with no
    // cgroup of its own — escaping the account's memory cap, invisible to the
    // netguard sweep (which walks cgroups), and liable to be torn down with the
    // CGI process that happened to start it.
    if let Commands::Restart { name } = command
        && let Ok(meta) = load_app_meta(state_dir, name)
    {
        limits::netguard::stop_app_tree(state_dir, name, &meta);
    }

    let mut spawned_pid = None;
    if spawns_into_scope(command)
        && let Commands::Start { name } | Commands::Restart { name } = command
        && let Ok(meta) = load_app_meta(state_dir, name)
    {
        // Re-resolve the running apps first: the app about to start counts
        // itself in `app_limits_for`, so the others must adjust before it
        // appears. Doing this after the spawn would delay the socket and trip
        // the readiness check.
        limits::usage::ensure_slice_cap(username, da_limits.memory_max);
        limits::usage::reapply_app_limits_including(state_dir, username, name);
        let cwd = PathBuf::from(&meta.cwd);
        if let Err(e) = init_app_logs_dir(&cwd, uid, gid) {
            sys::output::debug(format!("init_app_logs_dir: {e:#}"));
        }
        spawned_pid = app::start::spawn_into_scope(&meta, name, state_dir, username, uid, gid);
        // The first app of an account creates the slice, so the call above had
        // nothing to configure. Now it exists.
        if spawned_pid.is_some() {
            limits::usage::ensure_slice_cap(username, da_limits.memory_max);
        }
    }

    let admin_apps = if matches!(
        command,
        Commands::Admin {
            command: AdminCommands::List
        }
    ) {
        admin::server::collect_admin_list()
    } else {
        Vec::new()
    };

    let diagnostic = if matches!(
        command,
        Commands::Admin {
            command: AdminCommands::Diagnose
        }
    ) {
        Some(install::diagnose::run_diagnostic())
    } else {
        None
    };

    // Both write into the plugin's `etc/`, which only root can touch, and only
    // one of them can be the running command.
    let save_node_versions = if let Commands::Admin {
        command: AdminCommands::SaveNodeVersions { indices },
    } = command
    {
        Some(admin::server::save_node_versions(indices))
    } else if let Commands::Admin {
        command: AdminCommands::SaveDefaultIsolated { isolated },
    } = command
    {
        Some(admin::server::save_default_isolated(*isolated))
    } else {
        None
    };

    // Locale writes must happen as root: the state dir is owned by `diradmin`
    // (711) and the panel CGI runs as the web user, which cannot write there.
    let set_locale = match command {
        Commands::SetLocale { locale } => {
            Some(admin::locale::set_locale_user(state_dir, locale, uid, gid))
        }
        Commands::Admin {
            command: AdminCommands::SetLocale { locale },
        } => Some(admin::locale::set_locale_global(locale)),
        _ => None,
    };

    RootPrelude {
        diagnostic,
        da_limits,
        spawned_pid,
        domains,
        admin_apps,
        save_node_versions,
        set_locale,
        netguard_stopped,
        app_file_result,
        removed_meta,
        isolation_switch,
    }
}

fn dispatch(
    command: Commands,
    state_dir: &Path,
    username: &str,
    web_user: &str,
    prelude: RootPrelude,
    dbg: Option<&serde_json::Value>,
) -> ! {
    // A failed `.app` write means the command cannot have taken effect; report
    // it instead of running the rest as if the metadata were there.
    if let Some(Err((code, msg))) = prelude.app_file_result {
        sys::output::user_error(&code, &msg);
    }

    match command {
        Commands::List => app::commands::cmd_list(state_dir, dbg),
        Commands::Status { name } => app::commands::cmd_status(state_dir, &name, dbg),
        Commands::Stats { name } => limits::usage::cmd_stats(state_dir, &name, username, prelude.da_limits, dbg),
        Commands::Netguard { .. } => limits::netguard::report(prelude.netguard_stopped, dbg),
        // Handled before the privilege drop, in `run_server_wide`; the match
        // has to name it even though it never arrives here.
        Commands::BootRecover | Commands::SyncProxy | Commands::Setup | Commands::Teardown => sys::output::system_error(
            "internal",
            "server-wide commands run before the privilege drop",
        ),
        Commands::StatusIsolated => app::commands::cmd_status_isolated(state_dir, dbg),
        Commands::SetIsolated { isolated } => match prelude.isolation_switch {
            Some(Ok(switch)) => app::commands::cmd_set_isolated(isolated, switch, dbg),
            Some(Err((code, msg))) => sys::output::user_error(&code, &msg),
            None => sys::output::system_error("internal", "isolation switch result missing"),
        },
        Commands::SetMemoryMax { name, megabytes } => {
            app::commands::cmd_set_memory_max(state_dir, &name, megabytes, dbg)
        }
        Commands::Start { name } => {
            app::start::cmd_start(state_dir, &name, username, web_user, prelude.spawned_pid, dbg)
        }
        Commands::Stop { name, timeout } => app::commands::cmd_stop(state_dir, &name, timeout, dbg),
        Commands::Restart { name } => app::commands::cmd_restart(
            state_dir,
            &name,
            username,
            web_user,
            prelude.spawned_pid,
            dbg,
        ),
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
        } => app::commands::cmd_add(
            state_dir,
            &app::commands::AddArgs {
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
        Commands::Remove { name, delete_dir } => app::commands::cmd_remove(state_dir, &name, delete_dir, prelude.removed_meta, dbg),
        Commands::SetNodeVersion { name, node_version } => {
            app::commands::cmd_set_node_version(state_dir, &name, &node_version, dbg)
        }
        Commands::Logs {
            name,
            lines,
            stderr,
        } => app::commands::cmd_logs(state_dir, &name, lines, stderr, dbg),
        Commands::Domains { .. } => app::commands::cmd_domains(prelude.domains, dbg),
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
        } => admin::server::cmd_admin_list(&prelude.admin_apps, dbg),
        Commands::Admin {
            command: AdminCommands::Diagnose,
        } => emit_prelude_result(prelude.diagnostic, "diagnostic result missing", dbg),
        Commands::Admin {
            command: AdminCommands::DetectNodes,
        } => admin::server::cmd_admin_detect_nodes(dbg),
        Commands::Admin {
            command: AdminCommands::SaveNodeVersions { .. },
        } => emit_prelude_result(
            prelude.save_node_versions,
            "save_node_versions result missing for SaveNodeVersions",
            dbg,
        ),
        Commands::Admin {
            command: AdminCommands::SaveDefaultIsolated { .. },
        } => emit_prelude_result(
            prelude.save_node_versions,
            "result missing for SaveDefaultIsolated",
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

/// Emits a JSON result computed in the root prelude.
///
/// `run_root_prelude` fills `result` in for the command being dispatched, so
/// `None` means the two drifted apart — a bug here, not a bad request. It is
/// still reported as JSON rather than panicking: this binary's only caller is
/// the panel's PHP layer, which parses stdout, and a panic would leave it with
/// an empty body and no way to tell the user anything.
fn emit_prelude_result(
    result: Option<Result<serde_json::Value, (String, String)>>,
    missing_msg: &str,
    dbg: Option<&serde_json::Value>,
) -> ! {
    let Some(outcome) = result else {
        sys::output::system_error("internal", missing_msg);
    };
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
        Err((error, message)) => sys::output::user_error(&error, &message),
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

#[cfg(test)]
mod tests {
    use super::{Commands, spawns_into_scope, wants_da_limits};

    /// `Restart` must be treated exactly like `Start` on the privileged paths.
    ///
    /// It once was not: it read no account limits and never reached
    /// `spawn_into_scope`, so `cmd_restart` fell through to spawning the app
    /// after the privilege drop. The app then ran outside systemd entirely —
    /// no scope, no slice, no memory cap, and invisible to the netguard sweep,
    /// which finds processes by walking cgroups. A restarted app was a
    /// different, less contained thing than a started one.
    #[test]
    fn restart_is_privileged_exactly_like_start() {
        let start = Commands::Start { name: "api".into() };
        let restart = Commands::Restart { name: "api".into() };

        assert_eq!(wants_da_limits(&start), wants_da_limits(&restart));
        assert_eq!(spawns_into_scope(&start), spawns_into_scope(&restart));

        assert!(wants_da_limits(&restart), "restart needs the account cap");
        assert!(spawns_into_scope(&restart), "restart needs its own scope");
    }

    /// A command that neither starts nor restarts must not be dragged onto the
    /// spawn path by a predicate that is too broad.
    #[test]
    fn other_commands_do_not_spawn() {
        assert!(!spawns_into_scope(&Commands::List));
        assert!(!spawns_into_scope(&Commands::Stop {
            name: "api".into(),
            timeout: 10,
        }));
    }
}
