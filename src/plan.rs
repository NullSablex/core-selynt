//! Turning a parsed command into the work it takes, on both sides of the
//! privilege drop.
//!
//! Each command is one arm of [`plan`]: the arm's body runs as root, the
//! closure it returns runs as the account, and `drop_privileges` sits between
//! them. Writing both halves together is what lets the compiler enforce what
//! used to be left to memory — the match is exhaustive, so a command cannot be
//! added without deciding both sides, and values pass between them as captured
//! locals rather than as an `Option` that might be `None`.

use std::path::{Path, PathBuf};

use crate::{AdminCommands, Commands, admin, app, install, limits, sys};

/// Work to run once privileges have been dropped.
///
/// Boxed because each arm captures different values. The command exits from
/// inside, so this never returns normally.
pub type Deferred = Box<dyn FnOnce()>;

/// What both halves of a command may need. Gathered before the drop, since some
/// of it is unreadable afterwards.
pub struct Ctx<'a> {
    pub username: &'a str,
    pub state_dir: &'a Path,
    pub web_user: &'a str,
    pub uid: u32,
    pub gid: u32,
    /// Debug payload, already built: `--debug` adds it to the JSON output.
    pub dbg: Option<serde_json::Value>,
}

/// Decides what a command does, as root, and returns what it does afterwards.
///
/// The body of each arm is still privileged; the closure it returns is not.
// One arm per command, deliberately in one function: the exhaustive match is
// what stops a new command from being added with only half of it decided, and
// splitting by group would give that guarantee up. Each arm is around a dozen
// lines; the length is the number of commands, not complexity.
#[allow(clippy::too_many_lines)]
pub fn plan(command: Commands, ctx: &Ctx<'_>) -> Deferred {
    let Ctx {
        username,
        state_dir,
        web_user,
        uid,
        gid,
        ..
    } = *ctx;
    let dbg = ctx.dbg.clone();
    let username = username.to_string();
    let state_dir = state_dir.to_path_buf();
    let web_user = web_user.to_string();

    match command {
        // Read-only, and nothing here needs root.
        Commands::List => {
            let (sd, d) = (state_dir, dbg);
            Box::new(move || app::commands::cmd_list(&sd, d.as_ref()))
        }
        Commands::Status { name } => {
            let (sd, d) = (state_dir, dbg);
            Box::new(move || app::commands::cmd_status(&sd, &name, d.as_ref()))
        }
        Commands::StatusIsolated => {
            let (sd, d) = (state_dir, dbg);
            Box::new(move || app::commands::cmd_status_isolated(&sd, d.as_ref()))
        }
        Commands::Logs {
            name,
            lines,
            stderr,
        } => {
            let (sd, d) = (state_dir, dbg);
            Box::new(move || app::commands::cmd_logs(&sd, &name, lines, stderr, d.as_ref()))
        }

        // `user.conf` belongs to `diradmin` and cannot be read after the drop.
        Commands::Stats { name } => {
            let da = limits::usage::read_da_limits(&username);
            limits::usage::ensure_slice_cap(&username, da.memory_max);
            let (sd, u, d) = (state_dir, username, dbg);
            Box::new(move || limits::usage::cmd_stats(&sd, &name, &u, da, d.as_ref()))
        }
        Commands::Domains { domain } => {
            let data = crate::read_domains_files(&username, domain.as_deref());
            let d = dbg;
            Box::new(move || app::commands::cmd_domains(data, d.as_ref()))
        }
        Commands::SetLocale { locale } => {
            let out = admin::locale::set_locale_user(&state_dir, &locale, uid, gid);
            let d = dbg;
            Box::new(move || crate::emit_prelude_result(out, d.as_ref()))
        }

        // Every command below needs root for something. The account allowance
        // is read first where it applies: it is the pool the per-app limits are
        // divided from, and `user.conf` is unreadable after the drop.
        Commands::Start { name } => {
            let da = limits::usage::read_da_limits(&username);
            limits::usage::ensure_slice_cap(&username, da.memory_max);
            let spawned = spawn_for(&state_dir, &username, &name, uid, gid, da);
            let (sd, u, w, d) = (state_dir, username, web_user, dbg);
            Box::new(move || app::start::cmd_start(&sd, &name, &u, &w, spawned, d.as_ref()))
        }
        // Stopping frees the app's share, so the survivors are resized while
        // its scope is still alive — hence excluded explicitly.
        Commands::Stop { name, timeout } => {
            let da = limits::usage::read_da_limits(&username);
            limits::usage::ensure_slice_cap(&username, da.memory_max);
            limits::usage::reapply_app_limits_excluding(&state_dir, &username, &name);
            let (sd, d) = (state_dir, dbg);
            Box::new(move || app::commands::cmd_stop(&sd, &name, timeout, d.as_ref()))
        }
        // The stop happens here, not in the command: `stop_internal` resolves
        // the process through `get_status`, which requires the caller's uid to
        // match the app's — never true while still root. Stopping here is what
        // lets the respawn below land in a fresh systemd scope; spawned after
        // the drop it would land outside systemd altogether, with no cgroup of
        // its own, escaping the account cap and invisible to the netguard sweep.
        Commands::Restart { name } => {
            let da = limits::usage::read_da_limits(&username);
            limits::usage::ensure_slice_cap(&username, da.memory_max);
            if let Ok(meta) = crate::load_app_meta(&state_dir, &name) {
                limits::netguard::stop_app_tree(&state_dir, &name, &meta);
            }
            let spawned = spawn_for(&state_dir, &username, &name, uid, gid, da);
            let (sd, u, w, d) = (state_dir, username, web_user, dbg);
            Box::new(move || app::commands::cmd_restart(&sd, &name, &u, &w, spawned, d.as_ref()))
        }

        // The `.app` file is the only state saying *what to execute*, so it is
        // written here and left owned by root: an app shares its account's uid
        // and must not be able to forge one. A failed write means the command
        // cannot have taken effect, so it is reported instead of run.
        // The `.app` is the only state saying *what to execute*, so it is
        // written here and left owned by root: an app shares its account's uid
        // and must not be able to forge one.
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
        } => {
            // Built twice on purpose: `AddArgs` borrows, so it cannot outlive
            // this arm and be captured by the closure. The fields move instead,
            // and the closure rebuilds it on the far side of the drop.
            macro_rules! args {
                () => {
                    app::commands::AddArgs {
                        name: &name,
                        app_type: app_type.as_str(),
                        cwd: cwd.as_deref(),
                        entry: &entry,
                        host: &host,
                        domain: domain.as_deref(),
                        subdomain: subdomain.as_deref(),
                        node_version: node_version.as_deref(),
                        env_vars: &env_vars,
                    }
                };
            }
            if let Err((code, msg)) =
                app::appfile::create_for_add(&state_dir, &args!(), &username, gid)
            {
                sys::output::user_error(&code, &msg);
            }
            let (sd, d) = (state_dir, dbg);
            Box::new(move || app::commands::cmd_add(&sd, &args!(), d.as_ref()))
        }
        // The account cannot delete a root-owned file, so the prelude removes
        // it and hands over the metadata the command still needs to stop the
        // app and clean up after it.
        Commands::Remove { name, delete_dir } => {
            let da = limits::usage::read_da_limits(&username);
            limits::usage::ensure_slice_cap(&username, da.memory_max);
            limits::usage::reapply_app_limits_excluding(&state_dir, &username, &name);
            let meta = crate::load_app_meta(&state_dir, &name).ok();
            if meta.is_some() {
                app::appfile::remove(&state_dir, &name);
            }
            let (sd, d) = (state_dir, dbg);
            Box::new(move || app::commands::cmd_remove(&sd, &name, delete_dir, meta, d.as_ref()))
        }
        Commands::SetNodeVersion { name, node_version } => {
            if let Err((code, msg)) =
                app::appfile::update_key(&state_dir, &name, "node_version", &node_version, gid)
            {
                sys::output::user_error(&code, &msg);
            }
            let (sd, d) = (state_dir, dbg);
            Box::new(move || {
                app::commands::cmd_set_node_version(&sd, &name, &node_version, d.as_ref())
            })
        }
        // A pin applies to the live scope at once; waiting for a restart would
        // leave the app on its old, larger ceiling.
        Commands::SetMemoryMax { name, megabytes } => {
            let da = limits::usage::read_da_limits(&username);
            app::commands::apply_memory_max(&state_dir, &name, megabytes, uid, gid);
            limits::usage::ensure_slice_cap(&username, da.memory_max);
            limits::usage::reapply_app_limits(&state_dir, &username);
            let (sd, d) = (state_dir, dbg);
            Box::new(move || app::commands::cmd_set_memory_max(&sd, &name, megabytes, d.as_ref()))
        }
        // Switching isolation moves each app's socket and changes how it is
        // launched, so the running apps are restarted here to make the setting
        // take effect — recreating their scopes needs root.
        Commands::SetIsolated { isolated } => {
            match app::commands::switch_isolation(&state_dir, &username, isolated) {
                Err((code, msg)) => sys::output::user_error(&code, &msg),
                Ok(switch) => {
                    let d = dbg;
                    Box::new(move || app::commands::cmd_set_isolated(isolated, &switch, d.as_ref()))
                }
            }
        }
        // Stopping an offending app means signalling the account's processes.
        Commands::Netguard { .. } => {
            let stopped = limits::netguard::sweep_account(&state_dir, &username);
            let d = dbg;
            Box::new(move || limits::netguard::report(Some(stopped), d.as_ref()))
        }

        // Handled before this point, in `run_server_wide`, which never returns.
        // Naming them keeps the match exhaustive.
        Commands::BootRecover | Commands::SyncProxy | Commands::Setup | Commands::Teardown => {
            sys::output::system_error(
                "internal",
                "server-wide commands run before the privilege drop",
            )
        }

        // The admin pages read DirectAdmin's data directory and write the
        // plugin's own `etc/`, both out of reach after the drop.
        Commands::Admin { command } => match command {
            AdminCommands::Version => Box::new(|| {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "version": env!("CARGO_PKG_VERSION")})
                );
                std::process::exit(0);
            }),
            AdminCommands::List => {
                let apps = admin::server::collect_admin_list();
                let d = dbg;
                Box::new(move || admin::server::cmd_admin_list(&apps, d.as_ref()))
            }
            AdminCommands::Diagnose => {
                let out = install::diagnose::run_diagnostic();
                let d = dbg;
                Box::new(move || crate::emit_prelude_result(Ok(out), d.as_ref()))
            }
            AdminCommands::DetectNodes => {
                let d = dbg;
                Box::new(move || admin::server::cmd_admin_detect_nodes(d.as_ref()))
            }
            AdminCommands::SaveNodeVersions { indices } => {
                let out = admin::server::save_node_versions(&indices);
                let d = dbg;
                Box::new(move || crate::emit_prelude_result(out, d.as_ref()))
            }
            AdminCommands::SaveDefaultIsolated { isolated } => {
                let out = admin::server::save_default_isolated(isolated);
                let d = dbg;
                Box::new(move || crate::emit_prelude_result(out, d.as_ref()))
            }
            AdminCommands::SetLocale { locale } => {
                let out = admin::locale::set_locale_global(&locale);
                let d = dbg;
                Box::new(move || crate::emit_prelude_result(out, d.as_ref()))
            }
        },
    }
}

/// Prepares the account's limits and launches the app into its own scope.
///
/// Shared by `Start` and `Restart`, which must stay identical here: an app that
/// reaches `cmd_start` without a pid from this runs outside systemd.
fn spawn_for(
    state_dir: &Path,
    username: &str,
    name: &str,
    uid: u32,
    gid: u32,
    da: limits::usage::DaLimits,
) -> Option<u32> {
    let Ok(meta) = crate::load_app_meta(state_dir, name) else {
        return None;
    };
    // Resolve the siblings before this app appears, so they shrink first.
    limits::usage::reapply_app_limits_including(state_dir, username, name);
    if let Err(e) = crate::init_app_logs_dir(&PathBuf::from(&meta.cwd), uid, gid) {
        sys::output::debug(format!("init_app_logs_dir: {e:#}"));
    }
    let pid = app::start::spawn_into_scope(&meta, name, state_dir, username, uid, gid);
    // The first app of an account creates the slice; only now does it exist.
    if pid.is_some() {
        limits::usage::ensure_slice_cap(username, da.memory_max);
    }
    pid
}

#[cfg(test)]
mod tests {
    /// `Start` and `Restart` must both reach `spawn_for`.
    ///
    /// `Restart` once did not, and the app came back up outside systemd — no
    /// cgroup, escaping the account cap and invisible to the netguard sweep.
    /// The check reads the source because what makes the two arms agree is that
    /// each names `spawn_for`; an arm launching an app without it would compile
    /// and leave the app uncontained.
    #[test]
    fn start_and_restart_both_spawn_into_a_scope() {
        let src = include_str!("plan.rs");
        let arms = src
            .split("match command {")
            .nth(1)
            .expect("plan has one match over the command");

        for arm in ["Commands::Start {", "Commands::Restart {"] {
            let body = arms.split(arm).nth(1).expect("arm is present");
            let body = &body[..body.find("\n        Commands::").unwrap_or(body.len())];
            assert!(
                body.contains("spawn_for("),
                "{arm} must spawn into a scope, or the app runs outside systemd"
            );
        }
    }
}
