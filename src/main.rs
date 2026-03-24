mod acl;
mod cmd;
mod output;
mod proc;
mod state;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

use std::path::PathBuf;

use output::system_error;
use state::{drop_privileges, init_app_logs_dir, init_state_dir, load_app_meta, resolve_target_user};

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "core_selynt", version, about = "Selynt Panel — gerenciador de processos")]
struct Cli {
    /// Ativa modo debug: inclui _debug no JSON de saída
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Lista todos os apps registrados
    List,

    /// Mostra o status de um app
    Status { name: String },

    /// Inicia um app
    Start { name: String },

    /// Para um app
    Stop {
        name: String,
        /// Segundos de espera antes de SIGKILL (padrão: 10)
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },

    /// Reinicia um app (stop + start)
    Restart { name: String },

    /// Registra um novo app
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
        /// Path do binário Node.js (ex: /usr/local/bin/node)
        #[arg(long)]
        node_version: Option<String>,
        /// Variáveis de ambiente no formato KEY=VAL (repetível)
        #[arg(long = "env", value_name = "KEY=VAL")]
        env_vars: Vec<String>,
    },

    /// Remove um app (para se estiver rodando)
    Remove {
        name: String,
        /// Apaga também o diretório cwd do app
        #[arg(long)]
        delete_dir: bool,
    },

    /// Exibe as últimas linhas do log de um app
    Logs {
        name: String,
        /// Quantidade de linhas (padrão: 100)
        #[arg(long, default_value_t = 100)]
        lines: usize,
        /// Ler stderr em vez de stdout
        #[arg(long)]
        stderr: bool,
    },

    /// Lista domínios e subdomínios do usuário (lê arquivos DA como root)
    Domains {
        /// Filtrar por domínio específico
        #[arg(long)]
        domain: Option<String>,
    },

    /// Comandos administrativos (executar como diradmin)
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// Retorna a versão do binário
    Version,
    /// Lista todos os apps de todos os usuários
    List,
    /// Detecta versões do Node.js instaladas no sistema
    DetectNodes,
    /// Salva versões do Node.js selecionadas (por índice da detecção)
    SaveNodeVersions {
        /// Índices das versões a salvar
        indices: Vec<usize>,
    },
}

#[derive(Clone, ValueEnum)]
enum AppType {
    Node,
    Rust,
}

impl AppType {
    fn as_str(&self) -> &'static str {
        match self {
            AppType::Node => "node",
            AppType::Rust => "rust",
        }
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // Requer euid=0 — o binário deve ser setuid root
    if !nix::unistd::geteuid().is_root() {
        system_error("root_required", "core_selynt deve ser setuid root (euid=0)");
    }

    // Resolver user real a partir de USERNAME env
    let (uid, gid, home, username) = match resolve_target_user() {
        Ok(u) => u,
        Err(e) => system_error("user_resolve_failed", &format!("{e:#}")),
    };

    // Resolver state_dir: SELYNT_STATE_DIR tem precedência, mas deve estar sob /var/lib/selynt_panel/
    let state_dir = PathBuf::from(
        std::env::var("SELYNT_STATE_DIR")
            .ok()
            .filter(|p| p.starts_with("/var/lib/selynt_panel/") && !p.contains(".."))
            .unwrap_or_else(|| format!("/var/lib/selynt_panel/{username}")),
    );

    // [ROOT] Criar state_dir + subdirs, chown para o user real
    if let Err(e) = init_state_dir(&state_dir, uid, gid) {
        system_error("init_failed", &format!("{e:#} (uid={uid}, state_dir={state_dir:?})"));
    }

    // [ROOT] Para domains: ler arquivos DA antes do drop (owned por diradmin)
    let domains_data: Vec<(String, Vec<String>)> =
        if let Commands::Domains { ref domain } = cli.command {
            read_domains_files(&username, domain.as_deref())
        } else {
            Vec::new()
        };

    // [ROOT] Para start: criar {cwd}/logs/ com ownership do user real
    if let Commands::Start { name } = &cli.command {
        match load_app_meta(&state_dir, name) {
            Ok(meta) => {
                let cwd = PathBuf::from(&meta.cwd);
                if let Err(e) = init_app_logs_dir(&cwd, uid, gid) {
                    output::debug(format!("init_app_logs_dir: {e:#}"));
                }
            }
            Err(_) => {} // cmd_start reportará app_not_found
        }
    }

    // [ROOT] Para admin list: ler dados de todos os users antes do drop
    let admin_apps = if matches!(cli.command, Commands::Admin { command: AdminCommands::List }) {
        cmd::collect_admin_list()
    } else {
        Vec::new()
    };

    // [ROOT] Para admin save-node-versions: detectar + salvar antes do drop
    let save_nv_result = if let Commands::Admin { command: AdminCommands::SaveNodeVersions { ref indices } } = cli.command {
        Some(cmd::save_node_versions(indices))
    } else {
        None
    };

    // [ROOT] Ler web_user ANTES do drop (etc/ do plugin é owned por diradmin)
    let web_user = state::get_web_user();

    // DROP de privilégio: a partir daqui roda como o user real
    if let Err(e) = drop_privileges(uid, gid, &username) {
        system_error("privilege_drop_failed", &format!("{e:#}"));
    }

    output::debug(format!("state_dir={:?}", state_dir));

    let dbg = build_debug_base(cli.debug, &username, &home, Some(&state_dir));

    match cli.command {
        Commands::List => cmd::cmd_list(&state_dir, dbg.as_ref()),

        Commands::Status { name } => cmd::cmd_status(&state_dir, &name, dbg.as_ref()),

        Commands::Start { name } => cmd::cmd_start(&state_dir, &name, &web_user, dbg.as_ref()),

        Commands::Stop { name, timeout } => {
            cmd::cmd_stop(&state_dir, &name, timeout, dbg.as_ref())
        }

        Commands::Restart { name } => cmd::cmd_restart(&state_dir, &name, &web_user, dbg.as_ref()),

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
            &state_dir,
            &name,
            app_type.as_str(),
            cwd.as_deref(),
            &entry,
            &host,
            domain.as_deref(),
            subdomain.as_deref(),
            node_version.as_deref(),
            &env_vars,
            dbg.as_ref(),
        ),

        Commands::Remove { name, delete_dir } => {
            cmd::cmd_remove(&state_dir, &name, delete_dir, dbg.as_ref())
        }

        Commands::Logs {
            name,
            lines,
            stderr,
        } => cmd::cmd_logs(&state_dir, &name, lines, stderr, dbg.as_ref()),

        Commands::Domains { .. } => cmd::cmd_domains(domains_data, dbg.as_ref()),

        Commands::Admin { command: AdminCommands::Version } => {
            println!("{}", json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}));
            std::process::exit(0);
        }

        Commands::Admin { command: AdminCommands::List } => {
            cmd::cmd_admin_list(admin_apps, dbg.as_ref())
        }

        Commands::Admin { command: AdminCommands::DetectNodes } => {
            cmd::cmd_admin_detect_nodes(dbg.as_ref())
        }

        Commands::Admin { command: AdminCommands::SaveNodeVersions { .. } } => {
            match save_nv_result.unwrap() {
                Ok(val) => {
                    let mut obj = serde_json::Map::new();
                    obj.insert("ok".into(), json!(true));
                    if let serde_json::Value::Object(map) = val {
                        obj.extend(map);
                    }
                    if let Some(d) = dbg.as_ref() {
                        obj.insert("_debug".into(), d.clone());
                    }
                    println!("{}", serde_json::Value::Object(obj));
                    std::process::exit(0);
                }
                Err((error, message)) => output::user_error(&error, &message),
            }
        }
    }
}

/// Lê domínios e subdomínios dos arquivos DA como root.
/// `/usr/local/directadmin/data/users/{user}/domains.list`
/// `/usr/local/directadmin/data/users/{user}/domains/{domain}.subdomains`
fn read_domains_files(username: &str, filter: Option<&str>) -> Vec<(String, Vec<String>)> {
    let base = format!("/usr/local/directadmin/data/users/{username}");

    let list_content =
        std::fs::read_to_string(format!("{base}/domains.list")).unwrap_or_default();

    list_content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|d| filter.map_or(true, |f| *d == f))
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

/// Constrói a base do objeto _debug se --debug estiver ativo
fn build_debug_base(
    enabled: bool,
    user: &str,
    home: &str,
    state_dir: Option<&std::path::Path>,
) -> Option<serde_json::Value> {
    if !enabled {
        return None;
    }
    let sd = state_dir
        .and_then(|p| p.to_str())
        .unwrap_or("")
        .to_string();
    Some(json!({
        "user": user,
        "home": home,
        "state_dir": sd,
    }))
}
