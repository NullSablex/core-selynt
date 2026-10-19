use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::auth::user_exists;
use super::fs::{chown_path, chown_recursive, parse_kv};

pub const PLUGIN_PATH: &str = "/usr/local/directadmin/plugins/selynt_panel";
pub const DA_USERS_BASE: &str = "/usr/local/directadmin/data/users";
/// Where `DirectAdmin` keeps the vhost templates it generates configs from.
pub const DA_TEMPLATES: &str = "/usr/local/directadmin/data/templates";
/// Root of the panel's per-account state.
pub const STATE_BASE: &str = "/var/lib/selynt_panel";
/// Set when the proxy config no longer matches the live apps.
pub const SYNC_MARKER: &str = "/var/lib/selynt_panel/.sync_needed";

const STATE_SUBDIRS: [&str; 3] = [".run", ".sockets", ".proxy"];

#[derive(Debug, Clone)]
pub struct AppMeta {
    pub name: String,
    pub app_type: String,
    pub cwd: String,
    pub entry: String,
    pub host: String,
    /// The domain and subdomain the app was created under.
    ///
    /// Persisted and parsed back but never read — the panel derives an app's
    /// address from `host`. Kept because they record what the app was
    /// registered as, and scoped rather than allowed struct-wide so a field
    /// that really falls out of use still gets flagged.
    #[allow(dead_code)]
    pub domain: String,
    #[allow(dead_code)]
    pub subdomain: String,
    pub node_version: String,
    pub created_at: Option<u64>,
    /// Per-app memory cap in bytes. `None` means "auto": the app shares
    /// whatever is left of the account's allowance with the other auto apps.
    pub memory_max: Option<u64>,
}

/// Creates the state dir and operational subdirs as root, then recursively
/// chowns the whole tree to the target user. The recursive chown is required
/// because a previous run with different ownership could otherwise leave
/// stale entries the user can't touch.
pub fn init_state_dir(state_dir: &Path, uid: u32, gid: u32) -> Result<()> {
    for dir in std::iter::once(state_dir.to_path_buf())
        .chain(STATE_SUBDIRS.iter().map(|s| state_dir.join(s)))
    {
        if !dir.is_dir() {
            std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 700 {}", dir.display()))?;
        }
    }

    // The parent dir (`/var/lib/selynt_panel/`) needs world-traverse so the
    // web server can reach into per-user state dirs.
    if let Some(parent) = state_dir.parent() {
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o711));
    }

    chown_recursive(state_dir, uid, gid)
        .with_context(|| format!("chown -R {uid}:{gid} {}", state_dir.display()))?;

    // `.run` is handed back to root, with the sticky bit and group write. The
    // account still creates its own `.pid`/`.meta`/`.enabled` there, but the
    // sticky bit stops it removing or replacing entries it does not own — and
    // `.app`, the only file that says what to execute, is written as root.
    // Without this an app could delete a neighbour's `.app`, or drop in one of
    // its own for the panel to launch.
    let run_dir = state_dir.join(".run");
    if run_dir.is_dir() {
        chown_path(&run_dir, 0, gid)
            .with_context(|| format!("chown root:{gid} {}", run_dir.display()))?;
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o1770))
            .with_context(|| format!("chmod 1770 {}", run_dir.display()))?;
    }

    Ok(())
}

/// Creates `{cwd}/logs/` owned by the target user. Called as root before the
/// privilege drop so the app can write logs after dropping.
pub fn init_app_logs_dir(cwd: &Path, uid: u32, gid: u32) -> Result<()> {
    let logs_dir = cwd.join("logs");
    if !logs_dir.is_dir() {
        std::fs::create_dir_all(&logs_dir)
            .with_context(|| format!("mkdir {}", logs_dir.display()))?;
    }
    let logs_str = logs_dir
        .to_str()
        .with_context(|| format!("non-UTF8 path {}", logs_dir.display()))?;
    let cpath = std::ffi::CString::new(logs_str)
        .with_context(|| format!("invalid path {}", logs_dir.display()))?;
    if unsafe { libc::chown(cpath.as_ptr(), uid, gid) } != 0 {
        anyhow::bail!(
            "chown {} to {uid}:{gid}: {}",
            logs_dir.display(),
            std::io::Error::last_os_error()
        );
    }
    std::fs::set_permissions(&logs_dir, std::fs::Permissions::from_mode(0o750))
        .with_context(|| format!("chmod 750 {}", logs_dir.display()))?;

    // The log files themselves, not just the directory: they are created while
    // still root, in the prelude, so they would be left root-owned and the app
    // could not reopen them on the next start.
    if let Ok(entries) = std::fs::read_dir(&logs_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                let _ = chown_path(&p, uid, gid);
            }
        }
    }
    Ok(())
}

/// Every account with panel state, as `(state_dir, username)`.
///
/// One place to decide what counts as an account. The state base also holds
/// dotfiles, and a directory can outlive the account it belonged to — filtering
/// that in each caller is how the checks stopped agreeing with each other.
pub fn list_accounts() -> Vec<(PathBuf, String)> {
    let Ok(entries) = std::fs::read_dir(STATE_BASE) else {
        return Vec::new();
    };

    let mut accounts: Vec<(PathBuf, String)> = entries
        .flatten()
        .filter_map(|entry| {
            let dir = entry.path();
            let name = dir.file_name()?.to_str()?.to_string();
            if name.starts_with('.') || !dir.join(".run").is_dir() || !user_exists(&name) {
                return None;
            }
            Some((dir, name))
        })
        .collect();

    // Stable order, so output does not shuffle between runs.
    accounts.sort_by(|a, b| a.1.cmp(&b.1));
    accounts
}

/// Whether this account runs its apps isolated from each other.
///
/// Isolation is a property of the **account**, not of a single app. A namespace
/// confines what the process inside it can see; it does not change the uid, so
/// a non-isolated sibling — same uid, ordinary view of the host — could still
/// read an isolated app's files and signal its processes. Protecting one app
/// therefore only works if every app of the account is isolated.
pub fn account_is_isolated(state_dir: &Path) -> bool {
    std::fs::read_to_string(state_dir.join("isolated")).map_or_else(
        // No choice recorded for this account: fall back to the server-wide
        // default the admin set, so accounts that predate the setting behave as
        // decided without being touched one by one.
        //
        // With no default recorded either, isolation is **on**. It used to be
        // off, and for a reason that no longer holds: bubblewrap came from the
        // distribution and could simply be missing, so defaulting to on would
        // have refused to start apps on hosts that never had it. The panel now
        // ships its own binary, so the sandbox is there whenever the plugin is.
        //
        // Off by default meant every account paid nothing for isolation and got
        // none of it — an app reading its neighbour's `.env` was the norm, not
        // the exception.
        |_| {
            server_default_isolated(
                std::fs::read_to_string(format!("{PLUGIN_PATH}/etc/default_isolated")).ok(),
            )
        },
        |v| v.trim() == "1",
    )
}

/// O padrão do servidor, a partir do conteúdo de `etc/default_isolated`.
///
/// Separado para poder ser testado sem escrever no diretório do plugin.
fn server_default_isolated(conteudo: Option<String>) -> bool {
    conteudo.is_none_or(|v| v.trim() == "1")
}

/// Comandos npm que o painel sabe executar.
///
/// É o teto do preset: o admin escolhe quais destes ficam liberados, mas não
/// acrescenta um que não esteja aqui. Comando novo é código novo no core, com a
/// sua própria análise — `exec` e `publish`, por exemplo, nunca entram.
pub const NPM_COMMANDS: [&str; 4] = ["install", "update", "ci", "run"];

/// Política do servidor para os comandos npm do painel.
///
/// Uma só para o servidor inteiro, e só o admin altera: não há preset por
/// conta nem exceção por revendedor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmPolicy {
    /// Comandos liberados, na ordem de [`NPM_COMMANDS`].
    pub commands: Vec<String>,
    /// Se `install`, `update` e `ci` rodam com `--ignore-scripts`.
    pub ignore_scripts: bool,
}

impl NpmPolicy {
    pub fn allows(&self, command: &str) -> bool {
        self.commands.iter().any(|c| c == command)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "commands": self.commands,
            "ignore_scripts": self.ignore_scripts,
        })
    }

    /// Conteúdo do arquivo `etc/npm_policy`.
    pub fn to_file(&self) -> String {
        format!(
            "commands={}\nignore_scripts={}\n",
            self.commands.join(","),
            u8::from(self.ignore_scripts)
        )
    }

    /// Monta a política a partir do que o admin pediu, descartando o que não é
    /// comando conhecido.
    pub fn from_request(commands: &str, ignore_scripts: bool) -> Self {
        Self {
            commands: known_commands(commands),
            ignore_scripts,
        }
    }
}

/// Os comandos conhecidos de uma lista separada por vírgula, na ordem do
/// catálogo e sem repetição.
fn known_commands(lista: &str) -> Vec<String> {
    let pedidos: Vec<&str> = lista.split(',').map(str::trim).collect();
    NPM_COMMANDS
        .iter()
        .filter(|c| pedidos.contains(c))
        .map(ToString::to_string)
        .collect()
}

/// A política em vigor, lida de `etc/npm_policy`.
pub fn npm_policy() -> NpmPolicy {
    parse_npm_policy(
        std::fs::read_to_string(format!("{PLUGIN_PATH}/etc/npm_policy"))
            .ok()
            .as_deref(),
    )
}

/// A política a partir do conteúdo do arquivo.
///
/// Sem arquivo, vale o que o painel sempre fez: os quatro comandos, com os
/// scripts de instalação desligados. Na dúvida, o lado seguro: só um `0`
/// explícito libera os scripts, e comando desconhecido é descartado.
fn parse_npm_policy(conteudo: Option<&str>) -> NpmPolicy {
    let kv = conteudo.map(parse_kv).unwrap_or_default();

    let commands = kv.get("commands").map_or_else(
        || NPM_COMMANDS.iter().map(ToString::to_string).collect(),
        |lista| known_commands(lista),
    );
    let ignore_scripts = kv.get("ignore_scripts").is_none_or(|v| v.trim() != "0");

    NpmPolicy {
        commands,
        ignore_scripts,
    }
}

/// The socket path a running app actually has, recorded when it started.
///
/// Not the same as `socket_path_for` once the isolation mode changes: the path
/// moves, but a running app keeps the one it launched with. Stops and cleanups
/// must act on this, or they strand the real file and delete one that was never
/// there. Falls back to the configured path when nothing was recorded.
pub fn active_socket_path(state_dir: &Path, meta: &AppMeta) -> PathBuf {
    let meta_file = state_dir.join(".run").join(format!("{}.meta", meta.name));

    std::fs::read_to_string(meta_file)
        .ok()
        .and_then(|c| parse_kv(&c).get("socket").cloned())
        .map_or_else(|| socket_path_for(state_dir, meta), PathBuf::from)
}

/// Maior caminho que cabe em `sockaddr_un.sun_path` (108 bytes com o NUL).
///
/// É ABI do kernel, não escolha do painel: nenhum processo faz `bind()` ou
/// `connect()` num socket Unix de caminho maior. O app escuta neste caminho e
/// o servidor web conecta nele, então os dois lados falhariam.
pub const SUN_PATH_MAX: usize = 107;

/// Identificador de tamanho fixo do diretório de socket de um app.
///
/// O caminho já foi montado com o nome do app e o domínio — até 64 e 253
/// caracteres —, e passava do limite de `sun_path` sem nenhum aviso: o app
/// nunca ficava pronto e o proxy respondia 503. Aqui o nome entra num hash
/// FNV-1a de 64 bits, e o caminho fica com tamanho constante. A unicidade
/// dentro da conta é verificada no `add`, não presumida.
pub fn socket_id(name: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Where an app's Unix socket lives: `.sockets/<id>/app.sock`.
///
/// Um diretório por app, com ou sem isolamento: isolado, o sandbox monta só
/// esse diretório no namespace, e o socket de um vizinho nem existe ali. O
/// arquivo continua real no host — o proxy precisa alcançá-lo. Nada de tamanho
/// variável entra no caminho além do diretório de estado da conta.
pub fn socket_path_for(state_dir: &Path, meta: &AppMeta) -> PathBuf {
    state_dir
        .join(".sockets")
        .join(socket_id(&meta.name))
        .join("app.sock")
}

/// Apaga o socket com que o app subiu e o diretório dele, se ficar vazio.
///
/// O diretório é do app (`.sockets/<id>`, ou `.sockets/<nome>` no layout
/// anterior): deixá-lo para trás acumulava pastas vazias a cada troca de
/// layout. `remove_dir` só apaga diretório vazio, e o `.sockets` compartilhado
/// nunca é alvo.
pub fn remove_socket(state_dir: &Path, meta: &AppMeta) {
    let socket = active_socket_path(state_dir, meta);
    let _ = std::fs::remove_file(&socket);
    if let Some(dir) = socket.parent().filter(|d| *d != state_dir.join(".sockets")) {
        let _ = std::fs::remove_dir(dir);
    }
}

/// Se o caminho cabe num `sockaddr_un`.
pub fn socket_path_fits(path: &Path) -> bool {
    path.as_os_str().len() <= SUN_PATH_MAX
}

pub fn load_app_meta(state_dir: &Path, name: &str) -> Result<AppMeta> {
    let app_file = state_dir.join(".run").join(format!("{name}.app"));

    // `.run` has to stay writable for the account's own `.pid`/`.meta`, so an
    // app can still drop a file in it. Only root writes `.app`, so anything
    // with another owner was forged — refuse it rather than launch whatever it
    // describes.
    let owner = std::fs::metadata(&app_file)
        .with_context(|| format!("app '{name}' not found"))?
        .uid();
    if owner != 0 {
        anyhow::bail!("app '{name}' has untrusted metadata (owner uid {owner}, expected root)");
    }

    let content =
        std::fs::read_to_string(&app_file).with_context(|| format!("app '{name}' not found"))?;
    let kv = parse_kv(&content);

    Ok(AppMeta {
        name: name.to_string(),
        app_type: kv.get("type").cloned().unwrap_or_default(),
        cwd: kv.get("cwd").cloned().unwrap_or_default(),
        entry: kv.get("entry").cloned().unwrap_or_default(),
        host: kv.get("host").cloned().unwrap_or_default(),
        domain: kv.get("domain").cloned().unwrap_or_default(),
        subdomain: kv.get("subdomain").cloned().unwrap_or_default(),
        node_version: kv.get("node_version").cloned().unwrap_or_default(),
        memory_max: kv
            .get("memory_max")
            .and_then(|v| v.parse().ok())
            .filter(|&n| n > 0),
        created_at: kv.get("created_at").and_then(|v| v.parse().ok()),
    })
}

pub fn list_app_names(state_dir: &Path) -> Vec<String> {
    let run_dir = state_dir.join(".run");
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&run_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            // Same reasoning as `load_app_meta`: a `.app` not owned by root was
            // planted by the account, so it is not an app the panel knows.
            if path.extension().and_then(|e| e.to_str()) == Some("app")
                && std::fs::metadata(&path).is_ok_and(|m| m.uid() == 0)
                && let Some(name) = path.file_stem().and_then(|s| s.to_str())
            {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    names
}

/// Validates an app name against `^[A-Za-z0-9._-]{1,64}$`.
pub fn validate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Reads the web user used for ACLs from `etc/ols_web_user`, or an empty string
/// when unset, in which case `apply_acl` skips ACL configuration.
///
/// `SELYNT_WEB_USER` is honoured only for root, as a debugging escape hatch:
/// this decides which account ACLs are granted to, so an unprivileged caller
/// setting it could open up another user's app directories.
pub fn get_web_user() -> String {
    if unsafe { libc::getuid() } == 0
        && let Ok(u) = std::env::var("SELYNT_WEB_USER")
    {
        return u;
    }
    std::fs::read_to_string(format!("{PLUGIN_PATH}/etc/ols_web_user"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[cfg(test)]
mod default_isolated_tests {
    use super::server_default_isolated;

    /// Sem nada configurado, o isolamento vale. Foi uma inversão deliberada: só
    /// passou a ser possível quando o painel passou a distribuir o próprio
    /// bubblewrap, e antes disso ligar por padrão teria recusado iniciar
    /// aplicações em servidores sem o pacote da distribuição.
    #[test]
    fn isolation_is_on_when_nothing_was_configured() {
        assert!(server_default_isolated(None));
    }

    #[test]
    fn the_admin_choice_wins_in_both_directions() {
        assert!(server_default_isolated(Some("1".to_string())));
        assert!(!server_default_isolated(Some("0".to_string())));
        assert!(server_default_isolated(Some("1\n".to_string())));
        assert!(!server_default_isolated(Some("0\n".to_string())));
    }

    /// Um arquivo vazio ou corrompido não pode ligar o isolamento por engano:
    /// só o `1` explícito conta como escolha por ligar.
    #[test]
    fn only_an_explicit_one_counts_as_enabled() {
        assert!(!server_default_isolated(Some(String::new())));
        assert!(!server_default_isolated(Some("lixo".to_string())));
    }
}

#[cfg(test)]
mod npm_policy_tests {
    use super::{NPM_COMMANDS, NpmPolicy, parse_npm_policy};

    /// Sem preset gravado, o comportamento é o de antes de ele existir.
    #[test]
    fn without_a_file_everything_is_allowed_and_scripts_stay_off() {
        let p = parse_npm_policy(None);
        assert_eq!(p.commands, NPM_COMMANDS);
        assert!(p.ignore_scripts);
    }

    #[test]
    fn the_file_round_trips() {
        let p = NpmPolicy::from_request("run,install", false);
        assert_eq!(p.commands, ["install", "run"]);
        assert_eq!(parse_npm_policy(Some(&p.to_file())), p);
    }

    /// O arquivo não amplia o catálogo: um comando que o core não conhece não
    /// vira comando por estar escrito ali.
    #[test]
    fn unknown_commands_are_dropped() {
        let p = parse_npm_policy(Some("commands=install,exec, publish ,run\n"));
        assert_eq!(p.commands, ["install", "run"]);
    }

    /// Lista vazia é escolha do admin — nada liberado —, não arquivo ausente.
    #[test]
    fn an_empty_list_allows_nothing() {
        let p = parse_npm_policy(Some("commands=\nignore_scripts=1\n"));
        assert_eq!(p.commands, Vec::<String>::new());
        assert!(!p.allows("install"));
    }

    /// Só o `0` explícito libera os scripts de instalação.
    #[test]
    fn only_an_explicit_zero_enables_install_scripts() {
        for v in ["1", "", "lixo", "false"] {
            let p = parse_npm_policy(Some(&format!("ignore_scripts={v}\n")));
            assert!(p.ignore_scripts, "{v:?} não deveria liberar os scripts");
        }
        assert!(!parse_npm_policy(Some("ignore_scripts=0\n")).ignore_scripts);
    }
}

#[cfg(test)]
mod socket_path_tests {
    use super::{AppMeta, SUN_PATH_MAX, socket_id, socket_path_fits, socket_path_for};
    use std::path::Path;

    fn meta(name: &str, host: &str) -> AppMeta {
        AppMeta {
            name: name.to_string(),
            app_type: "node".to_string(),
            cwd: "/home/bob/apps/x".to_string(),
            entry: "index.js".to_string(),
            host: host.to_string(),
            domain: String::new(),
            subdomain: String::new(),
            node_version: String::new(),
            created_at: None,
            memory_max: None,
        }
    }

    /// O pior caso que o painel aceita — nome de 64 e domínio de 253 — cabe
    /// com folga. Antes, só o nome já passava do limite.
    #[test]
    fn the_longest_name_and_host_still_fit() {
        let state = Path::new("/var/lib/selynt_panel/uma-conta-de-nome-longo");
        let m = meta(&"a".repeat(64), &format!("{}.exemplo.com", "b".repeat(240)));
        let p = socket_path_for(state, &m);
        assert!(socket_path_fits(&p), "{} bytes", p.as_os_str().len());
        assert!(p.as_os_str().len() < SUN_PATH_MAX - 20);
    }

    /// O domínio não entra no caminho: trocar o host não move o socket.
    #[test]
    fn the_host_does_not_shape_the_path() {
        let state = Path::new("/var/lib/selynt_panel/bob");
        assert_eq!(
            socket_path_for(state, &meta("api", "a.exemplo.com")),
            socket_path_for(state, &meta("api", "outro.exemplo.org"))
        );
    }

    #[test]
    fn the_id_is_fixed_size_and_stable() {
        let id = socket_id("api");
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, socket_id("api"));
        assert_ne!(id, socket_id("api2"));
        assert_eq!(socket_id(&"z".repeat(64)).len(), 16);
    }

    /// A pasta do app sai junto com o socket; a `.sockets` compartilhada,
    /// onde o layout antigo sem isolamento punha o socket direto, fica.
    #[test]
    fn removing_the_socket_takes_the_app_folder_but_not_the_shared_one() {
        let base = std::env::temp_dir().join(format!("selynt-rmsock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let run = base.join(".run");
        let sockets = base.join(".sockets");
        std::fs::create_dir_all(&run).unwrap();

        for (nome, socket) in [
            ("novo", sockets.join("abc").join("app.sock")),
            ("antigo", sockets.join("antigo.exemplo.com")),
        ] {
            std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
            std::fs::write(&socket, "").unwrap();
            std::fs::write(
                run.join(format!("{nome}.meta")),
                format!("socket={}\n", socket.display()),
            )
            .unwrap();
            super::remove_socket(&base, &meta(nome, "x.exemplo.com"));
            assert!(!socket.exists(), "{nome}: o socket ficou");
        }
        assert!(!sockets.join("abc").exists(), "a pasta do app ficou");
        assert!(sockets.is_dir(), "a pasta compartilhada foi apagada");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_path_over_the_kernel_limit_is_refused() {
        let longo = format!("/{}", "x".repeat(SUN_PATH_MAX));
        assert!(!socket_path_fits(Path::new(&longo)));
        assert!(socket_path_fits(Path::new(&longo[..SUN_PATH_MAX])));
    }
}
