//! Execução de comandos npm de uma aplicação, como trabalho de fundo.
//!
//! O painel precisa oferecer `npm install` e os scripts do `package.json` a
//! quem não tem SSH — em hospedagem compartilhada, é comum não ter. O que torna
//! isso seguro é onde o comando roda, não o que ele é: sempre dentro do
//! bubblewrap que o painel distribui, vendo apenas o diretório da própria
//! aplicação.
//!
//! A execução se desprende da requisição HTTP de propósito. Presa a ela, um
//! `npm install` de três minutos morre quando o navegador desiste, e o cliente
//! fica sem saber se rodou — é a queixa conhecida de quem usa o painel da Cloud Linux. Aqui
//! o comando roda em processo próprio e escreve o progresso em disco; a página
//! consulta e pode ser fechada.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::sys::output::{success, user_error};
use crate::sys::state::{AppMeta, load_app_meta};

use super::with_debug;

/// Quanto um comando pode demorar antes de ser encerrado.
///
/// `npm install` de projeto grande passa de um minuto com folga; o que este
/// teto existe para cortar é o comando que travou — esperando entrada que
/// ninguém vai dar, ou preso numa rede que não responde.
const TIMEOUT_SECS: u64 = 900;

/// O que o painel pode pedir para executar.
///
/// Lista fechada: o cliente escolhe entre isto e os scripts que ele mesmo
/// declarou no `package.json`. Não há caminho para um comando arbitrário.
#[derive(Clone, Copy)]
pub enum Kind {
    Install,
    Update,
    Ci,
    Run,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "install" => Some(Self::Install),
            "update" => Some(Self::Update),
            "ci" => Some(Self::Ci),
            "run" => Some(Self::Run),
            _ => None,
        }
    }

    const fn npm_arg(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Update => "update",
            Self::Ci => "ci",
            Self::Run => "run",
        }
    }

    /// Se o comando reescreve `node_modules`.
    ///
    /// Estes exigem a aplicação parada: trocar a árvore de dependências sob um
    /// processo que está lendo dela quebra o app de formas que não dão erro
    /// claro — módulo que some no meio de um `require`, versão que muda entre
    /// dois imports.
    const fn rewrites_tree(self) -> bool {
        matches!(self, Self::Install | Self::Update | Self::Ci)
    }
}

/// Arquivos de um job, em `.run/` — do root, com sticky bit, onde a conta não
/// apaga nem reescreve o que não é dela.
struct Paths {
    state: PathBuf,
    log: PathBuf,
}

impl Paths {
    fn new(state_dir: &Path, app: &str) -> Self {
        let run = state_dir.join(".run");
        Self {
            state: run.join(format!("{app}.job")),
            log: run.join(format!("{app}.job.log")),
        }
    }
}

/// Monta o comando npm já confinado.
///
/// O npm é invocado com o `node` da aplicação no `PATH`, não com o do sistema:
/// a versão que instala as dependências tem de ser a mesma que vai executá-las,
/// senão módulo nativo compila para o binário errado.
fn build_command(meta: &AppMeta, kind: Kind, script: &str, args: &[String]) -> Command {
    let inner = build_inner(meta, kind, script, args);
    let cwd = PathBuf::from(&meta.cwd);
    crate::limits::sandbox::wrap_command(&inner, &cwd)
}

/// Monta o comando npm em si, antes do confinamento.
fn build_inner(meta: &AppMeta, kind: Kind, script: &str, args: &[String]) -> Command {
    let node_bin = if meta.node_version.is_empty() {
        crate::runtime::detect::default_node_path().unwrap_or_else(|| "node".to_string())
    } else {
        meta.node_version.clone()
    };

    // `npm` mora ao lado do `node` da mesma instalação.
    let node_dir = Path::new(&node_bin)
        .parent()
        .map_or_else(|| PathBuf::from("/usr/local/bin"), Path::to_path_buf);
    let npm = node_dir.join("npm");

    let mut inner = Command::new(&npm);
    inner.arg(kind.npm_arg());

    if matches!(kind, Kind::Run) {
        inner.arg(script);
    }

    // Sem os scripts do pacote: `postinstall` de uma dependência transitiva é
    // código de terceiro que o cliente nunca leu, e é por onde os ataques de
    // supply chain entram. Não protege contra o próprio cliente — ele tem FTP —,
    // e sim contra o que ele não escolheu.
    if kind.rewrites_tree() {
        inner.arg("--ignore-scripts");
    }
    inner.arg("--no-audit").arg("--no-fund");

    // Argumentos do usuário depois de `--`, senão o npm os consome como opções
    // dele em vez de repassar ao script.
    if !args.is_empty() && matches!(kind, Kind::Run) {
        inner.arg("--");
        for a in args {
            inner.arg(a);
        }
    }

    inner.current_dir(&meta.cwd);
    inner.env("PATH", format!("{}:/usr/bin:/bin", node_dir.display()));
    inner.env("HOME", &meta.cwd);
    // Sem TTY o npm ainda tenta desenhar barra de progresso, e o log fica cheio
    // de sequências de escape que ninguém vai ler.
    inner.env("NO_COLOR", "1");
    inner.env("npm_config_progress", "false");

    inner
}

/// Só o comando npm, sem o confinamento.
///
/// Existe para os testes: `build_command` termina em `wrap_command`, que encerra
/// o processo quando o bwrap não está instalado — e ele não está na máquina de
/// quem desenvolve nem na CI. Sem esta separação os testes do npm não teriam
/// como rodar, e a alternativa (pular quando falta o binário) já se mostrou
/// pior: eles passariam sem verificar nada.
/// Interrompe o comando em execução.
///
/// Envia `SIGINT` — o mesmo que o Ctrl+C de um terminal —, que é o sinal que o
/// npm e as ferramentas de build sabem tratar: elas limpam o que estavam
/// escrevendo antes de sair. Só depois, se o processo insistir, vem o
/// `SIGKILL`, que não dá essa chance e pode deixar `node_modules` pela metade.
///
/// O sinal vai para o **grupo** de processos, não só para o líder: o npm
/// delega a outros processos, e matar apenas o pai deixaria os filhos rodando.
pub fn cmd_stop_job(state_dir: &Path, app: &str, gid: u32, dbg: Option<&Value>) -> ! {
    if load_app_meta(state_dir, app).is_err() {
        user_error("app_not_found", &format!("app '{app}' not found"));
    }
    let paths = Paths::new(state_dir, app);

    let Ok(raw) = std::fs::read_to_string(&paths.state) else {
        user_error("no_job", "no command is running");
    };
    let Ok(estado) = serde_json::from_str::<Value>(&raw) else {
        user_error("no_job", "no command is running");
    };
    if estado.get("status").and_then(Value::as_str) != Some("running") {
        user_error("no_job", "no command is running");
    }
    let Some(pid) = estado.get("pid").and_then(Value::as_u64) else {
        user_error("no_job", "the running command has no process to stop");
    };

    let alvo = nix::unistd::Pid::from_raw(-(i32::try_from(pid).unwrap_or(0)));
    let _ = nix::sys::signal::kill(alvo, nix::sys::signal::Signal::SIGINT);

    // Dá tempo de encerrar por conta própria antes de insistir.
    for _ in 0..25 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if !crate::sys::proc::is_process_alive(u32::try_from(pid).unwrap_or(0)) {
            break;
        }
    }
    if crate::sys::proc::is_process_alive(u32::try_from(pid).unwrap_or(0)) {
        let _ = nix::sys::signal::kill(alvo, nix::sys::signal::Signal::SIGKILL);
    }

    write_state(
        &paths,
        gid,
        &json!({
            "status": "stopped",
            "command": estado.get("command").and_then(Value::as_str).unwrap_or(""),
            "started_at": estado.get("started_at").and_then(Value::as_u64).unwrap_or(0),
            "finished_at": now_secs(),
        }),
    );

    success(with_debug(json!({ "stopped": true }), dbg));
}

#[cfg(test)]
fn build_npm_command(meta: &AppMeta, kind: Kind, script: &str, args: &[String]) -> Command {
    build_inner(meta, kind, script, args)
}

/// Grava o estado do job. Escrita atômica: a página consulta a qualquer
/// momento e não pode ler um arquivo pela metade.
fn write_state(paths: &Paths, gid: u32, state: &Value) {
    let body = state.to_string();
    if crate::sys::fs::atomic_write(&paths.state, body.as_bytes()).is_ok() {
        // A conta precisa ler o próprio job; escrever, não — o arquivo fica em
        // `.run`, que tem sticky bit e dono root.
        let _ = crate::sys::fs::set_perm(&paths.state, 0o640);
        let _ = crate::sys::fs::chown_path(&paths.state, 0, gid);
    }
}

/// Executa o comando e devolve `(código de saída, encerrado por tempo)`.
///
/// Chamado no processo filho, depois do fork: aqui a espera não prende ninguém.
fn run_to_completion(mut cmd: Command, log: &Path) -> (i32, bool) {
    let Ok(file) = std::fs::File::create(log) else {
        return (-1, false);
    };
    let Ok(err_file) = file.try_clone() else {
        return (-1, false);
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(err_file));

    let Ok(mut child) = cmd.spawn() else {
        return (-1, false);
    };

    let inicio = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (status.code().unwrap_or(-1), false),
            Ok(None) => {}
            Err(_) => return (-1, false),
        }
        if inicio.elapsed().as_secs() >= TIMEOUT_SECS {
            let _ = child.kill();
            let _ = child.wait();
            return (-1, true);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Executa um comando npm da aplicação.
///
/// Roda do lado da conta, depois da queda de privilégio: o que instala
/// dependências e o que as executa precisam ser o mesmo usuário, senão os
/// arquivos saem com dono errado e a aplicação não os lê.
pub fn cmd_run_job(
    state_dir: &Path,
    app: &str,
    kind_raw: &str,
    script: &str,
    args_raw: &str,
    gid: u32,
    dbg: Option<&Value>,
) -> ! {
    let Ok(meta) = load_app_meta(state_dir, app) else {
        user_error("app_not_found", &format!("app '{app}' not found"));
    };
    if meta.app_type != "node" {
        user_error("not_node", "only Node.js apps run npm commands");
    }

    let Some(kind) = Kind::parse(kind_raw) else {
        user_error("invalid_command", &format!("unknown command '{kind_raw}'"));
    };

    // Nome de script vem do `package.json` do cliente, mas chega até aqui pela
    // rede: é aqui que ele deixa de ser dado e vira parte de uma linha de
    // comando.
    if matches!(kind, Kind::Run) && !super::commands::is_safe_script_name(script) {
        user_error("invalid_script", "script name is not acceptable");
    }
    let args = match super::commands::split_arguments(args_raw) {
        Ok(a) => a,
        Err(e) => user_error("invalid_arguments", &e),
    };

    // Reescrever `node_modules` sob a aplicação em execução a quebra sem dar
    // erro claro; melhor recusar e dizer o que fazer.
    if kind.rewrites_tree() {
        let (status, _, _) = super::get_status(state_dir, app);
        if status == "RUNNING" {
            user_error(
                "app_running",
                "stop the application before changing its dependencies",
            );
        }
    }

    let paths = Paths::new(state_dir, app);

    // Um job por aplicação: dois `npm install` na mesma árvore corrompem
    // `node_modules` de um jeito que só aparece depois, no start.
    if let Ok(raw) = std::fs::read_to_string(&paths.state)
        && let Ok(atual) = serde_json::from_str::<Value>(&raw)
        && atual.get("status").and_then(Value::as_str) == Some("running")
    {
        user_error("job_running", "another command is already running");
    }

    let rotulo = if matches!(kind, Kind::Run) {
        format!("npm run {script}")
    } else {
        format!("npm {}", kind.npm_arg())
    };
    let inicio = now_secs();

    write_state(
        &paths,
        gid,
        &json!({
            "status": "running",
            "command": rotulo,
            "started_at": inicio,
        }),
    );

    let cmd = build_command(&meta, kind, script, &args);

    // O comando roda desprendido da requisição. Um `npm install` grande passa
    // do timeout do CGI com folga, e prender a resposta a ele significaria a
    // página perder a execução no meio — exatamente o que o painel do
    // concorrente faz e que este desenho existe para evitar. Quem quer saber
    // como terminou consulta `job-status`.
    // `fork` é unsafe porque o filho herda o estado da memória e só pode chamar
    // funções async-signal-safe até o exec. Aqui é seguro: nada de threads (o
    // binário é single-threaded), e o filho vai direto para `setsid` e `spawn`,
    // sem alocar nem tocar em estado compartilhado.
    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { .. }) => {
            success(with_debug(
                json!({ "status": "running", "command": rotulo }),
                dbg,
            ));
        }
        Ok(nix::unistd::ForkResult::Child) => {}
        Err(e) => {
            user_error("fork_failed", &format!("could not start the command: {e}"));
        }
    }

    // Daqui para baixo é o filho. Nova sessão, para não morrer junto com o
    // processo que atendeu a requisição — e para ser o líder do grupo, de modo
    // que a interrupção alcance o npm e tudo o que ele criou.
    let _ = nix::unistd::setsid();

    // O PID vai para o estado: é por ele que `stop-job` encontra o que
    // interromper. Gravado antes de começar, senão um comando que trava logo no
    // início ficaria sem como ser parado.
    write_state(
        &paths,
        gid,
        &json!({
            "status": "running",
            "command": rotulo,
            "started_at": inicio,
            "pid": std::process::id(),
        }),
    );

    let (code, timed_out) = run_to_completion(cmd, &paths.log);

    let status = if timed_out {
        "timeout"
    } else if code == 0 {
        "ok"
    } else {
        "failed"
    };
    write_state(
        &paths,
        gid,
        &json!({
            "status": status,
            "command": rotulo,
            "started_at": inicio,
            "finished_at": now_secs(),
            "exit_code": code,
        }),
    );

    // O filho não responde ao painel: quem perguntou já recebeu "running".
    std::process::exit(0);
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Estado do último comando npm da aplicação, com o log.
///
/// É o que faz a página reencontrar uma execução em andamento depois de um
/// recarregamento — o job vive no servidor, não na aba do navegador.
pub fn cmd_job_status(state_dir: &Path, app: &str, dbg: Option<&Value>) -> ! {
    if load_app_meta(state_dir, app).is_err() {
        user_error("app_not_found", &format!("app '{app}' not found"));
    }
    let paths = Paths::new(state_dir, app);

    let Ok(raw) = std::fs::read_to_string(&paths.state) else {
        success(with_debug(json!({ "job": Value::Null }), dbg));
    };
    let Ok(mut estado) = serde_json::from_str::<Value>(&raw) else {
        success(with_debug(json!({ "job": Value::Null }), dbg));
    };

    // O log é a saída do npm, que já vem sem cor: as sequências de escape
    // atrapalhariam a leitura na tela tanto quanto no log da aplicação.
    let linhas = super::logs::read_tail(&paths.log, 400)
        .into_iter()
        .map(|l| super::logs::strip_ansi(&l))
        .collect::<Vec<_>>();

    if let Some(obj) = estado.as_object_mut() {
        obj.insert("lines".to_string(), json!(linhas));
    }

    success(with_debug(json!({ "job": estado }), dbg));
}

#[cfg(test)]
mod tests {
    use super::{Kind, build_npm_command};
    use crate::sys::state::AppMeta;

    fn meta(cwd: &str) -> AppMeta {
        AppMeta {
            name: "api".to_string(),
            app_type: "node".to_string(),
            cwd: cwd.to_string(),
            entry: "index.js".to_string(),
            host: "x.test".to_string(),
            domain: String::new(),
            subdomain: String::new(),
            node_version: "/usr/local/bin/node".to_string(),
            created_at: None,
            memory_max: None,
        }
    }

    fn args_of(c: &std::process::Command) -> Vec<String> {
        c.get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect()
    }

    /// Só o que o painel oferece; qualquer outra coisa não vira comando.
    #[test]
    fn only_known_commands_are_accepted() {
        for k in ["install", "update", "ci", "run"] {
            assert!(Kind::parse(k).is_some(), "{k} deveria ser aceito");
        }
        for k in ["exec", "publish", "login", "install --force", ""] {
            assert!(Kind::parse(k).is_none(), "{k:?} deveria ser recusado");
        }
    }

    /// Instalar dependências é o momento em que código de terceiros chega à
    /// máquina; os hooks ficam de fora.
    #[test]
    fn dependency_commands_run_without_package_scripts() {
        for k in [Kind::Install, Kind::Update, Kind::Ci] {
            let c = build_npm_command(&meta("/home/bob/apps/api"), k, "", &[]);
            assert!(
                args_of(&c).contains(&"--ignore-scripts".to_string()),
                "{} deveria ignorar scripts",
                k.npm_arg()
            );
        }
    }

    /// `npm run` é o cliente pedindo para executar o próprio script: a flag
    /// aqui só quebraria o que ele escreveu.
    #[test]
    fn running_the_customers_own_script_keeps_scripts_enabled() {
        let c = build_npm_command(&meta("/home/bob/apps/api"), Kind::Run, "build", &[]);
        assert!(!args_of(&c).contains(&"--ignore-scripts".to_string()));
    }

    /// Sem o `--`, o npm consome os argumentos como opções dele.
    #[test]
    fn user_arguments_go_after_the_separator() {
        let c = build_npm_command(
            &meta("/home/bob/apps/api"),
            Kind::Run,
            "build",
            &["--production".to_string()],
        );
        let a = args_of(&c);
        let sep = a.iter().position(|x| x == "--").expect("faltou o --");
        let arg = a
            .iter()
            .position(|x| x == "--production")
            .expect("faltou o argumento");
        assert!(sep < arg, "o argumento tem de vir depois do --");
    }

    /// O comando roda vendo apenas o diretório da aplicação — é o que impede
    /// um `postinstall` de ler o `.env` do app vizinho.
    #[test]
    fn command_is_confined_to_the_application_directory() {
        let inner = build_npm_command(&meta("/home/bob/apps/api"), Kind::Install, "", &[]);
        let c = crate::limits::sandbox::wrap_command_with(
            "/opt/bwrap",
            &inner,
            std::path::Path::new("/home/bob/apps/api"),
        );
        let a = args_of(&c);
        assert!(
            a.windows(3)
                .any(|w| w == ["--bind", "/home/bob/apps/api", "/home/bob/apps/api"]),
            "faltou o bind do diretório da aplicação"
        );
        assert!(a.contains(&"--unshare-pid".to_string()));
        // O diretório do vizinho não pode aparecer em nenhum bind.
        assert!(!a.iter().any(|x| x.contains("/home/bob/apps/outro")));
    }

    #[test]
    fn only_dependency_commands_require_the_app_stopped() {
        assert!(Kind::Install.rewrites_tree());
        assert!(Kind::Update.rewrites_tree());
        assert!(Kind::Ci.rewrites_tree());
        assert!(!Kind::Run.rewrites_tree());
    }
}
