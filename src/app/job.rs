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
use crate::sys::state::{AppMeta, NpmPolicy, load_app_meta, npm_policy};

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
/// declarou no `package.json`. Não há caminho para um comando arbitrário. O
/// admin restringe ainda mais pelo preset do servidor (`etc/npm_policy`), mas
/// não amplia: o catálogo é [`crate::sys::state::NPM_COMMANDS`].
#[derive(Clone, Copy)]
pub enum Kind {
    Install,
    Update,
    Ci,
    Run,
    /// Recompila os módulos nativos para o Node em uso. Não é escolha do
    /// cliente no preset: é consequência da troca de versão.
    Rebuild,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "install" => Some(Self::Install),
            "update" => Some(Self::Update),
            "ci" => Some(Self::Ci),
            "run" => Some(Self::Run),
            "rebuild" => Some(Self::Rebuild),
            _ => None,
        }
    }

    const fn npm_arg(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Update => "update",
            Self::Ci => "ci",
            Self::Run => "run",
            Self::Rebuild => "rebuild",
        }
    }

    /// Se o comando reescreve `node_modules`.
    ///
    /// Estes exigem a aplicação parada: trocar a árvore de dependências sob um
    /// processo que está lendo dela quebra o app de formas que não dão erro
    /// claro — módulo que some no meio de um `require`, versão que muda entre
    /// dois imports.
    const fn rewrites_tree(self) -> bool {
        matches!(
            self,
            Self::Install | Self::Update | Self::Ci | Self::Rebuild
        )
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
fn build_command(
    meta: &AppMeta,
    kind: Kind,
    script: &str,
    args: &[String],
    ignore_scripts: bool,
) -> Command {
    let inner = build_inner(meta, kind, script, args, ignore_scripts);
    let cwd = PathBuf::from(&meta.cwd);
    crate::limits::sandbox::wrap_command(&inner, &cwd)
}

/// Monta o comando npm em si, antes do confinamento.
fn build_inner(
    meta: &AppMeta,
    kind: Kind,
    script: &str,
    args: &[String],
    ignore_scripts: bool,
) -> Command {
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
    // e sim contra o que ele não escolheu. Ligado por padrão; o admin pode
    // desligar no preset, e é o que destrava pacote com build nativo.
    if kind.rewrites_tree() && ignore_scripts {
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

/// Nome do serviço do systemd em que o job de uma aplicação roda.
pub fn job_unit(username: &str, app: &str) -> String {
    format!("selynt-{username}-{app}-job.service")
}

/// O caminho do cgroup do job, como aparece em `/proc/<pid>/cgroup`.
fn job_cgroup(username: &str, app: &str) -> String {
    format!(
        "/{}/{}/{}",
        crate::limits::bindguard::SLICE_UNIT,
        crate::limits::policy::slice_unit_name(username),
        job_unit(username, app)
    )
}

/// PIDs do cgroup do job, ou vazio quando ele não está rodando.
pub fn job_pids(username: &str, app: &str) -> Vec<u32> {
    std::fs::read_to_string(format!(
        "/sys/fs/cgroup{}/cgroup.procs",
        job_cgroup(username, app)
    ))
    .unwrap_or_default()
    .lines()
    .filter_map(|l| l.trim().parse().ok())
    .collect()
}

/// Grava o estado do job. Escrita atômica: a página consulta a qualquer
/// momento e não pode ler um arquivo pela metade.
///
/// O arquivo fica com a conta: é ela, dentro do serviço do job, que grava o
/// andamento e o desfecho. Quando o lado root grava (início, interrupção), o
/// `atomic_write` não segue symlink e o dono volta para a conta.
fn write_state(paths: &Paths, uid: u32, gid: u32, state: &Value) {
    let body = state.to_string();
    if crate::sys::fs::atomic_write(&paths.state, body.as_bytes()).is_ok() {
        let _ = crate::sys::fs::set_perm(&paths.state, 0o640);
        let _ = crate::sys::fs::chown_path(&paths.state, uid, gid);
    }
}

fn read_state(paths: &Paths) -> Option<Value> {
    if !crate::sys::fs::is_regular_file(&paths.state) {
        return None;
    }
    serde_json::from_str(&std::fs::read_to_string(&paths.state).ok()?).ok()
}

/// O que foi pedido, já validado.
struct Request {
    meta: AppMeta,
    kind: Kind,
    policy: crate::sys::state::NpmPolicy,
    script: String,
    args: Vec<String>,
    rotulo: String,
}

/// Valida um pedido de job. Roda nos dois lados: no root antes de lançar, e
/// de novo dentro do serviço, que não confia no que recebeu pela linha de
/// comando.
fn validate(
    state_dir: &Path,
    app: &str,
    kind_raw: &str,
    script: &str,
    args_raw: &str,
) -> Result<Request, (String, String)> {
    let err = |c: &str, m: String| (c.to_string(), m);
    let meta = load_app_meta(state_dir, app)
        .map_err(|_| err("app_not_found", format!("app '{app}' not found")))?;
    if meta.app_type != "node" {
        return Err(err("not_node", "only Node.js apps run npm commands".into()));
    }
    let kind = Kind::parse(kind_raw)
        .ok_or_else(|| err("invalid_command", format!("unknown command '{kind_raw}'")))?;
    let policy = npm_policy();
    // O rebuild só existe para acompanhar a troca de versão e mexe na mesma
    // árvore que o install: vale o que o admin decidiu para o install. E sem
    // os scripts de instalação ele não recompila nada — recusar diz o motivo
    // em vez de rodar à toa e terminar "com sucesso".
    let liberado = if matches!(kind, Kind::Rebuild) {
        "install"
    } else {
        kind.npm_arg()
    };
    if !policy.allows(liberado) {
        return Err(err(
            "command_disabled",
            format!("the server administrator disabled 'npm {}'", kind.npm_arg()),
        ));
    }
    if matches!(kind, Kind::Rebuild) && policy.ignore_scripts {
        return Err(err(
            "rebuild_needs_scripts",
            "native modules cannot be rebuilt while install scripts are disabled on this server"
                .into(),
        ));
    }
    // Nome de script vem do `package.json` do cliente, mas chega até aqui pela
    // rede: é aqui que ele deixa de ser dado e vira parte de uma linha de
    // comando.
    if matches!(kind, Kind::Run) && !super::commands::is_safe_script_name(script) {
        return Err(err(
            "invalid_script",
            "script name is not acceptable".into(),
        ));
    }
    let args =
        super::commands::split_arguments(args_raw).map_err(|e| err("invalid_arguments", e))?;
    // Reescrever `node_modules` sob a aplicação em execução a quebra sem dar
    // erro claro; melhor recusar e dizer o que fazer.
    if kind.rewrites_tree() && super::get_status(state_dir, app).0 == "RUNNING" {
        return Err(err(
            "app_running",
            "stop the application before changing its dependencies".into(),
        ));
    }
    let rotulo = if matches!(kind, Kind::Run) {
        format!("npm run {script}")
    } else {
        format!("npm {}", kind.npm_arg())
    };
    Ok(Request {
        meta,
        kind,
        policy,
        script: script.to_string(),
        args,
        rotulo,
    })
}

fn unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .is_ok_and(|s| s.success())
}

/// Lança um comando npm da aplicação, num serviço próprio do systemd.
///
/// Roda no lado root, antes da queda de privilégio. O job não é mais filho do
/// processo que atendeu a requisição: nasce como `selynt-<conta>-<app>-job`,
/// dentro do slice da conta, rodando como a conta. Por estar sob o
/// `selynt.slice` herda o gancho de `bind()` (`limits::bindguard`), tem o
/// teto de memória do app e é varrido pelo netguard. E quando o processo
/// principal termina — por fim normal, tempo esgotado ou interrupção — o
/// systemd encerra o cgroup inteiro: nada do que o comando criou continua
/// rodando depois dele.
#[allow(clippy::too_many_arguments)]
pub fn launch(
    state_dir: &Path,
    username: &str,
    app: &str,
    kind_raw: &str,
    script: &str,
    args_raw: &str,
    uid: u32,
    gid: u32,
) -> Result<Value, (String, String)> {
    let req = validate(state_dir, app, kind_raw, script, args_raw)?;
    let unit = job_unit(username, app);
    let paths = Paths::new(state_dir, app);

    // Um job por aplicação: dois `npm install` na mesma árvore corrompem
    // `node_modules` de um jeito que só aparece depois, no start.
    if unit_active(&unit) {
        return Err((
            "job_running".into(),
            "another command is already running".into(),
        ));
    }

    // O slice e o gancho de bind têm de existir antes de o serviço nascer.
    crate::limits::bindguard::ensure(false)
        .map_err(|e| ("bindguard_failed".into(), format!("{e:#}")))?;

    let inicio = now_secs();
    write_state(
        &paths,
        uid,
        gid,
        &json!({ "status": "running", "command": req.rotulo, "started_at": inicio }),
    );

    let exe = std::env::current_exe().map_err(|e| ("launch_failed".into(), format!("{e:#}")))?;
    let mut run = Command::new("systemd-run");
    run.arg("--quiet")
        .arg("--collect")
        .arg(format!("--unit={unit}"))
        .arg(format!(
            "--slice={}",
            crate::limits::policy::slice_unit_name(username)
        ))
        .arg(format!("--uid={uid}"))
        .arg(format!("--gid={gid}"))
        .arg(format!("--setenv=USERNAME={username}"))
        // O cgroup inteiro sai junto com o processo principal.
        .arg("--property=KillMode=control-group")
        // Ctrl+C primeiro: o npm limpa o que estava escrevendo antes de sair.
        .arg("--property=KillSignal=SIGINT")
        .arg("--property=TimeoutStopSec=5")
        // Teto de garantia, acima do limite que o próprio job aplica.
        .arg(format!("--property=RuntimeMaxSec={}", TIMEOUT_SECS + 60));
    if let Some(l) = crate::limits::usage::app_limits_for(state_dir, username, app, &req.meta) {
        run.arg(format!("--property=MemoryHigh={}", l.high));
        run.arg(format!("--property=MemoryMax={}", l.max));
    }
    run.arg("--")
        .arg(exe)
        .arg("job-exec")
        .arg(app)
        .arg(kind_raw)
        .arg("--script")
        .arg(script)
        .arg("--args")
        .arg(args_raw)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let out = run
        .output()
        .map_err(|e| ("launch_failed".into(), format!("systemd-run: {e:#}")))?;
    if !out.status.success() {
        write_state(
            &paths,
            uid,
            gid,
            &json!({
                "status": "failed", "command": req.rotulo,
                "started_at": inicio, "finished_at": now_secs(), "exit_code": -1,
            }),
        );
        return Err((
            "launch_failed".into(),
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(json!({ "status": "running", "command": req.rotulo }))
}

/// Executa o job, dentro do serviço que `launch` criou.
///
/// Roda como a conta. Recusa se não estiver no cgroup do próprio job: fora
/// dele não há limite, gancho de bind nem garantia de que tudo o que o
/// comando criar termina junto — e chamar este subcomando direto não pode ser
/// um caminho para contornar o preset ou esses limites.
#[allow(clippy::too_many_arguments)]
pub fn cmd_job_exec(
    state_dir: &Path,
    username: &str,
    app: &str,
    kind_raw: &str,
    script: &str,
    args_raw: &str,
    uid: u32,
    gid: u32,
    dbg: Option<&Value>,
) -> ! {
    let esperado = format!("0::{}", job_cgroup(username, app));
    let atual = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    if !atual.lines().any(|l| l.trim_end() == esperado) {
        user_error(
            "not_in_job_unit",
            "job-exec only runs inside the job unit the panel creates",
        );
    }

    let req = match validate(state_dir, app, kind_raw, script, args_raw) {
        Ok(r) => r,
        Err((c, m)) => user_error(&c, &m),
    };
    let paths = Paths::new(state_dir, app);
    let inicio = read_state(&paths)
        .and_then(|v| v.get("started_at").and_then(Value::as_u64))
        .unwrap_or_else(now_secs);
    write_state(
        &paths,
        uid,
        gid,
        &json!({
            "status": "running", "command": req.rotulo,
            "started_at": inicio, "pid": std::process::id(),
        }),
    );

    let cmd = build_command(
        &req.meta,
        req.kind,
        &req.script,
        &req.args,
        req.policy.ignore_scripts,
    );
    let (code, timed_out) = run_to_completion(cmd, &paths.log);
    record_outcome(
        &paths,
        (uid, gid),
        &req.rotulo,
        inicio,
        code,
        timed_out,
        &skipped_if(&req.meta, req.kind, &req.policy, code),
    );
    // Ao sair, o systemd encerra o que restar no cgroup do job.
    success(with_debug(json!({ "finished": true }), dbg));
}

/// Interrompe o job em execução, encerrando o serviço inteiro.
///
/// `systemctl stop` manda `SIGINT` a todo o cgroup — o Ctrl+C que o npm e as
/// ferramentas de build sabem tratar — e, se algo insistir por 5s, `SIGKILL`.
/// Alcança tudo o que o comando criou, inclusive o que tenha saído do grupo de
/// processos.
pub fn stop(
    state_dir: &Path,
    username: &str,
    app: &str,
    uid: u32,
    gid: u32,
    reason: Option<&str>,
) -> Result<Value, (String, String)> {
    if load_app_meta(state_dir, app).is_err() {
        return Err(("app_not_found".into(), format!("app '{app}' not found")));
    }
    let paths = Paths::new(state_dir, app);
    let estado = read_state(&paths);
    let unit = job_unit(username, app);
    let rodando = estado
        .as_ref()
        .is_some_and(|v| v.get("status").and_then(Value::as_str) == Some("running"));
    if !rodando && !unit_active(&unit) {
        return Err(("no_job".into(), "no command is running".into()));
    }

    let _ = Command::new("systemctl")
        .args(["stop", &unit])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let campo = |k: &str| {
        estado
            .as_ref()
            .and_then(|v| v.get(k).cloned())
            .unwrap_or(Value::Null)
    };
    let mut novo = json!({
        "status": "stopped",
        "command": campo("command"),
        "started_at": campo("started_at"),
        "finished_at": now_secs(),
    });
    if let (Some(r), Some(o)) = (reason, novo.as_object_mut()) {
        o.insert("reason".into(), json!(r));
    }
    write_state(&paths, uid, gid, &novo);
    Ok(json!({ "stopped": true }))
}

/// Só o comando npm, sem o confinamento.
///
/// Existe para os testes: `build_command` termina em `wrap_command`, que encerra
/// o processo quando o bwrap não está instalado — e ele não está na máquina de
/// quem desenvolve nem na CI. Sem esta separação os testes do npm não teriam
/// como rodar, e a alternativa (pular quando falta o binário) já se mostrou
/// pior: eles passariam sem verificar nada.
#[cfg(test)]
fn build_npm_command(meta: &AppMeta, kind: Kind, script: &str, args: &[String]) -> Command {
    build_inner(meta, kind, script, args, true)
}

/// Executa o comando e devolve `(código de saída, encerrado por tempo)`.
///
/// Chamado dentro do serviço do job: aqui a espera não prende ninguém.
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

/// Pacotes nativos que ficaram sem compilar, e por quê.
///
/// Sem o script de instalação o `npm install` termina bem mesmo quando um
/// pacote precisava compilar — a falha só aparece no start, com um
/// `Cannot find module '.../build/Release/...'` que não diz a causa. Por isso
/// a verificação é na árvore instalada, não no log.
///
/// Há dois motivos, e a saída de cada um é de alguém diferente. Com
/// `--ignore-scripts`, quem libera é o admin. Sem ele, o que bloqueou foi o
/// próprio npm: a partir do 11.17 o script de uma dependência só roda se o
/// projeto o aprovar em `allowScripts` no `package.json` — e isso é do
/// cliente. Olhar o resultado, e não a configuração, pega os dois casos.
fn skipped_if(
    meta: &AppMeta,
    kind: Kind,
    policy: &NpmPolicy,
    code: i32,
) -> (Vec<String>, Option<&'static str>) {
    if !kind.rewrites_tree() || code != 0 {
        return (Vec::new(), None);
    }
    let pulados = skipped_native_builds(Path::new(&meta.cwd));
    if pulados.is_empty() {
        return (pulados, None);
    }
    let motivo = if policy.ignore_scripts {
        "ignore_scripts"
    } else {
        "not_approved"
    };
    (pulados, Some(motivo))
}

/// Grava o desfecho do job.
fn record_outcome(
    paths: &Paths,
    (uid, gid): (u32, u32),
    rotulo: &str,
    inicio: u64,
    code: i32,
    timed_out: bool,
    (skipped, reason): &(Vec<String>, Option<&str>),
) {
    let status = if timed_out {
        "timeout"
    } else if code == 0 {
        "ok"
    } else {
        "failed"
    };
    write_state(
        paths,
        uid,
        gid,
        &json!({
            "status": status,
            "command": rotulo,
            "started_at": inicio,
            "finished_at": now_secs(),
            "exit_code": code,
            "skipped_builds": skipped,
            "skipped_reason": reason,
        }),
    );
}

/// Quantos pacotes a verificação de build nativo visita antes de desistir.
///
/// Uma árvore real fica na casa do milhar; o teto existe para uma árvore
/// patológica não prender o job depois de o npm já ter terminado.
const MAX_PACKAGES_SCANNED: usize = 20_000;

/// Pacotes instalados que compilam código nativo — compilados ou não.
///
/// É o que precisa ser recompilado quando a versão do Node muda: o addon
/// compilado para uma versão não carrega em outra.
pub fn native_packages(app_dir: &Path) -> Vec<String> {
    scan_native(app_dir, false)
}

/// Pacotes instalados que precisavam compilar código nativo e não compilaram.
fn skipped_native_builds(app_dir: &Path) -> Vec<String> {
    scan_native(app_dir, true)
}

/// Pacotes nativos instalados; com `only_unbuilt`, só os que ficaram sem
/// addon compilado.
///
/// Roda como a conta, sobre a árvore dela, e não segue symlink: um link em
/// `node_modules` apontando para fora não leva a verificação junto.
fn scan_native(app_dir: &Path, only_unbuilt: bool) -> Vec<String> {
    let mut achados = std::collections::BTreeSet::new();
    let mut pendentes = vec![app_dir.join("node_modules")];
    let mut visitados = 0usize;

    while let Some(dir) = pendentes.pop() {
        for (nome, pacote) in packages_in(&dir) {
            visitados += 1;
            if visitados > MAX_PACKAGES_SCANNED {
                return achados.into_iter().collect();
            }
            if needs_native_build(&pacote) && !(only_unbuilt && has_compiled_addon(&pacote)) {
                achados.insert(nome);
            }
            let aninhado = pacote.join("node_modules");
            if is_real_dir(&aninhado) {
                pendentes.push(aninhado);
            }
        }
    }
    achados.into_iter().collect()
}

/// Os pacotes de um `node_modules`, como `(nome, diretório)`, incluindo os de
/// escopo (`@img/sharp`).
fn packages_in(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let Ok(entradas) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entradas.flatten() {
        let nome = e.file_name().to_string_lossy().to_string();
        let caminho = e.path();
        if nome.starts_with('.') || !is_real_dir(&caminho) {
            continue;
        }
        if nome.starts_with('@') {
            if let Ok(sub) = std::fs::read_dir(&caminho) {
                for s in sub.flatten() {
                    if is_real_dir(&s.path()) {
                        let n = s.file_name().to_string_lossy().to_string();
                        out.push((format!("{nome}/{n}"), s.path()));
                    }
                }
            }
        } else {
            out.push((nome, caminho));
        }
    }
    out
}

fn is_real_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir())
}

/// Se o pacote compila código nativo na instalação.
///
/// `binding.gyp` faz o npm rodar `node-gyp rebuild` sozinho; os demais
/// declaram a ferramenta no script. Pacote que já traz binários prontos em
/// `prebuilds/` carrega deles em tempo de execução e funciona sem o script —
/// é o caso de `bufferutil`, dependência comum do `ws`.
fn needs_native_build(pkg_dir: &Path) -> bool {
    if is_real_dir(&pkg_dir.join("prebuilds")) {
        return false;
    }
    if std::fs::symlink_metadata(pkg_dir.join("binding.gyp")).is_ok_and(|m| m.is_file()) {
        return true;
    }
    let Ok(raw) = std::fs::read_to_string(pkg_dir.join("package.json")) else {
        return false;
    };
    let Ok(pkg) = serde_json::from_str::<Value>(&raw) else {
        return false;
    };
    let Some(scripts) = pkg.get("scripts").and_then(Value::as_object) else {
        return false;
    };
    ["preinstall", "install", "postinstall"]
        .iter()
        .filter_map(|k| scripts.get(*k).and_then(Value::as_str))
        .any(|s| {
            ["node-gyp", "prebuild-install", "node-pre-gyp", "cmake-js"]
                .iter()
                .any(|f| s.contains(f))
        })
}

/// Se o pacote tem um addon compilado (`*.node`) em algum lugar dele.
///
/// É o que separa "precisava compilar e compilou" de "precisava e não
/// compilou", sem depender de onde cada ferramenta grava o resultado —
/// `build/Release/` no node-gyp, `lib/binding/...` no node-pre-gyp. Não desce
/// em `node_modules` (são outros pacotes) nem segue symlink.
fn has_compiled_addon(pkg_dir: &Path) -> bool {
    const MAX_ENTRIES: usize = 5_000;
    let mut pendentes = vec![pkg_dir.to_path_buf()];
    let mut vistos = 0usize;
    while let Some(dir) = pendentes.pop() {
        let Ok(entradas) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entradas.flatten() {
            vistos += 1;
            if vistos > MAX_ENTRIES {
                return false;
            }
            let Ok(tipo) = e.file_type() else { continue };
            let nome = e.file_name();
            if tipo.is_dir() {
                if nome != "node_modules" {
                    pendentes.push(e.path());
                }
            } else if tipo.is_file() && Path::new(&nome).extension().is_some_and(|x| x == "node") {
                return true;
            }
        }
    }
    false
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

    // "running" sem processo vivo: o job morreu sem gravar o desfecho (memória
    // esgotada, teto de tempo do serviço). Dizer isso, em vez de mostrar para
    // sempre algo que já não roda.
    let em_curso = estado.get("status").and_then(Value::as_str) == Some("running");
    let pid = estado
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|p| u32::try_from(p).ok());
    let iniciado = estado
        .get("started_at")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    // Sem pid, o serviço nunca chegou a executar; dá um minuto de folga.
    let morto = pid.map_or_else(
        || now_secs().saturating_sub(iniciado) > 60,
        |p| !crate::sys::proc::is_process_alive(p),
    );
    if em_curso
        && morto
        && let Some(o) = estado.as_object_mut()
    {
        o.insert("status".into(), json!("interrupted"));
    }

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
    use super::{Kind, build_inner, build_npm_command, skipped_native_builds};
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

    /// O admin pode liberar os scripts de instalação; o `npm run` não muda.
    #[test]
    fn the_policy_can_let_install_scripts_run() {
        let m = meta("/home/bob/apps/api");
        for k in [Kind::Install, Kind::Update, Kind::Ci] {
            let c = build_inner(&m, k, "", &[], false);
            assert!(!args_of(&c).contains(&"--ignore-scripts".to_string()));
        }
    }

    /// O catálogo do preset e o que o core sabe executar são a mesma lista.
    #[test]
    fn the_policy_catalog_matches_the_known_commands() {
        for c in crate::sys::state::NPM_COMMANDS {
            assert!(
                Kind::parse(c).is_some(),
                "{c} está no catálogo mas não é comando"
            );
        }
    }

    fn pacote(raiz: &std::path::Path, nome: &str, pkg: &str, extra: &[&str]) {
        let d = raiz.join("node_modules").join(nome);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("package.json"), pkg).unwrap();
        for e in extra {
            if e.ends_with('/') {
                std::fs::create_dir_all(d.join(e)).unwrap();
            } else {
                std::fs::write(d.join(e), "").unwrap();
            }
        }
    }

    /// Reconhece os casos reais — `bcrypt` (node-pre-gyp), `sharp` antigo
    /// (prebuild-install), pacote só com `binding.gyp`, mesmo aninhado ou com
    /// escopo — e deixa de fora quem não compila ou já traz o binário.
    #[test]
    fn finds_the_packages_whose_native_build_was_skipped() {
        let raiz = std::env::temp_dir().join(format!("selynt-native-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&raiz);

        pacote(
            &raiz,
            "bcrypt",
            r#"{"scripts":{"install":"node-pre-gyp install --fallback-to-build"}}"#,
            &[],
        );
        pacote(
            &raiz,
            "sharp",
            r#"{"scripts":{"install":"(node install/libvips && prebuild-install) || node-gyp rebuild"}}"#,
            &[],
        );
        pacote(&raiz, "@scope/nativo", "{}", &["binding.gyp"]);
        pacote(&raiz, "bcrypt/node_modules/interno", "{}", &["binding.gyp"]);
        pacote(
            &raiz,
            "bufferutil",
            r#"{"scripts":{"install":"node-gyp-build"}}"#,
            &["binding.gyp", "prebuilds/"],
        );
        pacote(
            &raiz,
            "core-js",
            r#"{"scripts":{"postinstall":"node -e \"hi\""}}"#,
            &[],
        );
        pacote(&raiz, "express", "{}", &[]);
        // Precisava compilar e compilou: o addon está lá.
        pacote(
            &raiz,
            "compilado",
            "{}",
            &["binding.gyp", "build/", "build/addon.node"],
        );

        let achados = skipped_native_builds(&raiz);
        let nativos = super::native_packages(&raiz);
        let _ = std::fs::remove_dir_all(&raiz);

        assert_eq!(achados, ["@scope/nativo", "bcrypt", "interno", "sharp"]);

        // Para a troca de versão contam também os que já compilaram: o addon
        // feito para um Node não carrega em outro.
        assert!(nativos.contains(&"compilado".to_string()));
        assert!(
            !nativos.contains(&"bufferutil".to_string()),
            "prebuilds já servem"
        );
    }

    #[test]
    fn without_node_modules_nothing_is_reported() {
        assert_eq!(
            skipped_native_builds(std::path::Path::new("/nonexistent-selynt")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn only_dependency_commands_require_the_app_stopped() {
        assert!(Kind::Install.rewrites_tree());
        assert!(Kind::Update.rewrites_tree());
        assert!(Kind::Ci.rewrites_tree());
        assert!(Kind::Rebuild.rewrites_tree());
        assert!(!Kind::Run.rewrites_tree());
    }
}
