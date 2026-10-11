//! Tarefas de desenvolvimento do core-selynt.
//!
//! `cargo xtask sonda <host>` confere se o binário **instalado** num servidor
//! faz o que promete. `cargo test` não alcança o que só aparece com o binário
//! setuid rodando de verdade — posse de arquivo, queda de privilégio, scope do
//! systemd —, e é isso que a sonda verifica.
//!
//! O mesmo executável roda dos dois lados. Na máquina de quem desenvolve, ele
//! se compila como binário musl estático, copia a si mesmo para o servidor,
//! executa lá como `sonda-remota` e apaga a cópia. Do lado do servidor não é
//! preciso nada além dele: nem shell script, nem interpretador.
//!
//! A sonda cobra o contrato inteiro, não só a presença de campos: uma linha de
//! JSON no stdout e nada no stderr, `ok` coerente com o código de saída, o tipo
//! de cada campo, e o código de erro *e* de saída de cada recusa. Um comando
//! que responde `{"ok":false}` com os campos certos é falha, não acerto.

use std::fmt::Write as _;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde_json::Value;

/// O plugin instalado e o binário dele.
const PLUGIN: &str = "/usr/local/directadmin/plugins/selynt_panel";
const CORE: &str = "/usr/local/directadmin/plugins/selynt_panel/bin/core-selynt";
/// Onde o `DirectAdmin` guarda as contas — é daqui que sai o revendedor de teste.
const DA_USERS: &str = "/usr/local/directadmin/data/users";
const TARGET: &str = "x86_64-unknown-linux-musl";

/// Os comandos que o preset npm pode conter. Espelha `NPM_COMMANDS` do core: a
/// sonda confere o binário instalado, não o código, então não o importa.
const NPM_COMMANDS: [&str; 4] = ["install", "update", "ci", "run"];
/// Estados que `status` pode reportar.
const STATUS: [&str; 2] = ["RUNNING", "STOPPED"];

/// Códigos de saída do core: `user_error` sai com 1, `system_error` com 2.
const ERRO_USUARIO: i32 = 1;
const ERRO_SISTEMA: i32 = 2;

const USO: &str = "\
uso:
  cargo xtask sonda <host-ssh> [--conta C] [--app A] [--binario ARQ] [--escrita]

  Roda a sonda no servidor <host-ssh> (um alias do ~/.ssh/config).
  --conta    conta usada nos comandos de leitura (padrão: user)
  --app      aplicação a inspecionar (padrão: a primeira da conta)
  --binario  core-selynt local que deveria estar instalado; a sonda falha se o
             do servidor for outro (evita testar contra o binário antigo)
  --escrita  inclui os comandos que escrevem (sync-proxy, netguard)";

#[derive(Default)]
struct Opcoes {
    conta: String,
    app: Option<String>,
    binario: Option<PathBuf>,
    hash: Option<String>,
    escrita: bool,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let resultado = match args.first().map(String::as_str) {
        Some("sonda") => args.get(1).filter(|h| !h.starts_with('-')).map_or_else(
            || Err("faltou o host".to_string()),
            |host| opcoes(&args[2..]).map(|o| sonda_local(host, &o)),
        ),
        Some("sonda-remota") => opcoes(&args[1..]).map(|o| sonda_remota(&o)),
        _ => Err("tarefa desconhecida".to_string()),
    };
    resultado.unwrap_or_else(|e| {
        eprintln!("{e}\n\n{USO}");
        ExitCode::from(2)
    })
}

fn opcoes(args: &[String]) -> Result<Opcoes, String> {
    let mut o = Opcoes {
        conta: "user".to_string(),
        ..Opcoes::default()
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut valor = || it.next().cloned().ok_or_else(|| format!("{a} sem valor"));
        match a.as_str() {
            "--conta" => o.conta = valor()?,
            "--app" => o.app = Some(valor()?),
            "--binario" => o.binario = Some(PathBuf::from(valor()?)),
            "--hash" => o.hash = Some(valor()?),
            "--escrita" => o.escrita = true,
            outro => return Err(format!("opção desconhecida: {outro}")),
        }
    }
    // Os nomes vão parar numa linha do ssh e do `su -c`: só o que um nome de
    // conta ou de aplicação pode ter.
    for nome in std::iter::once(&o.conta).chain(o.app.as_ref()) {
        if nome.is_empty()
            || !nome
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!("nome inválido: {nome:?}"));
        }
    }
    if let Some(h) = &o.hash
        && (h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(format!("hash inválido: {h:?}"));
    }
    Ok(o)
}

// ------------------------------------------------------------ lado local

fn sha256(arquivo: &Path) -> Option<String> {
    let out = Command::new("sha256sum").arg(arquivo).output().ok()?;
    let texto = String::from_utf8(out.stdout).ok()?;
    texto.split_whitespace().next().map(str::to_string)
}

fn sonda_local(host: &str, o: &Opcoes) -> ExitCode {
    let raiz = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");

    let hash = o.binario.as_deref().map(sha256);
    if hash == Some(None) {
        eprintln!("não consegui calcular o hash do --binario");
        return ExitCode::FAILURE;
    }
    let hash = hash.flatten();

    let compilou = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "--release", "--package", "xtask"])
        .args(["--target", TARGET])
        .current_dir(&raiz)
        .status()
        .is_ok_and(|s| s.success());
    if !compilou {
        eprintln!("falhou ao compilar a sonda para {TARGET}");
        return ExitCode::FAILURE;
    }
    let binario = raiz
        .join("target")
        .join(TARGET)
        .join("release")
        .join("xtask");

    let remoto = format!("/tmp/selynt-sonda.{}", std::process::id());
    let copiou = Command::new("scp")
        .args(["-q", "-o", "LogLevel=ERROR"])
        .arg(&binario)
        .arg(format!("{host}:{remoto}"))
        .status()
        .is_ok_and(|s| s.success());
    if !copiou {
        eprintln!("falhou ao copiar a sonda para {host}");
        return ExitCode::FAILURE;
    }

    let mut linha = format!("{remoto} sonda-remota --conta {}", o.conta);
    if let Some(app) = &o.app {
        let _ = write!(linha, " --app {app}");
    }
    if let Some(h) = &hash {
        let _ = write!(linha, " --hash {h}");
    }
    if o.escrita {
        linha.push_str(" --escrita");
    }
    // A cópia sai mesmo quando a sonda falha; o código de saída é o dela.
    let linha = format!("{linha}; rc=$?; rm -f {remoto}; exit $rc");

    let rodou = Command::new("ssh")
        .args(["-o", "LogLevel=ERROR", host, &linha])
        .status();
    match rodou {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

// ----------------------------------------------------------- lado remoto

/// O que um comando devolveu, separado por canal.
struct Resposta {
    codigo: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Resposta {
    fn bruto(&self) -> String {
        let s = format!("{} {}", self.stdout.trim(), self.stderr.trim());
        s.trim().chars().take(160).collect()
    }

    /// O stdout tem de ser exatamente uma linha com um objeto JSON.
    fn json(&self) -> Result<Value, String> {
        let linhas: Vec<&str> = self
            .stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        let [linha] = linhas.as_slice() else {
            return Err(format!(
                "esperava uma linha de JSON no stdout, vieram {}",
                linhas.len()
            ));
        };
        match serde_json::from_str::<Value>(linha) {
            Ok(v) if v.is_object() => Ok(v),
            Ok(_) => Err("o JSON não é um objeto".to_string()),
            Err(e) => Err(format!("JSON inválido: {e}")),
        }
    }
}

fn rodar(cmd: &mut Command) -> Resposta {
    cmd.output().map_or_else(
        |e| Resposta {
            codigo: None,
            stdout: String::new(),
            stderr: format!("não executou: {e}"),
        },
        |o| Resposta {
            codigo: o.status.code(),
            stdout: String::from_utf8_lossy(&o.stdout).to_string(),
            stderr: String::from_utf8_lossy(&o.stderr).to_string(),
        },
    )
}

/// Roda o core como root, agindo em nome de `conta`.
fn core(conta: &str, args: &[&str]) -> Resposta {
    rodar(Command::new(CORE).env("USERNAME", conta).args(args))
}

/// Roda o core a partir de outra conta do sistema, como o CGI faria.
fn core_como(usuario: &str, conta: &str, args: &str) -> Resposta {
    rodar(Command::new("su").args([
        "-s",
        "/bin/sh",
        "-c",
        &format!("USERNAME={conta} {CORE} {args}"),
        usuario,
    ]))
}

/// Tipo esperado de um campo.
#[derive(Clone, Copy)]
enum Tipo {
    Bool,
    Texto,
    Lista,
    Objeto,
    /// Qualquer valor, inclusive `null` — o campo só precisa existir.
    Qualquer,
}

impl Tipo {
    fn aceita(self, v: &Value) -> bool {
        match self {
            Self::Bool => v.is_boolean(),
            Self::Texto => v.is_string(),
            Self::Lista => v.is_array(),
            Self::Objeto => v.is_object(),
            Self::Qualquer => true,
        }
    }

    const fn nome(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Texto => "texto",
            Self::Lista => "lista",
            Self::Objeto => "objeto",
            Self::Qualquer => "qualquer",
        }
    }
}

#[derive(Default)]
struct Placar {
    ok: u32,
    falhas: u32,
}

impl Placar {
    fn passou(&mut self, rotulo: &str) {
        self.ok += 1;
        println!("  ok    {rotulo}");
    }

    fn falhou(&mut self, rotulo: &str, motivo: &str) {
        self.falhas += 1;
        println!("  FALHA {rotulo}\n        {motivo}");
    }

    fn confere(&mut self, rotulo: &str, resultado: Result<(), String>) {
        match resultado {
            Ok(()) => self.passou(rotulo),
            Err(e) => self.falhou(rotulo, &e),
        }
    }

    /// Sucesso pelo contrato: sai com 0, nada no stderr, uma linha de JSON com
    /// `ok:true` e cada campo pedido presente e do tipo certo.
    fn sucesso(&mut self, rotulo: &str, r: &Resposta, campos: &[(&str, Tipo)]) -> Option<Value> {
        match contrato_de_sucesso(r, campos) {
            Ok(v) => {
                self.passou(rotulo);
                Some(v)
            }
            Err(e) => {
                self.falhou(rotulo, &format!("{e} | bruto: {}", r.bruto()));
                None
            }
        }
    }

    /// Recusa pelo contrato: sai com o código dado, `ok:false`, o `error`
    /// esperado e uma `message` não vazia.
    fn recusa(&mut self, rotulo: &str, r: &Resposta, erro: &str, saida: i32) {
        match contrato_de_recusa(r, erro, saida) {
            Ok(()) => {
                self.ok += 1;
                println!("  ok    {rotulo} (recusado: {erro})");
            }
            Err(e) => self.falhou(rotulo, &format!("{e} | bruto: {}", r.bruto())),
        }
    }
}

fn contrato_de_sucesso(r: &Resposta, campos: &[(&str, Tipo)]) -> Result<Value, String> {
    if r.codigo != Some(0) {
        return Err(format!("saiu com {:?}, esperava 0", r.codigo));
    }
    if !r.stderr.trim().is_empty() {
        return Err("escreveu no stderr num sucesso".to_string());
    }
    let v = r.json()?;
    if v.get("ok") != Some(&Value::Bool(true)) {
        return Err("ok não é true".to_string());
    }
    for (nome, tipo) in campos {
        match v.get(*nome) {
            None => return Err(format!("campo ausente: {nome}")),
            Some(x) if !tipo.aceita(x) => {
                return Err(format!("campo {nome} deveria ser {}", tipo.nome()));
            }
            Some(_) => {}
        }
    }
    Ok(v)
}

fn contrato_de_recusa(r: &Resposta, erro: &str, saida: i32) -> Result<(), String> {
    let v = r.json()?;
    if v.get("ok") != Some(&Value::Bool(false)) {
        return Err("ok não é false".to_string());
    }
    let veio = v.get("error").and_then(Value::as_str).unwrap_or("");
    if veio != erro {
        return Err(format!("esperava erro {erro}, veio {veio:?}"));
    }
    if v.get("message")
        .and_then(Value::as_str)
        .is_none_or(|m| m.trim().is_empty())
    {
        return Err("recusa sem message".to_string());
    }
    if r.codigo != Some(saida) {
        return Err(format!("saiu com {:?}, esperava {saida}", r.codigo));
    }
    Ok(())
}

fn sonda_remota(o: &Opcoes) -> ExitCode {
    let mut p = Placar::default();
    let conta = o.conta.as_str();

    let hash = sha256(Path::new(CORE)).unwrap_or_default();
    println!("== sonda do core-selynt ==");
    println!(
        "binário: {}  conta: {conta}\n",
        hash.get(..16).unwrap_or("?")
    );

    sonda_instalacao(&mut p, o.hash.as_deref(), &hash);

    println!("\n-- comandos de leitura (conta {conta}) --");
    let lista = p.sucesso("list", &core(conta, &["list"]), &[("apps", Tipo::Lista)]);
    p.sucesso("domains", &core(conta, &["domains"]), &[]);
    p.sucesso(
        "status-isolated",
        &core(conta, &["status-isolated"]),
        &[
            ("isolated", Tipo::Bool),
            ("supported", Tipo::Bool),
            ("running", Tipo::Qualquer),
        ],
    );

    let apps = lista
        .as_ref()
        .and_then(|l| l.get("apps"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let app = o.app.clone().or_else(|| {
        apps.first()
            .and_then(|a| a.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    match app {
        Some(app) => {
            let tipo = apps
                .iter()
                .find(|a| a.get("name").and_then(Value::as_str) == Some(&app))
                .and_then(|a| a.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            sonda_app(&mut p, conta, &app, &tipo);
        }
        None => println!("  info  a conta {conta} não tem aplicação; verificações de app puladas"),
    }

    sonda_admin(&mut p);
    sonda_autorizacao(&mut p, conta);

    println!();
    if o.escrita {
        println!("-- ESCRITA (--escrita) --");
        p.sucesso(
            "sync-proxy",
            &core("admin", &["sync-proxy"]),
            &[("apps", Tipo::Qualquer)],
        );
        p.sucesso(
            "netguard",
            &core(conta, &["netguard"]),
            &[("stopped", Tipo::Qualquer)],
        );
    } else {
        println!("  (escrita desativada; --escrita inclui sync-proxy e netguard)");
    }

    println!("\n== {} ok, {} falha(s) ==", p.ok, p.falhas);
    if p.falhas == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// O binário e a configuração do plugin, antes de qualquer comando.
fn sonda_instalacao(p: &mut Placar, esperado: Option<&str>, instalado: &str) {
    println!("-- instalação --");

    if let Some(h) = esperado {
        p.confere(
            "o binário instalado é o esperado",
            if h.eq_ignore_ascii_case(instalado) {
                Ok(())
            } else {
                Err(format!("esperado {h}, instalado {instalado}"))
            },
        );
    }

    // Sem o setuid tudo falha com root_required; com escrita para grupo ou
    // outros, qualquer conta troca o binário que roda como root.
    p.confere(
        "binário root:root 4755",
        std::fs::metadata(CORE)
            .map_err(|e| e.to_string())
            .and_then(|m| {
                let mut erros = problemas_de_posse(&m);
                if m.mode() & 0o4000 == 0 {
                    erros.push("sem setuid");
                }
                if erros.is_empty() {
                    Ok(())
                } else {
                    Err(erros.join(", "))
                }
            }),
    );

    // O que está em `etc/` decide política do servidor inteiro — quem pode
    // agir por outras contas, o isolamento padrão, o preset npm. Ninguém além
    // do root pode reescrever.
    let etc = Path::new(PLUGIN).join("etc");
    let mut problemas = Vec::new();
    match std::fs::read_dir(&etc) {
        Ok(entradas) => {
            for e in entradas.flatten() {
                let Ok(m) = std::fs::symlink_metadata(e.path()) else {
                    continue;
                };
                let erros = problemas_de_posse(&m);
                if !erros.is_empty() {
                    problemas.push(format!(
                        "{} ({})",
                        e.file_name().to_string_lossy(),
                        erros.join(", ")
                    ));
                }
            }
        }
        Err(e) => problemas.push(format!("{}: {e}", etc.display())),
    }
    p.confere(
        "etc/ do plugin só gravável pelo root",
        if problemas.is_empty() {
            Ok(())
        } else {
            Err(problemas.join(", "))
        },
    );
}

/// O que há de errado na posse de um arquivo que só o root pode alterar.
///
/// Descreve o problema em vez de ecoar uid, gid e modo: a saída da sonda vai
/// para terminais e logs de quem a roda, e o número não diz o que corrigir.
fn problemas_de_posse(m: &std::fs::Metadata) -> Vec<&'static str> {
    let mut erros = Vec::new();
    if m.file_type().is_symlink() {
        erros.push("é symlink");
    }
    if m.uid() != 0 {
        erros.push("dono não é root");
    }
    if m.gid() != 0 {
        erros.push("grupo não é root");
    }
    if m.mode() & 0o022 != 0 {
        erros.push("gravável por grupo ou outros");
    }
    erros
}

fn sonda_app(p: &mut Placar, conta: &str, app: &str, tipo: &str) {
    println!("\n-- app: {app} ({tipo}) --");
    let status = p.sucesso(
        "status",
        &core(conta, &["status", app]),
        &[("status", Tipo::Texto)],
    );
    p.sucesso(
        "stats",
        &core(conta, &["stats", app]),
        &[("running", Tipo::Bool), ("memory", Tipo::Qualquer)],
    );
    p.sucesso(
        "logs",
        &core(conta, &["logs", app]),
        &[("lines", Tipo::Lista)],
    );

    // A tela de scripts só oferece o que o preset do servidor libera.
    if tipo == "node"
        && let Some(s) = p.sucesso(
            "scripts traz a política npm",
            &core(conta, &["scripts", app]),
            &[
                ("scripts", Tipo::Lista),
                ("deps", Tipo::Texto),
                ("policy", Tipo::Objeto),
            ],
        )
    {
        p.confere(
            "a política dos scripts é válida",
            politica_valida(&s["policy"]),
        );
    }

    let Some(status) = status else { return };
    let estado = status["status"].as_str().unwrap_or("");
    p.confere(
        "status é um estado conhecido",
        if STATUS.contains(&estado) {
            Ok(())
        } else {
            Err(format!("estado {estado:?}"))
        },
    );

    // A visão do admin e a da conta são calculadas por caminhos diferentes, e
    // já divergiram: um pid reaproveitado fazia o admin ver RUNNING um app
    // morto. Têm de concordar.
    let admin = core("admin", &["admin", "list"]).json().ok();
    let no_admin = admin
        .as_ref()
        .and_then(|v| v.get("apps"))
        .and_then(Value::as_array)
        .and_then(|apps| {
            apps.iter().find(|a| {
                a.get("user").and_then(Value::as_str) == Some(conta)
                    && a.get("name").and_then(Value::as_str) == Some(app)
            })
        })
        .and_then(|a| a.get("status"))
        .and_then(Value::as_str)
        .map(str::to_string);
    p.confere(
        "admin e conta veem o mesmo status",
        match no_admin.as_deref() {
            Some(a) if a == estado => Ok(()),
            Some(a) => Err(format!("admin vê {a}, a conta vê {estado}")),
            None => Err("o app não aparece no admin list".to_string()),
        },
    );
    if estado != "RUNNING" {
        return;
    }

    // O que o painel mostra tem de bater com o cgroup: um app RUNNING fora do
    // próprio scope escapa da cota e some do netguard.
    let pid = status.get("pid").and_then(Value::as_u64).unwrap_or(0);
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
    let esperado = format!("/selynt-{conta}-{app}.scope");
    p.confere(
        "RUNNING está no próprio scope",
        if pid > 0 && cgroup.lines().any(|l| l.trim_end().ends_with(&esperado)) {
            Ok(())
        } else {
            Err(format!(
                "pid {pid}, esperado …{esperado}, real: {}",
                cgroup.trim()
            ))
        },
    );

    // O painel diz que serve; o socket tem de existir e ser um socket.
    let meta = std::fs::read_to_string(format!("/var/lib/selynt_panel/{conta}/.run/{app}.meta"))
        .unwrap_or_default();
    let socket = meta
        .lines()
        .find_map(|l| l.strip_prefix("socket="))
        .unwrap_or("")
        .trim()
        .to_string();
    p.confere(
        "RUNNING tem socket",
        if std::fs::metadata(&socket).is_ok_and(|m| m.file_type().is_socket()) {
            Ok(())
        } else {
            Err(format!("sem socket em {socket:?}"))
        },
    );
}

/// A política npm tem de vir no formato que a tela espera, sem comando fora
/// do catálogo.
fn politica_valida(v: &Value) -> Result<(), String> {
    let Some(comandos) = v.get("commands").and_then(Value::as_array) else {
        return Err("commands não é lista".to_string());
    };
    if !v.get("ignore_scripts").is_some_and(Value::is_boolean) {
        return Err("ignore_scripts não é bool".to_string());
    }
    for c in comandos {
        let nome = c.as_str().unwrap_or("");
        if !NPM_COMMANDS.contains(&nome) {
            return Err(format!("comando fora do catálogo: {c}"));
        }
    }
    Ok(())
}

fn sonda_admin(p: &mut Placar) {
    println!("\n-- admin --");
    if let Some(v) = p.sucesso(
        "admin version",
        &core("admin", &["admin", "version"]),
        &[("version", Tipo::Texto)],
    ) {
        let versao = v["version"].as_str().unwrap_or("");
        p.confere(
            "a versão é semver",
            if versao.split('.').count() == 3 && versao.split('.').all(|n| n.parse::<u32>().is_ok())
            {
                Ok(())
            } else {
                Err(format!("versão {versao:?}"))
            },
        );
    }
    p.sucesso(
        "admin list",
        &core("admin", &["admin", "list"]),
        &[("apps", Tipo::Lista)],
    );
    p.sucesso(
        "admin detect-nodes",
        &core("admin", &["admin", "detect-nodes"]),
        &[("versions", Tipo::Lista)],
    );
    if let Some(v) = p.sucesso(
        "admin npm-policy",
        &core("admin", &["admin", "npm-policy"]),
        &[("commands", Tipo::Lista), ("ignore_scripts", Tipo::Bool)],
    ) {
        p.confere("a política do servidor é válida", politica_valida(&v));
    }

    let Some(diag) = p.sucesso(
        "admin diagnose",
        &core("admin", &["admin", "diagnose"]),
        &[],
    ) else {
        return;
    };
    let itens = diag
        .get("items")
        .or_else(|| diag.get("checks"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // `fail` do diagnóstico é falha da sonda: é o próprio core dizendo que a
    // instalação está quebrada. `warn` fica como informação.
    let mut falhas = Vec::new();
    for i in &itens {
        let nivel = i.get("level").and_then(Value::as_str).unwrap_or("?");
        let chave = i.get("key").and_then(Value::as_str).unwrap_or("?");
        match nivel {
            "pass" => {}
            "fail" => falhas.push(chave.to_string()),
            _ => println!("  info  diagnóstico {nivel}: {chave}"),
        }
    }
    p.confere(
        "diagnóstico sem fail",
        if itens.is_empty() {
            Err("diagnóstico sem itens".to_string())
        } else if falhas.is_empty() {
            Ok(())
        } else {
            Err(falhas.join(", "))
        },
    );
}

fn sonda_autorizacao(p: &mut Placar, conta: &str) {
    // Só root real instala ou remove. As contas de serviço têm de ser barradas
    // aqui — e não nos comandos de leitura, que o painel precisa para andar.
    println!("\n-- autorização (o que TEM de ser recusado) --");
    p.recusa(
        "nobody não instala",
        &core_como("nobody", "admin", "setup"),
        "root_required",
        ERRO_SISTEMA,
    );
    p.recusa(
        "apache não remove",
        &core_como("apache", "admin", "teardown"),
        "root_required",
        ERRO_SISTEMA,
    );
    p.recusa(
        "root sem USERNAME",
        &rodar(
            Command::new(CORE)
                .env_remove("USERNAME")
                .args(["admin", "version"]),
        ),
        "user_resolve_failed",
        ERRO_SISTEMA,
    );
    p.recusa(
        "app inexistente",
        &core(conta, &["status", "__nao_existe__"]),
        "app_not_found",
        ERRO_USUARIO,
    );
    p.recusa(
        "conta comum não lê o inventário do servidor",
        &core_como(conta, conta, "admin list"),
        "admin_required",
        ERRO_SISTEMA,
    );

    // O preset npm é do servidor inteiro: nem a conta nem o revendedor gravam.
    let gravar = "admin save-npm-policy --commands install --ignore-scripts true";
    p.recusa(
        "conta comum não grava o preset npm",
        &core_como(conta, conta, gravar),
        "admin_required",
        ERRO_SISTEMA,
    );
    match revendedor() {
        Some(r) => p.recusa(
            &format!("revendedor ({r}) não grava o preset npm"),
            &core_como(&r, &r, gravar),
            "server_admin_required",
            ERRO_SISTEMA,
        ),
        None => println!("  info  sem revendedor com conta no sistema; caso não testado"),
    }

    // As contas de serviço PRECISAM passar nos comandos de leitura (o CGI roda
    // como elas); se isso quebrar, o painel para.
    p.sucesso(
        "apache lê como conta",
        &core_como("apache", conta, "list"),
        &[("apps", Tipo::Lista)],
    );
}

/// Uma conta de revendedor que exista no sistema, para testar a recusa.
fn revendedor() -> Option<String> {
    let mut nomes: Vec<String> = std::fs::read_dir(DA_USERS)
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    nomes.sort();
    nomes.into_iter().find(|n| {
        let conf = std::fs::read_to_string(format!("{DA_USERS}/{n}/user.conf")).unwrap_or_default();
        conf.lines().any(|l| l.trim() == "usertype=reseller")
            && Command::new("id")
                .arg(n)
                .output()
                .is_ok_and(|o| o.status.success())
    })
}
