use std::io::Read as _;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};

use crate::acl::apply_acl;
use crate::output::{debug, success, system_error, user_error};
use crate::proc::{has_network_listen, is_process_alive, read_proc_starttime, read_proc_uid};
use crate::state::{
    AppMeta, atomic_write, list_app_names, load_app_meta, parse_kv, set_perm, validate_name,
};

// ─── Helper de debug ──────────────────────────────────────────────────────────

/// Mescla `_debug` no valor de saída, se debug estiver ativo.
fn with_debug(mut val: Value, debug: Option<&Value>) -> Value {
    if let Some(dbg) = debug {
        val["_debug"] = dbg.clone();
    }
    val
}

// ─── Helpers internos ─────────────────────────────────────────────────────────

/// Determina status (RUNNING/STOPPED) e PID de um app validando via /proc.
pub fn get_status(state_dir: &Path, name: &str) -> (String, Option<u32>, Option<u64>) {
    let pid_file = state_dir.join(".run").join(format!("{name}.pid"));
    let meta_file = state_dir.join(".run").join(format!("{name}.meta"));

    let pid_str = match std::fs::read_to_string(&pid_file) {
        Ok(s) => s,
        Err(_) => return ("STOPPED".to_string(), None, None),
    };

    let pid: u32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => return ("STOPPED".to_string(), None, None),
    };

    // Verificar UID — deve ser o mesmo usuário atual
    let my_uid = nix::unistd::getuid().as_raw();
    match read_proc_uid(pid) {
        Some(u) if u == my_uid => {}
        _ => return ("STOPPED".to_string(), None, None),
    }

    // Verificar starttime anti PID-reuse (se .meta existir)
    let meta_content = std::fs::read_to_string(&meta_file).unwrap_or_default();
    let meta_kv = parse_kv(&meta_content);
    if let Some(saved) = meta_kv.get("starttime") {
        let saved_start: u64 = saved.parse().unwrap_or(0);
        if saved_start > 0 {
            match read_proc_starttime(pid) {
                Some(proc_start) if proc_start == saved_start => {}
                _ => return ("STOPPED".to_string(), None, None),
            }
        }
    }

    let started_at: Option<u64> = meta_kv.get("started_at").and_then(|v| v.parse().ok());
    ("RUNNING".to_string(), Some(pid), started_at)
}

/// Status simples para admin: apenas verifica se /proc/{pid} existe (sem validação de UID)
fn admin_get_status(pid_file: &Path, meta_file: &Path) -> (String, Option<u32>, Option<u64>) {
    let pid_str = match std::fs::read_to_string(pid_file) {
        Ok(s) => s,
        Err(_) => return ("STOPPED".to_string(), None, None),
    };
    let pid: u32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => return ("STOPPED".to_string(), None, None),
    };
    if is_process_alive(pid) {
        let started_at: Option<u64> = std::fs::read_to_string(meta_file)
            .ok()
            .and_then(|c| parse_kv(&c).get("started_at").and_then(|v| v.parse().ok()));
        ("RUNNING".to_string(), Some(pid), started_at)
    } else {
        ("STOPPED".to_string(), None, None)
    }
}

/// Sinaliza que o sync é necessário (cron job executa a cada minuto)
fn signal_sync() {
    let _ = std::fs::write("/var/lib/selynt_panel/.sync_needed", b"");
}

/// Valida que um valor não contém path traversal (sem `..`, `/`, `\0`)
fn validate_safe_component(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && !s.contains('\0') && !s.contains("..")
}

/// Tail eficiente: lê as últimas `n` linhas do arquivo sem carregar tudo
fn read_tail(path: &Path, n: usize) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};

    if n == 0 {
        return vec![];
    }

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let size = match file.seek(SeekFrom::End(0)) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    if size == 0 {
        return vec![];
    }

    const CHUNK: u64 = 8192;
    let mut buf: Vec<u8> = Vec::new();
    let mut newlines: usize = 0;
    let mut cursor = size;

    while cursor > 0 && newlines <= n {
        let to_read = CHUNK.min(cursor);
        cursor -= to_read;

        if file.seek(SeekFrom::Start(cursor)).is_err() {
            break;
        }
        let mut chunk = vec![0u8; to_read as usize];
        if file.read_exact(&mut chunk).is_err() {
            break;
        }

        newlines += chunk.iter().filter(|&&b| b == b'\n').count();

        // Prepend: chunk + buf_antigo
        chunk.extend_from_slice(&buf);
        buf = chunk;
    }

    let s = String::from_utf8_lossy(&buf);
    let lines: Vec<String> = s.lines().map(|l| l.to_owned()).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].to_vec()
}

/// Rotação de log quando > 50 MB: mantém últimas 5000 linhas
fn rotate_log_if_needed(path: &Path) {
    const MAX_SIZE: u64 = 50 * 1024 * 1024;
    const KEEP: usize = 5000;

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size <= MAX_SIZE {
        return;
    }
    debug(format!("rotacionando log {:?} ({size} bytes)", path));

    let lines = read_tail(path, KEEP);
    let content = lines.join("\n") + "\n";
    let _ = atomic_write(path, content.as_bytes());
}

/// Para um processo sem sair (uso interno por remove/restart)
fn stop_internal(state_dir: &Path, name: &str, meta: &AppMeta, timeout_secs: u64) {
    let (status, pid_opt, _) = get_status(state_dir, name);
    if status == "STOPPED" {
        return;
    }
    let pid = match pid_opt {
        Some(p) => p,
        None => return,
    };
    let nix_pid = Pid::from_raw(pid as i32);

    // Remover marker antes de parar (desativa proxy primeiro)
    let marker = state_dir.join(".proxy").join(&meta.host);
    let _ = std::fs::remove_file(&marker);

    let _ = kill(nix_pid, Signal::SIGTERM);

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        if !is_process_alive(pid) {
            break;
        }
        if Instant::now() >= deadline {
            let _ = kill(nix_pid, Signal::SIGKILL);
            std::thread::sleep(Duration::from_millis(200));
            break;
        }
    }

    // Limpar arquivos de estado
    let _ = std::fs::remove_file(state_dir.join(".sockets").join(&meta.host));
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.pid")));
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.meta")));
}

// ─── Comandos públicos ────────────────────────────────────────────────────────

pub fn cmd_list(state_dir: &Path, dbg: Option<&Value>) -> ! {
    let names = list_app_names(state_dir);
    let mut apps = Vec::new();

    for name in &names {
        let meta = match load_app_meta(state_dir, name) {
            Ok(m) => m,
            Err(e) => {
                debug(format!("skipping '{name}': {e}"));
                continue;
            }
        };
        let (status, pid, started_at) = get_status(state_dir, name);
        let pid_val = pid.map(|p| json!(p)).unwrap_or(json!(null));

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
        user_error("app_not_found", &format!("app '{name}' não encontrado"));
    }
    let (status, pid, _) = get_status(state_dir, name);
    let pid_val = pid.map(|p| json!(p)).unwrap_or(json!(null));
    success(with_debug(json!({ "status": status, "pid": pid_val }), dbg))
}

pub fn cmd_start(state_dir: &Path, name: &str, web_user: &str, dbg: Option<&Value>) -> ! {
    let meta = match load_app_meta(state_dir, name) {
        Ok(m) => m,
        Err(_) => user_error("app_not_found", &format!("app '{name}' não encontrado")),
    };

    // 0. Defense in depth: validar campos antes de usar
    if !validate_safe_component(&meta.entry) {
        user_error(
            "invalid_entry",
            "entry contém path traversal — recrie o app",
        );
    }
    if !validate_safe_component(&meta.host) {
        user_error("invalid_host", "host contém path traversal — recrie o app");
    }

    // 1. Idempotente
    let (status, pid, _) = get_status(state_dir, name);
    if status == "RUNNING" {
        success(with_debug(json!({ "pid": pid }), dbg));
    }

    // 2. Limpar socket/marker antigos
    let socket_path = state_dir.join(".sockets").join(&meta.host);
    let marker_path = state_dir.join(".proxy").join(&meta.host);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&marker_path);

    // 3. Rodar logs + abrir arquivos
    let cwd_path = PathBuf::from(&meta.cwd);
    let log_out = cwd_path.join("logs").join(format!("{name}.out.log"));
    let log_err = cwd_path.join("logs").join(format!("{name}.err.log"));
    rotate_log_if_needed(&log_out);
    rotate_log_if_needed(&log_err);

    let stdout_file = match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_out)
    {
        Ok(f) => f,
        Err(e) => system_error("log_open_failed", &format!("stdout log: {e:#}")),
    };
    let stderr_file = match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_err)
    {
        Ok(f) => f,
        Err(e) => system_error("log_open_failed", &format!("stderr log: {e:#}")),
    };

    // Vars de ambiente do .env (no cwd do app)
    let env_file = PathBuf::from(&meta.cwd).join(".env");
    let env_vars: Vec<(String, String)> = if env_file.exists() {
        std::fs::read_to_string(&env_file)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                l.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect()
    } else {
        vec![]
    };

    // Montar comando
    let entry_path = PathBuf::from(&meta.cwd).join(&meta.entry);
    let socket_str = socket_path.to_string_lossy().to_string();

    let mut cmd = match meta.app_type.as_str() {
        "node" => {
            let node_bin = if meta.node_version.is_empty() {
                "node".to_string()
            } else {
                meta.node_version.clone()
            };
            // Validar versão mínima do Node.js
            if let Some(ver) = get_node_version_raw(Path::new(&node_bin))
                && !node_version_ok(&ver)
            {
                user_error(
                    "unsupported_node",
                    &format!(
                        "Node.js {ver} não é suportado. Mínimo: v{NODE_MIN_MAJOR}.{NODE_MIN_MINOR}.0"
                    ),
                );
            }
            let mut c = std::process::Command::new(&node_bin);
            c.arg("--import");
            c.arg(format!("{}/lib/node-loader.js", crate::state::PLUGIN_PATH));
            c.arg(&entry_path);
            c
        }
        _ => std::process::Command::new(&entry_path),
    };
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(stdout_file);
    cmd.stderr(stderr_file);
    cmd.current_dir(&meta.cwd);
    cmd.env("SELYNT_SOCKET", &socket_str);
    cmd.env("SELYNT_HOST", &meta.host);
    for (k, v) in &env_vars {
        cmd.env(k, v);
    }

    // setsid: processo filho vira líder de nova sessão
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid().map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(())
        });
    }

    let cmd_display = match meta.app_type.as_str() {
        "node" => format!("node {}", entry_path.display()),
        _ => format!("{}", entry_path.display()),
    };
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => system_error("spawn_failed", &format!("{cmd_display}: {e:#}")),
    };
    let pid = child.id();
    debug(format!("spawned '{name}' PID={pid}"));

    // 4. Salvar .pid
    let pid_file = state_dir.join(".run").join(format!("{name}.pid"));
    let meta_file = state_dir.join(".run").join(format!("{name}.meta"));

    if let Err(e) = atomic_write(&pid_file, format!("{pid}\n").as_bytes())
        .and_then(|_| set_perm(&pid_file, 0o600))
    {
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        system_error("state_write_failed", &format!("{e:#}"));
    }

    // Aguardar /proc/{pid} aparecer
    std::thread::sleep(Duration::from_millis(50));

    // Salvar .meta com uid + starttime + started_at
    let my_uid = nix::unistd::getuid().as_raw();
    let starttime = read_proc_starttime(pid).unwrap_or(0);
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let meta_content = format!("uid={my_uid}\nstarttime={starttime}\nstarted_at={started_at}\n");

    if let Err(e) =
        atomic_write(&meta_file, meta_content.as_bytes()).and_then(|_| set_perm(&meta_file, 0o600))
    {
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        let _ = std::fs::remove_file(&pid_file);
        system_error("state_write_failed", &format!("{e:#}"));
    }

    // 5. Aguardar socket Unix aparecer e estar funcional
    let socket_timeout = if meta.app_type == "rust" {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(10)
    };

    let t0 = Instant::now();
    loop {
        if socket_path.exists() {
            break;
        }
        if t0.elapsed() > socket_timeout {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
            let _ = std::fs::remove_file(&pid_file);
            let _ = std::fs::remove_file(&meta_file);
            system_error(
                "socket_timeout",
                "processo não criou o socket Unix no tempo esperado",
            );
        }
        if !is_process_alive(pid) {
            let _ = std::fs::remove_file(&pid_file);
            let _ = std::fs::remove_file(&meta_file);
            system_error(
                "process_exited",
                "processo encerrou antes de criar o socket",
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 5b. Verificar se o socket aceita conexões
    let connect_deadline = Instant::now() + Duration::from_secs(3);
    let mut socket_ok = false;
    while Instant::now() < connect_deadline {
        match std::os::unix::net::UnixStream::connect(&socket_path) {
            Ok(_) => {
                socket_ok = true;
                break;
            }
            Err(_) => {
                if !is_process_alive(pid) {
                    let _ = std::fs::remove_file(&pid_file);
                    let _ = std::fs::remove_file(&meta_file);
                    let _ = std::fs::remove_file(&socket_path);
                    system_error(
                        "process_exited",
                        "processo encerrou antes de aceitar conexões no socket",
                    );
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    if !socket_ok {
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        let _ = std::fs::remove_file(&pid_file);
        let _ = std::fs::remove_file(&meta_file);
        let _ = std::fs::remove_file(&socket_path);
        system_error(
            "socket_not_accepting",
            "socket Unix existe mas não está aceitando conexões",
        );
    }

    // 6. Verificar porta TCP — bloqueado
    if has_network_listen(pid) {
        let nix_pid = Pid::from_raw(pid as i32);
        let _ = kill(nix_pid, Signal::SIGTERM);
        std::thread::sleep(Duration::from_millis(500));
        let _ = kill(nix_pid, Signal::SIGKILL);
        let _ = std::fs::remove_file(&pid_file);
        let _ = std::fs::remove_file(&meta_file);
        let _ = std::fs::remove_file(&socket_path);
        user_error(
            "network_port_forbidden",
            "processo abriu porta de rede (TCP/UDP) — apenas Unix sockets são permitidos",
        );
    }

    // 7. Criar marker de proxy
    if let Err(e) = std::fs::write(&marker_path, b"").and_then(|_| {
        std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o644))
    }) {
        system_error("marker_failed", &format!("{e:#}"));
    }

    // 8. ACL
    apply_acl(state_dir, &socket_path, &marker_path, web_user);

    // 9+10. Sinalizar sync
    signal_sync();

    success(with_debug(json!({ "pid": pid }), dbg))
}

pub fn cmd_stop(state_dir: &Path, name: &str, timeout_secs: u64, dbg: Option<&Value>) -> ! {
    let meta = match load_app_meta(state_dir, name) {
        Ok(m) => m,
        Err(_) => user_error("app_not_found", &format!("app '{name}' não encontrado")),
    };

    let (status, pid_opt, _) = get_status(state_dir, name);
    if status == "STOPPED" {
        success(with_debug(json!({}), dbg)); // idempotente
    }

    let pid = pid_opt.unwrap();
    let nix_pid = Pid::from_raw(pid as i32);

    // 1. Remover marker imediatamente (desativa proxy antes do kill)
    let marker_path = state_dir.join(".proxy").join(&meta.host);
    let _ = std::fs::remove_file(&marker_path);

    // 2. SIGTERM → aguardar → SIGKILL
    let _ = kill(nix_pid, Signal::SIGTERM);

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        if !is_process_alive(pid) {
            break;
        }
        if Instant::now() >= deadline {
            let _ = kill(nix_pid, Signal::SIGKILL);
            std::thread::sleep(Duration::from_millis(200));
            break;
        }
    }

    // 3. Remover socket, .pid, .meta
    let _ = std::fs::remove_file(state_dir.join(".sockets").join(&meta.host));
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.pid")));
    let _ = std::fs::remove_file(state_dir.join(".run").join(format!("{name}.meta")));

    signal_sync();
    success(with_debug(json!({}), dbg))
}

pub fn cmd_restart(state_dir: &Path, name: &str, web_user: &str, dbg: Option<&Value>) -> ! {
    let meta = match load_app_meta(state_dir, name) {
        Ok(m) => m,
        Err(_) => user_error("app_not_found", &format!("app '{name}' não encontrado")),
    };

    let (status, _, _) = get_status(state_dir, name);
    if status == "RUNNING" {
        stop_internal(state_dir, name, &meta, 10);
    }

    cmd_start(state_dir, name, web_user, dbg)
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_add(
    state_dir: &Path,
    name: &str,
    app_type: &str,
    cwd: Option<&str>,
    entry: &str,
    host: &str,
    domain: Option<&str>,
    subdomain: Option<&str>,
    node_version: Option<&str>,
    env_vars: &[String],
    dbg: Option<&Value>,
) -> ! {
    // Resolver cwd: padrão {state_dir}/apps/nodejs/{host}
    let resolved_cwd = cwd.map(str::to_string).unwrap_or_else(|| {
        state_dir
            .join("apps")
            .join("nodejs")
            .join(host)
            .to_string_lossy()
            .into_owned()
    });
    let cwd = resolved_cwd.as_str();

    if !validate_name(name) {
        user_error("invalid_name", "nome deve seguir ^[A-Za-z0-9._-]{1,64}$");
    }
    if !validate_safe_component(entry) {
        user_error("invalid_entry", "entry não pode conter '/', '..' ou nulo");
    }
    if !validate_safe_component(host) {
        user_error("invalid_host", "host não pode conter '/', '..' ou nulo");
    }

    let app_file = state_dir.join(".run").join(format!("{name}.app"));

    // Criação atômica: create_new evita TOCTOU race condition
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&app_file)
    {
        Ok(_) => {} // arquivo criado, será escrito abaixo
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            user_error("app_exists", &format!("app '{name}' já existe"));
        }
        Err(e) => {
            system_error(
                "write_failed",
                &format!("criar {}: {e:#}", app_file.display()),
            );
        }
    }

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let content = format!(
        "type={app_type}\ncwd={cwd}\nentry={entry}\nhost={host}\ndomain={}\nsubdomain={}\nnode_version={}\ncreated_at={created_at}\n",
        domain.unwrap_or(""),
        subdomain.unwrap_or(""),
        node_version.unwrap_or(""),
    );

    if let Err(e) =
        atomic_write(&app_file, content.as_bytes()).and_then(|_| set_perm(&app_file, 0o600))
    {
        system_error("write_failed", &format!("{e:#}"));
    }

    // Criar diretório cwd
    let cwd_path = PathBuf::from(cwd);
    if let Err(e) = std::fs::create_dir_all(&cwd_path) {
        user_error(
            "cwd_create_failed",
            &format!("falha ao criar diretório cwd: {e:#}"),
        );
    }

    // Salvar .env no cwd do app
    if !env_vars.is_empty() {
        let env_file = cwd_path.join(".env");
        let env_content = env_vars.join("\n") + "\n";
        if let Err(e) =
            atomic_write(&env_file, env_content.as_bytes()).and_then(|_| set_perm(&env_file, 0o600))
        {
            system_error("write_failed", &format!("{e:#}"));
        }
    }

    // Validar entry para binários: deve existir e ser executável
    if app_type == "rust" {
        let entry_path = cwd_path.join(entry);
        if entry_path.exists() {
            if !is_executable_file(&entry_path) {
                user_error(
                    "entry_not_executable",
                    &format!("arquivo '{}' não é executável", entry_path.display()),
                );
            }
            if !is_elf(&entry_path) {
                user_error(
                    "entry_not_elf",
                    &format!(
                        "arquivo '{}' não é um binário ELF válido",
                        entry_path.display()
                    ),
                );
            }
        }
    }

    // Scaffold Node.js: gravar template se entry não existir
    if app_type == "node" {
        let entry_path = cwd_path.join(entry);
        if !entry_path.exists()
            && let Ok(exe) = std::env::current_exe()
            && let Some(bin_dir) = exe.parent()
            && let Some(plugin_dir) = bin_dir.parent()
        {
            let template = plugin_dir.join("templates/node/index.js");
            if let Ok(tpl) = std::fs::read_to_string(&template) {
                let rendered = tpl.replace("{{APP_NAME}}", name);
                let _ = std::fs::write(&entry_path, rendered.as_bytes());
            }
        }
    }

    success(with_debug(json!({}), dbg))
}

pub fn cmd_remove(state_dir: &Path, name: &str, delete_dir: bool, dbg: Option<&Value>) -> ! {
    let meta = match load_app_meta(state_dir, name) {
        Ok(m) => m,
        Err(_) => user_error("app_not_found", &format!("app '{name}' não encontrado")),
    };

    // Parar se estiver rodando
    stop_internal(state_dir, name, &meta, 10);

    // Remover arquivos de run
    let run_dir = state_dir.join(".run");
    for ext in &["app", "pid", "meta"] {
        let _ = std::fs::remove_file(run_dir.join(format!("{name}.{ext}")));
    }

    // Remover .env e logs do cwd
    let cwd_path = PathBuf::from(&meta.cwd);
    let _ = std::fs::remove_file(cwd_path.join(".env"));
    let logs_dir = cwd_path.join("logs");
    let _ = std::fs::remove_file(logs_dir.join(format!("{name}.out.log")));
    let _ = std::fs::remove_file(logs_dir.join(format!("{name}.err.log")));

    // Socket e marker (defensivo — stop_internal já removeu, mas pode ter falhado)
    let _ = std::fs::remove_file(state_dir.join(".sockets").join(&meta.host));
    let _ = std::fs::remove_file(state_dir.join(".proxy").join(&meta.host));

    if delete_dir {
        let _ = std::fs::remove_dir_all(&meta.cwd);
    }

    signal_sync();
    success(with_debug(json!({}), dbg))
}

/// Recebe dados pré-lidos como root (antes do drop de privilégio).
/// Cada entrada é (domain, vec_de_prefixos_de_subdominio).
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
    let meta = match load_app_meta(state_dir, name) {
        Ok(m) => m,
        Err(_) => user_error("app_not_found", &format!("app '{name}' não encontrado")),
    };

    let suffix = if use_stderr { "err" } else { "out" };
    let log_file = PathBuf::from(&meta.cwd)
        .join("logs")
        .join(format!("{name}.{suffix}.log"));

    let log_lines = read_tail(&log_file, lines);
    success(with_debug(json!({ "lines": log_lines }), dbg))
}

/// Coleta dados de todos os apps de todos os usuários.
/// Deve ser chamado como root (antes do privilege drop).
pub fn collect_admin_list() -> Vec<Value> {
    let mut apps = Vec::new();

    let state_base = Path::new("/var/lib/selynt_panel");
    let home_entries = match std::fs::read_dir(state_base) {
        Ok(e) => e,
        Err(_) => return apps,
    };

    for home_entry in home_entries.flatten() {
        let user_home = home_entry.path();
        if !user_home.is_dir() {
            continue;
        }
        let user = match user_home.file_name().and_then(|n| n.to_str()) {
            Some(u) => u.to_string(),
            None => continue,
        };

        let run_dir = user_home.join(".run");
        let run_entries = match std::fs::read_dir(&run_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in run_entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("app") {
                continue;
            }

            let name = match path.file_stem().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let kv = crate::state::parse_kv(&content);

            let app_type = kv.get("type").cloned().unwrap_or_default();
            let host = kv.get("host").cloned().unwrap_or_default();
            let cwd = kv.get("cwd").cloned().unwrap_or_default();
            let entry_file = kv.get("entry").cloned().unwrap_or_default();
            let created_at: Option<u64> = kv.get("created_at").and_then(|v| v.parse().ok());

            let pid_file = run_dir.join(format!("{name}.pid"));
            let meta_file = run_dir.join(format!("{name}.meta"));
            let (status, pid, started_at) = admin_get_status(&pid_file, &meta_file);
            let pid_val = pid.map(|p| json!(p)).unwrap_or(json!(null));

            apps.push(json!({
                "user":       user,
                "name":       name,
                "type":       app_type,
                "host":       host,
                "cwd":        cwd,
                "entry":      entry_file,
                "status":     status,
                "pid":        pid_val,
                "created_at": created_at,
                "started_at": started_at,
            }));
        }
    }

    apps.sort_by(|a, b| {
        let ua = a["user"].as_str().unwrap_or("");
        let ub = b["user"].as_str().unwrap_or("");
        let na = a["name"].as_str().unwrap_or("");
        let nb = b["name"].as_str().unwrap_or("");
        ua.cmp(ub).then(na.cmp(nb))
    });

    apps
}

/// Formata e retorna a lista de apps coletada como root.
pub fn cmd_admin_list(apps: Vec<Value>, dbg: Option<&Value>) -> ! {
    success(with_debug(json!({ "apps": apps }), dbg))
}

/// Detecta versões do Node.js instaladas no sistema.
/// Detecta versões do Node.js instaladas no sistema.
/// Retorna Vec de (path, version) — ex: ("/usr/bin/node", "v22.22.0")
fn detect_node_versions() -> Vec<(String, String)> {
    let fixed = ["/usr/local/bin/node", "/usr/bin/node"];
    let globs = [
        "/usr/local/nvm/versions/node/*/bin/node",
        "/opt/alt/alt-nodejs*/root/usr/bin/node",
    ];
    let nvm_dir_glob = std::env::var("NVM_DIR")
        .ok()
        .filter(|d| {
            let safe =
                d.starts_with("/home/") || d.starts_with("/opt/") || d.starts_with("/usr/local/");
            safe && !d.contains("..")
        })
        .map(|d| format!("{d}/versions/node/*/bin/node"));

    let mut candidates: Vec<std::path::PathBuf> = fixed.iter().map(PathBuf::from).collect();
    for pattern in globs.iter().map(|s| s.to_string()).chain(nvm_dir_glob) {
        if let Ok(paths) = glob_paths(&pattern) {
            candidates.extend(paths);
        }
    }

    let mut versions = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in &candidates {
        if !path.is_file() {
            continue;
        }
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        if !seen.insert(canonical) {
            continue;
        }
        if let Some(ver) = get_node_version(path) {
            versions.push((path.to_string_lossy().to_string(), ver));
        }
    }
    versions
}

pub fn cmd_admin_detect_nodes(dbg: Option<&Value>) -> ! {
    let versions: Vec<Value> = detect_node_versions()
        .into_iter()
        .map(|(path, ver)| json!({"version": ver, "path": path}))
        .collect();
    success(with_debug(json!({ "versions": versions }), dbg))
}

/// Salva versões do Node.js selecionadas por índice.
/// Roda como root (antes do drop de privilégio).
pub fn save_node_versions(indices: &[usize]) -> Result<Value, (String, String)> {
    let all = detect_node_versions();
    if all.is_empty() {
        return Err((
            "no_versions".into(),
            "Nenhuma versão do Node.js detectada.".into(),
        ));
    }

    // Validar índices e coletar selecionados
    let mut selected = Vec::new();
    let mut seen_ver = std::collections::HashSet::new();
    let mut dupes = Vec::new();

    for &idx in indices {
        if idx >= all.len() {
            return Err((
                "invalid_index".into(),
                format!("Índice {idx} inválido (máx: {}).", all.len() - 1),
            ));
        }
        let (ref path, ref ver) = all[idx];
        if !seen_ver.insert(ver.clone()) {
            dupes.push(ver.clone());
            continue;
        }
        selected.push(format!("{path} {ver}"));
    }

    if !dupes.is_empty() {
        let list = dupes.join(", ");
        return Err((
            "duplicate_versions".into(),
            format!("Versões duplicadas: {list}. Cada versão deve ter apenas um path."),
        ));
    }

    if selected.is_empty() {
        return Err((
            "no_selection".into(),
            "Nenhuma versão válida selecionada.".into(),
        ));
    }

    // Escrever arquivo
    let etc_dir = Path::new(crate::state::PLUGIN_PATH).join("etc");
    if !etc_dir.is_dir() {
        std::fs::create_dir_all(&etc_dir).map_err(|e| {
            (
                "write_failed".into(),
                format!("Erro ao criar {}: {e}", etc_dir.display()),
            )
        })?;
    }
    // etc/ deve ser 755 — CGI admin roda como o admin logado, não como diradmin
    let _ = std::fs::set_permissions(&etc_dir, std::fs::Permissions::from_mode(0o755));

    let nv_file = etc_dir.join("node_versions");
    let content = selected.join("\n") + "\n";
    std::fs::write(&nv_file, content.as_bytes()).map_err(|e| {
        (
            "write_failed".into(),
            format!("Erro ao gravar {}: {e}", nv_file.display()),
        )
    })?;
    let _ = std::fs::set_permissions(&nv_file, std::fs::Permissions::from_mode(0o644));

    Ok(
        json!({"message": "Versões salvas.", "saved": selected.len(), "file": nv_file.to_string_lossy()}),
    )
}

/// Versão mínima do Node.js suportada (--import requer 20.6+)
const NODE_MIN_MAJOR: u32 = 20;
const NODE_MIN_MINOR: u32 = 6;

/// Parseia "v20.15.1" → Some((20, 15, 1))
fn parse_node_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let s = ver.strip_prefix('v')?;
    let mut parts = s.splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Retorna true se a versão atende ao mínimo exigido
fn node_version_ok(ver: &str) -> bool {
    match parse_node_semver(ver) {
        Some((major, minor, _)) => {
            major > NODE_MIN_MAJOR || (major == NODE_MIN_MAJOR && minor >= NODE_MIN_MINOR)
        }
        None => false,
    }
}

/// Roda `{path} --version` e retorna a saída (ex: "v20.15.1"), sem validação.
fn get_node_version_raw(path: &Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if ver.starts_with('v') {
        Some(ver)
    } else {
        None
    }
}

/// Roda `{path} --version` e retorna a saída somente se >= mínimo suportado.
fn get_node_version(path: &Path) -> Option<String> {
    let ver = get_node_version_raw(path)?;
    if node_version_ok(&ver) {
        Some(ver)
    } else {
        None
    }
}

/// Glob simples para paths com *
fn glob_paths(pattern: &str) -> Result<Vec<PathBuf>, ()> {
    let mut results = Vec::new();
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() != 2 {
        return Ok(results);
    }
    let (prefix, suffix) = (parts[0], parts[1]);
    let parent = Path::new(prefix.trim_end_matches('/'));
    if !parent.is_dir() {
        return Ok(results);
    }
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let candidate = entry.path().join(suffix.trim_start_matches('/'));
            if candidate.is_file() {
                results.push(candidate);
            }
        }
    }
    Ok(results)
}

// ─── Validação de binários ───────────────────────────────────────────────────

/// Verifica se o arquivo tem permissão de execução
fn is_executable_file(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111) != 0,
        Err(_) => false,
    }
}

/// Verifica se o arquivo começa com o magic number ELF (\x7fELF)
fn is_elf(path: &Path) -> bool {
    let mut buf = [0u8; 4];
    match std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => buf == [0x7f, b'E', b'L', b'F'],
        Err(_) => false,
    }
}
