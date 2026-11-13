use serde_json::{Value, json};
use std::path::PathBuf;
use std::process;
use std::sync::Mutex;

/// O app sobre o qual esta execução está agindo, quando é um start.
///
/// Toda falha de start termina em `user_error` ou `system_error`; registrar
/// aqui pega todas, inclusive as que ainda não existem, sem depender de cada
/// ponto de falha lembrar de gravar.
static FAILURE_CTX: Mutex<Option<(PathBuf, String)>> = Mutex::new(None);

/// Passa a registrar como última falha do app qualquer erro desta execução.
pub fn track_failures_for(state_dir: &std::path::Path, name: &str) {
    if let Ok(mut c) = FAILURE_CTX.lock() {
        *c = Some((state_dir.to_path_buf(), name.to_string()));
    }
}

fn record_tracked_failure(error: &str, message: &str) {
    let ctx = FAILURE_CTX.lock().ok().and_then(|c| c.clone());
    if let Some((state_dir, name)) = ctx {
        // Quem chamou: o boot-recover marca a origem; o resto é a tela.
        let origin = std::env::var("SELYNT_ORIGIN").unwrap_or_else(|_| "panel".into());
        let origin = if origin == "boot" { "boot" } else { "panel" };
        crate::sys::state::record_failure(&state_dir, &name, error, message, origin);
    }
}

pub fn success(extra: Value) -> ! {
    let mut obj = serde_json::Map::new();
    obj.insert("ok".to_string(), Value::Bool(true));
    if let Value::Object(map) = extra {
        obj.extend(map);
    }
    println!("{}", Value::Object(obj));
    process::exit(0);
}

pub fn user_error(error: &str, message: &str) -> ! {
    record_tracked_failure(error, message);
    println!(
        "{}",
        json!({"ok": false, "error": error, "message": message})
    );
    process::exit(1);
}

pub fn system_error(error: &str, message: &str) -> ! {
    record_tracked_failure(error, message);
    println!(
        "{}",
        json!({"ok": false, "error": error, "message": message})
    );
    process::exit(2);
}

/// Emits a debug line on stderr only when `SELYNT_DEBUG=1`. The plugin never
/// parses stderr, so this is safe to call from any code path.
pub fn debug(msg: impl std::fmt::Display) {
    if std::env::var("SELYNT_DEBUG").as_deref() == Ok("1") {
        eprintln!("[DEBUG] {msg}");
    }
}
