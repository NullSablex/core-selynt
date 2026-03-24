use serde_json::{Value, json};
use std::process;

/// Saída de sucesso: {"ok": true, ...extra} → exit 0
pub fn success(extra: Value) -> ! {
    let mut obj = serde_json::Map::new();
    obj.insert("ok".to_string(), Value::Bool(true));
    if let Value::Object(map) = extra {
        obj.extend(map);
    }
    println!("{}", Value::Object(obj));
    process::exit(0);
}

/// Erro de usuário (input inválido, app não existe, estado incorreto) → exit 1
pub fn user_error(error: &str, message: &str) -> ! {
    println!(
        "{}",
        json!({"ok": false, "error": error, "message": message})
    );
    process::exit(1);
}

/// Erro de sistema (filesystem, permissão, processo, socket) → exit 2
pub fn system_error(error: &str, message: &str) -> ! {
    println!(
        "{}",
        json!({"ok": false, "error": error, "message": message})
    );
    process::exit(2);
}

/// Debug — apenas com SELYNT_DEBUG=1, nunca parseado pelo plugin
pub fn debug(msg: impl std::fmt::Display) {
    if std::env::var("SELYNT_DEBUG").as_deref() == Ok("1") {
        eprintln!("[DEBUG] {msg}");
    }
}
