use serde_json::{Value, json};
use std::process;

pub(crate) fn success(extra: Value) -> ! {
    let mut obj = serde_json::Map::new();
    obj.insert("ok".to_string(), Value::Bool(true));
    if let Value::Object(map) = extra {
        obj.extend(map);
    }
    println!("{}", Value::Object(obj));
    process::exit(0);
}

pub(crate) fn user_error(error: &str, message: &str) -> ! {
    println!(
        "{}",
        json!({"ok": false, "error": error, "message": message})
    );
    process::exit(1);
}

pub(crate) fn system_error(error: &str, message: &str) -> ! {
    println!(
        "{}",
        json!({"ok": false, "error": error, "message": message})
    );
    process::exit(2);
}

/// Emits a debug line on stderr only when `SELYNT_DEBUG=1`. The plugin never
/// parses stderr, so this is safe to call from any code path.
pub(crate) fn debug(msg: impl std::fmt::Display) {
    if std::env::var("SELYNT_DEBUG").as_deref() == Ok("1") {
        eprintln!("[DEBUG] {msg}");
    }
}
