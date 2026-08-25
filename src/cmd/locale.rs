//! Panel-language preference writes. These must run as root (in the prelude)
//! because the state dir is owned by `diradmin` (711) while the panel CGI runs
//! as the web user, which cannot write there. The PHP layer reads the files
//! back; here we only validate and persist them.

use std::path::Path;

use serde_json::{Value, json};

use crate::state::{PLUGIN_PATH, STATE_BASE, chown_path};


/// Validates a locale code against the dictionaries shipped under
/// `lib/i18n/*.json`. `en` is always accepted (the built-in default). Returns
/// the normalized code, or `None` if it isn't available.
fn validate_locale(locale: &str) -> Option<String> {
    let want = locale.trim().to_ascii_lowercase().replace('_', "-");
    if want.is_empty() {
        return None;
    }
    if want == "en" {
        return Some(want);
    }
    let dir = format!("{PLUGIN_PATH}/lib/i18n");
    let entries = std::fs::read_dir(&dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(code) = name.strip_suffix(".json")
            && code.eq_ignore_ascii_case(&want)
        {
            return Some(code.to_string());
        }
    }
    None
}

fn invalid_locale_err() -> (String, String) {
    ("invalid_locale".into(), "Unknown language code.".into())
}

/// Persists the plugin-wide default language to `<STATE_BASE>/locale`. An empty
/// `locale` clears it (falling back to the built-in default).
pub fn set_locale_global(locale: &str) -> Result<Value, (String, String)> {
    let path = Path::new(STATE_BASE).join("locale");
    write_locale(&path, locale).map(|code| json!({ "global": code }))
}

/// Persists the current user's own language preference to
/// `<state_dir>/locale`, owned by the user so the read path stays simple.
pub fn set_locale_user(
    state_dir: &Path,
    locale: &str,
    uid: u32,
    gid: u32,
) -> Result<Value, (String, String)> {
    let path = state_dir.join("locale");
    let code = write_locale(&path, locale)?;
    // Hand the file to the real user (the state dir itself is theirs already).
    if !code.is_empty() {
        let _ = chown_path(&path, uid, gid);
    }
    Ok(json!({ "pref": code }))
}

/// Writes a validated locale to `path` (0644) or removes it when `locale` is
/// empty. Returns the stored code (`""` once cleared).
fn write_locale(path: &Path, locale: &str) -> Result<String, (String, String)> {
    use std::os::unix::fs::PermissionsExt;

    if locale.trim().is_empty() {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(String::new()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err((
                "write_failed".into(),
                format!("failed to clear {}: {e}", path.display()),
            )),
        }
    } else {
        let code = validate_locale(locale).ok_or_else(invalid_locale_err)?;
        std::fs::write(path, format!("{code}\n")).map_err(|e| {
            (
                "write_failed".into(),
                format!("failed to write {}: {e}", path.display()),
            )
        })?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
        Ok(code)
    }
}
