use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const SOCKET_PATHS: &[&str] = &[
    "/usr/local/directadmin/shared/internal.sock",
    "/usr/local/directadmin/da-internal.sock",
];

const TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve o socket DA (testa na ordem, retorna o primeiro que existir)
pub fn resolve_socket() -> Option<&'static str> {
    SOCKET_PATHS
        .iter()
        .find(|&&p| Path::new(p).exists())
        .copied()
}

/// Resolve o cookie a partir das env vars CGI (ordem de prioridade)
pub fn resolve_cookie() -> String {
    if let Ok(c) = std::env::var("COOKIESTRING") {
        return c;
    }
    if let Ok(c) = std::env::var("HTTP_COOKIE") {
        return c;
    }
    if let Ok(s) = std::env::var("SESSION") {
        return format!("session={s}");
    }
    String::new()
}

/// Faz GET HTTP/1.0 sobre Unix socket.
/// Retorna `(body, raw_excerpt)` onde raw_excerpt são os primeiros 200 chars da resposta bruta.
pub fn da_get(socket_path: &str, path: &str, cookie: &str) -> Result<(String, String), String> {
    let mut stream =
        UnixStream::connect(socket_path).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();

    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: localhost\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read: {e}"))?;

    let raw_excerpt: String = response.chars().take(200).collect();

    // Separar headers do body (HTTP separa com \r\n\r\n ou \n\n)
    let body = if let Some(idx) = response.find("\r\n\r\n") {
        response[idx + 4..].to_string()
    } else if let Some(idx) = response.find("\n\n") {
        response[idx + 2..].to_string()
    } else {
        response
    };

    Ok((body, raw_excerpt))
}

/// Parse de `list[]=val1&list[]=val2` → Vec<String>
pub fn parse_list(body: &str) -> Vec<String> {
    body.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == "list[]" {
                Some(url_decode(v.trim()))
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    result.push(byte as char);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            result.push(' ');
        } else {
            result.push(bytes[i] as char);
        }
        i += 1;
    }
    result
}
