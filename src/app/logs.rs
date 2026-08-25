//! Reading and trimming an application's log files.
//!
//! Truncated at every start, so the panel shows what the app is saying now, and
//! read from the end — a log can be far larger than the few lines the interface
//! asks for. Escape sequences are stripped: the output lands in HTML and the
//! log is written by the customer's own process.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::sys::fs::atomic_write;

const LOG_TAIL_CHUNK: u64 = 8192;
const LOG_ROTATE_MAX_BYTES: u64 = 50 * 1024 * 1024;
const LOG_ROTATE_KEEP_LINES: usize = 5000;

/// Removes ANSI escape sequences (CSI/OSC and the shorter two-byte forms) from
/// `s`, leaving the plain text.
pub(super) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // CSI: params/intermediates, then a final byte in @..~
            Some('[') => {
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: runs until BEL or the ST sequence (ESC \).
            Some(']') => {
                let mut prev_esc = false;
                for c in chars.by_ref() {
                    if c == '\x07' || (prev_esc && c == '\\') {
                        break;
                    }
                    prev_esc = c == '\x1b';
                }
            }
            // Two-byte escapes (ESC c, ESC =, …): drop both.
            Some(_) => {}
            None => break,
        }
    }
    out
}

/// Efficient tail: reads back from EOF in `LOG_TAIL_CHUNK`-sized blocks until
/// at least `n` newlines have been seen, then returns the last `n` lines.
pub(super) fn read_tail(path: &Path, n: usize) -> Vec<String> {
    if n == 0 {
        return Vec::new();
    }

    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };

    let Ok(size) = file.seek(SeekFrom::End(0)) else {
        return Vec::new();
    };

    if size == 0 {
        return Vec::new();
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut newlines: usize = 0;
    let mut cursor = size;

    while cursor > 0 && newlines <= n {
        let to_read = LOG_TAIL_CHUNK.min(cursor);
        cursor -= to_read;

        if file.seek(SeekFrom::Start(cursor)).is_err() {
            break;
        }
        let Ok(to_read_usize) = usize::try_from(to_read) else {
            break;
        };
        let mut chunk = vec![0u8; to_read_usize];
        if file.read_exact(&mut chunk).is_err() {
            break;
        }

        #[allow(clippy::naive_bytecount)]
        let chunk_newlines = chunk.iter().filter(|&&b| b == b'\n').count();
        newlines += chunk_newlines;

        chunk.extend_from_slice(&buf);
        buf = chunk;
    }

    let s = String::from_utf8_lossy(&buf);
    let lines: Vec<String> = s.lines().map(str::to_owned).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].to_vec()
}

/// Truncates a log file to the last `LOG_ROTATE_KEEP_LINES` lines when it
/// grows past `LOG_ROTATE_MAX_BYTES`.
pub(super) fn rotate_log_if_needed(path: &Path) {
    let size = std::fs::metadata(path).map_or(0, |m| m.len());
    if size <= LOG_ROTATE_MAX_BYTES {
        return;
    }
    crate::sys::output::debug(format!("rotating log {} ({size} bytes)", path.display()));

    let lines = read_tail(path, LOG_ROTATE_KEEP_LINES);
    let content = lines.join("\n") + "\n";
    let _ = atomic_write(path, content.as_bytes());
}
