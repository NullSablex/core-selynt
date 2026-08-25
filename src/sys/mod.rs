//! The layer between the panel and the operating system.
//!
//! * [`auth`] — who the caller really is, and what they may act on. The most
//!   sensitive code here: this binary runs setuid root, so authority comes from
//!   the *real* uid and from DirectAdmin's own account database, never from the
//!   `USERNAME` the caller supplies.
//! * [`fs`] — writing to disk without leaving a half-written file behind, and
//!   setting ownership and modes.
//! * [`state`] — what the panel keeps about accounts and their apps: the state
//!   directory, `.app` metadata, socket paths.
//! * [`proc`] — reading `/proc`: whether a process is alive, who owns it, what
//!   it spawned, and whether it bound a port reachable from outside.
//! * [`output`] — the single JSON object every command prints. Its only reader
//!   is the panel's PHP layer, which is why even an internal failure has to
//!   come out as JSON rather than a panic.

pub(crate) mod auth;
pub(crate) mod fs;
pub(crate) mod output;
pub(crate) mod proc;
pub(crate) mod state;
