//! The layer between the panel and the operating system.
//!
//! [`auth`] is the sensitive one: the binary runs setuid root, so authority
//! comes from the real uid and from DirectAdmin's account database, never from
//! the `USERNAME` the caller supplies.

pub(crate) mod auth;
pub(crate) mod fs;
pub(crate) mod output;
pub(crate) mod proc;
pub(crate) mod state;
