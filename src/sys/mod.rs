//! The layer between the panel and the operating system.
//!
//! [`auth`] is the sensitive one: the binary runs setuid root, so authority
//! comes from the real uid and from `DirectAdmin`'s account database, never from
//! the `USERNAME` the caller supplies.

pub mod auth;
pub mod fs;
pub mod output;
pub mod proc;
pub mod state;
