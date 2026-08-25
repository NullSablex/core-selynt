//! What an application runs on.
//!
//! * [`kind`] — the runtimes the panel supports (Node.js, Rust) and what
//!   differs between them: whether the panel picks an interpreter, whether a
//!   starter file can be scaffolded, how a launch is described in errors.
//! * [`node`] — parsing and comparing Node.js versions, and the glob expansion
//!   the detector needs to find them.
//! * [`detect`] — locating the Node.js installations on this server and judging
//!   which are safe to execute as root.

pub(crate) mod detect;
pub(crate) mod kind;
pub(crate) mod node;
