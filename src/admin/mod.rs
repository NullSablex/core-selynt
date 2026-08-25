//! The administrator's side of the panel.
//!
//! Everything here answers to `/CMD_PLUGINS_ADMIN/`, which DirectAdmin only
//! serves to an account whose `usertype` is `admin` or `reseller` — a customer
//! reaching these URLs gets HTTP 500 before the binary is ever invoked. The
//! commands still verify authority themselves (see `sys::auth::caller_is_privileged`);
//! the web layer is the first gate, not the only one.
//!
//! * [`server`] — server-wide settings: which Node.js runtimes are offered,
//!   whether new accounts isolate their apps by default, and the cross-account
//!   inventory the admin dashboard lists.
//! * [`locale`] — the panel's language, both the server default and each
//!   account's own preference. Writes here need root because the state
//!   directory belongs to `diradmin`.

pub(crate) mod locale;
pub(crate) mod server;
