//! The administrator's side of the panel.
//!
//! DirectAdmin only serves `/CMD_PLUGINS_ADMIN/` to an `admin` or `reseller`
//! account, but that is the first gate, not the only one: the commands still
//! check authority themselves through [`crate::sys::auth`].

pub(crate) mod locale;
pub(crate) mod server;
