//! The panel's only web-server-specific code.
//!
//! An app serves over a Unix socket and never binds a port, so the web server
//! in front has to route to it. Supporting Apache or Nginx means writing
//! siblings to [`ols`] and [`proxysync`], and nothing outside this directory.

pub(crate) mod acl;
pub(crate) mod ols;
pub(crate) mod proxysync;
