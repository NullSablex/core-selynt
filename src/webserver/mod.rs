//! Everything that couples the panel to the web server in front of it.
//!
//! An app serves over a Unix socket and never binds a port, so something has to
//! route public traffic to it. That is the whole job of this module, split in
//! three:
//!
//! * [`ols`] — the OpenLiteSpeed installation itself: where its configuration
//!   lives, the vhost templates DirectAdmin renders, and asking it to reload.
//! * [`proxysync`] — regenerating the proxy handlers from the apps that are
//!   actually up, and reloading the server when they change.
//! * [`acl`] — granting the web server's account the access it needs to reach
//!   an app's socket, and nothing more.
//!
//! Kept together because they are the panel's only web-server-specific code:
//! supporting Apache or Nginx means writing siblings to `ols` and `proxysync`,
//! not touching anything outside this directory.

pub(crate) mod acl;
pub(crate) mod ols;
pub(crate) mod proxysync;
