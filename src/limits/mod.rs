//! What an application is allowed to consume, and what it is allowed to reach.
//!
//! Four layers, each enforced by the kernel rather than by the panel asking
//! nicely:
//!
//! * [`policy`] — how much memory an app may use. Decides the numbers; applies
//!   none of them.
//! * [`usage`] — reads what an app is actually consuming from its cgroup, reads
//!   the account's allowance from DirectAdmin, and pushes the resolved limits
//!   onto the live systemd scopes.
//! * [`netguard`] — stops an app that binds a port reachable from outside the
//!   host, which would bypass the proxy entirely.
//! * [`sandbox`] — mount and PID namespaces, so an account's apps cannot see
//!   each other's files or signal each other's processes.
//!
//! The cgroup is what ties them together: an app's scope is where its usage is
//! measured, where its memory ceiling is applied, and how `netguard` finds
//! every process it spawned — including children started without the panel's
//! knowledge.

pub(crate) mod netguard;
pub(crate) mod policy;
pub(crate) mod sandbox;
pub(crate) mod usage;
