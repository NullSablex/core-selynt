//! Putting the plugin in place, taking it out, and checking what is there.
//!
//! * [`setup`] — resolves the accounts the panel has to trust, creates the
//!   state directory, and fixes ownership across the plugin tree.
//! * [`teardown`] — undoes all of it, leaving the server as it was.
//! * [`units`] — the systemd units the panel installs, embedded here rather
//!   than shipped as files: this binary runs setuid root, so a unit on disk is
//!   a file whose contents become root execution.
//! * [`diagnose`] — reports what is actually installed, for the admin page.
//! * [`tree`] — walking the plugin tree and the permissions it should have.
//!
//! Install and diagnose are deliberately neighbours: one applies the expected
//! state and the other verifies it, so they must agree on what "expected"
//! means. [`tree::expected_mode`] is that shared definition — kept in one
//! place precisely because two copies would drift, and the drift would show up
//! as a diagnostic that passes on a tree the installer never produces.

pub(crate) mod diagnose;
pub(crate) mod setup;
pub(crate) mod teardown;
pub(crate) mod tree;
pub(crate) mod units;
