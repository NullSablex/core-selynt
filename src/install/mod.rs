//! Putting the plugin in place, taking it out, and checking what is there.
//!
//! [`setup`] and [`diagnose`] are neighbours on purpose: one applies the
//! expected state and the other verifies it, so they share
//! [`tree::expected_mode`] rather than each carrying a copy that could drift.

pub(crate) mod diagnose;
pub(crate) mod setup;
pub(crate) mod teardown;
pub(crate) mod tree;
pub(crate) mod units;
