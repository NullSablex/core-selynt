//! What an application may consume, and what it may reach.
//!
//! The cgroup ties these together: an app's scope is where usage is measured,
//! where its memory ceiling applies, and how [`netguard`] finds every process
//! it spawned — including children the panel never saw start.

pub mod netguard;
pub mod policy;
pub mod sandbox;
pub mod usage;
