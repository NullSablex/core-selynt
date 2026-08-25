//! The runtimes the panel supports, and what differs between them.
//!
//! These decisions used to be `if app_type == "node"` scattered across the
//! code, where a missed site failed at run time. Hanging them off this enum
//! makes the compiler point at each one a new variant has to answer.

use std::str::FromStr;

/// A supported application runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    /// Node.js: the panel picks the interpreter and runs the entry script.
    Node,
    /// Rust: the customer compiles a binary and the panel executes it directly.
    Rust,
}

impl Runtime {
    /// Every runtime, in the order the UI should offer them.
    pub const ALL: [Self; 2] = [Self::Node, Self::Rust];

    /// The stable identifier persisted in app metadata (`type=` in `.app`
    /// files) and sent over the JSON API. Changing one breaks existing apps.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Rust => "rust",
        }
    }

    /// Whether the panel chooses and runs an interpreter for this runtime.
    ///
    /// Interpreted runtimes take a version selected by the admin; compiled ones
    /// execute the entry file itself and have nothing to configure.
    pub const fn is_interpreted(self) -> bool {
        match self {
            Self::Node => true,
            Self::Rust => false,
        }
    }

    /// Whether a fresh app of this runtime gets a starter entry file written
    /// for it. Compiled runtimes cannot be scaffolded — there is nothing
    /// meaningful to emit before the customer builds their binary.
    pub const fn scaffolds_entry(self) -> bool {
        self.is_interpreted()
    }

    /// Whether the entry file must already exist and be executable at create
    /// time. True exactly for the runtimes the panel cannot scaffold.
    pub const fn requires_executable_entry(self) -> bool {
        !self.scaffolds_entry()
    }

    /// How to describe the launch in error messages, given the resolved entry
    /// path. Interpreted runtimes name the interpreter; compiled ones are just
    /// the binary.
    pub fn command_display(self, entry: &std::path::Path) -> String {
        if self.is_interpreted() {
            format!("{} {}", self.as_str(), entry.display())
        } else {
            entry.display().to_string()
        }
    }
}

impl FromStr for Runtime {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.into_iter().find(|r| r.as_str() == s).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::Runtime;
    use std::path::Path;
    use std::str::FromStr;

    /// The persisted identifiers must round-trip: metadata written by an older
    /// build has to keep parsing.
    #[test]
    fn round_trips_every_variant() {
        for r in Runtime::ALL {
            assert_eq!(Runtime::from_str(r.as_str()), Ok(r));
        }
    }

    #[test]
    fn rejects_unknown() {
        assert!(Runtime::from_str("python").is_err());
        assert!(Runtime::from_str("").is_err());
    }

    #[test]
    fn compiled_and_interpreted_split() {
        assert!(Runtime::Node.is_interpreted());
        assert!(Runtime::Node.scaffolds_entry());
        assert!(!Runtime::Node.requires_executable_entry());

        assert!(!Runtime::Rust.is_interpreted());
        assert!(!Runtime::Rust.scaffolds_entry());
        assert!(Runtime::Rust.requires_executable_entry());
    }

    #[test]
    fn command_display_names_the_interpreter() {
        let e = Path::new("/home/bob/app/index.js");
        assert_eq!(
            Runtime::Node.command_display(e),
            "node /home/bob/app/index.js"
        );
        let e = Path::new("/home/bob/app/server");
        assert_eq!(Runtime::Rust.command_display(e), "/home/bob/app/server");
    }
}
