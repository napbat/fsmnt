//! Core library for `fsmnt`.
//!
//! All functionality lives here; `src/main.rs` is a thin CLI wrapper around
//! this crate.

/// Returns the greeting printed by the `fsmnt` CLI.
#[must_use]
pub fn greeting() -> &'static str {
    "Hello, world!"
}
