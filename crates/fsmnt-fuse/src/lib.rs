//! FUSE mount backend for `fsmnt` (macOS and Linux).
//!
//! On non-Unix targets this crate compiles to an empty library so that
//! workspace-wide builds work everywhere; the platform-specific
//! dependencies are only pulled in on Unix.

#[cfg(unix)]
mod fuse;

#[cfg(unix)]
pub use fuse::{is_mounted, mount, unmount};
