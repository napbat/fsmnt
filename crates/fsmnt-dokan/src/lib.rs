//! Dokan mount backend for `fsmnt` (Windows).
//!
//! On non-Windows targets this crate compiles to an empty library so that
//! workspace-wide builds work everywhere; the platform-specific
//! dependencies are only pulled in on Windows.

#[cfg(windows)]
mod cache;

#[cfg(windows)]
mod dokan;

#[cfg(windows)]
pub use dokan::{is_mounted, mount, unmount};
