//! Shared support for filesystem integration tests.
//!
//! This crate is intended only for workspace dev-dependencies. Keeping fixture
//! I/O here prevents integration-test utilities from entering the parsers'
//! normal or `no_std` dependency graphs.

use std::path::{Path, PathBuf};

/// Resolves a fixture path relative to a crate's manifest directory.
#[must_use]
pub fn fixture_path(manifest_dir: impl AsRef<Path>, relative_path: impl AsRef<Path>) -> PathBuf {
    manifest_dir.as_ref().join(relative_path)
}

/// Reads a required binary fixture.
///
/// `regeneration_hint` is included in the panic message so a missing fixture is
/// actionable in local development and CI.
///
/// # Panics
///
/// Panics when the fixture cannot be read.
#[must_use]
pub fn read_required_fixture(
    manifest_dir: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
    regeneration_hint: &str,
) -> Vec<u8> {
    let path = fixture_path(manifest_dir, relative_path);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read fixture {}: {error}\n{regeneration_hint}",
            path.display()
        )
    })
}

/// Reads an optional binary fixture, returning `None` when it is absent.
///
/// I/O errors other than a missing file still panic because they indicate a
/// broken fixture rather than an intentionally ungenerated one.
///
/// # Panics
///
/// Panics when the fixture exists but cannot be read.
#[must_use]
pub fn read_optional_fixture(
    manifest_dir: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
) -> Option<Vec<u8>> {
    let path = fixture_path(manifest_dir, relative_path);
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("failed to read fixture {}: {error}", path.display()),
    }
}
