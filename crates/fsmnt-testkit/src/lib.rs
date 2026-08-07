//! Shared support for filesystem integration tests.
//!
//! This crate is intended only for workspace dev-dependencies. Keeping fixture
//! I/O here prevents integration-test utilities from entering the parsers'
//! normal or `no_std` dependency graphs.

use std::path::{Path, PathBuf};

/// In-memory cursor compatible with both `std::io` and the parsers'
/// no-std I/O traits.
#[derive(Clone, Debug, Default)]
pub struct Cursor<T> {
    inner: std::io::Cursor<T>,
}

impl<T> Cursor<T> {
    /// Creates a cursor over `inner`.
    pub fn new(inner: T) -> Self {
        Self {
            inner: std::io::Cursor::new(inner),
        }
    }

    /// Returns a shared reference to the underlying value.
    pub const fn get_ref(&self) -> &T {
        self.inner.get_ref()
    }

    /// Returns a mutable reference to the underlying value.
    pub const fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Consumes the cursor and returns the underlying value.
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }

    /// Returns the current byte position.
    pub const fn position(&self) -> u64 {
        self.inner.position()
    }

    /// Sets the current byte position.
    pub const fn set_position(&mut self, position: u64) {
        self.inner.set_position(position);
    }
}

impl<T> std::io::Write for Cursor<T>
where
    std::io::Cursor<T>: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.inner, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.inner)
    }
}

impl<T> fsmnt_parser_core::io::Read for Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn read(&mut self, buf: &mut [u8]) -> fsmnt_parser_core::io::Result<usize> {
        let data = self.inner.get_ref().as_ref();
        let position = usize::try_from(self.inner.position()).unwrap_or(usize::MAX);
        if position >= data.len() {
            return Ok(0);
        }
        let amount = buf.len().min(data.len() - position);
        buf[..amount].copy_from_slice(&data[position..position + amount]);
        let amount_u64 = u64::try_from(amount).expect("read length fits in u64");
        self.inner
            .set_position(self.inner.position().saturating_add(amount_u64));
        Ok(amount)
    }
}

impl<T> fsmnt_parser_core::io::Seek for Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn seek(
        &mut self,
        position: fsmnt_parser_core::io::SeekFrom,
    ) -> fsmnt_parser_core::io::Result<u64> {
        let new_position = match position {
            fsmnt_parser_core::io::SeekFrom::Start(offset) => Some(offset),
            fsmnt_parser_core::io::SeekFrom::End(offset) => {
                let len = u64::try_from(self.inner.get_ref().as_ref().len())
                    .expect("buffer length fits in u64");
                offset_position(len, offset)
            }
            fsmnt_parser_core::io::SeekFrom::Current(offset) => {
                offset_position(self.inner.position(), offset)
            }
        };
        let Some(new_position) = new_position else {
            return Err(fsmnt_parser_core::io::ErrorKind::InvalidInput.into());
        };
        self.inner.set_position(new_position);
        Ok(new_position)
    }
}

fn offset_position(position: u64, offset: i64) -> Option<u64> {
    if offset >= 0 {
        position.checked_add(u64::try_from(offset).ok()?)
    } else {
        position.checked_sub(offset.unsigned_abs())
    }
}

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
