//! Minimal, read-only Btrfs format support.
//!
//! This crate currently locates and validates the primary superblock and
//! exposes its core volume metadata. B-tree traversal, checksum validation,
//! file lookup, and data reads remain deliberately unimplemented.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![forbid(unsafe_code)]

mod error;
mod superblock;

pub use error::{BtrfsError, Result};
pub use fsmnt_parser_core::io;
pub use superblock::{
    BtrfsSuperblock, PRIMARY_SUPERBLOCK_OFFSET, SUPERBLOCK_MAGIC, SUPERBLOCK_SIZE,
};

use io::{Read, Seek, SeekFrom};

/// An opened Btrfs volume with its primary superblock metadata.
///
/// The reader is retained so future parser work can add tree traversal
/// without changing the opening API.
pub struct Btrfs<R> {
    reader: R,
    superblock: BtrfsSuperblock,
}

impl<R: Read + Seek> Btrfs<R> {
    /// Open a Btrfs volume and validate its primary superblock.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] when the reader cannot reach the primary
    /// superblock or its identifying fields and geometry are invalid.
    pub fn new(mut reader: R) -> Result<Self> {
        reader.seek(SeekFrom::Start(PRIMARY_SUPERBLOCK_OFFSET))?;
        let mut data = [0_u8; SUPERBLOCK_SIZE];
        reader.read_exact(&mut data)?;
        let superblock = BtrfsSuperblock::from_primary_bytes(&data)?;
        Ok(Self { reader, superblock })
    }

    /// Validated primary-superblock metadata.
    #[must_use]
    pub const fn superblock(&self) -> &BtrfsSuperblock {
        &self.superblock
    }

    /// Shared access to the underlying volume reader.
    #[must_use]
    pub const fn reader(&self) -> &R {
        &self.reader
    }

    /// Mutable access to the underlying volume reader.
    pub const fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consume the volume wrapper and return its reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }
}

#[cfg(test)]
mod tests;
