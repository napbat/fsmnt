use thiserror::Error;

use crate::io;

/// Result type returned by the Btrfs parser.
pub type Result<T, E = BtrfsError> = core::result::Result<T, E>;

/// Errors encountered while opening or parsing a Btrfs volume.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BtrfsError {
    /// The reader failed while locating or loading the primary superblock.
    #[error("I/O error: {0:?}")]
    Io(io::Error),
    /// A supplied superblock buffer is shorter than the on-disk structure.
    #[error("Btrfs superblock is too short: expected {expected} bytes, got {actual}")]
    BufferTooSmall {
        /// Minimum number of bytes required.
        expected: usize,
        /// Number of bytes supplied.
        actual: usize,
    },
    /// The primary superblock does not carry the Btrfs signature.
    #[error("invalid Btrfs magic: {actual:?}")]
    InvalidMagic {
        /// Eight bytes found in the magic field.
        actual: [u8; 8],
    },
    /// The superblock's physical self-address is not the primary location.
    #[error("invalid primary-superblock address: {actual:#x}")]
    InvalidPhysicalAddress {
        /// Physical address stored in the superblock.
        actual: u64,
    },
    /// The declared volume size cannot contain the primary superblock.
    #[error("invalid Btrfs volume size: {actual} bytes")]
    InvalidTotalBytes {
        /// Declared total volume size.
        actual: u64,
    },
    /// Allocated bytes exceed the declared volume size.
    #[error("Btrfs bytes used ({bytes_used}) exceed total bytes ({total_bytes})")]
    InvalidBytesUsed {
        /// Declared number of allocated bytes.
        bytes_used: u64,
        /// Declared total volume size.
        total_bytes: u64,
    },
    /// The filesystem claims to have no backing devices.
    #[error("Btrfs superblock declares zero devices")]
    InvalidDeviceCount,
    /// The sector size is not a supported power of two.
    #[error("invalid Btrfs sector size: {actual}")]
    InvalidSectorSize {
        /// Sector size stored in the superblock.
        actual: u32,
    },
    /// The tree node size is incompatible with the sector size.
    #[error("invalid Btrfs node size {actual} for sector size {sector_size}")]
    InvalidNodeSize {
        /// Tree node size stored in the superblock.
        actual: u32,
        /// Previously validated sector size.
        sector_size: u32,
    },
}

impl From<io::Error> for BtrfsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
