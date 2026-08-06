use fs_common::error::{self as fse, FsError};
use thiserror::Error;

use crate::io;

/// Central result type of fs-fat.
pub type Result<T, E = FatError> = core::result::Result<T, E>;

/// Central error type of fs-fat.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FatError {
    /// The volume does not end its boot sector with the FAT signature.
    #[error("Invalid boot signature: expected 0xAA55, found {actual:#06x}")]
    InvalidBootSignature {
        /// Signature value read from the boot sector.
        actual: u16,
    },

    /// The input is a `BitLocker` container rather than a directly readable FAT volume.
    #[error(
        "The volume is BitLocker-encrypted (OEM ID: {oem_id:?}). Decrypt the volume before parsing as FAT."
    )]
    BitLockerEncrypted {
        /// OEM identifier that marks the `BitLocker` container.
        oem_id: [u8; 8],
    },

    /// The BIOS parameter block specifies an unsupported sector size.
    #[error("Invalid bytes per sector: {actual} (must be 512, 1024, 2048, or 4096)")]
    InvalidBytesPerSector {
        /// Unsupported sector size from the parameter block.
        actual: u16,
    },

    /// The BIOS parameter block specifies an invalid cluster geometry.
    #[error("Invalid sectors per cluster: {actual} (must be a power of 2)")]
    InvalidSectorsPerCluster {
        /// Invalid sectors-per-cluster value from the parameter block.
        actual: u8,
    },

    /// The extended boot-sector structure could not be decoded.
    #[error("Failed to parse boot sector structure")]
    BootSectorParseFailed,

    /// The BIOS parameter block could not be decoded.
    #[error("Failed to parse BPB (BIOS Parameter Block)")]
    BpbParseFailed,

    /// Boot-sector geometry overflowed while deriving volume offsets.
    #[error("BPB fields cause arithmetic overflow")]
    BpbOverflow,

    /// The cluster count and boot-sector layout identify conflicting FAT variants.
    #[error(
        "Invalid FAT type: cluster count {cluster_count} does not match expected FAT32 structure"
    )]
    InvalidFatType {
        /// Number of data clusters derived from the boot sector.
        cluster_count: u32,
    },

    /// A FAT32 volume declares a fixed FAT12/16 root-entry table.
    #[error("Invalid root entry count: {actual} (must be 0 for FAT32)")]
    InvalidRootEntryCount {
        /// Invalid root-entry count from the parameter block.
        actual: u16,
    },

    /// The BIOS parameter block declares an invalid count of allocation tables.
    #[error("Invalid number of FATs: {actual} (typically 1 or 2)")]
    InvalidNumFats {
        /// Invalid allocation-table count from the parameter block.
        actual: u8,
    },

    /// The BIOS parameter block does not reserve any boot sectors.
    #[error("Invalid reserved sector count: {actual}")]
    InvalidReservedSectors {
        /// Invalid reserved-sector count from the parameter block.
        actual: u16,
    },

    /// The declared volume has no sectors available for file data.
    #[error("Invalid total sectors: filesystem appears to have no data area")]
    InvalidTotalSectors,

    /// A cluster number lies outside the volume's data-cluster range.
    #[error("Invalid cluster number: {cluster}")]
    InvalidCluster {
        /// Out-of-range cluster number.
        cluster: u32,
    },

    /// A cluster chain references a cluster marked unusable by the FAT.
    #[error("Cluster {cluster} is marked as bad")]
    BadCluster {
        /// Cluster number carrying the bad-cluster marker.
        cluster: u32,
    },

    /// Traversal exceeded the maximum possible length of a valid cluster chain.
    #[error("Cluster chain loop detected (exceeded maximum of {max_clusters} clusters)")]
    ClusterChainLoop {
        /// Maximum number of data clusters in the volume.
        max_clusters: u32,
    },

    /// An operation that requires a directory received a regular file.
    #[error("Not a directory")]
    NotADirectory,

    /// An operation that requires a regular file received a directory.
    #[error("Is a directory")]
    IsADirectory,

    /// No directory entry matched the requested path.
    #[error("File or directory not found")]
    NotFound,

    /// A directory record could not be decoded at its on-disk location.
    #[error("Malformed directory entry at byte offset {byte_offset:#x}")]
    MalformedDirEntry {
        /// Absolute byte offset of the malformed record.
        byte_offset: u64,
    },

    /// A timestamp could not be represented by FAT's 1980–2107 date range.
    #[error("Invalid time value")]
    InvalidTime,

    /// Reading or seeking the underlying volume failed.
    #[error("I/O error: {0:?}")]
    Io(io::Error),
}

impl From<io::Error> for FatError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

// In no_std mode, io::Error = IoError, so From<io::Error> already covers this.
// In std mode, we need an explicit conversion via From<IoError> for std::io::Error.
#[cfg(feature = "std")]
impl From<fse::IoError> for FatError {
    fn from(e: fse::IoError) -> Self {
        Self::Io(e.into())
    }
}

impl FsError for FatError {
    fn io_kind(&self) -> Option<fse::ErrorKind> {
        let Self::Io(e) = self else {
            return None;
        };
        Some(fse::ErrorKind::from(e.kind()))
    }

    fn byte_offset(&self) -> Option<u64> {
        match self {
            Self::MalformedDirEntry { byte_offset } => Some(*byte_offset),
            _ => None,
        }
    }
}

impl From<FatError> for io::Error {
    fn from(error: FatError) -> Self {
        match error {
            FatError::Io(e) => e,
            #[cfg(feature = "std")]
            other => std::io::Error::other(other),
            #[cfg(not(feature = "std"))]
            _ => io::ErrorKind::Other.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let fat_err: FatError = io_err.into();
        match fat_err {
            FatError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            _ => panic!("Expected FatError::Io variant"),
        }
    }

    #[test]
    fn into_io_error_unwraps_io_variant() {
        let original = io::Error::new(io::ErrorKind::NotFound, "original error");
        let fat_err = FatError::Io(original);
        let converted: io::Error = fat_err.into();
        assert_eq!(converted.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn into_io_error_wraps_non_io_variant() {
        let fat_err = FatError::NotFound;
        let converted: io::Error = fat_err.into();
        assert_eq!(converted.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn fs_error_io_kind_interrupted() {
        let err = FatError::Io(io::Error::new(io::ErrorKind::Interrupted, "test"));
        assert_eq!(FsError::io_kind(&err), Some(fse::ErrorKind::Interrupted),);
    }

    #[test]
    fn fs_error_io_kind_unexpected_eof() {
        let err = FatError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "test"));
        assert_eq!(FsError::io_kind(&err), Some(fse::ErrorKind::UnexpectedEof),);
    }

    #[test]
    fn fs_error_non_io_has_no_io_kind() {
        let err = FatError::NotFound;
        assert_eq!(FsError::io_kind(&err), None);
    }

    #[test]
    fn fs_error_byte_offset_none_for_non_positional() {
        let err = FatError::InvalidCluster { cluster: 42 };
        assert_eq!(FsError::byte_offset(&err), None);
    }

    #[test]
    fn fs_error_byte_offset_some_for_malformed_dir_entry() {
        let err = FatError::MalformedDirEntry {
            byte_offset: 0x2400,
        };
        assert_eq!(FsError::byte_offset(&err), Some(0x2400));
    }

    #[test]
    fn from_fs_common_io_error() {
        let io_err = fse::IoError::new(fse::ErrorKind::UnexpectedEof);
        let fat_err: FatError = io_err.into();
        match fat_err {
            FatError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
            }
            _ => panic!("Expected FatError::Io"),
        }
    }
}
