use fs_common::error::{self as fse, FsError};
use thiserror::Error;

use crate::io;

/// Central result type of fs-fat.
pub type Result<T, E = FatError> = core::result::Result<T, E>;

/// Central error type of fs-fat.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FatError {
    #[error("Invalid boot signature: expected 0xAA55, found {actual:#06x}")]
    InvalidBootSignature { actual: u16 },

    #[error(
        "The volume is BitLocker-encrypted (OEM ID: {oem_id:?}). Decrypt the volume before parsing as FAT."
    )]
    BitLockerEncrypted { oem_id: [u8; 8] },

    #[error("Invalid bytes per sector: {actual} (must be 512, 1024, 2048, or 4096)")]
    InvalidBytesPerSector { actual: u16 },

    #[error("Invalid sectors per cluster: {actual} (must be a power of 2)")]
    InvalidSectorsPerCluster { actual: u8 },

    #[error("Failed to parse boot sector structure")]
    BootSectorParseFailed,

    #[error("Failed to parse BPB (BIOS Parameter Block)")]
    BpbParseFailed,

    #[error("BPB fields cause arithmetic overflow")]
    BpbOverflow,

    #[error(
        "Invalid FAT type: cluster count {cluster_count} does not match expected FAT32 structure"
    )]
    InvalidFatType { cluster_count: u32 },

    #[error("Invalid root entry count: {actual} (must be 0 for FAT32)")]
    InvalidRootEntryCount { actual: u16 },

    #[error("Invalid number of FATs: {actual} (typically 1 or 2)")]
    InvalidNumFats { actual: u8 },

    #[error("Invalid reserved sector count: {actual}")]
    InvalidReservedSectors { actual: u16 },

    #[error("Invalid total sectors: filesystem appears to have no data area")]
    InvalidTotalSectors,

    #[error("Invalid cluster number: {cluster}")]
    InvalidCluster { cluster: u32 },

    #[error("Cluster {cluster} is marked as bad")]
    BadCluster { cluster: u32 },

    #[error("Cluster chain loop detected (exceeded maximum of {max_clusters} clusters)")]
    ClusterChainLoop { max_clusters: u32 },

    #[error("Not a directory")]
    NotADirectory,

    #[error("Is a directory")]
    IsADirectory,

    #[error("File or directory not found")]
    NotFound,

    #[error("Malformed directory entry at byte offset {byte_offset:#x}")]
    MalformedDirEntry { byte_offset: u64 },

    #[error("Invalid time value")]
    InvalidTime,

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
