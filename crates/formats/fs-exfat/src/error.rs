use thiserror::Error;

use crate::io;
use fsmnt_parser_core::error::{self as fse, ParserError};
// Only referenced by the std-gated `From<IoError>` impl below.
#[cfg(feature = "std")]
use fsmnt_parser_core::error::IoError;

/// Central result type of fs-exfat.
pub type Result<T, E = ExFatError> = core::result::Result<T, E>;

/// Central error type of fs-exfat.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExFatError {
    /// The filesystem name field does not contain "EXFAT   ".
    #[error("Invalid filesystem name: expected \"EXFAT   \", found {actual:?}")]
    InvalidFileSystemName {
        /// Eight-byte filesystem name read from the boot sector.
        actual: [u8; 8],
    },

    /// The boot signature is not 0xAA55.
    #[error("Invalid boot signature: expected 0xAA55, found {actual:#06x}")]
    InvalidBootSignature {
        /// Signature value read from the boot sector.
        actual: u16,
    },

    /// The `MustBeZero` BPB area contains non-zero bytes.
    #[error("MustBeZero BPB area contains non-zero bytes")]
    MustBeZeroViolation,

    /// The `BytesPerSectorShift` is outside the valid range 9-12.
    #[error("Invalid bytes per sector shift: {actual} (must be 9-12)")]
    InvalidBytesPerSectorShift {
        /// Invalid shift value read from the boot sector.
        actual: u8,
    },

    /// The `SectorsPerClusterShift` exceeds the maximum for the given
    /// sector size.
    #[error(
        "Invalid sectors per cluster shift: {actual} \
         (max {max} for BytesPerSectorShift {bps_shift})"
    )]
    InvalidSectorsPerClusterShift {
        /// Invalid sectors-per-cluster shift.
        actual: u8,
        /// Largest shift valid for the selected sector size.
        max: u8,
        /// Boot sector's bytes-per-sector shift.
        bps_shift: u8,
    },

    /// A cluster index is out of the valid range.
    #[error("Invalid cluster number: {cluster}")]
    InvalidCluster {
        /// Out-of-range cluster number.
        cluster: u32,
    },

    /// A cluster is marked as bad (0xFFFFFFF7).
    #[error("Cluster {cluster} is marked as bad")]
    BadCluster {
        /// Cluster number carrying the bad-cluster marker.
        cluster: u32,
    },

    /// A cluster chain loop was detected.
    #[error(
        "Cluster chain loop detected \
         (exceeded maximum of {max_clusters} clusters)"
    )]
    ChainLoop {
        /// Maximum number of data clusters in the volume.
        max_clusters: u32,
    },

    /// The `NumberOfFats` field is not 1 or 2.
    #[error("Invalid number of FATs: {actual} (must be 1 or 2)")]
    InvalidNumberOfFats {
        /// Invalid table count read from the boot sector.
        actual: u8,
    },

    /// An entry set ended before all secondary entries were read.
    #[error(
        "Truncated entry set at byte {byte_offset:#x}: \
         expected {expected} secondary entries, found {actual}"
    )]
    TruncatedEntrySet {
        /// Number of secondary records declared by the primary record.
        expected: u8,
        /// Number of secondary records available before the set ended.
        actual: u8,
        /// Absolute byte offset of the primary record.
        byte_offset: u64,
    },

    /// An unknown critical entry type was encountered.
    #[error("Unknown critical entry type {entry_type:#04x} at byte {byte_offset:#x}")]
    UnknownCriticalEntry {
        /// Unsupported critical entry type byte.
        entry_type: u8,
        /// Absolute byte offset of the entry.
        byte_offset: u64,
    },

    /// An entry set has an invalid structure.
    #[error("Invalid entry set at byte {byte_offset:#x}: {reason}")]
    InvalidEntrySet {
        /// Explanation of the structural violation.
        reason: &'static str,
        /// Absolute byte offset of the entry set.
        byte_offset: u64,
    },

    /// The allocation bitmap entry (0x81) was not found in the root directory.
    #[error("Allocation bitmap entry (0x81) not found in root directory")]
    BitmapNotFound,

    /// The up-case table entry (0x82) was not found in the root directory.
    #[error("Up-case table entry (0x82) not found in root directory")]
    UpcaseTableNotFound,

    /// The up-case table checksum does not match the stored value.
    #[error(
        "Up-case table checksum mismatch: expected {expected:#010x}, \
         actual {actual:#010x}"
    )]
    UpcaseChecksumMismatch {
        /// Checksum stored in the up-case table directory entry.
        expected: u32,
        /// Checksum computed over the table data.
        actual: u32,
    },

    /// A file or directory was not found.
    #[error("Entry not found")]
    NotFound,

    /// An intermediate path component is not a directory.
    #[error("Entry is not a directory")]
    NotADirectory,

    /// Metadata tables have not been loaded (call `load_metadata` first).
    #[error("Metadata not loaded (call load_metadata first)")]
    MetadataNotLoaded,

    /// The up-case table data is invalid.
    #[error("Invalid up-case table: {reason}")]
    InvalidUpcaseTable {
        /// Explanation of the invalid compressed table.
        reason: &'static str,
    },

    /// The `VolumeLength` field is zero.
    #[error("Invalid volume length: {actual} sectors (must be > 0)")]
    InvalidVolumeLength {
        /// Invalid sector count read from the boot sector.
        actual: u64,
    },

    /// The `PercentInUse` field is outside the valid range.
    #[error("Invalid percent in use: {actual} (must be 0-100 or 0xFF)")]
    InvalidPercentInUse {
        /// Invalid utilization percentage read from the boot sector.
        actual: u8,
    },

    /// The filesystem revision is not supported.
    #[error("Unsupported filesystem revision: {major}.{minor} (only 1.xx supported)")]
    UnsupportedRevision {
        /// Unsupported major revision number.
        major: u8,
        /// Minor revision paired with the unsupported major number.
        minor: u8,
    },

    /// An I/O error occurred.
    #[error("I/O error: {0:?}")]
    Io(io::Error),
}

#[cfg(feature = "std")]
impl From<IoError> for ExFatError {
    fn from(error: IoError) -> Self {
        Self::Io(error.into())
    }
}

impl ParserError for ExFatError {
    fn io_kind(&self) -> Option<fse::ErrorKind> {
        let Self::Io(e) = self else {
            return None;
        };
        Some(fse::ErrorKind::from(e.kind()))
    }

    fn byte_offset(&self) -> Option<u64> {
        match self {
            Self::TruncatedEntrySet { byte_offset, .. }
            | Self::UnknownCriticalEntry { byte_offset, .. }
            | Self::InvalidEntrySet { byte_offset, .. } => Some(*byte_offset),
            _ => None,
        }
    }
}

impl From<io::Error> for ExFatError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

// To stay compatible with standardized interfaces (e.g. io::Read,
// io::Seek), we sometimes need to convert from ExFatError to
// io::Error.
impl From<ExFatError> for io::Error {
    fn from(error: ExFatError) -> Self {
        match error {
            ExFatError::Io(e) => e,
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
        let io_err: io::Error = io::ErrorKind::InvalidInput.into();
        let exfat_err: ExFatError = io_err.into();
        match exfat_err {
            ExFatError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            }
            _ => panic!("Expected ExFatError::Io variant"),
        }
    }

    #[test]
    fn into_io_error_unwraps_io_variant() {
        let original: io::Error = io::ErrorKind::InvalidData.into();
        let exfat_err = ExFatError::Io(original);
        let converted: io::Error = exfat_err.into();
        assert_eq!(converted.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn into_io_error_wraps_non_io_variant() {
        let exfat_err = ExFatError::InvalidNumberOfFats { actual: 3 };
        let converted: io::Error = exfat_err.into();
        assert_eq!(converted.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn fs_error_impl() {
        use fsmnt_parser_core::error::{ErrorKind, IoError, ParserError};

        // From<IoError> conversion
        let io_err = IoError::new(ErrorKind::UnexpectedEof);
        let exfat_err: ExFatError = io_err.into();
        assert!(matches!(exfat_err, ExFatError::Io(_)));

        // io_kind returns Some for Io variant
        let io_err = IoError::new(ErrorKind::InvalidData);
        let exfat_err: ExFatError = io_err.into();
        assert_eq!(exfat_err.io_kind(), Some(ErrorKind::InvalidData));

        // io_kind returns None for non-Io variant
        let exfat_err = ExFatError::NotFound;
        assert_eq!(exfat_err.io_kind(), None);

        // byte_offset returns None for non-positional variants
        let exfat_err = ExFatError::NotFound;
        assert_eq!(exfat_err.byte_offset(), None);

        // byte_offset returns Some for positional variants
        let exfat_err = ExFatError::InvalidEntrySet {
            reason: "test",
            byte_offset: 0x1000,
        };
        assert_eq!(exfat_err.byte_offset(), Some(0x1000));
    }

    #[test]
    fn phase3_error_variants_display() {
        let e = ExFatError::BitmapNotFound;
        assert!(format!("{e}").contains("bitmap"));

        let e = ExFatError::UpcaseTableNotFound;
        assert!(format!("{e}").contains("Up-case"));

        let e = ExFatError::UpcaseChecksumMismatch {
            expected: 0xE619_D30D,
            actual: 0x0000_0000,
        };
        let msg = format!("{e}");
        assert!(msg.contains("0xe619d30d"));
        assert!(msg.contains("0x00000000"));

        let e = ExFatError::NotFound;
        assert!(format!("{e}").contains("not found"));

        let e = ExFatError::NotADirectory;
        assert!(format!("{e}").contains("not a directory"));

        let e = ExFatError::MetadataNotLoaded;
        assert!(format!("{e}").contains("load_metadata"));

        let e = ExFatError::InvalidUpcaseTable {
            reason: "table incomplete",
        };
        assert!(format!("{e}").contains("table incomplete"));

        let e = ExFatError::InvalidVolumeLength { actual: 0 };
        assert!(format!("{e}").contains("volume length"));

        let e = ExFatError::InvalidPercentInUse { actual: 200 };
        assert!(format!("{e}").contains("200"));

        let e = ExFatError::UnsupportedRevision { major: 2, minor: 0 };
        assert!(format!("{e}").contains("2.0"));
    }
}
