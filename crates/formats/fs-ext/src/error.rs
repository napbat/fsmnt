use fs_common::error::{self as fse, FsError};
use thiserror::Error;

use crate::io;

/// Central result type of fs-ext.
pub type Result<T, E = ExtError> = core::result::Result<T, E>;

/// Central error type of fs-ext.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExtError {
    // I/O (matches fs-fat/fs-ntfs wiring)
    #[error("I/O error: {0:?}")]
    Io(io::Error),

    // Superblock validation
    #[error("invalid magic: expected 0xEF53, got 0x{magic:04X}")]
    InvalidMagic { magic: u16 },
    #[error("invalid block size (s_log_block_size={raw})")]
    InvalidBlockSize { raw: u32 },
    #[error("invalid inode size: {raw}")]
    InvalidInodeSize { raw: u16 },
    #[error("invalid superblock: {reason}")]
    InvalidSuperblock { reason: &'static str },
    #[error("invalid descriptor size: {size}")]
    InvalidDescriptorSize { size: u16 },

    // Feature gating -- global (Ext::new rejects)
    #[error("unsupported incompat features: 0x{flags:08X}")]
    UnsupportedIncompatFeature { flags: u32 },
    #[error("unsupported ro_compat features: 0x{flags:08X}")]
    UnsupportedRoCompatFeature { flags: u32 },

    // Feature gating -- recognized, specific open-time rejects
    #[error("filesystem needs journal recovery")]
    NeedsRecovery,
    #[error("external journal device not supported")]
    UnsupportedJournalDevice,
    #[error(
        "external journal UUID mismatch: filesystem expects {fs_uuid:02x?}, journal device has {journal_uuid:02x?}"
    )]
    JournalUuidMismatch {
        fs_uuid: [u8; 16],
        journal_uuid: [u8; 16],
    },
    #[error("external journal with fast-commit replay is not supported")]
    ExternalJournalFastCommitUnsupported,
    #[error("compression filesystems (INCOMPAT_COMPRESSION) are not supported")]
    UnsupportedCompression,
    #[error("dirdata filesystems (INCOMPAT_DIRDATA) are not supported")]
    UnsupportedDirData,
    #[error("snapshot filesystems (RO_COMPAT_HAS_SNAPSHOT) are not supported")]
    UnsupportedSnapshotFeature,
    #[error("meta block group filesystems (INCOMPAT_META_BG) are not supported")]
    #[deprecated(note = "meta_bg filesystems are now supported. \
                This variant is retained for source-compatibility only and \
                has no remaining producer.")]
    UnsupportedMetaBlockGroup,
    #[error("filesystem has orphan entries requiring recovery")]
    OrphanRecoveryRequired,

    // Journal recovery — setup / parse rejects
    #[error("journal required but COMPAT_HAS_JOURNAL is not set")]
    JournalExpectedButAbsent,
    #[error("journal inode number is zero")]
    JournalInodeZero,
    #[error("invalid journal superblock: {reason}")]
    InvalidJournalSuperblock { reason: &'static str },
    #[error("fast commits (INCOMPAT_FAST_COMMIT) are not supported")]
    #[deprecated(note = "fast-commit journals are now replayed; see FastCommitPlan. \
                This variant is retained for source-compatibility only and \
                has no remaining producer.")]
    JournalFastCommitUnsupported,
    #[error("unsupported journal checksum type {code}")]
    JournalUnsupportedChecksumType { code: u8 },
    #[error("unsupported journal incompat features: 0x{flags:08X}")]
    JournalUnsupportedFeature { flags: u32 },
    #[error("journal block size {journal} does not match filesystem block size {fs}")]
    JournalBlockSizeMismatch { journal: u32, fs: u32 },
    #[error("journal invariant violated: {kind:?}")]
    JournalInvariant {
        kind: crate::journal::JournalInvariantKind,
    },

    // Orphan recovery — setup / parse rejects
    #[error("orphan file required (COMPAT_ORPHAN_FILE set) but s_orphan_file_inum is zero")]
    OrphanFileInodeZero,
    #[error("invalid orphan file: {reason}")]
    InvalidOrphanFile { reason: &'static str },

    // Quota tree parsing
    #[error("invalid quota file (inode {inode}): {reason}")]
    InvalidQuotaFile { inode: u32, reason: &'static str },

    // Feature gating -- object-local (fail at access)
    #[error("inode {inode} is encrypted")]
    EncryptedInode { inode: u32 },
    #[error("inode {inode} fscrypt policy: {reason}")]
    InvalidFscryptPolicy { inode: u32, reason: &'static str },
    #[error("inode {inode}: missing fscrypt master key (policy {policy_kind}, ref {key_ref})")]
    MissingFscryptKey {
        inode: u32,
        policy_kind: alloc::string::String,
        key_ref: alloc::string::String,
    },
    /// A hardware-wrapped fscrypt key was registered for this identifier
    /// but the operator-supplied unwrap callback failed (or the
    /// unwrapped key didn't derive the registered identifier).
    ///
    /// `inode` may be 0 here: the unwrap is keystore-internal and does
    /// not see the calling inode. The `key_ref` (32-char lowercase
    /// hex of the v2 identifier) plus `reason` are the actionable
    /// fields for the operator.
    #[error("fscrypt key unwrap failed (policy {policy_kind}, ref {key_ref}): {reason}")]
    FscryptKeyUnwrapFailed {
        inode: u32,
        policy_kind: alloc::string::String,
        key_ref: alloc::string::String,
        reason: alloc::string::String,
    },
    #[error(
        "inode {inode}: unsupported fscrypt mode (contents={contents}, filenames={filenames}, flags=0x{flags:02x})"
    )]
    UnsupportedFscryptMode {
        inode: u32,
        contents: u8,
        filenames: u8,
        flags: u8,
    },
    #[error("inode {inode} uses EA inode references")]
    UnsupportedEaInode { inode: u32 },
    #[error("inode {inode} has malformed inline data")]
    InvalidInlineData { inode: u32 },
    #[error("inode {inode} has invalid xattr block: {reason}")]
    InvalidXattrBlock { inode: u32, reason: &'static str },

    // fs-verity (RO_COMPAT_VERITY / VERITY_FL inodes)
    #[error("inode {inode} has invalid fs-verity descriptor: {reason}")]
    InvalidVerityDescriptor { inode: u32, reason: &'static str },
    #[error("inode {inode}: fs-verity hash mismatch at file offset {offset}")]
    VerityHashMismatch { inode: u32, offset: u64 },
    #[error("inode {inode} combines fs-verity and encryption, which is not supported")]
    UnsupportedEncryptedVerity { inode: u32 },

    #[error("inode {inode} has malformed POSIX ACL xattr (len {len}) at relative offset {offset}")]
    InvalidPosixAclLength { inode: u32, offset: u64, len: usize },
    #[error(
        "inode {inode} has unsupported POSIX ACL xattr version {version} at relative offset {offset}"
    )]
    InvalidPosixAclVersion {
        inode: u32,
        offset: u64,
        version: u32,
    },
    #[error("inode {inode} has unknown POSIX ACL tag 0x{tag:04X} at relative offset {offset}")]
    InvalidPosixAclTag { inode: u32, offset: u64, tag: u16 },

    // Traversal semantics
    #[error("not found")]
    NotFound,
    #[error("inode {inode} is not a directory")]
    NotADirectory { inode: u32 },
    #[error("inode {inode} is a directory")]
    IsADirectory { inode: u32 },

    // Structure parsing
    #[error("invalid group descriptor {group}: {reason}")]
    InvalidGroupDescriptor { group: u32, reason: &'static str },
    #[error("invalid inode {inode}: {reason}")]
    InvalidInode { inode: u32, reason: &'static str },
    #[error("invalid extent header in inode {inode}")]
    InvalidExtentHeader { inode: u32 },
    #[error("invalid directory entry in inode {inode} at relative offset {offset}")]
    InvalidDirectoryEntry { inode: u32, offset: u64 },
    #[error("{context} at offset {offset}")]
    UnexpectedEof { context: &'static str, offset: u64 },

    // Multi-mount protection (MMP)
    #[error("invalid MMP block: {reason}")]
    InvalidMmpBlock { reason: &'static str },

    // Data access
    #[error("block {block} out of range")]
    BlockOutOfRange { block: u64 },
    #[error("inode {inode} out of range")]
    InodeOutOfRange { inode: u32 },
    #[error("inode {inode} has malformed indirect block map: {reason}")]
    InvalidIndirectBlock { inode: u32, reason: &'static str },

    // Timestamp conversion
    #[error("timestamp out of range for target type")]
    TimestampOutOfRange,
}

impl From<io::Error> for ExtError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

// In no_std mode, io::Error = IoError, so From<io::Error> already covers this.
// In std mode, we need an explicit conversion via From<IoError> for std::io::Error.
#[cfg(feature = "std")]
impl From<fse::IoError> for ExtError {
    fn from(e: fse::IoError) -> Self {
        Self::Io(e.into())
    }
}

impl FsError for ExtError {
    fn io_kind(&self) -> Option<fse::ErrorKind> {
        let Self::Io(e) = self else {
            return None;
        };
        Some(fse::ErrorKind::from(e.kind()))
    }

    fn byte_offset(&self) -> Option<u64> {
        match self {
            Self::UnexpectedEof { offset, .. } => Some(*offset),
            // `InvalidPosixAcl{Length,Version,Tag}` carry buffer-relative
            // offsets and are not surfaced here per the trait contract.
            _ => None,
        }
    }
}

impl From<ExtError> for io::Error {
    fn from(error: ExtError) -> Self {
        match error {
            ExtError::Io(e) => e,
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
    fn error_display_messages() {
        let err = ExtError::InvalidMagic { magic: 0x1234 };
        assert_eq!(
            err.to_string(),
            "invalid magic: expected 0xEF53, got 0x1234"
        );

        let err = ExtError::NeedsRecovery;
        assert_eq!(err.to_string(), "filesystem needs journal recovery");

        let err = ExtError::UnsupportedIncompatFeature { flags: 0x0000_0200 };
        assert_eq!(err.to_string(), "unsupported incompat features: 0x00000200");
    }

    #[test]
    fn from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let ext_err: ExtError = io_err.into();
        match ext_err {
            ExtError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            _ => panic!("Expected ExtError::Io variant"),
        }
    }

    #[test]
    fn into_io_error_unwraps_io_variant() {
        let original = io::Error::new(io::ErrorKind::NotFound, "original error");
        let ext_err = ExtError::Io(original);
        let converted: io::Error = ext_err.into();
        assert_eq!(converted.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn into_io_error_wraps_non_io_variant() {
        let ext_err = ExtError::NotFound;
        let converted: io::Error = ext_err.into();
        assert_eq!(converted.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn fs_error_io_kind() {
        let err = ExtError::Io(io::Error::new(io::ErrorKind::Interrupted, "test"));
        assert_eq!(FsError::io_kind(&err), Some(fse::ErrorKind::Interrupted));

        let err = ExtError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "test"));
        assert_eq!(FsError::io_kind(&err), Some(fse::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn fs_error_non_io_has_no_io_kind() {
        let err = ExtError::NotFound;
        assert_eq!(FsError::io_kind(&err), None);
    }

    #[test]
    fn fs_error_byte_offset() {
        let err = ExtError::UnexpectedEof {
            context: "reading superblock",
            offset: 0x400,
        };
        assert_eq!(FsError::byte_offset(&err), Some(0x400));

        let err = ExtError::InvalidMagic { magic: 0xEF53 };
        assert_eq!(FsError::byte_offset(&err), None);
    }

    #[test]
    fn new_journal_error_display() {
        let err = ExtError::JournalExpectedButAbsent;
        assert_eq!(
            err.to_string(),
            "journal required but COMPAT_HAS_JOURNAL is not set"
        );

        let err = ExtError::JournalInodeZero;
        assert_eq!(err.to_string(), "journal inode number is zero");

        let err = ExtError::InvalidJournalSuperblock {
            reason: "bad magic",
        };
        assert_eq!(err.to_string(), "invalid journal superblock: bad magic");

        let err = ExtError::JournalUnsupportedChecksumType { code: 2 };
        assert_eq!(err.to_string(), "unsupported journal checksum type 2");

        let err = ExtError::JournalUnsupportedFeature { flags: 0x0080 };
        assert_eq!(
            err.to_string(),
            "unsupported journal incompat features: 0x00000080"
        );

        let err = ExtError::JournalBlockSizeMismatch {
            journal: 2048,
            fs: 4096,
        };
        assert_eq!(
            err.to_string(),
            "journal block size 2048 does not match filesystem block size 4096",
        );

        let err = ExtError::JournalInvariant {
            kind: crate::journal::JournalInvariantKind::ChecksumModeConflict,
        };
        assert_eq!(
            err.to_string(),
            "journal invariant violated: ChecksumModeConflict",
        );
    }

    #[test]
    #[expect(
        deprecated,
        reason = "verifying source-compat: variant retained after feature landed"
    )]
    fn deprecated_fast_commit_variant_still_displays_legacy_message() {
        let err = ExtError::JournalFastCommitUnsupported;
        assert_eq!(
            format!("{err}"),
            "fast commits (INCOMPAT_FAST_COMMIT) are not supported"
        );
    }

    #[test]
    fn from_fs_common_io_error() {
        let io_err = fse::IoError::new(fse::ErrorKind::UnexpectedEof);
        let ext_err: ExtError = io_err.into();
        match ext_err {
            ExtError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
            }
            _ => panic!("Expected ExtError::Io"),
        }
    }

    #[test]
    fn new_orphan_error_display() {
        let err = ExtError::OrphanFileInodeZero;
        assert_eq!(
            err.to_string(),
            "orphan file required (COMPAT_ORPHAN_FILE set) but s_orphan_file_inum is zero"
        );

        let err = ExtError::InvalidOrphanFile {
            reason: "inode size is zero",
        };
        assert_eq!(err.to_string(), "invalid orphan file: inode size is zero");
    }

    #[test]
    #[expect(
        deprecated,
        reason = "verifying source-compat: variant retained after feature landed"
    )]
    fn unsupported_meta_block_group_variant_still_constructible_and_formats() {
        let err = ExtError::UnsupportedMetaBlockGroup;
        assert_eq!(
            format!("{err}"),
            "meta block group filesystems (INCOMPAT_META_BG) are not supported"
        );
    }
}
