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
    /// The underlying byte source failed an I/O operation.
    #[error("I/O error: {0:?}")]
    Io(io::Error),

    // Superblock validation
    /// The superblock does not contain the ext-family magic value.
    #[error("invalid magic: expected 0xEF53, got 0x{magic:04X}")]
    InvalidMagic {
        /// Magic value read from the superblock.
        magic: u16,
    },
    /// The encoded block-size exponent cannot describe a supported block size.
    #[error("invalid block size (s_log_block_size={raw})")]
    InvalidBlockSize {
        /// Raw `s_log_block_size` value.
        raw: u32,
    },
    /// The superblock declares an invalid inode record size.
    #[error("invalid inode size: {raw}")]
    InvalidInodeSize {
        /// Raw `s_inode_size` value.
        raw: u16,
    },
    /// A superblock invariant other than its magic or record sizes failed.
    #[error("invalid superblock: {reason}")]
    InvalidSuperblock {
        /// Description of the violated invariant.
        reason: &'static str,
    },
    /// The group-descriptor size is invalid for the enabled features.
    #[error("invalid descriptor size: {size}")]
    InvalidDescriptorSize {
        /// Descriptor size declared by the superblock.
        size: u16,
    },

    // Feature gating -- global (Ext::new rejects)
    /// The filesystem requires incompatible features this parser cannot honor.
    #[error("unsupported incompat features: 0x{flags:08X}")]
    UnsupportedIncompatFeature {
        /// Unsupported bits from `s_feature_incompat`.
        flags: u32,
    },
    /// The filesystem requires read-only-compatible features that are unsupported.
    #[error("unsupported ro_compat features: 0x{flags:08X}")]
    UnsupportedRoCompatFeature {
        /// Unsupported bits from `s_feature_ro_compat`.
        flags: u32,
    },

    // Feature gating -- recognized, specific open-time rejects
    /// The filesystem is dirty and must have its journal replayed before access.
    #[error("filesystem needs journal recovery")]
    NeedsRecovery,
    /// The filesystem stores its journal on an unsupported external device.
    #[error("external journal device not supported")]
    UnsupportedJournalDevice,
    /// An external journal's UUID differs from the UUID recorded by the filesystem.
    #[error(
        "external journal UUID mismatch: filesystem expects {fs_uuid:02x?}, journal device has {journal_uuid:02x?}"
    )]
    JournalUuidMismatch {
        /// External-journal UUID recorded in the filesystem superblock.
        fs_uuid: [u8; 16],
        /// UUID read from the supplied journal device.
        journal_uuid: [u8; 16],
    },
    /// Fast-commit replay was requested for an external journal.
    #[error("external journal with fast-commit replay is not supported")]
    ExternalJournalFastCommitUnsupported,
    /// The filesystem enables ext compression, which this parser does not support.
    #[error("compression filesystems (INCOMPAT_COMPRESSION) are not supported")]
    UnsupportedCompression,
    /// The filesystem enables directory-entry data, which is unsupported.
    #[error("dirdata filesystems (INCOMPAT_DIRDATA) are not supported")]
    UnsupportedDirData,
    /// The filesystem enables the unsupported ext snapshot feature.
    #[error("snapshot filesystems (RO_COMPAT_HAS_SNAPSHOT) are not supported")]
    UnsupportedSnapshotFeature,
    /// Legacy error retained for callers that matched unsupported `meta_bg`.
    #[error("meta block group filesystems (INCOMPAT_META_BG) are not supported")]
    #[deprecated(note = "meta_bg filesystems are now supported. \
                This variant is retained for source-compatibility only and \
                has no remaining producer.")]
    UnsupportedMetaBlockGroup,
    /// Pending orphan records require recovery before ordinary access.
    #[error("filesystem has orphan entries requiring recovery")]
    OrphanRecoveryRequired,

    // Journal recovery — setup / parse rejects
    /// Journal replay was requested for a filesystem without a journal feature bit.
    #[error("journal required but COMPAT_HAS_JOURNAL is not set")]
    JournalExpectedButAbsent,
    /// The superblock advertises a journal but names inode zero.
    #[error("journal inode number is zero")]
    JournalInodeZero,
    /// The journal superblock violates a structural invariant.
    #[error("invalid journal superblock: {reason}")]
    InvalidJournalSuperblock {
        /// Description of the violated journal-superblock invariant.
        reason: &'static str,
    },
    /// Legacy error retained for callers that matched unsupported fast commits.
    #[error("fast commits (INCOMPAT_FAST_COMMIT) are not supported")]
    #[deprecated(note = "fast-commit journals are now replayed; see FastCommitPlan. \
                This variant is retained for source-compatibility only and \
                has no remaining producer.")]
    JournalFastCommitUnsupported,
    /// The journal uses an unknown checksum algorithm identifier.
    #[error("unsupported journal checksum type {code}")]
    JournalUnsupportedChecksumType {
        /// Raw checksum type from the journal superblock.
        code: u8,
    },
    /// The journal requires an unsupported incompatible feature.
    #[error("unsupported journal incompat features: 0x{flags:08X}")]
    JournalUnsupportedFeature {
        /// Unsupported bits from the journal incompatibility flags.
        flags: u32,
    },
    /// The journal and filesystem use different block sizes.
    #[error("journal block size {journal} does not match filesystem block size {fs}")]
    JournalBlockSizeMismatch {
        /// Journal block size in bytes.
        journal: u32,
        /// Filesystem block size in bytes.
        fs: u32,
    },
    /// Journal feature flags form a combination that cannot be interpreted safely.
    #[error("journal invariant violated: {kind:?}")]
    JournalInvariant {
        /// Specific invariant that failed.
        kind: crate::journal::JournalInvariantKind,
    },

    // Orphan recovery — setup / parse rejects
    /// The orphan-file feature is enabled but its inode number is zero.
    #[error("orphan file required (COMPAT_ORPHAN_FILE set) but s_orphan_file_inum is zero")]
    OrphanFileInodeZero,
    /// The orphan file violates an on-disk structural invariant.
    #[error("invalid orphan file: {reason}")]
    InvalidOrphanFile {
        /// Description of the violated orphan-file invariant.
        reason: &'static str,
    },

    // Quota tree parsing
    /// A quota inode or its tree contains malformed data.
    #[error("invalid quota file (inode {inode}): {reason}")]
    InvalidQuotaFile {
        /// Inode number of the quota file.
        inode: u32,
        /// Description of the malformed quota structure.
        reason: &'static str,
    },

    // Feature gating -- object-local (fail at access)
    /// Data from an encrypted inode was requested without decryption.
    #[error("inode {inode} is encrypted")]
    EncryptedInode {
        /// Encrypted inode number.
        inode: u32,
    },
    /// An inode's fscrypt policy bytes are malformed or inconsistent.
    #[error("inode {inode} fscrypt policy: {reason}")]
    InvalidFscryptPolicy {
        /// Inode carrying the invalid policy.
        inode: u32,
        /// Description of the policy violation.
        reason: &'static str,
    },
    /// No registered fscrypt master key matches an inode's policy.
    #[error("inode {inode}: missing fscrypt master key (policy {policy_kind}, ref {key_ref})")]
    MissingFscryptKey {
        /// Inode whose key lookup failed.
        inode: u32,
        /// Human-readable fscrypt policy version.
        policy_kind: alloc::string::String,
        /// Hexadecimal descriptor or identifier used for lookup.
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
        /// Calling inode, or zero when failure occurred inside the keystore.
        inode: u32,
        /// Human-readable fscrypt policy version.
        policy_kind: alloc::string::String,
        /// Hexadecimal v2 key identifier used for lookup.
        key_ref: alloc::string::String,
        /// Operator-facing failure returned by the unwrap callback.
        reason: alloc::string::String,
    },
    /// An fscrypt policy selects a cipher or flag combination that is unsupported.
    #[error(
        "inode {inode}: unsupported fscrypt mode (contents={contents}, filenames={filenames}, flags=0x{flags:02x})"
    )]
    UnsupportedFscryptMode {
        /// Inode carrying the unsupported policy.
        inode: u32,
        /// Raw content-encryption mode identifier.
        contents: u8,
        /// Raw filename-encryption mode identifier.
        filenames: u8,
        /// Raw fscrypt policy flags.
        flags: u8,
    },
    /// The inode references an external-value EA inode in an unsupported context.
    #[error("inode {inode} uses EA inode references")]
    UnsupportedEaInode {
        /// Inode containing the unsupported EA-inode reference.
        inode: u32,
    },
    /// An inode's inline-data layout is malformed.
    #[error("inode {inode} has malformed inline data")]
    InvalidInlineData {
        /// Inode containing malformed inline data.
        inode: u32,
    },
    /// An inode's external extended-attribute block is malformed.
    #[error("inode {inode} has invalid xattr block: {reason}")]
    InvalidXattrBlock {
        /// Inode referencing the malformed block.
        inode: u32,
        /// Description of the xattr-block violation.
        reason: &'static str,
    },

    // fs-verity (RO_COMPAT_VERITY / VERITY_FL inodes)
    /// An inode's fs-verity descriptor is malformed.
    #[error("inode {inode} has invalid fs-verity descriptor: {reason}")]
    InvalidVerityDescriptor {
        /// Inode carrying the malformed descriptor.
        inode: u32,
        /// Description of the descriptor violation.
        reason: &'static str,
    },
    /// File data or a Merkle-tree block failed fs-verity authentication.
    #[error("inode {inode}: fs-verity hash mismatch at file offset {offset}")]
    VerityHashMismatch {
        /// Inode whose content failed authentication.
        inode: u32,
        /// Byte offset of the affected data block.
        offset: u64,
    },
    /// An inode combines encryption and fs-verity, which is unsupported.
    #[error("inode {inode} combines fs-verity and encryption, which is not supported")]
    UnsupportedEncryptedVerity {
        /// Inode enabling both features.
        inode: u32,
    },

    /// A POSIX ACL xattr has a truncated header or misaligned entry array.
    #[error("inode {inode} has malformed POSIX ACL xattr (len {len}) at relative offset {offset}")]
    InvalidPosixAclLength {
        /// Inode owning the ACL xattr.
        inode: u32,
        /// Relative byte offset at which decoding failed.
        offset: u64,
        /// Invalid payload or trailing length.
        len: usize,
    },
    /// A POSIX ACL xattr uses an unsupported on-disk version.
    #[error(
        "inode {inode} has unsupported POSIX ACL xattr version {version} at relative offset {offset}"
    )]
    InvalidPosixAclVersion {
        /// Inode owning the ACL xattr.
        inode: u32,
        /// Relative byte offset of the ACL header.
        offset: u64,
        /// Version value read from the header.
        version: u32,
    },
    /// A POSIX ACL entry uses an unknown tag value.
    #[error("inode {inode} has unknown POSIX ACL tag 0x{tag:04X} at relative offset {offset}")]
    InvalidPosixAclTag {
        /// Inode owning the ACL xattr.
        inode: u32,
        /// Relative byte offset of the offending entry.
        offset: u64,
        /// Unknown ACL tag.
        tag: u16,
    },

    // Traversal semantics
    /// No directory entry matches the requested path component.
    #[error("not found")]
    NotFound,
    /// A directory operation targeted a non-directory inode.
    #[error("inode {inode} is not a directory")]
    NotADirectory {
        /// Inode that was expected to be a directory.
        inode: u32,
    },
    /// A regular-file operation targeted a directory inode.
    #[error("inode {inode} is a directory")]
    IsADirectory {
        /// Inode that was unexpectedly a directory.
        inode: u32,
    },

    // Structure parsing
    /// A block-group descriptor is malformed or inconsistent.
    #[error("invalid group descriptor {group}: {reason}")]
    InvalidGroupDescriptor {
        /// Zero-based block-group index.
        group: u32,
        /// Description of the descriptor violation.
        reason: &'static str,
    },
    /// An inode record is malformed or inconsistent.
    #[error("invalid inode {inode}: {reason}")]
    InvalidInode {
        /// Invalid inode number.
        inode: u32,
        /// Description of the inode violation.
        reason: &'static str,
    },
    /// An inode's extent-tree header is invalid.
    #[error("invalid extent header in inode {inode}")]
    InvalidExtentHeader {
        /// Inode containing the invalid extent tree.
        inode: u32,
    },
    /// A directory record is malformed.
    #[error("invalid directory entry in inode {inode} at relative offset {offset}")]
    InvalidDirectoryEntry {
        /// Directory inode containing the malformed record.
        inode: u32,
        /// Byte offset relative to the directory data stream.
        offset: u64,
    },
    /// A fixed-size structure ended before all required bytes were available.
    #[error("{context} at offset {offset}")]
    UnexpectedEof {
        /// Operation or structure being decoded.
        context: &'static str,
        /// Absolute or structure-relative byte offset, as documented by the caller.
        offset: u64,
    },

    // Multi-mount protection (MMP)
    /// The multi-mount-protection block is malformed.
    #[error("invalid MMP block: {reason}")]
    InvalidMmpBlock {
        /// Description of the MMP invariant that failed.
        reason: &'static str,
    },

    // Data access
    /// A physical block number lies outside the filesystem.
    #[error("block {block} out of range")]
    BlockOutOfRange {
        /// Invalid physical block number.
        block: u64,
    },
    /// An inode number lies outside the filesystem's inode table.
    #[error("inode {inode} out of range")]
    InodeOutOfRange {
        /// Invalid inode number.
        inode: u32,
    },
    /// A legacy direct/indirect block map is malformed.
    #[error("inode {inode} has malformed indirect block map: {reason}")]
    InvalidIndirectBlock {
        /// Inode containing the malformed block map.
        inode: u32,
        /// Description of the block-map violation.
        reason: &'static str,
    },

    // Timestamp conversion
    /// A decoded ext timestamp cannot be represented by the requested type.
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
        let io_err: io::Error = io::ErrorKind::InvalidInput.into();
        let ext_err: ExtError = io_err.into();
        match ext_err {
            ExtError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
            _ => panic!("Expected ExtError::Io variant"),
        }
    }

    #[test]
    fn into_io_error_unwraps_io_variant() {
        let original: io::Error = io::ErrorKind::InvalidData.into();
        let ext_err = ExtError::Io(original);
        let converted: io::Error = ext_err.into();
        assert_eq!(converted.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn into_io_error_wraps_non_io_variant() {
        let ext_err = ExtError::NotFound;
        let converted: io::Error = ext_err.into();
        assert_eq!(converted.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn fs_error_io_kind() {
        let err = ExtError::Io(io::ErrorKind::Interrupted.into());
        assert_eq!(FsError::io_kind(&err), Some(fse::ErrorKind::Interrupted));

        let err = ExtError::Io(io::ErrorKind::UnexpectedEof.into());
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
