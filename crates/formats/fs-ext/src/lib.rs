//! Read-only parsing, traversal, and recovery support for ext2, ext3, and ext4
//! filesystems.
//!
//! The crate can inspect filesystem metadata and file contents directly from a
//! seekable byte source. Optional features add fscrypt decryption and fs-verity
//! verification. Journal and orphan replay produce overlays rather than
//! mutating the source image.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Upstream gated `OnceCell::get_or_try_init` behind
// `#![feature(once_cell_try)]`. fsmnt builds on stable, so the gate is
// dropped and `file::once_get_or_try_init` provides the same behaviour.
#![forbid(unsafe_code)]

extern crate alloc;

mod block_group;
mod block_map;
mod casefold;
mod checksum;
mod directory;
mod extent;
mod feature_flags;
#[cfg(feature = "fscrypt")]
mod fscrypt;
mod hash;
mod htree;
mod inline_xattr;
mod mmp;
pub mod orphan;
mod positioned_file;
mod posix_acl;
mod superblock;
mod time;
#[cfg(feature = "verity")]
mod verity;
mod xattr;

/// Error and result types returned by the parser.
pub mod error;
/// Filesystem opening, feature inspection, and top-level accessors.
pub mod ext;
/// File-content readers for regular files and symlinks.
pub mod file;
/// Parsed inode metadata and inode-type helpers.
pub mod inode;
pub mod quota;
pub mod traverse;

pub mod journal;

#[cfg(test)]
mod test_support;

pub use checksum::ChecksumState;
pub use error::{ExtError, Result};
pub use ext::Ext;
pub use file::ExtFile;
#[cfg(feature = "fscrypt")]
pub use fscrypt::{
    FSCRYPT_MAX_KEY_SIZE, FSCRYPT_MIN_KEY_SIZE, FscryptKeyDescriptor, FscryptKeyIdentifier,
    FscryptKeyUnwrapError, FscryptKeyUnwrapper, FscryptMasterKey, FscryptPolicy, FscryptPolicyKind,
};
pub use fsmnt_parser_core::io;
pub use inode::{ExtDeviceId, ExtFileKind, ExtInode};
pub use journal::JournalInvariantKind;
pub use journal::JournalReplay;
pub use journal::OverlayReader;
pub use mmp::{ExtMmpBlock, ExtMmpSeqState};
pub use orphan::{
    LegacyOrphanEntry, OrphanDisposition, OrphanFileEntry, OrphanPlan, OrphanPosition,
    OrphanReplay, OrphanSourceKind, OrphanStop, OrphanStopReason, OrphanWarning, OrphanWarningKind,
};
pub use positioned_file::ExtPositionedFile;
pub use posix_acl::PosixAclEntry;
pub use quota::{QuotaIter, QuotaKind, QuotaRecord};
pub use superblock::{ExtSuperblockError, ExtSuperblockForensics};
pub use time::ExtTimestamp;
pub use traverse::{
    ExtDirectory, ExtLookupEntry, ExtRawDirEntry, ExtRawDirectoryIter, ExtTraversalEntry,
};
#[cfg(feature = "verity")]
pub use verity::{VerityDescriptor, VerityHashAlgorithm};
pub use xattr::{Xattr, XattrBlockHashReport, XattrEntryHashStatus, verify_xattr_block_hashes};

/// Validate a directory entry name against the kernel's strict-mode
/// UTF-8 rule for casefolded ext4 directories.
///
/// Returns `true` when `name` is well-formed UTF-8 — the rule kernel
/// `utf8n_lookup` and friends require entries to satisfy at creation
/// time on filesystems with `SB_ENC_STRICT_MODE_FL` set
/// (`include/linux/fs.h:1265`). `fs-ext` is read-only; consumers use
/// this helper to surface forensic warnings on entries the kernel
/// would have rejected.
///
/// Apply this check only when both [`Ext::has_strict_encoding`]
/// returns `true` and the parent directory's
/// [`ExtInode::is_casefolded`] is `true`.
#[must_use]
pub fn is_strict_encoding_valid_name(name: &[u8]) -> bool {
    core::str::from_utf8(name).is_ok()
}

#[cfg(test)]
mod strict_encoding_tests {
    use super::is_strict_encoding_valid_name;

    #[test]
    fn ascii_names_are_valid() {
        assert!(is_strict_encoding_valid_name(b"hello.txt"));
        assert!(is_strict_encoding_valid_name(b""));
        assert!(is_strict_encoding_valid_name(b".."));
    }

    #[test]
    fn well_formed_utf8_names_are_valid() {
        assert!(is_strict_encoding_valid_name("café.txt".as_bytes()));
        assert!(is_strict_encoding_valid_name("测试-Ω.txt".as_bytes()));
        // 4-byte UTF-8 (emoji).
        assert!(is_strict_encoding_valid_name("📂.dir".as_bytes()));
    }

    #[test]
    fn malformed_utf8_lone_continuation_is_invalid() {
        // A lone continuation byte (0x80) is not a valid UTF-8 sequence.
        assert!(!is_strict_encoding_valid_name(b"\x80"));
        assert!(!is_strict_encoding_valid_name(b"plain\xC3\x28"));
        // Overlong-form (would have produced a valid ASCII char) — invalid.
        assert!(!is_strict_encoding_valid_name(b"\xC0\xAF"));
        // Truncated 2-byte sequence at end of name.
        assert!(!is_strict_encoding_valid_name(b"good\xC3"));
    }
}
