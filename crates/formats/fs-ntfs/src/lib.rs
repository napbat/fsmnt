//! A low-level NTFS filesystem library implemented in Rust.
//!
//! [NTFS](https://en.wikipedia.org/wiki/NTFS) is the primary filesystem in all versions of Windows (since Windows NT 3.1 in 1993).
//! This crate is geared towards the NTFS 3.x versions used in Windows 2000 up to the current Windows 11.
//! However, the basics are expected to be compatible to even earlier versions.
//!
//! The crate is `no_std`-compatible and therefore usable from firmware level code up to user-mode applications.
//!
//! # Getting started
//! 1. Create an [`Ntfs`] structure from a reader by calling [`Ntfs::new`].
//! 2. Retrieve the [`NtfsFile`] of the root directory via [`Ntfs::root_directory`].
//! 3. Dig into its attributes via [`NtfsFile::attributes`], go even deeper via [`NtfsFile::attributes_raw`] or use one of the convenience functions, like [`NtfsFile::directory_index`], [`NtfsFile::info`] or [`NtfsFile::name`].
//!
//! # Example
//! The following example dumps the names of all files and folders in the root directory of a given NTFS filesystem.
//! The list is directly taken from the NTFS index, hence it's sorted in ascending order with respect to NTFS's understanding of case-insensitive string comparison.
//!
//! ```no_run
//! # use fs_common::iter::FsTryIterator;
//! # use fs_ntfs::Ntfs;
//! # let mut fs = fsmnt_testkit::Cursor::new(vec![]);
//! let mut ntfs = Ntfs::new(&mut fs).unwrap();
//! let root_dir = ntfs.root_directory(&mut fs).unwrap();
//! let index = root_dir.directory_index(&mut fs).unwrap();
//! let mut iter = index.entries();
//!
//! while let Some(entry) = iter.try_next(&mut fs).unwrap() {
//!     let file_name = entry.key().unwrap().unwrap();
//!     println!("{}", file_name.name());
//! }
//! ```
//!
//! Check out the [docs](https://docs.rs/ntfs), the tests, and the supplied [`ntfs-shell`](https://github.com/ColinFinck/ntfs/tree/master/examples/ntfs-shell) application for more examples on how to use the `ntfs` library.
//!
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
// Upstream gated `core::hint::unlikely` behind `#![feature(likely_unlikely)]`.
// fsmnt builds on stable, so the gate is dropped and the single call site in
// `indexes/file_name.rs` uses the bare condition (the hint is advisory only).

extern crate alloc;

#[macro_use]
mod helpers;

pub mod analysis;
mod attribute;
pub mod attribute_value;
mod boot_sector;
mod cluster_bitmap;
mod cluster_carving;
#[cfg(feature = "compression")]
pub mod compression_recovery;
mod data_run_map;
#[cfg(feature = "std")]
mod deleted_files;
mod error;
mod file;
mod file_reference;
mod guid;
mod index;
mod index_entry;
mod index_record;
pub mod indexes;
#[cfg(feature = "std")]
mod logfile;
pub mod metafiles;
mod mft;
mod ntfs;
#[cfg(feature = "std")]
mod parent_map;
mod record;
mod secure;
mod slack_recovery;
pub mod structured_values;
mod time;
mod traverse;
/// Address, position, cluster, and record-size types used by the parser.
pub mod types;
mod upcase_table;
mod usn_journal;

/// Re-export of [`fs_common::io`] for convenience.
pub use fs_common::io;

pub use crate::attribute::{
    NtfsAttribute, NtfsAttributeFlags, NtfsAttributeItem, NtfsAttributeType, NtfsAttributes,
    NtfsAttributesAttached, NtfsAttributesRaw,
};
pub use crate::cluster_bitmap::{ClusterRangeStatus, NtfsClusterBitmap};
pub use crate::cluster_carving::{CarvedFile, CarvingConfig, FileSignature, NtfsClusterCarver};
pub use crate::error::{NtfsError, Result};
pub use crate::file::{KnownNtfsFileRecordNumber, NtfsFile, NtfsFileFlags, NtfsFileNamePair};
pub use crate::file_reference::NtfsFileReference;
pub use crate::guid::NtfsGuid;
pub use crate::index::{
    NtfsDirEntries, NtfsIndex, NtfsIndexEntries, NtfsIndexFinder, NtfsOwnedIndexEntries,
};
pub use crate::index_entry::{
    NtfsDirEntry, NtfsIndexEntry, NtfsIndexEntryFlags, NtfsIndexNodeEntries,
};
pub use crate::index_record::NtfsIndexRecord;
pub use crate::metafiles::NtfsBadClusters;
pub use crate::metafiles::{NtfsAttrDef, NtfsAttrDefEntries, NtfsAttrDefEntry, NtfsAttrDefFlags};
pub use crate::mft::NtfsMftEntries;
pub use crate::ntfs::Ntfs;
pub use crate::secure::{
    NtfsSdsEntries, NtfsSdsEntry, NtfsSdsMirrorStatus, NtfsSdsStreamInfo, ntfs_secure_lookup,
    ntfs_secure_lookup_by_hash, ntfs_secure_sdh_entries, ntfs_secure_sds_entries,
    ntfs_secure_sds_info,
};
pub use crate::slack_recovery::{
    EntryValidation, NtfsDirectoryEntry, NtfsRecoveredEntry, NtfsSlackEntryScanner,
    SlackRecoveryConfig,
};
pub use crate::structured_values::NtfsFileNamespace;
pub use crate::time::{NTFS_TIMESTAMP_1997, NTFS_TIMESTAMP_2030, NtfsTime, TimestampBounds};
pub use crate::traverse::{NtfsDirectory, NtfsDirectoryIter, NtfsTraversalEntry};
pub use crate::upcase_table::{CaseSensitiveOrd, UpcaseOrd};
pub use crate::usn_journal::{
    NtfsUsnJournal, NtfsUsnRecords, UsnJournalMetadata, UsnReason, UsnRecord, UsnRecordV3,
    UsnRecordVersion, UsnSourceInfo,
};

pub use crate::analysis::{
    NtfsMftMirrRecordStatus, NtfsMftMirrValidation, NtfsTimestampAnomaly,
    detect_timestamp_anomalies, detect_timestamp_anomalies_with_threshold, validate_mft_mirror,
};

#[cfg(feature = "std")]
pub use crate::deleted_files::{
    ClusterStatus, DeletedDataRun, DeletedFileScanConfig, NtfsDeletedFile, NtfsDeletedFileScanner,
    RecoveryAssessment,
};
#[cfg(feature = "std")]
pub use crate::logfile::{
    AttributeNameEntry, LfsRestartInfo, LogFileNameFields, LogFileRecordView, LogIndexEntryView,
    LogRecordType, NtfsClientRestartArea, NtfsLogFile, NtfsLogOperation, NtfsLogOperationData,
    NtfsLogRecord, OpenAttributeEntry, ResidentDataPatch, ResidentDataValue, TransactionEntry,
    TransactionState, TransactionTableDumpEntry, operation_is_unit,
};
#[cfg(feature = "std")]
pub use crate::parent_map::{NtfsChildEntry, NtfsParentMap};
