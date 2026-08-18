//! Portable foundations shared by filesystem-format parsers.
//!
//! This crate is the canonical owner of parser I/O and error traits,
//! traversal interfaces, boot-sector detection, and MBR/GPT byte
//! structures. It is `no_std` by default; consumers that need
//! `std::io` compatibility must opt into the `std` feature explicitly.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

/// Error types shared by filesystem parsers.
pub mod error;
pub mod io;
/// Fallible iterator traits for reader-backed data.
pub mod iter;

pub mod boot_sector;
pub mod partition;
pub mod simd;
pub mod traverse;

pub use boot_sector::{
    BOOT_SECTOR_SIZE, BTRFS_PRIMARY_SUPERBLOCK_OFFSET, BTRFS_SUPERBLOCK_MAGIC,
    BTRFS_SUPERBLOCK_PROBE_SIZE, BootSectorDiagnosis, BootSectorUnknownReason, DetectedBootSector,
    ExtBackupSuperblock, ExtSuperblockInfo, FS_DETECT_PROBE_SIZE, diagnose_boot_sector,
    ext_backup_superblock_group, ext_backup_superblock_info, ext_superblock_info,
    is_btrfs_primary_superblock,
};
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use error::IntoStdIoError;
pub use error::{ErrorKind, IoError, ParserError};
pub use io::{Attached, FsReadSeek};
pub use iter::{FsTryIterator, FsTryIteratorExt, FsTryIteratorType};
pub use simd::SimdLevel;
pub use traverse::{EntryKind, FsDirEntry, FsDirectory, FsId, walk_dir};
