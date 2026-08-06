//! Common functionality shared between filesystem crates (fs-ntfs, fs-fat, etc.).
//!
//! This crate provides `no_std`-compatible abstractions that work in both `std` and `no_std` environments.

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
    BOOT_SECTOR_SIZE, BootSectorDiagnosis, BootSectorUnknownReason, DetectedBootSector,
    FS_DETECT_PROBE_SIZE, diagnose_boot_sector,
};
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use error::IntoStdIoError;
pub use error::{ErrorKind, FsError, IoError};
pub use io::{Attached, FsReadSeek};
pub use iter::{FsTryIterator, FsTryIteratorExt, FsTryIteratorType};
pub use simd::SimdLevel;
pub use traverse::{EntryKind, FsDirEntry, FsDirectory, FsId, walk_dir};
