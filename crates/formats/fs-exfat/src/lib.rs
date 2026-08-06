//! A low-level exFAT filesystem library implemented in Rust.
//!
//! [exFAT](https://en.wikipedia.org/wiki/ExFAT) is a filesystem
//! designed for flash memory such as USB drives and SD cards.
//! It supports large files (> 4 GiB) and large volumes without the
//! complexity of NTFS.
//!
//! The crate is `no_std`-compatible and therefore usable from
//! firmware level code up to user-mode applications.
//!
//! # Getting started
//! 1. Create an [`ExFat`] structure from a reader by calling
//!    [`ExFat::new`].
//! 2. Query boot sector fields via typed accessors.
//! 3. Compute cluster byte offsets with [`ExFat::cluster_offset`].

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

extern crate alloc;

mod bitmap;
mod boot_sector;
mod dir_entry;
mod dir_iter;
mod entry_set;
mod error;
mod exfat;
mod fat;
mod file;
#[cfg(test)]
mod test_helpers;
mod time;
pub mod traverse;
mod upcase;

pub use bitmap::ExFatBitmap;
pub use boot_sector::VolumeFlags;
pub use dir_entry::{
    BitmapDirectoryEntry, DIR_ENTRY_SIZE, ENTRY_TYPE_BITMAP, ENTRY_TYPE_END, ENTRY_TYPE_FILE,
    ENTRY_TYPE_NAME, ENTRY_TYPE_STREAM, ENTRY_TYPE_TEXFAT_PADDING, ENTRY_TYPE_UPCASE,
    ENTRY_TYPE_VENDOR_ALLOC, ENTRY_TYPE_VENDOR_EXT, ENTRY_TYPE_VOLUME_GUID,
    ENTRY_TYPE_VOLUME_LABEL, EntryTypeInfo, ExFatFileAttributes, FileDirectoryEntry, FileNameEntry,
    StreamExtensionEntry, UpcaseTableDirectoryEntry, VolumeLabelEntry,
};
pub use dir_iter::ExFatDirEntries;
pub use entry_set::{ExFatDirItem, ExFatEntrySet};
pub use error::{ExFatError, Result};
pub use exfat::ExFat;
pub use fat::ExFatClusterIterator;
pub use file::ExFatFile;
pub use fs_common::FsReadSeek;
pub use time::ExFatTimestamp;
pub use traverse::{ExFatDirectory, ExFatDirectoryIter, ExFatTraversalEntry};
pub use upcase::{ExFatUpcaseTable, compute_name_hash, compute_upcase_checksum};

pub use fs_common::io;
