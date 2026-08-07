//! A low-level FAT filesystem library implemented in Rust.
//!
//! [FAT](https://en.wikipedia.org/wiki/File_Allocation_Table) is a widely-used filesystem format,
//! commonly found on removable media (USB drives, SD cards), boot partitions, and for cross-platform
//! compatibility. This crate supports FAT12, FAT16, and FAT32. `ExFAT` has enough differences that
//! it should be treated as a completely different filesystem.
//!
//! The crate is `no_std`-compatible and therefore usable from firmware level code up to user-mode applications.
//!
//! # Getting started
//! 1. Create a [`Fat`] structure from a reader by calling [`Fat::new`].
//! 2. Retrieve the root directory via [`Fat::root_directory`] or iterate entries via [`Fat::root_dir_entries`].
//! 3. Navigate to files using [`Fat::open`] with a path, or iterate directory entries manually.
//! 4. Read file contents using [`FatFile::data`] which returns a [`FatFileValue`] for reading.
//!
//! # Example
//! The following example dumps the names of all files and folders in the root directory of a given FAT filesystem.
//!
//! ```no_run
//! # use fsmnt_parser_core::iter::FsTryIterator;
//! # use fs_fat::Fat;
//! # let mut fs = fsmnt_testkit::Cursor::new(vec![0u8; 512]);
//! let fat = Fat::new(&mut fs).unwrap();
//! let mut entries = fat.root_dir_entries();
//!
//! while let Some(entry) = entries.try_next(&mut fs).unwrap() {
//!     println!("{}", entry.name());
//! }
//! ```
//!
//! # Reading a file
//! ```ignore
//! use fsmnt_parser_core::io::FsReadSeek;
//! use fs_fat::Fat;
//!
//! let fat = Fat::new(&mut fs)?;
//! let file = fat.open(&mut fs, "/Documents/readme.txt")?;
//! let mut data = file.data()?;
//!
//! let mut buffer = [0u8; 1024];
//! let bytes_read = data.read(&mut fs, &mut buffer)?;
//! ```
//!

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

extern crate alloc;

mod dir_entry;
mod error;
mod fat;
mod file;
mod time;
mod traverse;
mod value;

pub use dir_entry::{
    DIR_ENTRY_SIZE, DirFileEntryData, FatAttributes, FatDirEntries, FatDirEntry, LfnEntryData,
};
pub use error::{FatError, Result};
pub use fat::{Fat, FatType};
pub use file::FatFile;
pub use time::FatTime;
pub use traverse::{FatDirectory, FatDirectoryEntry, FatDirectoryIter};
pub use value::FatFileValue;

pub use fsmnt_parser_core::io;
