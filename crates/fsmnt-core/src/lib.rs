//! Core abstractions for `fsmnt`.
//!
//! Defines the [`TargetFilesystem`] trait that filesystem sources implement
//! to become mountable, its supporting types, the [`DirFilesystem`]
//! host-directory backend, and platform-neutral helpers shared by the mount
//! backends.  This crate has no platform-specific dependencies.

mod dir_fs;
mod filesystem;
mod filter;
mod fstab;
mod namespace;

pub use dir_fs::DirFilesystem;
pub use filesystem::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, OpenedDirectory, OpenedFile,
    OpenedTarget, TargetFilesystem, normalize_path,
};
pub use filter::filter_entries;
pub use fstab::{Fstab, FstabEntry, FstabParseError, FstabSource};
pub use namespace::MountNamespace;
