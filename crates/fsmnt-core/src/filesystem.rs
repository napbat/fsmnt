//! Filesystem abstraction consumed by the mount backends.
//!
//! [`TargetFilesystem`] is the interface a filesystem source must implement
//! to be mountable with [`crate::mount`]. Implementations can be backed by
//! anything that looks like a file tree: a host directory
//! ([`crate::DirFilesystem`]), a raw partition image parsed in userspace, a
//! remote system, and so on.

use std::io::{self, Cursor, Read};
use std::path::PathBuf;

use chrono::{DateTime, Utc};

/// Errors returned by [`TargetFilesystem`] operations.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The path does not exist.
    #[error("Path not found: {0}")]
    NotFound(String),

    /// The path exists but is not a directory.
    #[error("Not a directory: {0}")]
    NotADirectory(String),

    /// The path exists but is not a file.
    #[error("Not a file: {0}")]
    NotAFile(String),

    /// Access to the path was denied.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// The path is malformed or escapes the filesystem root.
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Backend-specific filesystem failure.
    #[error("Filesystem error: {0}")]
    Filesystem(String),
}

/// Result alias for [`TargetFilesystem`] operations.
pub type FsResult<T> = Result<T, FsError>;

/// Metadata about a file or directory.
///
/// Timestamps are stored as `chrono::DateTime<Utc>` rather than
/// `std::time::SystemTime` because forensic filesystems (NTFS, FAT) can have
/// dates outside the Unix epoch range (e.g. NTFS dates back to 1601-01-01).
/// `DateTime<Utc>` also serializes cleanly for reports and exports.
///
/// If `is_dir` is `false` the entry is implicitly a file.
#[allow(
    clippy::struct_excessive_bools,
    reason = "mirrors independent OS file attributes; not a state machine"
)]
#[derive(Debug, Clone, Default)]
pub struct FsMetadata {
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Whether the entry is a directory.
    pub is_dir: bool,
    /// Creation timestamp, if the filesystem records one.
    pub created: Option<DateTime<Utc>>,
    /// Last-modification timestamp, if the filesystem records one.
    pub modified: Option<DateTime<Utc>>,
    /// Last-access timestamp, if the filesystem records one.
    pub accessed: Option<DateTime<Utc>>,
    /// Whether the entry is marked read-only.
    pub readonly: bool,
    /// Windows-only hidden attribute.
    pub hidden: bool,
    /// Windows-only system attribute.
    pub system: bool,
}

bitflags::bitflags! {
    /// Flags describing special properties of a directory entry.
    ///
    /// These are filesystem-agnostic — different backends set whichever
    /// flags apply.  Consumers can filter on them: e.g. a mount hides
    /// `SHORT_NAME` entries, while a forensic export keeps everything.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FsEntryFlags: u16 {
        /// DOS 8.3 short name (NTFS `Dos` namespace, FAT SFN).
        const SHORT_NAME       = 0x0001;
        /// NTFS alternate data stream (e.g. `file.txt:hidden:$DATA`).
        const ALTERNATE_STREAM = 0x0002;
        /// Hard link — same file, different name/directory.
        const HARD_LINK        = 0x0004;
        /// Reparse point (symlink, junction, mount point).
        const REPARSE_POINT    = 0x0008;
        /// Deleted entry (FAT `0xE5`, NTFS with no `IN_USE` flag).
        const DELETED          = 0x0010;
        /// Volume label entry (FAT).
        const VOLUME_LABEL     = 0x0020;
        /// OS/filesystem metadata file (e.g. NTFS `$MFT`, `$Volume`).
        const SYSTEM_FILE      = 0x0040;
    }
}

/// A directory entry returned by [`TargetFilesystem::read_dir`].
///
/// The entry carries both the name/path information specific to the
/// directory listing *and* cached file metadata.  The metadata comes from
/// whatever the filesystem stores in its directory index (e.g. NTFS
/// `$FILE_NAME`, FAT directory entry).  It may be slightly stale compared to
/// the canonical metadata obtained via [`TargetFilesystem::metadata`], but
/// for a read-only mount that is acceptable and avoids an extra I/O per
/// entry.
#[derive(Debug, Clone)]
pub struct FsEntry {
    /// Entry name within its parent directory.
    pub name: String,
    /// Full path of the entry as reported by the backend.
    pub path: PathBuf,
    /// Special properties of this entry.  Empty for normal files/dirs.
    pub flags: FsEntryFlags,
    /// Filesystem-level file identifier (NTFS file record number, ext4
    /// inode, FAT starting cluster, etc.).
    ///
    /// Used to correlate multiple entries that refer to the same file
    /// (e.g. a Win32 long name and a DOS 8.3 short name).
    /// `None` if the filesystem doesn't expose this.
    pub file_id: Option<u64>,
    /// Cached metadata from the directory index.
    pub metadata: FsMetadata,
}

/// Unified read-only filesystem interface.
///
/// This trait abstracts over different filesystem sources: live directories
/// (via `std::fs`), raw filesystem images parsed in userspace, remote
/// systems, and so on.
///
/// Paths are forward-slash separated and relative to the filesystem root
/// (no leading slash required; one is tolerated).
///
/// Methods take `&mut self` because some backends require mutable access to
/// an underlying reader.
pub trait TargetFilesystem: Send {
    /// Read the entire contents of a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the path does not exist, is not a file, or
    /// cannot be read.
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>>;

    /// Open a file and return a reader.
    ///
    /// The default implementation reads the entire file into memory via
    /// [`read()`](Self::read) and wraps it in a [`Cursor`].  Backends that
    /// support true streaming should override this.
    ///
    /// # Errors
    ///
    /// Returns an error if the path does not exist, is not a file, or
    /// cannot be opened.
    fn open(&mut self, path: &str) -> FsResult<Box<dyn Read + Send + '_>> {
        let data = self.read(path)?;
        Ok(Box::new(Cursor::new(data)))
    }

    /// Check if a path exists (fallible version).
    ///
    /// # Errors
    ///
    /// Returns an error if existence could not be determined (e.g. an I/O
    /// failure while querying the backend).
    fn try_exists(&mut self, path: &str) -> FsResult<bool>;

    /// Check if a path is a directory (fallible version).
    ///
    /// # Errors
    ///
    /// Returns an error if the check itself failed; a missing path is
    /// `Ok(false)`, not an error.
    fn try_is_dir(&mut self, path: &str) -> FsResult<bool>;

    /// Check if a path is a file (fallible version).
    ///
    /// # Errors
    ///
    /// Returns an error if the check itself failed; a missing path is
    /// `Ok(false)`, not an error.
    fn try_is_file(&mut self, path: &str) -> FsResult<bool>;

    /// Check if a path exists.
    ///
    /// Returns `false` on error. Use [`try_exists`](Self::try_exists) when
    /// you need to distinguish "not found" from I/O errors.
    fn exists(&mut self, path: &str) -> bool {
        self.try_exists(path).unwrap_or(false)
    }

    /// Check if a path is a directory.
    ///
    /// Returns `false` on error. Use [`try_is_dir`](Self::try_is_dir) when
    /// you need to distinguish "not a directory" from I/O errors.
    fn is_dir(&mut self, path: &str) -> bool {
        self.try_is_dir(path).unwrap_or(false)
    }

    /// Check if a path is a file.
    ///
    /// Returns `false` on error. Use [`try_is_file`](Self::try_is_file)
    /// when you need to distinguish "not a file" from I/O errors.
    fn is_file(&mut self, path: &str) -> bool {
        self.try_is_file(path).unwrap_or(false)
    }

    /// Get metadata for a path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path does not exist or metadata could not
    /// be read.
    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata>;

    /// List directory contents.
    ///
    /// # Errors
    ///
    /// Returns an error if the path does not exist, is not a directory,
    /// or cannot be listed.
    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>>;

    /// Read a file as a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or its contents are
    /// not valid UTF-8.
    fn read_to_string(&mut self, path: &str) -> FsResult<String> {
        let bytes = self.read(path)?;
        String::from_utf8(bytes).map_err(|e| FsError::Filesystem(format!("Invalid UTF-8: {e}")))
    }

    /// Returns the total size of the filesystem volume in bytes, if known.
    ///
    /// Used by mount backends to report disk space to the OS.
    /// Returns `None` by default (unknown / not applicable).
    fn total_size(&self) -> Option<u64> {
        None
    }

    /// Returns the number of free (unallocated) bytes on the volume, if
    /// known.
    ///
    /// Used by mount backends to report free space to the OS.
    /// Returns `None` by default (unknown / not applicable).
    fn free_space(&mut self) -> Option<u64> {
        None
    }
}

/// Normalize a filesystem path: convert backslashes to forward slashes and
/// strip a leading drive letter (e.g. `C:\foo` -> `foo`).
#[must_use]
pub fn normalize_path(path: &str) -> String {
    let with_forward_slashes = path.replace('\\', "/");

    if with_forward_slashes.len() >= 2
        && with_forward_slashes.as_bytes()[0].is_ascii_alphabetic()
        && with_forward_slashes.as_bytes()[1] == b':'
    {
        with_forward_slashes[2..]
            .trim_start_matches('/')
            .to_string()
    } else {
        with_forward_slashes.trim_start_matches('/').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_strips_drive_letter() {
        assert_eq!(normalize_path("C:\\Windows\\System32"), "Windows/System32");
    }

    #[test]
    fn normalize_path_strips_drive_with_forward_slash() {
        assert_eq!(normalize_path("C:/Users/test"), "Users/test");
    }

    #[test]
    fn normalize_path_strips_leading_slash() {
        assert_eq!(normalize_path("/etc/passwd"), "etc/passwd");
    }

    #[test]
    fn normalize_path_converts_backslashes() {
        assert_eq!(normalize_path("foo\\bar\\baz"), "foo/bar/baz");
    }

    #[test]
    fn normalize_path_empty_string() {
        assert_eq!(normalize_path(""), "");
    }

    #[test]
    fn normalize_path_drive_letter_only() {
        assert_eq!(normalize_path("C:\\"), "");
    }

    #[test]
    fn normalize_path_lowercase_drive() {
        assert_eq!(normalize_path("d:\\data\\file.txt"), "data/file.txt");
    }

    #[test]
    fn normalize_path_no_prefix() {
        assert_eq!(normalize_path("relative/path"), "relative/path");
    }

    #[test]
    fn fs_metadata_default_is_file() {
        let meta = FsMetadata::default();
        assert!(!meta.is_dir);
        assert_eq!(meta.size, 0);
        assert!(!meta.readonly);
        assert!(!meta.hidden);
        assert!(!meta.system);
    }
}
