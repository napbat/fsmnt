//! ext2/ext3/ext4 adapter over the vendored `fs-ext` parser.
//!
//! [`ExtFilesystem`] exposes a raw ext volume through
//! [`TargetFilesystem`]; [`ExtDriver`] registers it for
//! [`DetectedBootSector::Ext`].
//!
//! Dirty-image recovery (journal replay, then orphan-inode processing) is
//! handled inside the adapter, so callers always receive a handle onto the
//! post-recovery filesystem state.

mod dir;

use std::io;

use chrono::{DateTime, Utc};
use fs_ext::io::{Read, Seek, SeekFrom};
use fs_ext::{Ext, ExtError, ExtTimestamp, JournalReplay, OrphanReplay, OverlayReader};
use fsmnt_core::{FsEntry, FsError, FsMetadata, FsResult, TargetFilesystem};
use fsmnt_device::{DetectedBootSector, DeviceReader, FilesystemDriver};
use fsmnt_parser_core::io::FsReadSeek;
use fsmnt_parser_core::traverse::EntryKind;

use crate::adapter::{found, read_up_to};
use crate::identity;

/// Root inode number for ext2/ext3/ext4.
const EXT4_ROOT_INO: u32 = 2;

/// A raw ext2/ext3/ext4 volume exposed as a [`TargetFilesystem`].
///
/// Construction strict-opens the filesystem; if that reports
/// `NeedsRecovery` or `OrphanRecoveryRequired`, the canonical recovery
/// flow runs and the handle is re-opened through the resulting overlay.
pub struct ExtFilesystem<R: Read + Seek + Send> {
    reader: R,
    ext: Ext,
    overlay: Overlay,
}

/// Which replay artifact, if any, serves overlay reads.
///
/// The [`Ext`] handle in [`ExtFilesystem`] is always strict-opened through
/// the matching overlay, so feature-flag validation reflects the
/// post-recovery state.
enum Overlay {
    /// The strict open succeeded directly; no recovery was needed.
    Clean,
    /// Journal replay ran; no pending orphan state.
    Journal(JournalReplay),
    /// Journal *and* orphan replay ran. Transitively owns the journal.
    Orphan(OrphanReplay),
}

/// Per-call reader view.
///
/// `dyn Read + Seek` is not valid Rust, and the fs-ext APIs bound
/// `T: Read + Seek + Sized`, so a trait object would not satisfy them.
/// This concrete enum yields one monomorphization per overlay variant
/// with no dispatch cost beyond the match.
enum Reader<'fs, R: Read + Seek> {
    Direct(&'fs mut R),
    Journal(OverlayReader<'fs, 'fs, R, JournalReplay>),
    Orphan(OverlayReader<'fs, 'fs, R, OrphanReplay>),
}

impl<R: Read + Seek> Read for Reader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Reader::Direct(r) => r.read(buf),
            Reader::Journal(r) => r.read(buf),
            Reader::Orphan(r) => r.read(buf),
        }
    }
}

impl<R: Read + Seek> Seek for Reader<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Reader::Direct(r) => r.seek(pos),
            Reader::Journal(r) => r.seek(pos),
            Reader::Orphan(r) => r.seek(pos),
        }
    }
}

/// Convert an [`ExtTimestamp`] to `DateTime<Utc>`, returning `None` only
/// when the value is out of range.
///
/// `(seconds = 0, nanoseconds = 0)` is a legitimate 1970-01-01T00:00:00Z
/// value on ext, not an "unset" sentinel the way it is on FAT and NTFS.
fn ts_to_utc(ts: ExtTimestamp) -> Option<DateTime<Utc>> {
    DateTime::try_from(ts).ok()
}

/// Split a forensic ext path into byte-exact components, resolving `.`
/// and `..` lexically.
///
/// Unlike [`fsmnt_core::normalize_path`], every non-`/` byte is preserved
/// verbatim: ext permits `\` and `:` in filenames, so rewriting them would
/// make those entries unopenable.
fn canonicalise_ext_path(path: &str) -> Vec<&str> {
    let stripped = path.trim_start_matches('/');
    let mut stack: Vec<&str> = Vec::new();
    for component in stripped.split('/').filter(|s| !s.is_empty()) {
        match component {
            "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    stack
}

/// Map an [`ExtError`] onto the closest [`FsError`] variant.
///
/// `NeedsRecovery` and `OrphanRecoveryRequired` never reach steady-state
/// methods — they surface only during [`ExtFilesystem::new`] and are
/// consumed by the recovery flow — but are still mapped here defensively.
/// `TimestampOutOfRange` is swallowed by [`ts_to_utc`] and surfaces as
/// `None` rather than reaching this helper.
fn map_ext_error(e: ExtError, path: &str) -> FsError {
    match e {
        ExtError::NotFound => FsError::NotFound(path.to_string()),
        ExtError::NotADirectory { .. } => FsError::NotADirectory(path.to_string()),
        ExtError::IsADirectory { .. } => FsError::NotAFile(path.to_string()),
        ExtError::Io(io_err) => FsError::Io(io_err),
        ExtError::JournalExpectedButAbsent => FsError::Filesystem(
            "filesystem requires recovery but no journal is available".to_string(),
        ),
        ExtError::EncryptedInode { inode } => {
            FsError::Filesystem(format!("inode {inode} is encrypted"))
        }
        ExtError::UnsupportedEaInode { inode } => {
            FsError::Filesystem(format!("inode {inode} uses EA inode references"))
        }
        other => FsError::Filesystem(format!("{other}")),
    }
}

impl<R: Read + Seek + Send> ExtFilesystem<R> {
    /// Open an ext2/ext3/ext4 volume from `reader`.
    ///
    /// A dirty image is recovered automatically:
    /// 1. Strict-open first. Success → no overlay.
    /// 2. On `NeedsRecovery` / `OrphanRecoveryRequired`, build a
    ///    [`JournalReplay`] and strict-reopen through the overlay.
    /// 3. If that still reports `OrphanRecoveryRequired`, build an
    ///    [`OrphanReplay`] on top of the journal and strict-reopen through
    ///    the combined overlay.
    ///
    /// # Errors
    ///
    /// Returns an error if the superblock cannot be parsed, if recovery is
    /// required but no journal is present, or if the post-recovery strict
    /// open still fails (e.g. an unsupported incompatible feature flag).
    pub fn new(mut reader: R) -> FsResult<Self> {
        match Ext::new(&mut reader) {
            Ok(ext) => Ok(Self {
                reader,
                ext,
                overlay: Overlay::Clean,
            }),
            Err(ExtError::NeedsRecovery | ExtError::OrphanRecoveryRequired) => {
                Self::recover(reader)
            }
            Err(e) => Err(map_ext_error(e, "<open>")),
        }
    }

    /// Run journal (and, if still needed, orphan) replay, then strict-open
    /// through the resulting overlay.
    fn recover(mut reader: R) -> FsResult<Self> {
        let lenient = Ext::open_lenient(&mut reader).map_err(|e| map_ext_error(e, "<lenient>"))?;
        let journal = JournalReplay::build(&lenient, &mut reader)
            .map_err(|e| map_ext_error(e, "<journal>"))?;

        let strict_attempt = {
            let mut or = OverlayReader::new(&mut reader, &journal);
            Ext::new(&mut or)
        };

        match strict_attempt {
            Ok(ext) => Ok(Self {
                reader,
                ext,
                overlay: Overlay::Journal(journal),
            }),
            Err(ExtError::OrphanRecoveryRequired) => {
                // Parse a lenient Ext through the journal overlay so the
                // orphan stage consumes the post-journal metadata snapshot.
                let post_journal_lenient = {
                    let mut or = OverlayReader::new(&mut reader, &journal);
                    Ext::open_lenient(&mut or)
                        .map_err(|e| map_ext_error(e, "<post-journal-lenient>"))?
                };
                let orphan = OrphanReplay::build(journal, &post_journal_lenient, &mut reader)
                    .map_err(|e| map_ext_error(e, "<orphan>"))?;
                let ext = {
                    let mut or = OverlayReader::new(&mut reader, &orphan);
                    Ext::new(&mut or).map_err(|e| map_ext_error(e, "<strict-orphan>"))?
                };
                Ok(Self {
                    reader,
                    ext,
                    overlay: Overlay::Orphan(orphan),
                })
            }
            Err(e) => Err(map_ext_error(e, "<strict-journal>")),
        }
    }

    /// Resolve a path to its inode number.
    ///
    /// Returns [`EXT4_ROOT_INO`] for an empty or root-only path.
    fn navigate_to_inode(&mut self, path: &str) -> FsResult<u32> {
        let stack = canonicalise_ext_path(path);
        if stack.is_empty() {
            return Ok(EXT4_ROOT_INO);
        }

        self.with_reader(|ext, reader| -> FsResult<u32> {
            let mut current_inum = EXT4_ROOT_INO;
            for (idx, component) in stack.iter().enumerate() {
                let mut dir = ext.directory_at(current_inum);
                let entry = dir
                    .lookup(reader, component.as_bytes())
                    .map_err(|e| map_ext_error(e, path))?;
                let is_last = idx == stack.len() - 1;
                if !is_last && !matches!(entry.kind, EntryKind::Directory) {
                    return Err(FsError::NotADirectory(path.to_string()));
                }
                current_inum = entry.inode_number;
            }
            Ok(current_inum)
        })
    }

    /// Run `f` with a reader view that routes through the active overlay.
    fn with_reader<T>(&mut self, f: impl FnOnce(&Ext, &mut Reader<'_, R>) -> T) -> T {
        let mut reader = match &self.overlay {
            Overlay::Clean => Reader::Direct(&mut self.reader),
            Overlay::Journal(j) => Reader::Journal(OverlayReader::new(&mut self.reader, j)),
            Overlay::Orphan(o) => Reader::Orphan(OverlayReader::new(&mut self.reader, o)),
        };
        f(&self.ext, &mut reader)
    }

    /// Which recovery overlay is serving reads: `"clean"`, `"journal"` or
    /// `"orphan"`.
    ///
    /// Reported by the CLI and useful in tests to confirm a dirty image
    /// took the expected recovery path.
    #[must_use]
    pub fn overlay_kind(&self) -> &'static str {
        match &self.overlay {
            Overlay::Clean => "clean",
            Overlay::Journal(_) => "journal",
            Overlay::Orphan(_) => "orphan",
        }
    }
}

impl<R: Read + Seek + Send> TargetFilesystem for ExtFilesystem<R> {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let inum = self.navigate_to_inode(path)?;
        self.with_reader(|ext, reader| -> FsResult<Vec<u8>> {
            let inode = ext
                .inode(reader, inum)
                .map_err(|e| map_ext_error(e, path))?;
            // Gate on is_regular_file(), NOT merely !is_directory: a
            // symlink's target bytes must not leak through the file reader.
            if !inode.is_regular_file() {
                return Err(FsError::NotAFile(path.to_string()));
            }
            let mut file = inode.open_file().map_err(|e| map_ext_error(e, path))?;
            read_up_to(inode.size(), |buffer| {
                file.read(reader, buffer)
                    .map_err(|e| map_ext_error(e, path))
            })
        })
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        found(self.navigate_to_inode(path))
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        let inum = match self.navigate_to_inode(path) {
            Ok(i) => i,
            Err(FsError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        self.with_reader(|ext, reader| -> FsResult<bool> {
            let inode = ext
                .inode(reader, inum)
                .map_err(|e| map_ext_error(e, path))?;
            Ok(inode.is_directory())
        })
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        let inum = match self.navigate_to_inode(path) {
            Ok(i) => i,
            Err(FsError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        self.with_reader(|ext, reader| -> FsResult<bool> {
            let inode = ext
                .inode(reader, inum)
                .map_err(|e| map_ext_error(e, path))?;
            Ok(inode.is_regular_file())
        })
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        let inum = self.navigate_to_inode(path)?;
        self.with_reader(|ext, reader| -> FsResult<FsMetadata> {
            let inode = ext
                .inode(reader, inum)
                .map_err(|e| map_ext_error(e, path))?;
            let is_dir = inode.is_directory();
            Ok(FsMetadata {
                size: if is_dir { 0 } else { inode.size() },
                is_dir,
                created: inode.crtime().and_then(ts_to_utc),
                modified: ts_to_utc(inode.mtime()),
                accessed: ts_to_utc(inode.atime()),
                readonly: false,
                hidden: false,
                system: false,
            })
        })
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let inum = self.navigate_to_inode(path)?;
        self.with_reader(|ext, reader| dir::list(ext, reader, inum, path))
    }

    fn total_size(&self) -> Option<u64> {
        Some(self.ext.size())
    }

    fn free_space(&mut self) -> Option<u64> {
        Some(self.ext.free_bytes())
    }

    fn volume_uuid(&self) -> Option<String> {
        Some(identity::uuid(self.ext.uuid()))
    }
}

/// [`FilesystemDriver`] for ext2/ext3/ext4 volumes.
pub struct ExtDriver;

impl FilesystemDriver for ExtDriver {
    fn name(&self) -> &'static str {
        "ext"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Ext
    }

    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(ExtFilesystem::new(reader)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn driver_supports_only_ext() {
        assert!(ExtDriver.supports(DetectedBootSector::Ext));
        for other in [
            DetectedBootSector::Ntfs,
            DetectedBootSector::Fat32,
            DetectedBootSector::ExFat,
            DetectedBootSector::Apfs,
            DetectedBootSector::Btrfs,
            DetectedBootSector::BitLocker,
            DetectedBootSector::GptPartitioned,
            DetectedBootSector::Unknown,
        ] {
            assert!(!ExtDriver.supports(other), "must not claim {other:?}");
        }
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(ExtDriver.name(), "ext");
    }

    #[test]
    fn opening_a_non_ext_image_fails() {
        let reader = Box::new(Cursor::new(vec![0u8; 8192]));
        assert!(
            ExtDriver.open(reader, DetectedBootSector::Ext).is_err(),
            "an all-zero image must not parse as ext"
        );
    }

    #[test]
    fn canonicalise_handles_root_and_empty_paths() {
        assert!(canonicalise_ext_path("").is_empty());
        assert!(canonicalise_ext_path("/").is_empty());
    }

    #[test]
    fn canonicalise_collapses_separators() {
        assert_eq!(canonicalise_ext_path("/foo/bar"), ["foo", "bar"]);
        assert_eq!(canonicalise_ext_path("foo/bar"), ["foo", "bar"]);
        assert_eq!(canonicalise_ext_path("//foo///bar//"), ["foo", "bar"]);
    }

    #[test]
    fn canonicalise_preserves_backslash_and_colon() {
        // Both are legal filename bytes on ext; the Windows-oriented
        // normalisation must not be applied here.
        assert_eq!(canonicalise_ext_path("/a\\b"), ["a\\b"]);
        assert_eq!(canonicalise_ext_path("/C:literal"), ["C:literal"]);
        assert_eq!(canonicalise_ext_path("/foo/a:b:c"), ["foo", "a:b:c"]);
    }

    #[test]
    fn canonicalise_resolves_dot_and_dotdot() {
        assert_eq!(canonicalise_ext_path("/./foo"), ["foo"]);
        assert_eq!(canonicalise_ext_path("/foo/./bar"), ["foo", "bar"]);
        assert_eq!(canonicalise_ext_path("/foo/../bar"), ["bar"]);
        assert_eq!(canonicalise_ext_path("/foo/bar/.."), ["foo"]);
        // `..` beyond the root is clamped rather than escaping it.
        assert_eq!(canonicalise_ext_path("/../../foo"), ["foo"]);
    }

    #[test]
    fn timestamp_zero_is_the_unix_epoch_not_unset() {
        let dt = ts_to_utc(ExtTimestamp {
            seconds: 0,
            nanoseconds: 0,
        })
        .expect("epoch is a valid ext timestamp");
        assert_eq!(dt.timestamp(), 0);
    }

    #[test]
    fn timestamp_out_of_range_maps_to_none() {
        assert!(
            ts_to_utc(ExtTimestamp {
                seconds: 0,
                nanoseconds: 2_000_000_000,
            })
            .is_none()
        );
    }

    #[test]
    fn error_mapping_preserves_semantic_variants() {
        assert!(matches!(
            map_ext_error(ExtError::NotFound, "/foo"),
            FsError::NotFound(p) if p == "/foo"
        ));
        assert!(matches!(
            map_ext_error(ExtError::NotADirectory { inode: 42 }, "/foo"),
            FsError::NotADirectory(_)
        ));
        assert!(matches!(
            map_ext_error(ExtError::IsADirectory { inode: 7 }, "/foo"),
            FsError::NotAFile(_)
        ));
        assert!(matches!(
            map_ext_error(ExtError::EncryptedInode { inode: 123 }, "/foo"),
            FsError::Filesystem(msg) if msg.contains("123") && msg.contains("encrypted")
        ));
        assert!(matches!(
            map_ext_error(ExtError::JournalExpectedButAbsent, "<open>"),
            FsError::Filesystem(msg) if msg.contains("no journal is available")
        ));
    }
}
