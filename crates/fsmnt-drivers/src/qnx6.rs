//! QNX6 Power-Safe adapter over the `fs-qnx6` parser.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use fs_qnx6::{Qnx6, Qnx6Error, Qnx6Inode};
use fsmnt_core::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, TargetFilesystem, normalize_path,
};
use fsmnt_device::{DetectedBootSector, DeviceReader, FilesystemDriver};
use fsmnt_parser_core::io::{Read, Seek};
use tracing::debug;

use crate::adapter::{PathCache, found, found_and};
use crate::identity;

/// Map a parser error onto the mount abstraction's semantic error variants.
fn map_qnx6_error(error: Qnx6Error, path: &str) -> FsError {
    match error {
        Qnx6Error::NotFound => FsError::NotFound(path.to_string()),
        Qnx6Error::NotADirectory(_) => FsError::NotADirectory(path.to_string()),
        Qnx6Error::NotAFile(_) => FsError::NotAFile(path.to_string()),
        Qnx6Error::Io(error) => FsError::Io(error),
        other => FsError::Filesystem(format!("QNX6 error: {other}")),
    }
}

/// Convert QNX's unsigned Unix-seconds timestamps to UTC.
fn timestamp(seconds: u32) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(i64::from(seconds), 0)
}

/// Metadata shared by direct queries and directory-listing entries.
fn metadata_of(inode: &Qnx6Inode) -> FsMetadata {
    let is_dir = inode.file_type().is_directory();
    FsMetadata {
        size: if is_dir { 0 } else { inode.size() },
        is_dir,
        created: timestamp(inode.created_time()),
        modified: timestamp(inode.modified_time()),
        accessed: timestamp(inode.accessed_time()),
        readonly: inode.permissions() & 0o222 == 0,
        hidden: false,
        system: false,
    }
}

/// Cross-platform entry flags inferred from a QNX6 inode.
fn entry_flags(inode: &Qnx6Inode) -> FsEntryFlags {
    let mut flags = FsEntryFlags::empty();
    if inode.file_type().is_symbolic_link() {
        flags |= FsEntryFlags::REPARSE_POINT;
    }
    // QNX6 status 2 marks a deleted inode. A live snapshot should not
    // normally point at one, but preserving the flag is useful on damaged
    // or forensically interesting directory trees.
    if inode.status() == 2 {
        flags |= FsEntryFlags::DELETED;
    }
    flags
}

/// A QNX6 Power-Safe volume exposed through [`TargetFilesystem`].
pub struct Qnx6Filesystem<R: Read + Seek> {
    volume: Qnx6<R>,
    notices: Vec<String>,
    resolved: PathCache<Qnx6Inode>,
}

impl<R: Read + Seek> Qnx6Filesystem<R> {
    /// Open the newest valid QNX6 snapshot over `reader`.
    ///
    /// # Errors
    ///
    /// Returns an error when neither superblock copy validates, their
    /// immutable geometry conflicts, or the active inode tree/root cannot be
    /// read.
    pub fn new(reader: R) -> FsResult<Self> {
        let volume = Qnx6::new(reader).map_err(|error| map_qnx6_error(error, "<open>"))?;
        let mut notices = Vec::new();
        if !volume.primary_copy_valid() {
            notices.push(
                "QNX6 primary superblock is invalid; opened the trailing snapshot copy".to_string(),
            );
        }
        if !volume.secondary_copy_valid() {
            notices.push(
                "QNX6 trailing superblock is invalid; opened the primary snapshot copy".to_string(),
            );
        }
        debug!(
            active_copy = ?volume.active_copy(),
            serial = volume.superblock().serial(),
            block_size = volume.superblock().block_size(),
            blocks = volume.superblock().num_blocks(),
            inodes = volume.superblock().num_inodes(),
            volume_id = %identity::uuid(volume.superblock().volume_id()),
            "opened a QNX6 Power-Safe volume"
        );
        Ok(Self {
            volume,
            notices,
            resolved: PathCache::new(),
        })
    }

    /// Access the underlying format parser.
    #[must_use]
    pub const fn volume(&self) -> &Qnx6<R> {
        &self.volume
    }

    fn resolve(&mut self, path: &str) -> FsResult<Qnx6Inode> {
        if let Some(inode) = self.resolved.get(path) {
            return Ok(inode.clone());
        }
        let normalized = normalize_path(path);
        let inode = self
            .volume
            .resolve_path(normalized.as_bytes())
            .map_err(|error| map_qnx6_error(error, path))?;
        self.resolved.insert(path, inode.clone());
        Ok(inode)
    }
}

impl<R: Read + Seek + Send> TargetFilesystem for Qnx6Filesystem<R> {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let inode = self.resolve(path)?;
        self.volume
            .read_file(&inode)
            .map_err(|error| map_qnx6_error(error, path))
    }

    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> FsResult<usize> {
        let inode = self.resolve(path)?;
        self.volume
            .read_file_range(&inode, offset, buffer)
            .map_err(|error| map_qnx6_error(error, path))
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        found(self.resolve(path))
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        found_and(self.resolve(path), |inode| inode.file_type().is_directory())
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        found_and(self.resolve(path), |inode| {
            !inode.file_type().is_directory()
        })
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        self.resolve(path).map(|inode| metadata_of(&inode))
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let directory = self.resolve(path)?;
        let raw_entries = self
            .volume
            .read_directory(&directory)
            .map_err(|error| map_qnx6_error(error, path))?;
        let normalized = normalize_path(path);
        let parent = if normalized.is_empty() {
            PathBuf::from("/")
        } else {
            PathBuf::from("/").join(normalized)
        };

        let mut entries = Vec::new();
        entries
            .try_reserve(raw_entries.len())
            .map_err(|_| FsError::Filesystem("could not allocate QNX6 directory listing".into()))?;
        for raw in raw_entries {
            if matches!(raw.name(), b"." | b"..") {
                continue;
            }
            let inode = self
                .volume
                .inode(raw.inode())
                .map_err(|error| map_qnx6_error(error, path))?;
            let name = String::from_utf8_lossy(raw.name()).into_owned();
            entries.push(FsEntry {
                path: parent.join(&name),
                name,
                flags: entry_flags(&inode),
                file_id: Some(u64::from(inode.number())),
                metadata: metadata_of(&inode),
            });
        }
        Ok(entries)
    }

    fn total_size(&self) -> Option<u64> {
        self.volume.superblock().volume_size().ok()
    }

    fn free_space(&mut self) -> Option<u64> {
        Some(
            u64::from(self.volume.superblock().free_blocks())
                * u64::from(self.volume.superblock().block_size()),
        )
    }

    fn volume_uuid(&self) -> Option<String> {
        Some(identity::uuid(self.volume.superblock().volume_id()))
    }

    fn notices(&self) -> Vec<String> {
        self.notices.clone()
    }
}

/// Driver for QNX6 Power-Safe volumes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Qnx6Driver;

impl FilesystemDriver for Qnx6Driver {
    fn name(&self) -> &'static str {
        "qnx6"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Qnx6
    }

    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(Qnx6Filesystem::new(reader)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsmnt_testkit::qnx6::{
        self, FixtureByteOrder, HELLO_DATA, INDIRECT_FILE_SIZE, INNER_DATA, LONG_DATA, LONG_NAME,
        PRIMARY_SUPERBLOCK_OFFSET,
    };

    fn fixture_filesystem() -> Box<dyn TargetFilesystem> {
        Qnx6Driver
            .open(
                Box::new(std::io::Cursor::new(qnx6::image(
                    FixtureByteOrder::Little,
                    1,
                    2,
                ))),
                DetectedBootSector::Qnx6,
            )
            .expect("open synthetic QNX6 through the driver")
    }

    #[test]
    fn driver_identity_is_stable() {
        assert_eq!(Qnx6Driver.name(), "qnx6");
        crate::test_support::assert_supports_exactly(&Qnx6Driver, &[DetectedBootSector::Qnx6]);
    }

    #[test]
    fn timestamps_cover_the_unsigned_qnx_range() {
        assert_eq!(
            timestamp(u32::MAX)
                .expect("u32 seconds fit chrono")
                .timestamp(),
            i64::from(u32::MAX)
        );
    }

    #[test]
    fn adapter_lists_and_reads_every_name_form() {
        let mut filesystem = fixture_filesystem();
        let entries = filesystem.read_dir("/").expect("root listing");
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            [
                "hello.txt",
                "subdir",
                LONG_NAME,
                "indirect.bin",
                "sparse.bin"
            ]
        );
        assert_eq!(filesystem.read("/hello.txt").expect("hello"), HELLO_DATA);
        assert_eq!(
            filesystem.read("/subdir/inner.txt").expect("nested file"),
            INNER_DATA
        );
        assert_eq!(
            filesystem.read(LONG_NAME).expect("long-named file"),
            LONG_DATA
        );
    }

    #[test]
    fn adapter_metadata_ranges_and_identity_are_mount_ready() {
        let mut filesystem = fixture_filesystem();
        let hello = filesystem.metadata("hello.txt").expect("hello metadata");
        assert_eq!(
            hello.size,
            u64::try_from(HELLO_DATA.len()).expect("fixture length fits u64")
        );
        assert!(!hello.is_dir);
        assert!(!hello.readonly);
        let inner = filesystem
            .metadata("subdir/inner.txt")
            .expect("inner metadata");
        assert!(inner.readonly, "mode 0400 has no write permission bits");

        let mut boundary = [0_u8; 6];
        assert_eq!(
            filesystem
                .read_at(
                    "indirect.bin",
                    u64::try_from(INDIRECT_FILE_SIZE).expect("fixture size fits u64") - 2,
                    &mut boundary,
                )
                .expect("tail range"),
            2
        );
        assert_eq!(&boundary[..2], [16, 16]);
        assert_eq!(
            filesystem.volume_uuid().as_deref(),
            Some("12345678-9abc-4def-8001-23456789abcd")
        );
        assert_eq!(
            filesystem.total_size(),
            Some(u64::try_from(qnx6::VOLUME_SIZE).expect("fixture volume fits u64"))
        );
        assert!(filesystem.free_space().is_some());
    }

    #[test]
    fn adapter_reports_superblock_fallback() {
        let mut image = qnx6::image(FixtureByteOrder::Little, 1, 2);
        image[PRIMARY_SUPERBLOCK_OFFSET + 4] ^= 1;
        let filesystem =
            Qnx6Filesystem::new(std::io::Cursor::new(image)).expect("trailing superblock survives");
        assert_eq!(filesystem.notices.len(), 1);
        assert!(filesystem.notices[0].contains("primary superblock"));
    }
}
