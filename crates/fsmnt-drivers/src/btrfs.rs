//! Read-only Btrfs adapter over the no_std-capable `fs-btrfs` parser.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs_btrfs::{
    Btrfs, BtrfsDirEntry, BtrfsEntry, BtrfsError, BtrfsFileType, BtrfsInode, BtrfsTimestamp,
};
use fsmnt_core::{FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, TargetFilesystem};
use fsmnt_device::{DetectedBootSector, DeviceReader, DeviceSet, FilesystemDriver};

fn map_btrfs_error(error: BtrfsError, path: &str) -> FsError {
    match error {
        BtrfsError::Io(error) => FsError::Io(error),
        BtrfsError::NotFound => FsError::NotFound(path.to_string()),
        BtrfsError::NotADirectory => FsError::NotADirectory(path.to_string()),
        BtrfsError::NotAFile => FsError::NotAFile(path.to_string()),
        other => FsError::Filesystem(other.to_string()),
    }
}

fn canonicalise_btrfs_path(path: &str) -> Vec<&str> {
    let mut components = Vec::new();
    for component in path
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
    {
        match component {
            "." => {}
            ".." => {
                components.pop();
            }
            name => components.push(name),
        }
    }
    components
}

fn timestamp_to_utc(timestamp: BtrfsTimestamp) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(timestamp.seconds(), timestamp.nanoseconds())
}

fn metadata_of(inode: &BtrfsInode) -> FsMetadata {
    let is_dir = inode.file_type().is_directory();
    FsMetadata {
        size: if is_dir { 0 } else { inode.size() },
        is_dir,
        created: timestamp_to_utc(inode.created()),
        modified: timestamp_to_utc(inode.modified()),
        accessed: timestamp_to_utc(inode.accessed()),
        readonly: inode.mode() & 0o222 == 0,
        hidden: false,
        system: false,
    }
}

fn entry_flags(file_type: BtrfsFileType, inode: &BtrfsInode) -> FsEntryFlags {
    let mut flags = FsEntryFlags::empty();
    if file_type.is_symbolic_link() {
        flags.insert(FsEntryFlags::REPARSE_POINT);
    }
    if inode.link_count() > 1 {
        flags.insert(FsEntryFlags::HARD_LINK);
    }
    flags
}

/// A raw Btrfs volume exposed through [`TargetFilesystem`].
pub struct BtrfsFilesystem<R: fs_btrfs::io::Read + fs_btrfs::io::Seek> {
    volume: Btrfs<R>,
}

impl<R: fs_btrfs::io::Read + fs_btrfs::io::Seek> BtrfsFilesystem<R> {
    /// Open and fully bootstrap one Btrfs device.
    ///
    /// # Errors
    ///
    /// Returns an error when the superblock, chunk mapping, root tree, default
    /// subvolume, or root inode cannot be read and validated.
    pub fn new(reader: R) -> FsResult<Self> {
        Self::from_volume(Btrfs::new(reader).map_err(|error| map_btrfs_error(error, "<open>"))?)
    }

    /// Open and fully bootstrap every member of a Btrfs filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, duplicate, foreign, unreadable, or
    /// structurally invalid device members.
    pub fn from_devices(readers: Vec<R>) -> FsResult<Self> {
        Self::from_volume(
            Btrfs::from_devices(readers).map_err(|error| map_btrfs_error(error, "<open>"))?,
        )
    }

    fn from_volume(mut volume: Btrfs<R>) -> FsResult<Self> {
        volume
            .initialize()
            .map_err(|error| map_btrfs_error(error, "<bootstrap>"))?;
        Ok(Self { volume })
    }

    /// Access the format parser.
    #[must_use]
    pub const fn volume(&self) -> &Btrfs<R> {
        &self.volume
    }

    fn resolve(&mut self, path: &str) -> FsResult<BtrfsEntry> {
        let components = canonicalise_btrfs_path(path);
        self.volume
            .resolve_path(components.iter().map(|component| component.as_bytes()))
            .map_err(|error| map_btrfs_error(error, path))
    }

    fn directory_entry(
        &mut self,
        parent: &Path,
        raw: &BtrfsDirEntry,
        source_path: &str,
    ) -> FsResult<FsEntry> {
        let inode = self
            .volume
            .inode(raw.entry())
            .map_err(|error| map_btrfs_error(error, source_path))?;
        let name = String::from_utf8_lossy(raw.name()).into_owned();
        Ok(FsEntry {
            path: parent.join(&name),
            name,
            flags: entry_flags(inode.file_type(), &inode),
            file_id: Some(raw.entry().object_id()),
            metadata: metadata_of(&inode),
        })
    }
}

impl<R: fs_btrfs::io::Read + fs_btrfs::io::Seek + Send> TargetFilesystem for BtrfsFilesystem<R> {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let entry = self.resolve(path)?;
        self.volume
            .read_file(entry)
            .map_err(|error| map_btrfs_error(error, path))
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        match self.resolve(path) {
            Ok(_) => Ok(true),
            Err(FsError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        match self.metadata(path) {
            Ok(metadata) => Ok(metadata.is_dir),
            Err(FsError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        match self.metadata(path) {
            Ok(metadata) => Ok(!metadata.is_dir),
            Err(FsError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        let entry = self.resolve(path)?;
        let inode = self
            .volume
            .inode(entry)
            .map_err(|error| map_btrfs_error(error, path))?;
        Ok(metadata_of(&inode))
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let directory = self.resolve(path)?;
        let raw_entries = self
            .volume
            .read_dir(directory)
            .map_err(|error| map_btrfs_error(error, path))?;
        let normalized = canonicalise_btrfs_path(path).join("/");
        let parent = if normalized.is_empty() {
            PathBuf::from("/")
        } else {
            PathBuf::from(normalized)
        };
        raw_entries
            .into_iter()
            .map(|entry| self.directory_entry(&parent, &entry, path))
            .collect()
    }

    fn total_size(&self) -> Option<u64> {
        Some(self.volume.superblock().total_bytes())
    }

    fn free_space(&mut self) -> Option<u64> {
        Some(
            self.volume
                .superblock()
                .total_bytes()
                .saturating_sub(self.volume.superblock().bytes_used()),
        )
    }
}

/// Driver for read-only Btrfs volumes, including native multi-device layouts.
#[derive(Clone, Copy, Debug, Default)]
pub struct BtrfsDriver;

impl FilesystemDriver for BtrfsDriver {
    fn name(&self) -> &'static str {
        "btrfs"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Btrfs
    }

    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(BtrfsFilesystem::new(reader)?))
    }

    fn open_devices(
        &self,
        devices: DeviceSet,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let readers = devices
            .into_members()
            .into_iter()
            .map(fsmnt_device::DeviceMember::into_reader)
            .collect();
        Ok(Box::new(BtrfsFilesystem::from_devices(readers)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_supports_only_btrfs() {
        assert!(BtrfsDriver.supports(DetectedBootSector::Btrfs));
        for other in [
            DetectedBootSector::Ntfs,
            DetectedBootSector::Fat32,
            DetectedBootSector::ExFat,
            DetectedBootSector::Ext,
            DetectedBootSector::Apfs,
            DetectedBootSector::BitLocker,
            DetectedBootSector::GptPartitioned,
            DetectedBootSector::Unknown,
        ] {
            assert!(
                !BtrfsDriver.supports(other),
                "driver must not claim {other:?}"
            );
        }
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(BtrfsDriver.name(), "btrfs");
    }

    #[test]
    fn path_resolution_preserves_btrfs_filename_bytes() {
        assert_eq!(
            canonicalise_btrfs_path("/a\\b/C:literal/./child/../tail"),
            ["a\\b", "C:literal", "tail"]
        );
    }

    #[test]
    fn invalid_superblock_is_reported_before_bootstrap() {
        let reader = Box::new(std::io::Cursor::new(vec![0_u8; 0x1_1000]));
        let Err(error) = BtrfsDriver.open(reader, DetectedBootSector::Btrfs) else {
            panic!("zeroed superblock must fail");
        };

        assert!(error.to_string().contains("invalid Btrfs magic"), "{error}");
    }
}
