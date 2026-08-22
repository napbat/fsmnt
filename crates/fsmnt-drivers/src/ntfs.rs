//! NTFS adapter over the vendored `fs-ntfs` parser.
//!
//! [`NtfsFilesystem`] exposes a raw NTFS volume through
//! [`TargetFilesystem`]; [`NtfsDriver`] registers it for
//! [`DetectedBootSector::Ntfs`].

use std::io::{self, Read, Seek};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use fs_ntfs::indexes::NtfsFileNameIndex;
use fs_ntfs::structured_values::NtfsFileAttributeFlags;
use fs_ntfs::{Ntfs, NtfsTime};
use fsmnt_core::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, TargetFilesystem, normalize_path,
};
use fsmnt_device::{DetectedBootSector, DeviceReader, FilesystemDriver};
use tracing::debug;

use crate::adapter::{PathCache, found, read_at_through};
use crate::boot_backup;
use crate::identity;
use fsmnt_parser_core::iter::FsTryIterator;

/// Convert an [`NtfsTime`] to `DateTime<Utc>`, mapping the zero timestamp
/// (NTFS's "not set" sentinel) to `None`.
fn ntfs_time_to_datetime(nt: NtfsTime) -> Option<DateTime<Utc>> {
    if nt.nt_timestamp() == 0 {
        return None;
    }
    Some(DateTime::<Utc>::from(nt))
}

/// A raw NTFS volume exposed as a [`TargetFilesystem`].
pub struct NtfsFilesystem<T: Read + Seek> {
    reader: T,
    ntfs: Ntfs,
    /// How the volume was opened, when that departed from the normal path.
    notices: Vec<String>,
    /// Most recently resolved file record for adjacent mount reads.
    resolved: PathCache<u64>,
}

impl<T: Read + Seek> NtfsFilesystem<T> {
    /// Open an NTFS volume from `reader` (offset 0 = start of the volume).
    ///
    /// Reads and caches the `$UpCase` table so filename lookups use NTFS's
    /// own case-insensitive collation.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::Filesystem`] if the boot sector or `$MFT` cannot
    /// be parsed, or if the up-case table cannot be read.
    pub fn new(mut reader: T) -> FsResult<Self> {
        let mut ntfs = Ntfs::new(&mut reader)
            .map_err(|e| FsError::Filesystem(format!("failed to parse NTFS: {e}")))?;

        ntfs.read_upcase_table(&mut reader)
            .map_err(|e| FsError::Filesystem(format!("failed to read upcase table: {e}")))?;

        debug!(
            cluster_size = ntfs.cluster_size(),
            sector_size = ntfs.sector_size(),
            file_record_size = ntfs.file_record_size(),
            size_bytes = ntfs.size(),
            "opened an NTFS volume"
        );

        Ok(Self {
            reader,
            ntfs,
            notices: Vec::new(),
            resolved: PathCache::new(),
        })
    }

    /// The underlying parser handle, for callers that need NTFS-specific
    /// details the [`TargetFilesystem`] interface does not expose.
    #[must_use]
    pub fn ntfs(&self) -> &Ntfs {
        &self.ntfs
    }

    /// Resolve `path` to a file record number.
    ///
    /// Returning a record number rather than an `NtfsFile` keeps the
    /// borrow of `self.reader` from escaping the helper.
    fn navigate_to_record(&mut self, path: &str) -> FsResult<u64> {
        if let Some(record) = self.resolved.get(path) {
            return Ok(*record);
        }
        let normalized = normalize_path(path);

        let root = self
            .ntfs
            .root_directory(&mut self.reader)
            .map_err(|e| FsError::Filesystem(format!("failed to get root directory: {e}")))?;

        let mut record = root.file_record_number();
        for target_name in normalized
            .split('/')
            .filter(|component| !component.is_empty())
        {
            let dir_file = self
                .ntfs
                .file(&mut self.reader, record)
                .map_err(|e| FsError::Filesystem(format!("failed to get directory: {e}")))?;

            let index = dir_file
                .directory_index(&mut self.reader)
                .map_err(|e| FsError::NotADirectory(format!("not a directory: {e}")))?;

            // The B-tree is ordered by the volume's up-case table, so lookups
            // must go through NTFS's own comparison rather than Rust's.
            let mut finder = index.finder();
            let maybe_entry = NtfsFileNameIndex::find_case_insensitive(
                &mut finder,
                &self.ntfs,
                &mut self.reader,
                target_name,
            );

            match maybe_entry {
                Some(Ok(entry)) => {
                    record = entry.file_reference().file_record_number();
                }
                Some(Err(e)) => {
                    return Err(FsError::Filesystem(format!("error finding entry: {e}")));
                }
                None => return Err(FsError::NotFound(target_name.to_string())),
            }
        }
        self.resolved.insert(path, record);
        Ok(record)
    }

    /// Whether the record at `path` is a directory, or `None` when the
    /// path does not exist.
    fn record_is_directory(&mut self, path: &str) -> FsResult<Option<bool>> {
        match self.navigate_to_record(path) {
            Ok(record) => {
                let file = self
                    .ntfs
                    .file(&mut self.reader, record)
                    .map_err(|e| FsError::Filesystem(format!("failed to get file: {e}")))?;
                Ok(Some(file.is_directory()))
            }
            Err(FsError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<T: Read + Seek + Send> TargetFilesystem for NtfsFilesystem<T> {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        use fsmnt_parser_core::io::FsReadSeek;

        let record = self.navigate_to_record(path)?;

        let file = self
            .ntfs
            .file(&mut self.reader, record)
            .map_err(|e| FsError::Filesystem(format!("failed to get file: {e}")))?;

        let data_attr = file
            .data(&mut self.reader, "")
            .ok_or_else(|| FsError::NotAFile(path.to_string()))?
            .map_err(|e| FsError::Filesystem(format!("failed to get data attribute: {e}")))?;

        let data_attr = data_attr
            .to_attribute()
            .map_err(|e| FsError::Filesystem(format!("failed to convert attribute: {e}")))?;

        let mut data_value = data_attr
            .value(&mut self.reader)
            .map_err(|e| FsError::Filesystem(format!("failed to get attribute value: {e}")))?;

        let len = usize::try_from(data_value.len())
            .map_err(|_| FsError::Filesystem("file too large to read in one call".to_string()))?;
        let mut buffer = vec![0u8; len];
        data_value
            .read_exact(&mut self.reader, &mut buffer)
            .map_err(|e| FsError::Io(io::Error::other(e.to_string())))?;

        Ok(buffer)
    }

    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> FsResult<usize> {
        let record = self.navigate_to_record(path)?;
        let file = self
            .ntfs
            .file(&mut self.reader, record)
            .map_err(|e| FsError::Filesystem(format!("failed to get file: {e}")))?;
        let data_attr = file
            .data(&mut self.reader, "")
            .ok_or_else(|| FsError::NotAFile(path.to_string()))?
            .map_err(|e| FsError::Filesystem(format!("failed to get data attribute: {e}")))?;
        let data_attr = data_attr
            .to_attribute()
            .map_err(|e| FsError::Filesystem(format!("failed to convert attribute: {e}")))?;
        let mut data_value = data_attr
            .value(&mut self.reader)
            .map_err(|e| FsError::Filesystem(format!("failed to get attribute value: {e}")))?;
        read_at_through(&mut data_value, &mut self.reader, offset, buffer, |e| {
            FsError::Io(io::Error::other(e.to_string()))
        })
    }

    // `open` is deliberately left at the trait default (read into a
    // `Cursor`): every fs-ntfs read needs the volume reader passed in, so
    // a standalone `Read` handle cannot borrow it out of `self` and NTFS
    // has no true streaming path to override with.

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        found(self.navigate_to_record(path))
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        Ok(self.record_is_directory(path)?.unwrap_or(false))
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        Ok(self
            .record_is_directory(path)?
            .is_some_and(|is_dir| !is_dir))
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        let record = self.navigate_to_record(path)?;

        // First pass: `info()` needs no reader, so it can borrow the file.
        let file = self
            .ntfs
            .file(&mut self.reader, record)
            .map_err(|e| FsError::Filesystem(format!("failed to get file: {e}")))?;

        let info = file
            .info()
            .map_err(|e| FsError::Filesystem(format!("failed to get file info: {e}")))?;

        let is_dir = file.is_directory();
        let flags = info.file_attributes();
        let created = ntfs_time_to_datetime(info.creation_time());
        let modified = ntfs_time_to_datetime(info.modification_time());
        let accessed = ntfs_time_to_datetime(info.access_time());
        let readonly = flags.contains(NtfsFileAttributeFlags::READ_ONLY);
        let hidden = flags.contains(NtfsFileAttributeFlags::HIDDEN);
        let system = flags.contains(NtfsFileAttributeFlags::SYSTEM);

        // Release the file before the size lookup, which needs the reader.
        drop(file);

        let size = if is_dir {
            0
        } else {
            let file = self
                .ntfs
                .file(&mut self.reader, record)
                .map_err(|e| FsError::Filesystem(format!("failed to get file: {e}")))?;
            let mut file_size = 0u64;
            if let Some(Ok(data_item)) = file.data(&mut self.reader, "")
                && let Ok(data_attr) = data_item.to_attribute()
            {
                file_size = data_attr.value_length();
            }
            file_size
        };

        Ok(FsMetadata {
            size,
            is_dir,
            created,
            modified,
            accessed,
            readonly,
            hidden,
            system,
        })
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let record = self.navigate_to_record(path)?;

        let dir = self
            .ntfs
            .file(&mut self.reader, record)
            .map_err(|e| FsError::Filesystem(format!("failed to get directory: {e}")))?;

        if !dir.is_directory() {
            return Err(FsError::NotADirectory(path.to_string()));
        }

        let index = dir
            .directory_index(&mut self.reader)
            .map_err(|e| FsError::Filesystem(format!("failed to get directory index: {e}")))?;

        let mut entries = Vec::new();
        let mut iter = index.entries();

        while let Some(entry) = iter
            .try_next(&mut self.reader)
            .map_err(|e| FsError::Filesystem(format!("failed to read entry: {e}")))?
        {
            let Some(Ok(file_name)) = entry.key() else {
                continue;
            };
            let name = file_name.name().to_string_lossy();

            // NTFS indexes normally hold neither, but a carved or damaged
            // index can, and they must never escape into a listing.
            if name == "." || name == ".." {
                continue;
            }

            let file_ref = entry.file_reference();
            let mut flags = FsEntryFlags::empty();
            if file_name.namespace() == fs_ntfs::NtfsFileNamespace::Dos {
                flags |= FsEntryFlags::SHORT_NAME;
            }
            if file_ref.is_system_metafile() {
                flags |= FsEntryFlags::SYSTEM_FILE;
            }

            let file_attrs = file_name.file_attributes();

            entries.push(FsEntry {
                path: PathBuf::from(path).join(&name),
                name,
                flags,
                file_id: Some(file_ref.file_record_number()),
                metadata: FsMetadata {
                    size: file_name.data_size(),
                    is_dir: file_name.is_directory(),
                    created: ntfs_time_to_datetime(file_name.creation_time()),
                    modified: ntfs_time_to_datetime(file_name.modification_time()),
                    accessed: ntfs_time_to_datetime(file_name.access_time()),
                    readonly: file_attrs.contains(NtfsFileAttributeFlags::READ_ONLY),
                    hidden: file_attrs.contains(NtfsFileAttributeFlags::HIDDEN),
                    system: file_attrs.contains(NtfsFileAttributeFlags::SYSTEM),
                },
            });
        }

        Ok(entries)
    }

    fn total_size(&self) -> Option<u64> {
        Some(self.ntfs.size())
    }

    fn free_space(&mut self) -> Option<u64> {
        let mut bitmap = self.ntfs.cluster_bitmap(&mut self.reader).ok()?;
        let free_clusters = bitmap.free_clusters(&mut self.reader).ok()?;
        Some(free_clusters * u64::from(self.ntfs.cluster_size()))
    }

    fn volume_uuid(&self) -> Option<String> {
        Some(identity::ntfs_serial(self.ntfs.serial_number()))
    }

    fn notices(&self) -> Vec<String> {
        self.notices.clone()
    }
}

/// [`FilesystemDriver`] for NTFS volumes.
pub struct NtfsDriver;

impl FilesystemDriver for NtfsDriver {
    fn name(&self) -> &'static str {
        "ntfs"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Ntfs
    }

    /// Opens the volume normally when sector 0 is a healthy boot sector, and
    /// through the format's backup boot region when it is not (see
    /// [`crate::boot_backup`]); the fallback is reported through
    /// [`TargetFilesystem::notices`].
    fn open(
        &self,
        mut reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let backup = boot_backup::find_if_primary_damaged(&mut reader, boot_backup::Family::Ntfs)
            .map_err(FsError::Io)?;
        reader
            .seek(std::io::SeekFrom::Start(0))
            .map_err(FsError::Io)?;
        match backup {
            Some(backup) => {
                let mut fs = NtfsFilesystem::new(backup.apply(reader))?;
                fs.notices.push(backup.notice());
                Ok(Box::new(fs))
            }
            None => Ok(Box::new(NtfsFilesystem::new(reader)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn driver_supports_only_ntfs() {
        crate::test_support::assert_supports_exactly(&NtfsDriver, &[DetectedBootSector::Ntfs]);
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(NtfsDriver.name(), "ntfs");
    }

    #[test]
    fn opening_a_non_ntfs_image_reports_a_parse_failure() {
        let reader = Box::new(Cursor::new(vec![0u8; 4096]));
        let Err(err) = NtfsDriver.open(reader, DetectedBootSector::Ntfs) else {
            panic!("an all-zero image must not parse as NTFS");
        };
        assert!(
            matches!(&err, FsError::Filesystem(msg) if msg.contains("NTFS")),
            "expected an NTFS parse error, got {err:?}"
        );
    }

    #[test]
    fn zero_timestamp_is_treated_as_unset() {
        assert!(ntfs_time_to_datetime(NtfsTime::from(0)).is_none());
        // 1601-01-01 + 1 s, in 100 ns intervals.
        assert!(ntfs_time_to_datetime(NtfsTime::from(10_000_000)).is_some());
    }
}
