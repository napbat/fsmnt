//! FAT12/16/32 adapter over the vendored `fs-fat` parser.
//!
//! [`FatFilesystem`] exposes a raw FAT volume through
//! [`TargetFilesystem`]; [`FatDriver`] registers it for the
//! [`DetectedBootSector::Fat12`] / [`Fat16`](DetectedBootSector::Fat16) /
//! [`Fat32`](DetectedBootSector::Fat32) variants.

use std::io::{Read, Seek};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use fs_fat::{Fat, FatAttributes, FatTime};
use fsmnt_core::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, TargetFilesystem, normalize_path,
};
use fsmnt_device::{DetectedBootSector, DeviceReader, FilesystemDriver};
use fsmnt_parser_core::io::FsReadSeek;
use fsmnt_parser_core::iter::FsTryIterator;

use crate::adapter::{found, found_and, read_up_to};

/// Timestamps and DOS attribute bits read from a directory entry.
#[derive(Debug, Default, Clone, Copy)]
struct EntryAttrs {
    created: Option<DateTime<Utc>>,
    modified: Option<DateTime<Utc>>,
    accessed: Option<DateTime<Utc>>,
    readonly: bool,
    hidden: bool,
    system: bool,
}

/// Map a [`fs_fat::FatError`] onto the closest [`FsError`] variant.
///
/// The semantic variants are preserved rather than collapsed into
/// [`FsError::Filesystem`], so callers can still distinguish "missing"
/// from "wrong kind" from "I/O failure".
fn map_fat_error(e: fs_fat::FatError, path: &str) -> FsError {
    match e {
        fs_fat::FatError::NotFound => FsError::NotFound(path.to_string()),
        fs_fat::FatError::NotADirectory => FsError::NotADirectory(path.to_string()),
        fs_fat::FatError::IsADirectory => FsError::NotAFile(path.to_string()),
        fs_fat::FatError::Io(io_err) => FsError::Io(io_err),
        other => FsError::Filesystem(format!("FAT error: {other}")),
    }
}

/// Convert a [`FatTime`] to `DateTime<Utc>`, mapping the "not recorded"
/// encoding to `None`.
///
/// A zero packed date decodes to month 0 / day 0, which is not a real
/// date; FAT writers use it for fields they do not record (most often the
/// access date, and the creation time on older implementations). Without
/// this guard the conversion silently falls back to the FAT epoch,
/// 1980-01-01, and an unset field would be reported as a real timestamp.
fn fat_time_to_datetime(ft: FatTime) -> Option<DateTime<Utc>> {
    if ft.raw_date() == 0 {
        return None;
    }
    Some(DateTime::<Utc>::from(ft))
}

/// Build the attribute/timestamp block for one directory entry.
fn attrs_of(entry: &fs_fat::FatDirEntry) -> EntryAttrs {
    let attributes = entry.attributes();
    EntryAttrs {
        created: fat_time_to_datetime(entry.creation_time()),
        modified: fat_time_to_datetime(entry.modification_time()),
        accessed: fat_time_to_datetime(entry.access_date()),
        readonly: attributes.contains(FatAttributes::READ_ONLY),
        hidden: attributes.contains(FatAttributes::HIDDEN),
        system: attributes.contains(FatAttributes::SYSTEM),
    }
}

/// A raw FAT12/16/32 volume exposed as a [`TargetFilesystem`].
pub struct FatFilesystem<T: Read + Seek> {
    reader: T,
    fat: Fat,
}

impl<T: Read + Seek> FatFilesystem<T> {
    /// Open a FAT volume from `reader` (offset 0 = start of the volume).
    ///
    /// # Errors
    ///
    /// Returns an error if the BPB cannot be parsed as FAT12, FAT16 or
    /// FAT32.
    pub fn new(mut reader: T) -> FsResult<Self> {
        let fat = Fat::new(&mut reader).map_err(|e| map_fat_error(e, "<root>"))?;
        Ok(Self { reader, fat })
    }

    /// The underlying parser handle, for callers that need FAT-specific
    /// details the [`TargetFilesystem`] interface does not expose.
    #[must_use]
    pub fn fat(&self) -> &Fat {
        &self.fat
    }

    /// Look up a path's directory entry in its parent to recover the
    /// timestamps and DOS attributes an open `FatFile` does not carry.
    ///
    /// Best-effort: the root directory has no entry of its own, and an
    /// unreadable parent yields defaults rather than an error, so
    /// `metadata` still reports size and kind.
    fn entry_attrs(&mut self, normalized_path: &str) -> EntryAttrs {
        if normalized_path.is_empty() || normalized_path == "/" {
            return EntryAttrs::default();
        }

        let path = normalized_path.trim_end_matches('/');
        let (parent, filename) = match path.rfind('/') {
            Some(idx) => (&path[..idx], &path[idx + 1..]),
            None => ("", path),
        };

        let parent_dir = match self.fat.open(
            &mut self.reader,
            if parent.is_empty() { "/" } else { parent },
        ) {
            Ok(d) if d.is_directory() => d,
            _ => return EntryAttrs::default(),
        };

        let Ok(mut entries) = parent_dir.dir_entries() else {
            return EntryAttrs::default();
        };

        // FAT lookups are case-insensitive; `Fat::open` already matched
        // this name, so an uppercase comparison finds the same entry.
        let filename_upper = filename.to_uppercase();
        while let Some(entry) = entries.try_next(&mut self.reader).unwrap_or(None) {
            if entry.name().to_uppercase() == filename_upper {
                return attrs_of(&entry);
            }
        }

        EntryAttrs::default()
    }
}

impl<T: Read + Seek + Send> TargetFilesystem for FatFilesystem<T> {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let normalized = normalize_path(path);

        let file = self
            .fat
            .open(&mut self.reader, &normalized)
            .map_err(|e| map_fat_error(e, path))?;

        if file.is_directory() {
            return Err(FsError::NotAFile(path.to_string()));
        }

        let mut data_value = file.data().map_err(|e| map_fat_error(e, path))?;

        read_up_to(u64::from(file.file_size()), |buffer| {
            data_value
                .read(&mut self.reader, buffer)
                .map_err(|e| map_fat_error(e, path))
        })
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        let normalized = normalize_path(path);
        found(
            self.fat
                .open(&mut self.reader, &normalized)
                .map_err(|e| map_fat_error(e, path)),
        )
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        let normalized = normalize_path(path);
        found_and(
            self.fat
                .open(&mut self.reader, &normalized)
                .map_err(|e| map_fat_error(e, path)),
            |file| file.is_directory(),
        )
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        let normalized = normalize_path(path);
        found_and(
            self.fat
                .open(&mut self.reader, &normalized)
                .map_err(|e| map_fat_error(e, path)),
            |file| !file.is_directory(),
        )
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        let normalized = normalize_path(path);

        let file = self
            .fat
            .open(&mut self.reader, &normalized)
            .map_err(|e| map_fat_error(e, path))?;

        let is_dir = file.is_directory();
        let size = if is_dir {
            0
        } else {
            u64::from(file.file_size())
        };

        // A FatFile carries only kind and size; the timestamps and DOS
        // attributes live in the parent directory's entry.
        let attrs = self.entry_attrs(&normalized);

        Ok(FsMetadata {
            size,
            is_dir,
            created: attrs.created,
            modified: attrs.modified,
            accessed: attrs.accessed,
            readonly: attrs.readonly,
            hidden: attrs.hidden,
            system: attrs.system,
        })
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let normalized = normalize_path(path);

        let dir = self
            .fat
            .open(&mut self.reader, &normalized)
            .map_err(|e| map_fat_error(e, path))?;

        if !dir.is_directory() {
            return Err(FsError::NotADirectory(path.to_string()));
        }

        let mut dir_entries = dir.dir_entries().map_err(|e| map_fat_error(e, path))?;
        let parent = if normalized.is_empty() || normalized == "/" {
            PathBuf::from("/")
        } else {
            PathBuf::from(&normalized)
        };

        let mut entries = Vec::new();
        while let Some(entry) = dir_entries
            .try_next(&mut self.reader)
            .map_err(|e| map_fat_error(e, path))?
        {
            let name = entry.name();

            // `.`/`..` are real on-disk entries in FAT, and the volume
            // label is filesystem metadata rather than a child.
            if name == "." || name == ".." || entry.is_volume_id() {
                continue;
            }

            let is_dir = entry.is_directory();
            let size = if is_dir {
                0
            } else {
                u64::from(entry.file_size())
            };
            let attrs = attrs_of(&entry);
            let first_cluster = entry.first_cluster();

            entries.push(FsEntry {
                path: parent.join(&name),
                name,
                flags: FsEntryFlags::empty(),
                // Cluster 0 means "no allocation yet" (an empty file), so
                // it identifies nothing.
                file_id: (first_cluster != 0).then(|| u64::from(first_cluster)),
                metadata: FsMetadata {
                    size,
                    is_dir,
                    created: attrs.created,
                    modified: attrs.modified,
                    accessed: attrs.accessed,
                    readonly: attrs.readonly,
                    hidden: attrs.hidden,
                    system: attrs.system,
                },
            });
        }

        Ok(entries)
    }

    fn total_size(&self) -> Option<u64> {
        Some(self.fat.size())
    }
}

/// [`FilesystemDriver`] for FAT12, FAT16 and FAT32 volumes.
pub struct FatDriver;

impl FilesystemDriver for FatDriver {
    fn name(&self) -> &'static str {
        "fat"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        matches!(
            detected,
            DetectedBootSector::Fat12 | DetectedBootSector::Fat16 | DetectedBootSector::Fat32
        )
    }

    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(FatFilesystem::new(reader)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn driver_supports_every_fat_width() {
        for detected in [
            DetectedBootSector::Fat12,
            DetectedBootSector::Fat16,
            DetectedBootSector::Fat32,
        ] {
            assert!(FatDriver.supports(detected), "must claim {detected:?}");
        }
    }

    #[test]
    fn driver_rejects_non_fat_types() {
        for detected in [
            DetectedBootSector::Ntfs,
            // exFAT shares FAT's name but not its on-disk layout.
            DetectedBootSector::ExFat,
            DetectedBootSector::Ext,
            DetectedBootSector::Apfs,
            DetectedBootSector::BitLocker,
            DetectedBootSector::MbrPartitioned,
            DetectedBootSector::Unknown,
        ] {
            assert!(!FatDriver.supports(detected), "must not claim {detected:?}");
        }
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(FatDriver.name(), "fat");
    }

    #[test]
    fn opening_a_non_fat_image_fails() {
        let reader = Box::new(Cursor::new(vec![0u8; 4096]));
        assert!(
            FatDriver.open(reader, DetectedBootSector::Fat32).is_err(),
            "an all-zero image must not parse as FAT"
        );
    }

    #[test]
    fn unrecorded_timestamp_is_treated_as_unset() {
        // A zero packed date is month 0 / day 0 — "not recorded".
        assert!(fat_time_to_datetime(FatTime::new(0, 0, 0)).is_none());
        assert!(fat_time_to_datetime(FatTime::from_date(0)).is_none());
    }

    #[test]
    fn fat_epoch_timestamp_is_kept() {
        // 1980-01-01 is a genuine date (packed 0x0021), unlike a zero date.
        let dt = fat_time_to_datetime(FatTime::new(0x0021, 0, 0)).expect("real date");
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "1980-01-01");
    }

    #[test]
    fn error_mapping_preserves_semantic_variants() {
        assert!(matches!(
            map_fat_error(fs_fat::FatError::NotFound, "/a"),
            FsError::NotFound(p) if p == "/a"
        ));
        assert!(matches!(
            map_fat_error(fs_fat::FatError::NotADirectory, "/a"),
            FsError::NotADirectory(_)
        ));
        assert!(matches!(
            map_fat_error(fs_fat::FatError::IsADirectory, "/a"),
            FsError::NotAFile(_)
        ));
        assert!(matches!(
            map_fat_error(fs_fat::FatError::InvalidTime, "/a"),
            FsError::Filesystem(_)
        ));
    }
}
