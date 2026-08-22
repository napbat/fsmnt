//! `exFAT` adapter over the vendored `fs-exfat` parser.
//!
//! [`ExFatFilesystem`] exposes a raw `exFAT` volume through
//! [`TargetFilesystem`]; [`ExFatDriver`] registers it for
//! [`DetectedBootSector::ExFat`].
//!
//! The up-case table and allocation bitmap are loaded at open time: the
//! former is required for `exFAT`'s case-insensitive name lookups, the
//! latter backs [`free_space`](TargetFilesystem::free_space).

use std::io::{Read, Seek};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use fs_exfat::{
    ExFat, ExFatDirItem, ExFatEntrySet, ExFatError, ExFatFileAttributes, ExFatTimestamp,
};
use fsmnt_core::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, TargetFilesystem, normalize_path,
};
use fsmnt_device::{DetectedBootSector, DeviceReader, FilesystemDriver};
use fsmnt_parser_core::io::FsReadSeek;
use tracing::debug;

use crate::adapter::{found, read_at_through, read_up_to};
use crate::boot_backup;
use crate::identity;

/// Map an [`ExFatError`] onto the closest [`FsError`] variant.
fn map_exfat_error(e: ExFatError, path: &str) -> FsError {
    match e {
        ExFatError::NotFound => FsError::NotFound(path.to_string()),
        ExFatError::NotADirectory => FsError::NotADirectory(path.to_string()),
        ExFatError::Io(io_err) => FsError::Io(io_err),
        other => FsError::Filesystem(format!("exFAT error: {other}")),
    }
}

/// Convert an [`ExFatTimestamp`] to UTC.
///
/// Returns `None` for the all-zero timestamp, whose month and day of 0 are
/// not a representable date — `exFAT`'s "not set" encoding.
fn ts_to_utc(ts: ExFatTimestamp) -> Option<DateTime<Utc>> {
    ts.to_chrono().map(|dt| dt.with_timezone(&Utc))
}

/// Build [`FsMetadata`] from an entry set.
fn metadata_of(entry: &ExFatEntrySet) -> FsMetadata {
    let attributes = entry.file_attributes();
    let is_dir = entry.is_directory();
    FsMetadata {
        // A directory's data_length covers its dirent blocks, which is not
        // a meaningful file size; report 0 as the other adapters do.
        size: if is_dir { 0 } else { entry.data_length() },
        is_dir,
        created: ts_to_utc(entry.create_timestamp()),
        modified: ts_to_utc(entry.modify_timestamp()),
        accessed: ts_to_utc(entry.access_timestamp()),
        readonly: attributes.contains(ExFatFileAttributes::READ_ONLY),
        hidden: attributes.contains(ExFatFileAttributes::HIDDEN),
        system: attributes.contains(ExFatFileAttributes::SYSTEM),
    }
}

/// A raw `exFAT` volume exposed as a [`TargetFilesystem`].
pub struct ExFatFilesystem<T: Read + Seek> {
    reader: T,
    exfat: ExFat,
    /// How the volume was opened, when that departed from the normal path.
    notices: Vec<String>,
}

impl<T: Read + Seek> ExFatFilesystem<T> {
    /// Open an `exFAT` volume from `reader` (offset 0 = start of the
    /// volume).
    ///
    /// # Errors
    ///
    /// Returns an error if the boot sector is not a valid `exFAT` VBR, or
    /// if the allocation bitmap / up-case table cannot be loaded from the
    /// root directory.
    pub fn new(mut reader: T) -> FsResult<Self> {
        let mut exfat = ExFat::new(&mut reader).map_err(|e| map_exfat_error(e, "<boot-sector>"))?;
        // Path lookups are case-insensitive through the up-case table, and
        // free_space() needs the bitmap; both are loaded together.
        exfat
            .load_metadata(&mut reader)
            .map_err(|e| map_exfat_error(e, "<metadata>"))?;
        debug!(
            cluster_size = exfat.cluster_size(),
            sector_size = exfat.bytes_per_sector(),
            cluster_count = exfat.cluster_count(),
            root_cluster = exfat.root_directory_cluster(),
            boot_checksum_valid = exfat.boot_checksum_valid(),
            "opened an exFAT volume"
        );
        Ok(Self {
            reader,
            exfat,
            notices: Vec::new(),
        })
    }

    /// The underlying parser handle, for callers that need `exFAT`-specific
    /// details the [`TargetFilesystem`] interface does not expose.
    #[must_use]
    pub fn exfat(&self) -> &ExFat {
        &self.exfat
    }

    /// Resolve a path to its entry set, or `None` for the root directory
    /// (which has no directory entry of its own).
    fn entry_at(&mut self, path: &str) -> FsResult<Option<ExFatEntrySet>> {
        let normalized = normalize_path(path);
        if normalized.is_empty() {
            return Ok(None);
        }
        self.exfat
            .open(&mut self.reader, &normalized)
            .map(Some)
            .map_err(|e| map_exfat_error(e, path))
    }

    /// The first cluster of the directory at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotADirectory`] if `path` is a file.
    fn directory_cluster(&mut self, path: &str) -> FsResult<u32> {
        match self.entry_at(path)? {
            None => Ok(self.exfat.root_directory_cluster()),
            Some(entry) if entry.is_directory() => Ok(entry.first_cluster()),
            Some(_) => Err(FsError::NotADirectory(path.to_string())),
        }
    }
}

impl<T: Read + Seek + Send> TargetFilesystem for ExFatFilesystem<T> {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let Some(entry) = self.entry_at(path)? else {
            return Err(FsError::NotAFile(path.to_string()));
        };
        if entry.is_directory() {
            return Err(FsError::NotAFile(path.to_string()));
        }

        let length = entry.data_length();
        let mut file = fs_exfat::ExFatFile::new(
            &self.exfat,
            &mut self.reader,
            entry.first_cluster(),
            length,
            entry.no_fat_chain(),
        )
        .map_err(|e| map_exfat_error(e, path))?;

        read_up_to(length, |buffer| {
            file.read(&mut self.reader, buffer)
                .map_err(|e| map_exfat_error(e, path))
        })
    }

    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> FsResult<usize> {
        let Some(entry) = self.entry_at(path)? else {
            return Err(FsError::NotAFile(path.to_string()));
        };
        if entry.is_directory() {
            return Err(FsError::NotAFile(path.to_string()));
        }
        let mut file = fs_exfat::ExFatFile::new(
            &self.exfat,
            &mut self.reader,
            entry.first_cluster(),
            entry.data_length(),
            entry.no_fat_chain(),
        )
        .map_err(|e| map_exfat_error(e, path))?;
        read_at_through(&mut file, &mut self.reader, offset, buffer, |e| {
            map_exfat_error(e, path)
        })
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        found(self.entry_at(path))
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        match self.entry_at(path) {
            // The root is always a directory.
            Ok(None) => Ok(true),
            Ok(Some(entry)) => Ok(entry.is_directory()),
            Err(FsError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        match self.entry_at(path) {
            Ok(Some(entry)) => Ok(!entry.is_directory()),
            // The root is a directory, and a missing path is not a file.
            Ok(None) | Err(FsError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        match self.entry_at(path)? {
            // The root directory carries no timestamps or attributes.
            None => Ok(FsMetadata {
                is_dir: true,
                ..FsMetadata::default()
            }),
            Some(entry) => Ok(metadata_of(&entry)),
        }
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let cluster = self.directory_cluster(path)?;
        let parent = PathBuf::from(path);

        let mut entries = Vec::new();
        let mut iter = self.exfat.dir_entries(cluster);
        while let Some(item) = iter.next(&mut self.reader) {
            // Volume labels, benign and deleted entries are filtered by the
            // iterator's default options; only file entry sets arrive here.
            let ExFatDirItem::FileEntry(entry) = item.map_err(|e| map_exfat_error(e, path))? else {
                continue;
            };
            let name = entry.name_string();
            let first_cluster = entry.first_cluster();
            entries.push(FsEntry {
                path: parent.join(&name),
                name,
                flags: FsEntryFlags::empty(),
                // Cluster 0 means "no allocation yet" (an empty file), so
                // it identifies nothing.
                file_id: (first_cluster != 0).then(|| u64::from(first_cluster)),
                metadata: metadata_of(&entry),
            });
        }
        Ok(entries)
    }

    fn total_size(&self) -> Option<u64> {
        // The boot sector's volume length is not exposed, but the cluster
        // heap is the last region on the volume, so its end is the volume
        // size to within the final partial cluster.
        Some(
            self.exfat.cluster_heap_offset()
                + u64::from(self.exfat.cluster_count()) * u64::from(self.exfat.cluster_size()),
        )
    }

    fn free_space(&mut self) -> Option<u64> {
        let bitmap = self.exfat.bitmap()?;
        Some(u64::from(bitmap.free_count()) * u64::from(self.exfat.cluster_size()))
    }

    fn volume_uuid(&self) -> Option<String> {
        Some(identity::fat_serial(self.exfat.volume_serial_number()))
    }

    fn notices(&self) -> Vec<String> {
        self.notices.clone()
    }
}

/// [`FilesystemDriver`] for `exFAT` volumes.
pub struct ExFatDriver;

impl FilesystemDriver for ExFatDriver {
    fn name(&self) -> &'static str {
        "exfat"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::ExFat
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
        let backup = boot_backup::find_if_primary_damaged(&mut reader, boot_backup::Family::ExFat)
            .map_err(FsError::Io)?;
        reader
            .seek(std::io::SeekFrom::Start(0))
            .map_err(FsError::Io)?;
        match backup {
            Some(backup) => {
                let mut fs = ExFatFilesystem::new(backup.apply(reader))?;
                fs.notices.push(backup.notice());
                Ok(Box::new(fs))
            }
            None => Ok(Box::new(ExFatFilesystem::new(reader)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn driver_supports_only_exfat() {
        crate::test_support::assert_supports_exactly(&ExFatDriver, &[DetectedBootSector::ExFat]);
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(ExFatDriver.name(), "exfat");
    }

    #[test]
    fn opening_a_non_exfat_image_fails() {
        let reader = Box::new(Cursor::new(vec![0u8; 4096]));
        assert!(
            ExFatDriver.open(reader, DetectedBootSector::ExFat).is_err(),
            "an all-zero image must not parse as exFAT"
        );
    }

    #[test]
    fn error_mapping_preserves_semantic_variants() {
        assert!(matches!(
            map_exfat_error(ExFatError::NotFound, "/a"),
            FsError::NotFound(p) if p == "/a"
        ));
        assert!(matches!(
            map_exfat_error(ExFatError::NotADirectory, "/a"),
            FsError::NotADirectory(_)
        ));
        assert!(matches!(
            map_exfat_error(ExFatError::MetadataNotLoaded, "/a"),
            FsError::Filesystem(_)
        ));
    }

    #[test]
    fn all_zero_timestamp_is_treated_as_unset() {
        // Month and day of 0 are not a representable date.
        assert!(ts_to_utc(ExFatTimestamp::new(0, 0, 0, 0)).is_none());
    }

    #[test]
    fn valid_timestamp_converts_to_utc() {
        // 2023-06-15 12:00:00, no UTC-offset validity bit.
        let dt = ts_to_utc(ExFatTimestamp::new(image::DATE, image::TIME, 0, 0))
            .expect("representable date");
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2023-06-15 12:00:00"
        );
    }

    // ------------------------------------------------------------------
    // End-to-end coverage over a synthetic image
    //
    // No exFAT adapter existed upstream to port, so the traversal and read
    // paths are exercised against a hand-built volume rather than trusted
    // by inspection. See [`image`] for the layout.
    // ------------------------------------------------------------------

    /// Builds the synthetic volume and opens it through the driver.
    fn open_image() -> Box<dyn TargetFilesystem> {
        let reader = Box::new(Cursor::new(image::build()));
        ExFatDriver
            .open(reader, DetectedBootSector::ExFat)
            .expect("synthetic exFAT volume must open")
    }

    #[test]
    fn lists_the_root_directory() {
        let mut fs = open_image();
        let entries = fs.read_dir("/").expect("read_dir");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["hello.txt", "subdir"], "names = {names:?}");
    }

    #[test]
    fn root_listing_omits_the_bitmap_and_upcase_entries() {
        let mut fs = open_image();
        let entries = fs.read_dir("/").expect("read_dir");
        assert_eq!(
            entries.len(),
            2,
            "filesystem-metadata entries must not appear as children"
        );
    }

    #[test]
    fn root_entries_carry_paths_ids_and_timestamps() {
        let mut fs = open_image();
        let entries = fs.read_dir("/").expect("read_dir");
        let hello = &entries[0];
        assert_eq!(hello.path, std::path::Path::new("/").join("hello.txt"));
        assert_eq!(hello.file_id, Some(u64::from(image::HELLO_CLUSTER)));
        assert_eq!(hello.metadata.size, image::HELLO_TEXT.len() as u64);
        assert!(!hello.metadata.is_dir);
        assert!(hello.metadata.modified.is_some(), "mtime must be populated");

        let subdir = &entries[1];
        assert!(subdir.metadata.is_dir);
        assert_eq!(
            subdir.metadata.size, 0,
            "a directory's dirent-block length is not a file size"
        );
    }

    #[test]
    fn reads_a_file_in_the_root() {
        let mut fs = open_image();
        assert_eq!(fs.read("/hello.txt").expect("read"), image::HELLO_TEXT);
    }

    #[test]
    fn reads_a_file_in_a_subdirectory() {
        let mut fs = open_image();
        assert_eq!(
            fs.read("/subdir/inner.txt").expect("read"),
            image::INNER_TEXT
        );
    }

    #[test]
    fn lists_a_subdirectory() {
        let mut fs = open_image();
        let entries = fs.read_dir("/subdir").expect("read_dir");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["inner.txt"]);
    }

    #[test]
    fn metadata_reports_size_kind_and_timestamps() {
        let mut fs = open_image();
        let meta = fs.metadata("/hello.txt").expect("metadata");
        assert!(!meta.is_dir);
        assert_eq!(meta.size, image::HELLO_TEXT.len() as u64);
        assert_eq!(
            meta.modified
                .expect("mtime")
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
            "2023-06-15 12:00:00"
        );
        assert!(!meta.readonly);
    }

    #[test]
    fn metadata_maps_dos_attribute_bits() {
        let mut fs = open_image();
        // inner.txt is written with READ_ONLY | HIDDEN | SYSTEM set.
        let meta = fs.metadata("/subdir/inner.txt").expect("metadata");
        assert!(meta.readonly);
        assert!(meta.hidden);
        assert!(meta.system);
    }

    #[test]
    fn root_metadata_reports_a_directory() {
        let mut fs = open_image();
        let meta = fs.metadata("/").expect("metadata");
        assert!(meta.is_dir);
        assert_eq!(meta.size, 0);
        assert!(meta.modified.is_none(), "the root has no directory entry");
    }

    #[test]
    fn kind_predicates_agree_with_the_layout() {
        let mut fs = open_image();
        assert!(fs.try_exists("/").expect("root exists"));
        assert!(fs.try_exists("/hello.txt").expect("file exists"));
        assert!(!fs.try_exists("/nope.txt").expect("missing path"));

        assert!(fs.try_is_dir("/").expect("root is a directory"));
        assert!(fs.try_is_dir("/subdir").expect("subdir is a directory"));
        assert!(
            !fs.try_is_dir("/hello.txt")
                .expect("file is not a directory")
        );
        assert!(!fs.try_is_dir("/nope.txt").expect("missing path"));

        assert!(fs.try_is_file("/hello.txt").expect("file is a file"));
        assert!(!fs.try_is_file("/subdir").expect("directory is not a file"));
        assert!(!fs.try_is_file("/").expect("root is not a file"));
        assert!(!fs.try_is_file("/nope.txt").expect("missing path"));
    }

    #[test]
    fn reading_a_directory_reports_not_a_file() {
        let mut fs = open_image();
        assert!(matches!(fs.read("/subdir"), Err(FsError::NotAFile(_))));
        assert!(matches!(fs.read("/"), Err(FsError::NotAFile(_))));
    }

    #[test]
    fn listing_a_file_reports_not_a_directory() {
        let mut fs = open_image();
        assert!(matches!(
            fs.read_dir("/hello.txt"),
            Err(FsError::NotADirectory(_))
        ));
    }

    #[test]
    fn missing_paths_report_not_found() {
        let mut fs = open_image();
        assert!(matches!(fs.read("/nope.txt"), Err(FsError::NotFound(_))));
        assert!(matches!(
            fs.metadata("/nope.txt"),
            Err(FsError::NotFound(_))
        ));
        assert!(matches!(fs.read_dir("/nope"), Err(FsError::NotFound(_))));
    }

    #[test]
    fn volume_sizes_come_from_the_cluster_heap_and_bitmap() {
        let mut fs = open_image();
        let cluster_bytes = image::CLUSTER_SIZE as u64;
        assert_eq!(
            fs.total_size(),
            Some(
                image::CLUSTER_HEAP_OFFSET as u64 + u64::from(image::CLUSTER_COUNT) * cluster_bytes
            )
        );
        // The bitmap marks clusters 2..=7 allocated.
        assert_eq!(
            fs.free_space(),
            Some((u64::from(image::CLUSTER_COUNT) - 6) * cluster_bytes)
        );
    }

    /// Builds a minimal but structurally valid exFAT volume in memory.
    ///
    /// Layout (512-byte sectors and 512-byte clusters, 103 sectors):
    ///
    /// | Region        | Location                                    |
    /// |---------------|---------------------------------------------|
    /// | Boot sector   | sector 0                                    |
    /// | FAT           | sector 1                                    |
    /// | Cluster heap  | sector 3 onwards (cluster 2 = first)        |
    /// | Root dir      | cluster 2                                   |
    /// | Bitmap        | cluster 3                                   |
    /// | Up-case table | cluster 4                                   |
    /// | `hello.txt`   | cluster 5                                   |
    /// | `subdir`      | cluster 6, holding `inner.txt`              |
    /// | `inner.txt`   | cluster 7                                   |
    ///
    /// The up-case table is the identity mapping, so name matching is
    /// effectively case-sensitive here; the case-insensitivity of a real
    /// volume comes from its own table and is the parser's concern.
    mod image {
        use fs_exfat::{
            DIR_ENTRY_SIZE, ENTRY_TYPE_BITMAP, ENTRY_TYPE_FILE, ENTRY_TYPE_NAME, ENTRY_TYPE_STREAM,
            ENTRY_TYPE_UPCASE, ExFatFileAttributes, compute_name_hash, compute_upcase_checksum,
        };

        pub const BYTES_PER_SECTOR: usize = 512;
        pub const CLUSTER_SIZE: usize = 512;
        pub const CLUSTER_HEAP_OFFSET: usize = 3 * BYTES_PER_SECTOR;
        pub const CLUSTER_COUNT: u32 = 100;
        const TOTAL_SECTORS: usize = 103;

        const ROOT_CLUSTER: u32 = 2;
        const BITMAP_CLUSTER: u32 = 3;
        const UPCASE_CLUSTER: u32 = 4;
        pub const HELLO_CLUSTER: u32 = 5;
        const SUBDIR_CLUSTER: u32 = 6;
        const INNER_CLUSTER: u32 = 7;
        /// Clusters 2..=7, the ones the bitmap marks as allocated.
        const ALLOCATED_CLUSTERS: u8 = 0b0011_1111;

        pub const HELLO_TEXT: &[u8] = b"Hello, exFAT!";
        pub const INNER_TEXT: &[u8] = b"inner";

        /// DOS packed date for 2023-06-15.
        pub const DATE: u16 = ((2023 - 1980) << 9) | (6 << 5) | 15;
        /// DOS packed time for 12:00:00.
        pub const TIME: u16 = 12 << 11;

        /// The identity up-case table, in the on-disk compressed form:
        /// a `0xFFFF` marker, a skip of 65535 entries, then U+FFFF
        /// mapping to itself.
        const UPCASE_DATA: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

        /// End-of-chain marker for a FAT entry.
        const FAT_EOC: u32 = 0xFFFF_FFFF;

        /// Byte offset of `cluster` within the image.
        fn cluster_offset(cluster: u32) -> usize {
            let index = usize::try_from(cluster).expect("cluster fits in usize");
            CLUSTER_HEAP_OFFSET + (index - 2) * CLUSTER_SIZE
        }

        /// The entry-set checksum: a rotate-right-with-carry accumulator
        /// over every byte of the set except the checksum field itself.
        fn set_checksum(entries: &[u8]) -> u16 {
            let mut checksum: u16 = 0;
            for (i, &byte) in entries.iter().enumerate() {
                if i == 2 || i == 3 {
                    continue;
                }
                let carry: u16 = if checksum & 1 == 0 { 0 } else { 0x8000 };
                checksum = carry
                    .wrapping_add(checksum >> 1)
                    .wrapping_add(u16::from(byte));
            }
            checksum
        }

        fn write_boot_sector(image: &mut [u8]) {
            image[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
            image[3..11].copy_from_slice(b"EXFAT   ");
            // 0x0B..0x40 must stay zero.
            let volume_length = u64::try_from(TOTAL_SECTORS).expect("sector count fits in u64");
            image[0x48..0x50].copy_from_slice(&volume_length.to_le_bytes());
            image[0x50..0x54].copy_from_slice(&1u32.to_le_bytes()); // FAT offset
            image[0x54..0x58].copy_from_slice(&1u32.to_le_bytes()); // FAT length
            image[0x58..0x5C].copy_from_slice(&3u32.to_le_bytes()); // heap offset
            image[0x5C..0x60].copy_from_slice(&CLUSTER_COUNT.to_le_bytes());
            image[0x60..0x64].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
            image[0x64..0x68].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // serial
            image[0x68..0x6A].copy_from_slice(&0x0100u16.to_le_bytes()); // revision 1.0
            image[0x6C] = 9; // bytes-per-sector shift
            image[0x6D] = 0; // sectors-per-cluster shift
            image[0x6E] = 1; // number of FATs
            image[0x6F] = 0x80; // drive select
            image[0x70] = 50; // percent in use
            image[0x1FE..0x200].copy_from_slice(&0xAA55u16.to_le_bytes());
            // The VBR checksum sectors are left zero: the parser records
            // the mismatch but still opens the volume.
        }

        fn set_fat_entry(image: &mut [u8], cluster: u32, value: u32) {
            let index = usize::try_from(cluster).expect("cluster fits in usize");
            let offset = BYTES_PER_SECTOR + index * 4;
            image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn write_bitmap_entry(image: &mut [u8], offset: usize, length: u64) {
            image[offset] = ENTRY_TYPE_BITMAP;
            image[offset + 1] = 0; // the first (and only) bitmap
            image[offset + 20..offset + 24].copy_from_slice(&BITMAP_CLUSTER.to_le_bytes());
            image[offset + 24..offset + 32].copy_from_slice(&length.to_le_bytes());
        }

        fn write_upcase_entry(image: &mut [u8], offset: usize) {
            let length = u64::try_from(UPCASE_DATA.len()).expect("table length fits in u64");
            image[offset] = ENTRY_TYPE_UPCASE;
            image[offset + 4..offset + 8]
                .copy_from_slice(&compute_upcase_checksum(UPCASE_DATA).to_le_bytes());
            image[offset + 20..offset + 24].copy_from_slice(&UPCASE_CLUSTER.to_le_bytes());
            image[offset + 24..offset + 32].copy_from_slice(&length.to_le_bytes());
        }

        /// One file or directory to place in a directory's dirent blocks.
        struct EntrySpec<'a> {
            name: &'a str,
            first_cluster: u32,
            data_length: u64,
            attributes: ExFatFileAttributes,
        }

        /// Writes a three-entry set (file + stream extension + name).
        fn write_entry_set(image: &mut [u8], offset: usize, spec: &EntrySpec<'_>) {
            let name: Vec<u16> = spec.name.encode_utf16().collect();
            assert!(name.len() <= 15, "test names fit one file-name entry");

            let mut raw = [0u8; 3 * DIR_ENTRY_SIZE];
            raw[0] = ENTRY_TYPE_FILE;
            raw[1] = 2; // two secondary entries follow
            raw[4..6].copy_from_slice(&spec.attributes.bits().to_le_bytes());
            raw[8..10].copy_from_slice(&TIME.to_le_bytes()); // create time
            raw[10..12].copy_from_slice(&DATE.to_le_bytes()); // create date
            raw[12..14].copy_from_slice(&TIME.to_le_bytes()); // modify time
            raw[14..16].copy_from_slice(&DATE.to_le_bytes()); // modify date
            raw[16..18].copy_from_slice(&TIME.to_le_bytes()); // access time
            raw[18..20].copy_from_slice(&DATE.to_le_bytes()); // access date

            raw[32] = ENTRY_TYPE_STREAM;
            raw[33] = 0x01; // AllocationPossible; the FAT chain is in use
            raw[35] = u8::try_from(name.len()).expect("name length fits in u8");
            raw[36..38].copy_from_slice(&compute_name_hash(&name).to_le_bytes());
            raw[40..48].copy_from_slice(&spec.data_length.to_le_bytes()); // valid length
            raw[52..56].copy_from_slice(&spec.first_cluster.to_le_bytes());
            raw[56..64].copy_from_slice(&spec.data_length.to_le_bytes());

            raw[64] = ENTRY_TYPE_NAME;
            for (i, &unit) in name.iter().enumerate() {
                raw[66 + i * 2..68 + i * 2].copy_from_slice(&unit.to_le_bytes());
            }

            let checksum = set_checksum(&raw);
            raw[2..4].copy_from_slice(&checksum.to_le_bytes());
            image[offset..offset + raw.len()].copy_from_slice(&raw);
        }

        /// Builds the image described in the module docs.
        pub fn build() -> Vec<u8> {
            let mut image = vec![0u8; TOTAL_SECTORS * BYTES_PER_SECTOR];
            write_boot_sector(&mut image);

            // Every allocated cluster is a one-cluster chain.
            for cluster in 0..=INNER_CLUSTER {
                set_fat_entry(&mut image, cluster, FAT_EOC);
            }

            let root = cluster_offset(ROOT_CLUSTER);
            let bitmap_length = u64::from(CLUSTER_COUNT).div_ceil(8);
            write_bitmap_entry(&mut image, root, bitmap_length);
            write_upcase_entry(&mut image, root + DIR_ENTRY_SIZE);
            write_entry_set(
                &mut image,
                root + 2 * DIR_ENTRY_SIZE,
                &EntrySpec {
                    name: "hello.txt",
                    first_cluster: HELLO_CLUSTER,
                    data_length: HELLO_TEXT.len() as u64,
                    attributes: ExFatFileAttributes::ARCHIVE,
                },
            );
            write_entry_set(
                &mut image,
                root + 5 * DIR_ENTRY_SIZE,
                &EntrySpec {
                    name: "subdir",
                    first_cluster: SUBDIR_CLUSTER,
                    data_length: CLUSTER_SIZE as u64,
                    attributes: ExFatFileAttributes::DIRECTORY,
                },
            );

            write_entry_set(
                &mut image,
                cluster_offset(SUBDIR_CLUSTER),
                &EntrySpec {
                    name: "inner.txt",
                    first_cluster: INNER_CLUSTER,
                    data_length: INNER_TEXT.len() as u64,
                    attributes: ExFatFileAttributes::ARCHIVE
                        | ExFatFileAttributes::READ_ONLY
                        | ExFatFileAttributes::HIDDEN
                        | ExFatFileAttributes::SYSTEM,
                },
            );

            image[cluster_offset(BITMAP_CLUSTER)] = ALLOCATED_CLUSTERS;

            let upcase = cluster_offset(UPCASE_CLUSTER);
            image[upcase..upcase + UPCASE_DATA.len()].copy_from_slice(UPCASE_DATA);

            let hello = cluster_offset(HELLO_CLUSTER);
            image[hello..hello + HELLO_TEXT.len()].copy_from_slice(HELLO_TEXT);

            let inner = cluster_offset(INNER_CLUSTER);
            image[inner..inner + INNER_TEXT.len()].copy_from_slice(INNER_TEXT);

            image
        }
    }
}
