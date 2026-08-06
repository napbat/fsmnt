use crate::bitmap::ExFatBitmap;
use crate::boot_sector::{VolumeFlags, read_and_validate_boot_sector, verify_boot_checksum};
use crate::dir_entry::{
    BitmapDirectoryEntry, DIR_ENTRY_SIZE, ENTRY_TYPE_BITMAP, ENTRY_TYPE_END, ENTRY_TYPE_UPCASE,
    UpcaseTableDirectoryEntry,
};
use crate::dir_iter::ExFatDirEntries;
use crate::error::{ExFatError, Result};
use crate::fat::ExFatClusterIterator;
use crate::io::{Read, Seek};
use crate::upcase::ExFatUpcaseTable;
use zerocopy::FromBytes;

use fs_common::boot_sector::ExFatBootSector;

/// Root structure describing an exFAT filesystem.
///
/// Created via [`ExFat::new`] by reading and validating the boot
/// sector of an exFAT volume. Provides typed accessors for every
/// boot sector field and a [`cluster_offset`](ExFat::cluster_offset)
/// helper to translate cluster indices to byte offsets.
#[derive(Debug)]
pub struct ExFat {
    bytes_per_sector: u32,
    cluster_size: u32,
    cluster_heap_byte_offset: u64,
    cluster_count: u32,
    fat_byte_offset: u64,
    fat_length_bytes: u64,
    root_directory_cluster: u32,
    volume_serial_number: u32,
    filesystem_revision: u16,
    volume_flags: VolumeFlags,
    percent_in_use: u8,
    number_of_fats: u8,
    drive_select: u8,
    boot_checksum_valid: bool,
    bitmap: Option<ExFatBitmap>,
    upcase_table: Option<ExFatUpcaseTable>,
}

/// Extracts precomputed values from a validated boot sector.
fn precompute(bs: &ExFatBootSector) -> PrecomputedFields {
    let bps = 1u32 << bs.bytes_per_sector_shift;
    let cluster_size = 1u32 << (bs.bytes_per_sector_shift + bs.sectors_per_cluster_shift);
    let cluster_heap_byte_offset = bs.cluster_heap_offset.get() as u64 * bps as u64;
    let fat_byte_offset = bs.fat_offset.get() as u64 * bps as u64;
    let fat_length_bytes = bs.fat_length.get() as u64 * bps as u64;

    PrecomputedFields {
        bytes_per_sector: bps,
        cluster_size,
        cluster_heap_byte_offset,
        cluster_count: bs.cluster_count.get(),
        fat_byte_offset,
        fat_length_bytes,
        root_directory_cluster: bs.root_directory_cluster.get(),
        volume_serial_number: bs.volume_serial_number.get(),
        filesystem_revision: bs.filesystem_revision.get(),
        volume_flags: VolumeFlags::from_bits_truncate(bs.volume_flags.get()),
        percent_in_use: bs.percent_in_use,
        number_of_fats: bs.number_of_fats,
        drive_select: bs.drive_select,
    }
}

/// Intermediate bag of values extracted from a boot sector.
struct PrecomputedFields {
    bytes_per_sector: u32,
    cluster_size: u32,
    cluster_heap_byte_offset: u64,
    cluster_count: u32,
    fat_byte_offset: u64,
    fat_length_bytes: u64,
    root_directory_cluster: u32,
    volume_serial_number: u32,
    filesystem_revision: u16,
    volume_flags: VolumeFlags,
    percent_in_use: u8,
    number_of_fats: u8,
    drive_select: u8,
}

impl ExFat {
    /// Creates a new [`ExFat`] object from a reader and validates
    /// its boot sector information.
    ///
    /// The reader must cover the entire exFAT partition. It will be
    /// rewound to the beginning before reading anything.
    ///
    /// If the primary boot sector is invalid the backup boot sector
    /// at sector 12 is attempted. If both fail, the primary error is
    /// returned.
    pub fn new<T>(fs: &mut T) -> Result<Self>
    where
        T: Read + Seek,
    {
        let (bs, used_backup) = read_and_validate_boot_sector(fs)?;
        let pf = precompute(&bs);

        // Verify VBR checksum (best-effort; I/O failure sets false).
        let checksum_base = if used_backup {
            12u64 * pf.bytes_per_sector as u64
        } else {
            0
        };
        let checksum_valid =
            verify_boot_checksum(fs, pf.bytes_per_sector, checksum_base).unwrap_or(false);

        Ok(Self {
            bytes_per_sector: pf.bytes_per_sector,
            cluster_size: pf.cluster_size,
            cluster_heap_byte_offset: pf.cluster_heap_byte_offset,
            cluster_count: pf.cluster_count,
            fat_byte_offset: pf.fat_byte_offset,
            fat_length_bytes: pf.fat_length_bytes,
            root_directory_cluster: pf.root_directory_cluster,
            volume_serial_number: pf.volume_serial_number,
            filesystem_revision: pf.filesystem_revision,
            volume_flags: pf.volume_flags,
            percent_in_use: pf.percent_in_use,
            number_of_fats: pf.number_of_fats,
            drive_select: pf.drive_select,
            boot_checksum_valid: checksum_valid,
            bitmap: None,
            upcase_table: None,
        })
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    /// Returns the sector size in bytes (always a power of two,
    /// 512 to 4096).
    pub fn bytes_per_sector(&self) -> u32 {
        self.bytes_per_sector
    }

    /// Returns the cluster size in bytes.
    pub fn cluster_size(&self) -> u32 {
        self.cluster_size
    }

    /// Returns the total number of clusters in the cluster heap.
    pub fn cluster_count(&self) -> u32 {
        self.cluster_count
    }

    /// Returns the byte offset of the cluster heap from the start
    /// of the volume.
    pub fn cluster_heap_offset(&self) -> u64 {
        self.cluster_heap_byte_offset
    }

    /// Returns the byte offset of the FAT from the start of the
    /// volume.
    pub fn fat_offset(&self) -> u64 {
        self.fat_byte_offset
    }

    /// Returns the total length of the FAT in bytes.
    pub fn fat_length_bytes(&self) -> u64 {
        self.fat_length_bytes
    }

    /// Returns the cluster number of the root directory.
    pub fn root_directory_cluster(&self) -> u32 {
        self.root_directory_cluster
    }

    /// Returns the 32-bit volume serial number.
    pub fn volume_serial_number(&self) -> u32 {
        self.volume_serial_number
    }

    /// Returns the filesystem revision as a raw u16 (major.minor).
    pub fn filesystem_revision(&self) -> u16 {
        self.filesystem_revision
    }

    /// Returns the major component of the filesystem revision.
    pub fn filesystem_revision_major(&self) -> u8 {
        (self.filesystem_revision >> 8) as u8
    }

    /// Returns the minor component of the filesystem revision.
    pub fn filesystem_revision_minor(&self) -> u8 {
        (self.filesystem_revision & 0xFF) as u8
    }

    /// Returns the parsed volume flags.
    pub fn volume_flags(&self) -> VolumeFlags {
        self.volume_flags
    }

    /// Returns the percentage of clusters in use (0-100, or 0xFF
    /// if unknown).
    pub fn percent_in_use(&self) -> u8 {
        self.percent_in_use
    }

    /// Returns the number of FATs (1 or 2).
    pub fn number_of_fats(&self) -> u8 {
        self.number_of_fats
    }

    /// Returns the BIOS drive select value (typically 0x80).
    ///
    /// Per spec, implementations shall not validate this field.
    pub fn drive_select(&self) -> u8 {
        self.drive_select
    }

    /// Returns whether the VBR boot region checksum was valid when
    /// the volume was opened.
    pub fn boot_checksum_valid(&self) -> bool {
        self.boot_checksum_valid
    }

    // ---------------------------------------------------------------
    // Directory iteration
    // ---------------------------------------------------------------

    /// Creates a directory entry iterator for the directory starting
    /// at the given cluster.
    pub fn dir_entries(&self, start_cluster: u32) -> ExFatDirEntries<'_> {
        ExFatDirEntries::new(self, start_cluster)
    }

    /// Creates a directory entry iterator for the root directory.
    pub fn root_dir_entries(&self) -> ExFatDirEntries<'_> {
        self.dir_entries(self.root_directory_cluster())
    }

    // ---------------------------------------------------------------
    // Cluster helpers
    // ---------------------------------------------------------------

    /// Returns the byte offset on the volume for the given cluster
    /// number.
    ///
    /// Cluster indices start at 2. Valid clusters are 2 through
    /// `cluster_count + 1`.
    ///
    /// # Errors
    ///
    /// Returns [`ExFatError::InvalidCluster`] if `cluster` is
    /// outside the valid range.
    pub fn cluster_offset(&self, cluster: u32) -> Result<u64> {
        if cluster < 2 {
            return Err(ExFatError::InvalidCluster { cluster });
        }
        if cluster > self.cluster_count.saturating_add(1) {
            return Err(ExFatError::InvalidCluster { cluster });
        }
        let offset =
            self.cluster_heap_byte_offset + (cluster - 2) as u64 * self.cluster_size as u64;
        Ok(offset)
    }

    // ---------------------------------------------------------------
    // Metadata loading
    // ---------------------------------------------------------------

    /// Scans the root directory to locate and load the allocation
    /// bitmap and up-case table.
    ///
    /// This reads raw 32-byte entries (bypassing the `ExFatDirEntries`
    /// iterator) to find the 0x81 (bitmap) and 0x82 (up-case table)
    /// entries, then reads and processes their data.
    ///
    /// Must be called before `open()` or any case-insensitive
    /// operations.
    pub fn load_metadata<T>(&mut self, fs: &mut T) -> Result<()>
    where
        T: Read + Seek,
    {
        let mut bitmap_entry: Option<BitmapDirectoryEntry> = None;
        let mut upcase_entry: Option<UpcaseTableDirectoryEntry> = None;

        // Scan root directory cluster by cluster
        let mut done = false;
        let mut cluster_iter = ExFatClusterIterator::new(self, self.root_directory_cluster);
        while !done {
            let cluster = match cluster_iter.next(fs) {
                Some(Ok(c)) => c,
                Some(Err(e)) => return Err(e),
                None => break,
            };
            let offset = self.cluster_offset(cluster)?;
            let entries_per_cluster = self.cluster_size as usize / DIR_ENTRY_SIZE;

            for entry_idx in 0..entries_per_cluster {
                let entry_offset = offset + (entry_idx * DIR_ENTRY_SIZE) as u64;
                fs.seek(crate::io::SeekFrom::Start(entry_offset))?;

                let mut buf = [0u8; DIR_ENTRY_SIZE];
                fs.read_exact(&mut buf)?;

                let entry_type = buf[0];

                if entry_type == ENTRY_TYPE_END {
                    done = true;
                    break;
                }

                if entry_type == ENTRY_TYPE_BITMAP {
                    let parsed = BitmapDirectoryEntry::read_from_bytes(&buf).map_err(|_| {
                        ExFatError::InvalidEntrySet {
                            reason: "failed to parse BitmapDirectoryEntry",
                            byte_offset: entry_offset,
                        }
                    })?;
                    if parsed.bitmap_flags & 0x01 == 0 {
                        bitmap_entry = Some(parsed);
                    }
                } else if entry_type == ENTRY_TYPE_UPCASE {
                    let parsed =
                        UpcaseTableDirectoryEntry::read_from_bytes(&buf).map_err(|_| {
                            ExFatError::InvalidEntrySet {
                                reason: "failed to parse UpcaseTableDirectoryEntry",
                                byte_offset: entry_offset,
                            }
                        })?;
                    upcase_entry = Some(parsed);
                }
            }
        }

        // Validate both entries were found
        let bm = bitmap_entry.ok_or(ExFatError::BitmapNotFound)?;
        let uc = upcase_entry.ok_or(ExFatError::UpcaseTableNotFound)?;

        // Load bitmap data
        let bitmap_data =
            self.read_data_from_cluster(fs, bm.first_cluster.get(), bm.data_length.get())?;
        self.bitmap = Some(ExFatBitmap::new(bitmap_data, self.cluster_count));

        // Load and validate upcase table
        let upcase_data =
            self.read_data_from_cluster(fs, uc.first_cluster.get(), uc.data_length.get())?;
        let upcase_table = ExFatUpcaseTable::load(&upcase_data, uc.table_checksum.get())?;
        self.upcase_table = Some(upcase_table);

        Ok(())
    }

    /// Reads data from a cluster chain into a byte vector.
    ///
    /// Follows the FAT chain starting at `first_cluster`, reading
    /// up to `length` bytes total.
    fn read_data_from_cluster<T>(
        &self,
        fs: &mut T,
        first_cluster: u32,
        length: u64,
    ) -> Result<alloc::vec::Vec<u8>>
    where
        T: Read + Seek,
    {
        let len = usize::try_from(length).map_err(|_| ExFatError::InvalidEntrySet {
            reason: "data length exceeds addressable memory",
            byte_offset: 0,
        })?;
        let mut data = alloc::vec![0u8; len];
        let mut bytes_read = 0usize;
        let mut cluster_iter = ExFatClusterIterator::new(self, first_cluster);

        while bytes_read < len {
            let cluster = match cluster_iter.next(fs) {
                Some(Ok(c)) => c,
                Some(Err(e)) => return Err(e),
                None => break,
            };

            let offset = self.cluster_offset(cluster)?;
            fs.seek(crate::io::SeekFrom::Start(offset))?;

            let remaining = len - bytes_read;
            let to_read = remaining.min(self.cluster_size as usize);
            fs.read_exact(&mut data[bytes_read..bytes_read + to_read])?;
            bytes_read += to_read;
        }

        Ok(data)
    }

    /// Returns a reference to the loaded allocation bitmap, if any.
    pub fn bitmap(&self) -> Option<&ExFatBitmap> {
        self.bitmap.as_ref()
    }

    /// Returns a reference to the loaded up-case table, if any.
    pub fn upcase_table(&self) -> Option<&ExFatUpcaseTable> {
        self.upcase_table.as_ref()
    }

    // ---------------------------------------------------------------
    // Path-based navigation
    // ---------------------------------------------------------------

    /// Opens a file or directory by path, returning its entry set.
    ///
    /// Splits the path on `/` and `\`, resolves each component by
    /// scanning the current directory with case-insensitive matching
    /// via the up-case table.
    ///
    /// # Errors
    ///
    /// - [`ExFatError::MetadataNotLoaded`] if `load_metadata` has
    ///   not been called.
    /// - [`ExFatError::NotFound`] if a path component does not exist
    ///   or the path is empty.
    /// - [`ExFatError::NotADirectory`] if an intermediate component
    ///   is not a directory.
    pub fn open<T>(&self, fs: &mut T, path: &str) -> Result<crate::entry_set::ExFatEntrySet>
    where
        T: Read + Seek,
    {
        let upcase = self
            .upcase_table
            .as_ref()
            .ok_or(ExFatError::MetadataNotLoaded)?;

        let mut components = path
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
            .peekable();

        if components.peek().is_none() {
            return Err(ExFatError::NotFound);
        }

        let mut current_cluster = self.root_directory_cluster;

        while let Some(component) = components.next() {
            let is_last = components.peek().is_none();

            let entry_set = self.find_in_directory(fs, current_cluster, component, upcase)?;

            if is_last {
                return Ok(entry_set);
            }

            if !entry_set.is_directory() {
                return Err(ExFatError::NotADirectory);
            }
            current_cluster = entry_set.first_cluster();
        }

        unreachable!()
    }

    /// Scans a directory for an entry matching `name`
    /// (case-insensitive).
    ///
    /// Uses NameHash for fast pre-filtering before full name
    /// comparison.
    fn find_in_directory<T>(
        &self,
        fs: &mut T,
        dir_cluster: u32,
        name: &str,
        upcase: &ExFatUpcaseTable,
    ) -> Result<crate::entry_set::ExFatEntrySet>
    where
        T: Read + Seek,
    {
        let search_utf16: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        let search_hash = upcase.name_hash_for_name(&search_utf16);

        let mut iter = self.dir_entries(dir_cluster);
        while let Some(result) = iter.next(fs) {
            match result {
                Ok(crate::entry_set::ExFatDirItem::FileEntry(entry_set)) => {
                    if entry_set.name_hash() != search_hash {
                        continue;
                    }
                    if upcase.name_equals_str(entry_set.name(), name) {
                        return Ok(entry_set);
                    }
                }
                Ok(_) => continue,
                Err(e) => return Err(e),
            }
        }

        Err(ExFatError::NotFound)
    }

    /// Opens a file by path and returns an [`ExFatFile`] handle for
    /// reading its data.
    ///
    /// Combines [`open`](ExFat::open) (path resolution) with
    /// [`ExFatFile::new`] (data stream setup). The returned handle
    /// supports seeking and reading via [`FsReadSeek`](fs_common::FsReadSeek).
    pub fn open_file<T>(&self, fs: &mut T, path: &str) -> Result<crate::file::ExFatFile<'_>>
    where
        T: Read + Seek,
    {
        let entry_set = self.open(fs, path)?;
        crate::file::ExFatFile::new(
            self,
            fs,
            entry_set.first_cluster(),
            entry_set.data_length(),
            entry_set.no_fat_chain(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;
    use alloc::vec;
    use std::io::Cursor;

    #[test]
    fn drive_select_accessor() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        assert_eq!(exfat.drive_select(), 0x80);
    }

    #[test]
    fn new_succeeds_on_valid_image() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        assert_eq!(exfat.bytes_per_sector(), 512);
        assert_eq!(exfat.cluster_size(), 512);
        assert_eq!(exfat.cluster_count(), 100);
        assert_eq!(exfat.number_of_fats(), 1);
    }

    #[test]
    fn accessors_return_expected_values() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        assert_eq!(exfat.bytes_per_sector(), 512);
        assert_eq!(exfat.cluster_size(), 512);
        assert_eq!(exfat.cluster_count(), 100);
        assert_eq!(exfat.fat_offset(), 512); // sector 1 * 512
        assert_eq!(exfat.fat_length_bytes(), 512); // 1 sector * 512
        assert_eq!(exfat.cluster_heap_offset(), 3 * 512);
        assert_eq!(exfat.root_directory_cluster(), 2);
        assert_eq!(exfat.volume_serial_number(), 0xDEAD_BEEF);
        assert_eq!(exfat.filesystem_revision(), 0x0100);
        assert_eq!(exfat.filesystem_revision_major(), 1);
        assert_eq!(exfat.filesystem_revision_minor(), 0);
        assert_eq!(exfat.volume_flags(), VolumeFlags::empty());
        assert_eq!(exfat.percent_in_use(), 50);
        assert_eq!(exfat.number_of_fats(), 1);
    }

    #[test]
    fn boot_checksum_valid_on_correct_image() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        assert!(exfat.boot_checksum_valid());
    }

    #[test]
    fn boot_checksum_invalid_on_corrupted_image() {
        let mut image = make_image();
        // Corrupt sector 5 data (well within sectors 0-10)
        image[5 * 512] = 0xFF;
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        assert!(!exfat.boot_checksum_valid());
    }

    #[test]
    fn new_rejects_all_zeros() {
        let image = vec![0u8; 512 * 20];
        let mut cursor = Cursor::new(image);
        assert!(ExFat::new(&mut cursor).is_err());
    }

    #[test]
    fn backup_boot_sector_fallback() {
        let mut image = make_image();

        // Corrupt primary boot sector filesystem name.
        image[3] = b'X';

        // Write a valid boot sector at backup offset (sector 12).
        let backup_offset = 12 * 512;
        // Ensure the image is large enough.
        if image.len() < backup_offset + 512 {
            image.resize(backup_offset + 512 + 512 * 100, 0);
        }
        let valid_image = make_image();
        image[backup_offset..backup_offset + 512].copy_from_slice(&valid_image[..512]);

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        assert_eq!(exfat.cluster_count(), 100);
    }

    #[test]
    fn primary_error_returned_when_both_fail() {
        let mut image = vec![0u8; 512 * 20];
        // Give it a valid-ish filesystem name but bad signature.
        image[3..11].copy_from_slice(b"EXFAT   ");
        // boot_signature at 0x1FE is 0 -> invalid

        let mut cursor = Cursor::new(image);
        let err = ExFat::new(&mut cursor).unwrap_err();
        // Should be the primary error (InvalidBootSignature).
        assert!(
            matches!(err, ExFatError::InvalidBootSignature { .. }),
            "Expected InvalidBootSignature, got: {err:?}"
        );
    }

    #[test]
    fn cluster_offset_first_cluster() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        // cluster 2 should be at cluster_heap_byte_offset
        let offset = exfat.cluster_offset(2).unwrap();
        assert_eq!(offset, exfat.cluster_heap_offset());
    }

    #[test]
    fn cluster_offset_last_valid() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        // Last valid cluster = cluster_count + 1 = 101
        let offset = exfat.cluster_offset(101).unwrap();
        let expected = exfat.cluster_heap_offset() + (101 - 2) as u64 * exfat.cluster_size() as u64;
        assert_eq!(offset, expected);
    }

    #[test]
    fn cluster_offset_rejects_zero() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        let err = exfat.cluster_offset(0).unwrap_err();
        assert!(matches!(err, ExFatError::InvalidCluster { cluster: 0 }));
    }

    #[test]
    fn cluster_offset_rejects_one() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        let err = exfat.cluster_offset(1).unwrap_err();
        assert!(matches!(err, ExFatError::InvalidCluster { cluster: 1 }));
    }

    #[test]
    fn cluster_offset_rejects_out_of_range() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        // cluster_count + 2 = 102 is invalid
        let err = exfat.cluster_offset(102).unwrap_err();
        assert!(matches!(err, ExFatError::InvalidCluster { cluster: 102 }));
    }

    #[test]
    fn volume_flags_dirty() {
        let mut image = make_image();
        // Set VolumeDirty flag (bit 1) at offset 0x6A
        image[0x6A] = 0x02;

        // Recompute checksum since we changed the image.
        // Note: bytes 106 (0x6A) and 107 (0x6B) are skipped in the
        // checksum, so the old checksum in sector 11 is still valid.
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        assert!(exfat.volume_flags().contains(VolumeFlags::VOLUME_DIRTY));
    }

    #[test]
    fn load_metadata_bitmap_and_upcase() {
        let mut image = make_image();

        // Set up FAT: cluster 2 (root dir) -> EOC,
        // cluster 3 (bitmap data) -> EOC,
        // cluster 4 (upcase data) -> EOC
        let fat_base = 512; // sector 1
        // Cluster 2 = EOC
        image[fat_base + 2 * 4..fat_base + 2 * 4 + 4]
            .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // Cluster 3 = EOC
        image[fat_base + 3 * 4..fat_base + 3 * 4 + 4]
            .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // Cluster 4 = EOC
        image[fat_base + 4 * 4..fat_base + 4 * 4 + 4]
            .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let cluster_heap = 3 * 512; // sector 3
        let root_dir_off = cluster_heap; // cluster 2

        // Write bitmap entry (0x81) at slot 0 of root dir
        image[root_dir_off] = 0x81;
        image[root_dir_off + 1] = 0x00; // first bitmap
        // first_cluster = 3 at offset 20
        image[root_dir_off + 20..root_dir_off + 24].copy_from_slice(&3u32.to_le_bytes());
        // data_length = 13 bytes
        image[root_dir_off + 24..root_dir_off + 32].copy_from_slice(&13u64.to_le_bytes());

        // Write bitmap data in cluster 3
        let bitmap_cluster_off = cluster_heap + 512; // cluster 3
        image[bitmap_cluster_off] = 0xFF;
        image[bitmap_cluster_off + 1] = 0x03;

        // Build compressed identity upcase table
        let mut upcase_compressed: Vec<u8> = Vec::new();
        // Skip 0x8000 entries, then skip 0x8000 more (total 65536)
        upcase_compressed.extend_from_slice(&0xFFFFu16.to_le_bytes());
        upcase_compressed.extend_from_slice(&0x8000u16.to_le_bytes());
        upcase_compressed.extend_from_slice(&0xFFFFu16.to_le_bytes());
        upcase_compressed.extend_from_slice(&0x8000u16.to_le_bytes());

        let upcase_checksum = {
            let mut cs: u32 = 0;
            for &byte in &upcase_compressed {
                let bit0 = if cs & 1 != 0 { 0x8000_0000u32 } else { 0 };
                cs = bit0.wrapping_add(cs >> 1).wrapping_add(byte as u32);
            }
            cs
        };

        // Write upcase entry (0x82) at slot 1 of root dir
        let upcase_entry_off = root_dir_off + 32;
        image[upcase_entry_off] = 0x82;
        // table_checksum at offset 4
        image[upcase_entry_off + 4..upcase_entry_off + 8]
            .copy_from_slice(&upcase_checksum.to_le_bytes());
        // first_cluster = 4 at offset 20
        image[upcase_entry_off + 20..upcase_entry_off + 24].copy_from_slice(&4u32.to_le_bytes());
        // data_length
        image[upcase_entry_off + 24..upcase_entry_off + 32]
            .copy_from_slice(&(upcase_compressed.len() as u64).to_le_bytes());

        // Write upcase data in cluster 4
        let upcase_cluster_off = cluster_heap + 2 * 512;
        image[upcase_cluster_off..upcase_cluster_off + upcase_compressed.len()]
            .copy_from_slice(&upcase_compressed);

        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();

        // Before load_metadata, bitmap and upcase should be None
        assert!(exfat.bitmap().is_none());
        assert!(exfat.upcase_table().is_none());

        exfat.load_metadata(&mut cursor).unwrap();

        // Bitmap should be loaded
        let bitmap = exfat.bitmap().unwrap();
        assert!(bitmap.is_allocated(2).unwrap()); // byte 0 bit 0
        assert!(!bitmap.is_allocated(12).unwrap()); // byte 1 bit 2

        // Upcase table should be loaded (all identity)
        let upcase = exfat.upcase_table().unwrap();
        assert_eq!(upcase.upcase(0x0041), 0x0041); // 'A' -> 'A'
        assert_eq!(upcase.upcase(0x0061), 0x0061); // identity table
    }

    #[test]
    fn load_metadata_missing_bitmap_returns_error() {
        let mut image = make_image();
        let fat_base = 512;
        image[fat_base + 2 * 4..fat_base + 2 * 4 + 4]
            .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        // Root dir is empty (all zeros = end-of-directory)
        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();

        let err = exfat.load_metadata(&mut cursor).unwrap_err();
        assert!(matches!(err, ExFatError::BitmapNotFound));
    }

    /// Sets up FAT entries, bitmap entry+data, and upcase entry+data
    /// in an image. Returns the next free root dir slot offset.
    fn setup_metadata(image: &mut [u8]) -> usize {
        use crate::dir_entry::*;

        let fat_base = 512;
        let cluster_heap = 3 * 512;
        let root_off = cluster_heap;

        // FAT: cluster 2-4 -> EOC
        for c in 2..=4u32 {
            let off = fat_base + c as usize * 4;
            image[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        }

        // Bitmap entry (0x81) at slot 0
        image[root_off] = ENTRY_TYPE_BITMAP;
        image[root_off + 20..root_off + 24].copy_from_slice(&3u32.to_le_bytes());
        image[root_off + 24..root_off + 32].copy_from_slice(&13u64.to_le_bytes());

        // Bitmap data in cluster 3
        image[cluster_heap + 512] = 0xFF;

        // Compressed identity upcase table (two 0x8000 skips = 65536 total)
        let mut upcase_data = Vec::new();
        upcase_data.extend_from_slice(&0xFFFFu16.to_le_bytes());
        upcase_data.extend_from_slice(&0x8000u16.to_le_bytes());
        upcase_data.extend_from_slice(&0xFFFFu16.to_le_bytes());
        upcase_data.extend_from_slice(&0x8000u16.to_le_bytes());
        let upcase_cs = {
            let mut cs: u32 = 0;
            for &b in &upcase_data {
                let bit0 = if cs & 1 != 0 { 0x8000_0000u32 } else { 0 };
                cs = bit0.wrapping_add(cs >> 1).wrapping_add(b as u32);
            }
            cs
        };

        // Upcase entry (0x82) at slot 1
        let slot1 = root_off + DIR_ENTRY_SIZE;
        image[slot1] = ENTRY_TYPE_UPCASE;
        image[slot1 + 4..slot1 + 8].copy_from_slice(&upcase_cs.to_le_bytes());
        image[slot1 + 20..slot1 + 24].copy_from_slice(&4u32.to_le_bytes());
        image[slot1 + 24..slot1 + 32].copy_from_slice(&(upcase_data.len() as u64).to_le_bytes());

        // Upcase data in cluster 4
        let uc_off = cluster_heap + 2 * 512;
        image[uc_off..uc_off + upcase_data.len()].copy_from_slice(&upcase_data);

        // Return offset of slot 2 (first free root dir entry)
        root_off + 2 * DIR_ENTRY_SIZE
    }

    /// Writes a file entry set (0x85 + 0xC0 + 0xC1) at the given
    /// offset in the image. Uses the identity upcase table for
    /// NameHash (name must already be uppercase or not use a-z).
    fn write_file_entry(
        image: &mut [u8],
        offset: usize,
        name: &str,
        first_cluster: u32,
        data_length: u64,
        is_directory: bool,
    ) {
        use crate::dir_entry::*;
        use crate::entry_set::compute_set_checksum;
        use crate::upcase::compute_name_hash;

        let utf16: Vec<u16> = name.encode_utf16().collect();
        // Identity upcase table => name_hash of already-uppercase name
        let name_hash = compute_name_hash(&utf16);

        let mut entry_bytes = vec![0u8; 3 * DIR_ENTRY_SIZE];
        // Primary (0x85)
        entry_bytes[0] = ENTRY_TYPE_FILE;
        entry_bytes[1] = 2; // secondary_count
        if is_directory {
            entry_bytes[4] = 0x10; // DIRECTORY attribute
        } else {
            entry_bytes[4] = 0x20; // ARCHIVE attribute
        }
        // Stream (0xC0)
        entry_bytes[32] = ENTRY_TYPE_STREAM;
        entry_bytes[33] = 0x01;
        entry_bytes[35] = utf16.len() as u8;
        entry_bytes[36..38].copy_from_slice(&name_hash.to_le_bytes());
        entry_bytes[52..56].copy_from_slice(&first_cluster.to_le_bytes());
        entry_bytes[56..64].copy_from_slice(&data_length.to_le_bytes());
        entry_bytes[40..48].copy_from_slice(&data_length.to_le_bytes());
        // Name (0xC1)
        entry_bytes[64] = ENTRY_TYPE_NAME;
        for (i, &ch) in utf16.iter().enumerate() {
            let [lo, hi] = ch.to_le_bytes();
            entry_bytes[66 + i * 2] = lo;
            entry_bytes[66 + i * 2 + 1] = hi;
        }
        // Checksum
        let cs = compute_set_checksum(&entry_bytes);
        entry_bytes[2..4].copy_from_slice(&cs.to_le_bytes());

        image[offset..offset + entry_bytes.len()].copy_from_slice(&entry_bytes);
    }

    #[test]
    fn open_file_in_root_directory() {
        let mut image = make_image();
        let slot2 = setup_metadata(&mut image);

        write_file_entry(&mut image, slot2, "README.TXT", 10, 100, false);

        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();
        exfat.load_metadata(&mut cursor).unwrap();

        let es = exfat.open(&mut cursor, "README.TXT").unwrap();
        assert_eq!(es.name_string(), "README.TXT");
        assert_eq!(es.first_cluster(), 10);
    }

    #[test]
    fn open_not_found() {
        let mut image = make_image();
        setup_metadata(&mut image);

        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();
        exfat.load_metadata(&mut cursor).unwrap();

        assert!(matches!(
            exfat.open(&mut cursor, "nonexistent.txt"),
            Err(ExFatError::NotFound)
        ));
    }

    #[test]
    fn open_empty_path_not_found() {
        let mut image = make_image();
        setup_metadata(&mut image);

        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();
        exfat.load_metadata(&mut cursor).unwrap();

        assert!(matches!(
            exfat.open(&mut cursor, ""),
            Err(ExFatError::NotFound)
        ));
    }

    #[test]
    fn open_without_metadata_returns_error() {
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        assert!(matches!(
            exfat.open(&mut cursor, "anything"),
            Err(ExFatError::MetadataNotLoaded)
        ));
    }

    #[test]
    fn open_multi_component_path() {
        let mut image = make_image();
        let slot2 = setup_metadata(&mut image);

        // Add DOCS/ directory pointing to cluster 5
        write_file_entry(&mut image, slot2, "DOCS", 5, 0, true);

        // FAT: cluster 5 -> EOC
        let fat_base = 512;
        let off = fat_base + 5 * 4;
        image[off..off + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        // Write README.TXT in cluster 5 (DOCS directory)
        let cluster5_off = 3 * 512 + (5 - 2) * 512;
        write_file_entry(&mut image, cluster5_off, "README.TXT", 10, 100, false);

        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();
        exfat.load_metadata(&mut cursor).unwrap();

        let es = exfat.open(&mut cursor, "DOCS/README.TXT").unwrap();
        assert_eq!(es.name_string(), "README.TXT");
        assert_eq!(es.first_cluster(), 10);
    }

    /// Pins `filesystem_revision_major` and `filesystem_revision_minor`
    /// to actual u16 byte extraction. Default `make_image()` produces
    /// revision 0x0100 (major=1, minor=0) which collides with the
    /// `→ 1` and `→ 0` accessor-constant mutations. Using revision
    /// 0x0001 (major=0, minor=1) makes both mutations observably
    /// wrong.
    #[test]
    fn filesystem_revision_accessors_extract_high_and_low_bytes() {
        let mut image = make_image();
        // Revision 0x0001 (major=0, minor=1). Major must be 0 or 1
        // for validate_boot_sector to accept it.
        image[0x68..0x6A].copy_from_slice(&0x0001u16.to_le_bytes());
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        assert_eq!(exfat.filesystem_revision_major(), 0);
        assert_eq!(exfat.filesystem_revision_minor(), 1);
    }

    /// `number_of_fats` accessor must return the stored value
    /// (1 or 2 per spec). Default image has 1 FAT; this test pins
    /// the 2-FAT case and kills `→ 1` accessor-constant mutation.
    #[test]
    fn number_of_fats_returns_two_for_two_fat_image() {
        let mut image = make_image();
        image[0x6E] = 2; // NumberOfFats byte
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        assert_eq!(exfat.number_of_fats(), 2);
    }

    /// `load_metadata` computes `entries_per_cluster = cluster_size /
    /// DIR_ENTRY_SIZE` to bound the per-cluster slot scan. Mutating
    /// `/` to `*` blows the bound to `cluster_size * DIR_ENTRY_SIZE`
    /// (16384 here), so the inner loop keeps reading 32-byte slots
    /// far past the cluster boundary and into uninitialised image
    /// regions until it hits EOF and errors. By stamping a non-END
    /// entry-type byte (0xAB) at every slot byte-0 position past
    /// the bitmap+upcase entries, no ENTRY_TYPE_END short-circuit
    /// fires before EOF.
    #[test]
    fn load_metadata_uses_cluster_size_divided_by_entry_size() {
        let mut image = make_image();
        let _ = setup_metadata(&mut image);

        let cluster_heap = 3 * 512;
        // Slot byte-0 positions are at cluster_heap + slot_idx * 32.
        // Preserve byte-0 of cluster 3 (bitmap data, set to 0xFF by
        // setup_metadata) and cluster 4 (upcase data, starts with
        // 0xFF marker). All other byte-0 positions in 2..1600 must
        // be non-zero so the mutated loop never finds ENTRY_TYPE_END.
        let bitmap_data_off = cluster_heap + 512;
        let upcase_data_off = cluster_heap + 2 * 512;
        for slot_idx in 2..1600usize {
            let off = cluster_heap + slot_idx * 32;
            if off >= image.len() {
                break;
            }
            if off == bitmap_data_off || off == upcase_data_off {
                continue;
            }
            image[off] = 0xAB;
        }

        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();
        // Original `/`: scans 16 slots in cluster 2 (bitmap@0,
        // upcase@1, slots 2..15 are 0xAB → skip), exits loop, no
        // more clusters, returns Ok.
        // Mutated `*`: scans 16384 slots, eventually reads past EOF
        // (image is only 52736 bytes) → returns Err.
        exfat
            .load_metadata(&mut cursor)
            .expect("original entries_per_cluster bound stops at slot 16");
    }

    /// `read_data_from_cluster`'s `while bytes_read < len` loop must
    /// stop the moment the declared data length is satisfied — any
    /// extra iteration may step the cluster iterator onto invalid
    /// FAT entries that follow the data. Setting up FAT[3]→5 and
    /// FAT[5]=cluster_count+99 (out of range) means an unwanted
    /// extra step yields `InvalidCluster`, which the mutation
    /// `< → <=` surfaces but the correct `<` avoids.
    #[test]
    fn read_data_from_cluster_does_not_advance_past_completed_data() {
        let mut image = make_image();
        let _ = setup_metadata(&mut image);
        // FAT[3] -> 5 (extra cluster); FAT[5] = 200 (well beyond
        // cluster_count = 100, so InvalidCluster).
        let fat_base = 512;
        image[fat_base + 3 * 4..fat_base + 3 * 4 + 4].copy_from_slice(&5u32.to_le_bytes());
        image[fat_base + 5 * 4..fat_base + 5 * 4 + 4].copy_from_slice(&200u32.to_le_bytes());

        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();
        exfat
            .load_metadata(&mut cursor)
            .expect("bitmap data is 13 bytes — fits in one cluster, no extra step needed");
    }

    /// The `open` path splitter filters out empty components and
    /// `"."` via `!s.is_empty() && *s != "."`. Mutating `&&` to
    /// `||` keeps both empty strings and `"."` as path components.
    /// Even with a file literally named `"."` in the root, the
    /// original implementation returns `NotFound` for path `"."`
    /// because no real component remains after filtering. The
    /// mutation would instead resolve the dot entry and return it.
    #[test]
    fn open_dot_path_returns_not_found_even_when_dot_file_exists() {
        let mut image = make_image();
        let slot2 = setup_metadata(&mut image);
        write_file_entry(&mut image, slot2, ".", 10, 100, false);

        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();
        exfat.load_metadata(&mut cursor).unwrap();

        assert!(matches!(
            exfat.open(&mut cursor, "."),
            Err(ExFatError::NotFound)
        ));
    }

    #[test]
    fn open_not_a_directory_error() {
        let mut image = make_image();
        let slot2 = setup_metadata(&mut image);

        // Add a regular file (not a directory)
        write_file_entry(&mut image, slot2, "FILE.TXT", 10, 100, false);

        let mut cursor = Cursor::new(image);
        let mut exfat = ExFat::new(&mut cursor).unwrap();
        exfat.load_metadata(&mut cursor).unwrap();

        // Try to traverse through a file as if it were a directory
        assert!(matches!(
            exfat.open(&mut cursor, "FILE.TXT/sub.txt"),
            Err(ExFatError::NotADirectory)
        ));
    }
}
