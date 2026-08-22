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

use fsmnt_parser_core::boot_sector::ExFatBootSector;

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
    let cluster_heap_byte_offset = u64::from(bs.cluster_heap_offset.get()) * u64::from(bps);
    let fat_byte_offset = u64::from(bs.fat_offset.get()) * u64::from(bps);
    let fat_length_bytes = u64::from(bs.fat_length.get()) * u64::from(bps);

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
    ///
    /// # Errors
    ///
    /// Returns an error when neither boot-sector copy can be read and
    /// validated.
    pub fn new<T>(fs: &mut T) -> Result<Self>
    where
        T: Read + Seek,
    {
        let (bs, used_backup) = read_and_validate_boot_sector(fs)?;
        let pf = precompute(&bs);

        // Verify VBR checksum (best-effort; I/O failure sets false).
        let checksum_base = if used_backup {
            12u64 * u64::from(pf.bytes_per_sector)
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
    #[must_use]
    pub fn bytes_per_sector(&self) -> u32 {
        self.bytes_per_sector
    }

    /// Returns the cluster size in bytes.
    #[must_use]
    pub fn cluster_size(&self) -> u32 {
        self.cluster_size
    }

    /// Returns the total number of clusters in the cluster heap.
    #[must_use]
    pub fn cluster_count(&self) -> u32 {
        self.cluster_count
    }

    /// Returns the byte offset of the cluster heap from the start
    /// of the volume.
    #[must_use]
    pub fn cluster_heap_offset(&self) -> u64 {
        self.cluster_heap_byte_offset
    }

    /// Returns the byte offset of the FAT from the start of the
    /// volume.
    #[must_use]
    pub fn fat_offset(&self) -> u64 {
        self.fat_byte_offset
    }

    /// Returns the total length of the FAT in bytes.
    #[must_use]
    pub fn fat_length_bytes(&self) -> u64 {
        self.fat_length_bytes
    }

    /// Returns the cluster number of the root directory.
    #[must_use]
    pub fn root_directory_cluster(&self) -> u32 {
        self.root_directory_cluster
    }

    /// Returns the 32-bit volume serial number.
    #[must_use]
    pub fn volume_serial_number(&self) -> u32 {
        self.volume_serial_number
    }

    /// Returns the filesystem revision as a raw u16 (major.minor).
    #[must_use]
    pub fn filesystem_revision(&self) -> u16 {
        self.filesystem_revision
    }

    /// Returns the major component of the filesystem revision.
    #[must_use]
    pub fn filesystem_revision_major(&self) -> u8 {
        self.filesystem_revision.to_be_bytes()[0]
    }

    /// Returns the minor component of the filesystem revision.
    #[must_use]
    pub fn filesystem_revision_minor(&self) -> u8 {
        self.filesystem_revision.to_be_bytes()[1]
    }

    /// Returns the parsed volume flags.
    #[must_use]
    pub fn volume_flags(&self) -> VolumeFlags {
        self.volume_flags
    }

    /// Returns the percentage of clusters in use (0-100, or 0xFF
    /// if unknown).
    #[must_use]
    pub fn percent_in_use(&self) -> u8 {
        self.percent_in_use
    }

    /// Returns the number of FATs (1 or 2).
    #[must_use]
    pub fn number_of_fats(&self) -> u8 {
        self.number_of_fats
    }

    /// Returns the BIOS drive select value (typically 0x80).
    ///
    /// Per spec, implementations shall not validate this field.
    #[must_use]
    pub fn drive_select(&self) -> u8 {
        self.drive_select
    }

    /// Returns whether the VBR boot region checksum was valid when
    /// the volume was opened.
    #[must_use]
    pub fn boot_checksum_valid(&self) -> bool {
        self.boot_checksum_valid
    }

    // ---------------------------------------------------------------
    // Directory iteration
    // ---------------------------------------------------------------

    /// Creates a directory entry iterator for the directory starting
    /// at the given cluster.
    #[must_use]
    pub fn dir_entries(&self, start_cluster: u32) -> ExFatDirEntries<'_> {
        ExFatDirEntries::new(self, start_cluster)
    }

    /// Creates a directory entry iterator for the root directory.
    #[must_use]
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
            self.cluster_heap_byte_offset + u64::from(cluster - 2) * u64::from(self.cluster_size);
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
    ///
    /// # Errors
    ///
    /// Returns an error if the root directory or cluster chains cannot
    /// be read, required metadata entries are absent, or the up-case table
    /// fails validation.
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
            let cluster_size =
                usize::try_from(self.cluster_size).map_err(|_| ExFatError::InvalidEntrySet {
                    reason: "cluster size exceeds addressable memory",
                    byte_offset: offset,
                })?;
            let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

            for entry_idx in 0..entries_per_cluster {
                let relative_offset = u64::try_from(entry_idx * DIR_ENTRY_SIZE).map_err(|_| {
                    ExFatError::InvalidEntrySet {
                        reason: "directory offset exceeds the supported range",
                        byte_offset: offset,
                    }
                })?;
                let entry_offset = offset.saturating_add(relative_offset);
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

        let cluster_size =
            usize::try_from(self.cluster_size).map_err(|_| ExFatError::InvalidEntrySet {
                reason: "cluster size exceeds addressable memory",
                byte_offset: 0,
            })?;

        while bytes_read < len {
            let cluster = match cluster_iter.next(fs) {
                Some(Ok(c)) => c,
                Some(Err(e)) => return Err(e),
                None => break,
            };

            let offset = self.cluster_offset(cluster)?;
            fs.seek(crate::io::SeekFrom::Start(offset))?;

            let remaining = len - bytes_read;
            let to_read = remaining.min(cluster_size);
            fs.read_exact(&mut data[bytes_read..bytes_read + to_read])?;
            bytes_read += to_read;
        }

        Ok(data)
    }

    /// Returns a reference to the loaded allocation bitmap, if any.
    #[must_use]
    pub fn bitmap(&self) -> Option<&ExFatBitmap> {
        self.bitmap.as_ref()
    }

    /// Returns a reference to the loaded up-case table, if any.
    #[must_use]
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
    /// Uses `NameHash` for fast pre-filtering before full name
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
                Ok(_) => {}
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
    /// supports seeking and reading via [`FsReadSeek`](fsmnt_parser_core::FsReadSeek).
    ///
    /// # Errors
    ///
    /// Returns any path-resolution error from [`ExFat::open`], an I/O
    /// error while resolving a FAT chain, or an invalid-chain error.
    pub fn open_file<T>(&self, fs: &mut T, path: &str) -> Result<crate::file::ExFatFile>
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
#[path = "exfat_tests/mod.rs"]
mod tests;
