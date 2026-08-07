use alloc::string::String;
use core::fmt;

use crate::dir_entry::FatDirEntries;
use crate::error::{FatError, Result};
use crate::file::FatFile;
use crate::io::{Read, Seek};

use fsmnt_parser_core::boot_sector::{
    BOOT_SECTOR_SIZE, BOOT_SIGNATURE, DosBpb, Fat16BootSector, Fat32BootSector,
};
use zerocopy::FromBytes;

/// A type of FAT filesystem.
///
/// `FatType` values are based on the size of File Allocation Table entry.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum FatType {
    /// FAT12 filesystem.
    Fat12,
    /// FAT16 filesystem.
    Fat16,
    /// FAT32 filesystem.
    Fat32,
}

impl FatType {
    const FAT16_MIN_CLUSTERS: u32 = 0x0FF5;
    const FAT32_MIN_CLUSTERS: u32 = 0xFFF5;

    pub(crate) fn from_clusters(total_clusters: u32) -> Self {
        if total_clusters < Self::FAT16_MIN_CLUSTERS {
            FatType::Fat12
        } else if total_clusters < Self::FAT32_MIN_CLUSTERS {
            FatType::Fat16
        } else {
            FatType::Fat32
        }
    }
}

impl fmt::Display for FatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FatType::Fat12 => write!(f, "FAT12"),
            FatType::Fat16 => write!(f, "FAT16"),
            FatType::Fat32 => write!(f, "FAT32"),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for FatType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Use the `int_in_range` helper rather than `arbitrary::<usize>() %
        // variants.len()` — the modulo form generates cargo-mutants `% with
        // /` and `% with +` mutants that are extremely awkward to test
        // deterministically (the survivors either match the original by
        // chance, panic via index-out-of-bounds, or are functionally
        // indistinguishable on the inputs the fuzzer actually feeds in).
        match u.int_in_range(0u8..=2u8)? {
            0 => Ok(FatType::Fat12),
            1 => Ok(FatType::Fat16),
            _ => Ok(FatType::Fat32),
        }
    }
}

/// Root structure describing a FAT filesystem.
#[derive(Debug)]
#[allow(
    clippy::struct_field_names,
    reason = "the fields retain canonical FAT specification names such as fat_type, sectors_per_fat, and fat_start_sector"
)]
pub struct Fat {
    /// The type of FAT filesystem (FAT12, FAT16, or FAT32).
    fat_type: FatType,
    /// The size of a single cluster, in bytes.
    cluster_size: u32,
    /// The size of a single sector, in bytes.
    sector_size: u16,
    /// Size of the filesystem, in bytes.
    size: u64,
    /// Number of sectors per FAT.
    sectors_per_fat: u32,
    /// First sector of the FAT region.
    fat_start_sector: u32,
    /// Number of sectors in the root directory (FAT12/16 only, 0 for FAT32).
    root_dir_sectors: u32,
    /// First data sector (where cluster 2 begins).
    first_data_sector: u32,
    /// Total number of data clusters.
    total_clusters: u32,
    /// Root directory cluster (FAT32) or 0 (FAT12/16 uses fixed location).
    root_cluster: u32,
    /// Volume serial number.
    serial_number: u32,
}

impl Fat {
    /// Creates a new [`Fat`] object from a reader and validates its boot sector information.
    ///
    /// The reader must cover the entire FAT partition, not more and not less.
    /// It will be rewound to the beginning before reading anything.
    ///
    /// # Errors
    ///
    /// Returns an error when the boot sector is unreadable, malformed, internally
    /// inconsistent, or identifies a `BitLocker` container.
    pub fn new<T>(fs: &mut T) -> Result<Self>
    where
        T: Read + Seek,
    {
        // Read the boot sector
        fs.rewind()?;
        let mut boot_sector_bytes = [0u8; BOOT_SECTOR_SIZE];
        fs.read_exact(&mut boot_sector_bytes)?;

        // Validate boot signature
        let signature = u16::from_le_bytes([boot_sector_bytes[510], boot_sector_bytes[511]]);
        if signature != BOOT_SIGNATURE {
            return Err(FatError::InvalidBootSignature { actual: signature });
        }

        // Check for BitLocker-encrypted volume (BitLocker-to-Go on removable
        // media uses FAT). Detect before BPB parsing so the error is clear.
        if &boot_sector_bytes[3..11] == b"-FVE-FS-" {
            let mut oem_id = [0u8; 8];
            oem_id.copy_from_slice(&boot_sector_bytes[3..11]);
            return Err(FatError::BitLockerEncrypted { oem_id });
        }

        // Parse the DOS BPB to determine if this is FAT32 or FAT12/16
        let bpb = DosBpb::ref_from_bytes(&boot_sector_bytes[0x0B..0x24])
            .map_err(|_| FatError::BpbParseFailed)?;

        // Validate bytes per sector
        let sector_size = bpb.bytes_per_sector.get();
        if !matches!(sector_size, 512 | 1024 | 2048 | 4096) {
            return Err(FatError::InvalidBytesPerSector {
                actual: sector_size,
            });
        }

        // FAT32 is identified by sectors_per_fat_16 being 0 and root_entry_count being 0
        let is_fat32 = bpb.sectors_per_fat_16.get() == 0 && bpb.root_entry_count.get() == 0;

        if is_fat32 {
            Self::new_fat32(&boot_sector_bytes, bpb, sector_size)
        } else {
            Self::new_fat12_16(&boot_sector_bytes, bpb, sector_size)
        }
    }

    /// Returns the root directory of this FAT volume as a [`FatFile`].
    ///
    /// For FAT12/16, the root directory is at a fixed location.
    /// For FAT32, the root directory starts at `root_cluster`.
    #[must_use]
    pub fn root_directory(&self) -> FatFile<'_> {
        match self.fat_type {
            FatType::Fat12 | FatType::Fat16 => {
                // FAT12/16: root directory has no cluster, it's at a fixed location
                FatFile::new(self, None, true, 0)
            }
            FatType::Fat32 => {
                // FAT32: root directory starts at root_cluster
                FatFile::new(self, Some(self.root_cluster), true, 0)
            }
        }
    }

    /// Returns an iterator over the entries in the root directory.
    ///
    /// This is a convenience method that creates a [`FatDirEntries`] iterator
    /// for the root directory.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let fat = Fat::new(&mut fs)?;
    /// let mut entries = fat.root_dir_entries();
    /// while let Some(entry) = entries.try_next(&mut fs)? {
    ///     println!("Found: {:?}", entry.name);
    /// }
    /// ```
    #[must_use]
    pub fn root_dir_entries(&self) -> FatDirEntries<'_> {
        match self.fat_type {
            FatType::Fat12 | FatType::Fat16 => {
                // FAT12/16: root directory is at a fixed location
                FatDirEntries::new_fixed(self, self.root_dir_offset(), self.root_dir_size())
            }
            FatType::Fat32 => {
                // FAT32: root directory is a cluster chain
                FatDirEntries::new_cluster_chain(self, self.root_cluster)
            }
        }
    }

    /// Validates that `sectors_per_cluster` is a power of 2 (1, 2, 4, 8, 16, 32, 64, 128).
    //
    // The two clauses must reject independently:
    //   `== 0`         catches a zero spc (which is_power_of_two would
    //                  itself reject in principle, but the explicit
    //                  guard makes the intent visible and resilient
    //                  to upstream API drift);
    //   `!is_power_of_two()` catches non-power-of-two values.
    // The `||` cannot collapse to `&&` because a zero spc is not a
    // power of two anyway, so the AND form would never reject when
    // either condition is true alone. The boundary tests in the
    // `tests` module assert both arms by feeding spc=0 and spc=3.
    fn validate_sectors_per_cluster(sectors_per_cluster: u8) -> Result<()> {
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(FatError::InvalidSectorsPerCluster {
                actual: sectors_per_cluster,
            });
        }
        Ok(())
    }

    /// Parse a FAT32 boot sector
    fn new_fat32(boot_sector_bytes: &[u8], bpb: &DosBpb, sector_size: u16) -> Result<Self> {
        let boot_sector = Fat32BootSector::ref_from_bytes(boot_sector_bytes)
            .map_err(|_| FatError::BootSectorParseFailed)?;
        let ebpb = &boot_sector.ebpb;

        // Validate sectors per cluster
        Self::validate_sectors_per_cluster(bpb.sectors_per_cluster)?;

        let sectors_per_cluster = u32::from(bpb.sectors_per_cluster);
        let cluster_size = u32::from(sector_size)
            .checked_mul(sectors_per_cluster)
            .ok_or(FatError::BpbOverflow)?;
        let reserved_sectors = u32::from(bpb.reserved_sectors.get());
        let num_fats = u32::from(bpb.num_fats);
        let sectors_per_fat = ebpb.sectors_per_fat_32.get();
        let total_sectors = bpb.total_sectors();

        // FAT32 has no fixed root directory
        let root_dir_sectors = 0u32;

        // Calculate first data sector (use checked arithmetic to reject
        // crafted BPBs whose field products overflow u32).
        let fat_start_sector = reserved_sectors;
        let fat_area = num_fats
            .checked_mul(sectors_per_fat)
            .ok_or(FatError::BpbOverflow)?;
        let first_data_sector = reserved_sectors
            .checked_add(fat_area)
            .and_then(|v| v.checked_add(root_dir_sectors))
            .ok_or(FatError::BpbOverflow)?;

        // Calculate total clusters
        let data_sectors = total_sectors.saturating_sub(first_data_sector);
        let total_clusters = data_sectors / sectors_per_cluster;

        // Determine FAT type based on cluster count (should be FAT32)
        let fat_type = FatType::from_clusters(total_clusters);

        let size = u64::from(total_sectors) * u64::from(sector_size);
        let serial_number = ebpb.volume_serial_number.get();
        let root_cluster = ebpb.root_cluster.get();

        Ok(Self {
            fat_type,
            cluster_size,
            sector_size,
            size,
            sectors_per_fat,
            fat_start_sector,
            root_dir_sectors,
            first_data_sector,
            total_clusters,
            root_cluster,
            serial_number,
        })
    }

    /// Parse a FAT12/FAT16 boot sector
    fn new_fat12_16(boot_sector_bytes: &[u8], bpb: &DosBpb, sector_size: u16) -> Result<Self> {
        let boot_sector = Fat16BootSector::ref_from_bytes(boot_sector_bytes)
            .map_err(|_| FatError::BootSectorParseFailed)?;
        let ebpb = &boot_sector.ebpb;

        // Validate sectors per cluster
        Self::validate_sectors_per_cluster(bpb.sectors_per_cluster)?;

        let sectors_per_cluster = u32::from(bpb.sectors_per_cluster);
        let cluster_size = u32::from(sector_size)
            .checked_mul(sectors_per_cluster)
            .ok_or(FatError::BpbOverflow)?;
        let reserved_sectors = u32::from(bpb.reserved_sectors.get());
        let num_fats = u32::from(bpb.num_fats);
        let sectors_per_fat = u32::from(bpb.sectors_per_fat_16.get());
        let total_sectors = bpb.total_sectors();

        // Calculate root directory sectors (FAT12/16 have a fixed root directory)
        let root_entry_count = u32::from(bpb.root_entry_count.get());
        let root_dir_bytes = root_entry_count
            .checked_mul(32)
            .ok_or(FatError::BpbOverflow)?;
        let root_dir_sectors = root_dir_bytes.div_ceil(u32::from(sector_size));

        // Calculate first data sector (use checked arithmetic to reject
        // crafted BPBs whose field products overflow u32).
        let fat_start_sector = reserved_sectors;
        let fat_area = num_fats
            .checked_mul(sectors_per_fat)
            .ok_or(FatError::BpbOverflow)?;
        let first_data_sector = reserved_sectors
            .checked_add(fat_area)
            .and_then(|v| v.checked_add(root_dir_sectors))
            .ok_or(FatError::BpbOverflow)?;

        // Calculate total clusters
        let data_sectors = total_sectors.saturating_sub(first_data_sector);
        let total_clusters = data_sectors / sectors_per_cluster;

        // Determine FAT type based on cluster count
        let fat_type = FatType::from_clusters(total_clusters);

        let size = u64::from(total_sectors) * u64::from(sector_size);
        let serial_number = ebpb.volume_serial_number.get();

        // FAT12/16 don't have a root cluster field; root directory is at a fixed location
        let root_cluster = 0;

        Ok(Self {
            fat_type,
            cluster_size,
            sector_size,
            size,
            sectors_per_fat,
            fat_start_sector,
            root_dir_sectors,
            first_data_sector,
            total_clusters,
            root_cluster,
            serial_number,
        })
    }

    /// Returns the type of FAT filesystem (FAT12, FAT16, or FAT32).
    #[must_use]
    pub fn fat_type(&self) -> FatType {
        self.fat_type
    }

    /// Returns the size of a single cluster, in bytes.
    #[must_use]
    pub fn cluster_size(&self) -> u32 {
        self.cluster_size
    }

    /// Returns the size of a single sector, in bytes.
    #[must_use]
    pub fn sector_size(&self) -> u16 {
        self.sector_size
    }

    /// Returns the partition size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the number of sectors per FAT.
    #[must_use]
    pub fn sectors_per_fat(&self) -> u32 {
        self.sectors_per_fat
    }

    /// Returns the first sector of the FAT region.
    #[must_use]
    pub fn fat_start_sector(&self) -> u32 {
        self.fat_start_sector
    }

    /// Returns the number of sectors in the root directory (FAT12/16 only).
    ///
    /// For FAT32, this returns 0 as the root directory is stored in the data region.
    #[must_use]
    pub fn root_dir_sectors(&self) -> u32 {
        self.root_dir_sectors
    }

    /// Returns the first data sector (where cluster 2 begins).
    #[must_use]
    pub fn first_data_sector(&self) -> u32 {
        self.first_data_sector
    }

    /// Returns the total number of data clusters.
    #[must_use]
    pub fn total_clusters(&self) -> u32 {
        self.total_clusters
    }

    /// Returns the root directory cluster number (FAT32 only).
    ///
    /// For FAT12/16, this returns 0 as the root directory is at a fixed location.
    #[must_use]
    pub fn root_cluster(&self) -> u32 {
        self.root_cluster
    }

    /// Returns the 32-bit volume serial number.
    #[must_use]
    pub fn serial_number(&self) -> u32 {
        self.serial_number
    }

    /// Returns the byte offset on disk for the given cluster number.
    ///
    /// Cluster numbers start at 2 (clusters 0 and 1 are reserved).
    ///
    /// # Errors
    ///
    /// Returns an error if `cluster` is less than 2 (reserved cluster numbers)
    /// or exceeds the total number of clusters in the filesystem.
    pub fn cluster_offset(&self, cluster: u32) -> Result<u64> {
        if cluster < 2 {
            return Err(FatError::InvalidCluster { cluster });
        }
        // Valid cluster numbers are 2 through (total_clusters + 1), since
        // clusters 0 and 1 are reserved and total_clusters counts data clusters.
        // Use saturating_add to avoid overflow on corrupted filesystems.
        if cluster > self.total_clusters.saturating_add(1) {
            return Err(FatError::InvalidCluster { cluster });
        }
        // Clusters are numbered starting from 2
        let cluster_offset = u64::from(cluster - 2) * u64::from(self.cluster_size);
        Ok(u64::from(self.first_data_sector) * u64::from(self.sector_size) + cluster_offset)
    }

    /// Returns the byte offset of the root directory for FAT12/16.
    ///
    /// For FAT32, use `root_cluster()` and `cluster_offset()` instead.
    #[must_use]
    pub fn root_dir_offset(&self) -> u64 {
        // Root directory is located just before the first data sector
        // Use saturating_sub to prevent underflow on corrupted filesystems
        u64::from(self.first_data_sector.saturating_sub(self.root_dir_sectors))
            * u64::from(self.sector_size)
    }

    /// Returns the size of the root directory in bytes for FAT12/16.
    ///
    /// For FAT32, the root directory size is not fixed.
    #[must_use]
    pub fn root_dir_size(&self) -> u32 {
        self.root_dir_sectors * u32::from(self.sector_size)
    }

    /// Reads the next cluster number from the FAT table.
    ///
    /// Returns `Ok(Some(next))` if there is a next cluster in the chain,
    /// `Ok(None)` if this is the end of the chain, or an error if the
    /// cluster is invalid or marked as bad.
    ///
    /// # Errors
    ///
    /// Returns an error if `cluster` is outside the data region, is marked bad,
    /// or if the allocation-table entry cannot be read.
    pub fn next_cluster<T>(&self, fs: &mut T, cluster: u32) -> Result<Option<u32>>
    where
        T: Read + Seek,
    {
        // Validate cluster number: must be >= 2 (0 and 1 are reserved) and
        // <= total_clusters + 1 (since total_clusters counts data clusters starting at 2)
        if cluster < 2 || cluster > self.total_clusters + 1 {
            return Err(FatError::InvalidCluster { cluster });
        }

        match self.fat_type {
            FatType::Fat12 => self.next_cluster_fat12(fs, cluster),
            FatType::Fat16 => self.next_cluster_fat16(fs, cluster),
            FatType::Fat32 => self.next_cluster_fat32(fs, cluster),
        }
    }

    /// Read next cluster for FAT12.
    fn next_cluster_fat12<T>(&self, fs: &mut T, cluster: u32) -> Result<Option<u32>>
    where
        T: Read + Seek,
    {
        // FAT12 entries are 12 bits (1.5 bytes) each
        let fat_offset = cluster + (cluster / 2); // cluster * 1.5
        let fat_byte_offset =
            u64::from(self.fat_start_sector) * u64::from(self.sector_size) + u64::from(fat_offset);

        fs.seek(crate::io::SeekFrom::Start(fat_byte_offset))?;
        let mut buf = [0u8; 2];
        fs.read_exact(&mut buf)?;

        let entry = u16::from_le_bytes(buf);
        let value = if cluster & 1 == 1 {
            entry >> 4 // Odd cluster: high 12 bits
        } else {
            entry & 0x0FFF // Even cluster: low 12 bits
        };

        // FAT12 end-of-chain markers: 0xFF8-0xFFF
        if value >= 0x0FF8 {
            Ok(None)
        } else if value == 0x0FF7 {
            Err(FatError::BadCluster { cluster })
        } else {
            Ok(Some(u32::from(value)))
        }
    }

    /// Read next cluster for FAT16.
    fn next_cluster_fat16<T>(&self, fs: &mut T, cluster: u32) -> Result<Option<u32>>
    where
        T: Read + Seek,
    {
        let fat_offset = u64::from(cluster) * 2;
        let fat_byte_offset =
            u64::from(self.fat_start_sector) * u64::from(self.sector_size) + fat_offset;

        fs.seek(crate::io::SeekFrom::Start(fat_byte_offset))?;
        let mut buf = [0u8; 2];
        fs.read_exact(&mut buf)?;

        let value = u16::from_le_bytes(buf);

        // FAT16 end-of-chain markers: 0xFFF8-0xFFFF
        if value >= 0xFFF8 {
            Ok(None)
        } else if value == 0xFFF7 {
            Err(FatError::BadCluster { cluster })
        } else {
            Ok(Some(u32::from(value)))
        }
    }

    /// Read next cluster for FAT32.
    fn next_cluster_fat32<T>(&self, fs: &mut T, cluster: u32) -> Result<Option<u32>>
    where
        T: Read + Seek,
    {
        let fat_offset = u64::from(cluster) * 4;
        let fat_byte_offset =
            u64::from(self.fat_start_sector) * u64::from(self.sector_size) + fat_offset;

        fs.seek(crate::io::SeekFrom::Start(fat_byte_offset))?;
        let mut buf = [0u8; 4];
        fs.read_exact(&mut buf)?;

        // FAT32 uses only 28 bits; mask off the high 4 bits
        let value = u32::from_le_bytes(buf) & 0x0FFF_FFFF;

        // FAT32 end-of-chain markers: 0x0FFFFFF8-0x0FFFFFFF
        if value >= 0x0FFF_FFF8 {
            Ok(None)
        } else if value == 0x0FFF_FFF7 {
            Err(FatError::BadCluster { cluster })
        } else {
            Ok(Some(value))
        }
    }

    /// Returns the volume name (label) from the root directory, if present.
    ///
    /// The volume name is stored as a directory entry with the `VOLUME_ID` attribute
    /// in the root directory. If no volume name is found, returns `Ok(None)`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let fat = Fat::new(&mut fs)?;
    /// if let Some(name) = fat.volume_name(&mut fs)? {
    ///     println!("Volume name: {}", name);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the root directory or its cluster chain cannot be read.
    pub fn volume_name<T>(&self, fs: &mut T) -> Result<Option<String>>
    where
        T: Read + Seek,
    {
        let mut entries = self.root_dir_entries();

        while let Some(entry) = entries.next(fs) {
            let entry = entry?;
            if entry.is_volume_id() {
                // Extract the 11-byte name field and convert to string
                let name = entry.short_name();

                // Find the end of the label (trim trailing spaces)
                let end = name
                    .iter()
                    .rposition(|&b| b != b' ' && b != 0)
                    .map_or(0, |i| i + 1);

                // Convert to string (volume labels are ASCII in FAT)
                let label = String::from_utf8_lossy(&name[..end]).into_owned();
                return Ok(Some(label));
            }
        }

        Ok(None)
    }

    /// Opens a file or directory at the given path.
    ///
    /// The path can use either `/` or `\` as separators. The path is resolved
    /// starting from the root directory. The `.` and `..` entries are handled
    /// appropriately.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let fat = Fat::new(&mut fs)?;
    /// let file = fat.open(&mut fs, "/Documents/readme.txt")?;
    /// println!("File size: {}", file.file_size());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is not found
    /// - A component in the path is not a directory (except for the last component)
    /// - An I/O error occurs
    pub fn open<T>(&self, fs: &mut T, path: &str) -> Result<FatFile<'_>>
    where
        T: Read + Seek,
    {
        // Create an iterator over path components, handling both / and \ separators
        // Use peekable to check if we're on the last component without collecting
        let mut components = path
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
            .peekable();

        // Start from root directory
        let mut current_file = self.root_directory();

        // If path is empty or just "/", return root directory
        if components.peek().is_none() {
            return Ok(current_file);
        }

        // Traverse the path
        while let Some(component) = components.next() {
            let is_last = components.peek().is_none();

            // Current must be a directory to continue traversal
            if !current_file.is_directory() {
                return Err(FatError::NotADirectory);
            }

            // Get directory entries
            let mut entries = current_file.dir_entries()?;

            // Handle ".." specially - we need to track parent directories
            // For simplicity, we'll just search for the ".." entry in the directory
            // which points to the parent cluster
            if component == ".." {
                // Find the ".." entry
                match entries.find_by_name(fs, "..") {
                    Some(Ok(entry)) => {
                        let cluster = entry.first_cluster();
                        // Cluster 0 means root directory
                        if cluster == 0 {
                            current_file = self.root_directory();
                        } else {
                            current_file = FatFile::new(self, Some(cluster), true, 0);
                        }
                        continue;
                    }
                    Some(Err(e)) => return Err(e),
                    None => {
                        // No ".." entry, we're at root
                        current_file = self.root_directory();
                        continue;
                    }
                }
            }

            // Find the entry by name
            match entries.find_by_name(fs, component) {
                Some(Ok(entry)) => {
                    let cluster = entry.first_cluster();
                    let is_dir = entry.is_directory();
                    let size = entry.file_size();

                    // If not last component, it must be a directory
                    if !is_last && !is_dir {
                        return Err(FatError::NotADirectory);
                    }

                    // Create the file/directory
                    if cluster == 0 && is_dir {
                        // Root directory reference
                        current_file = self.root_directory();
                    } else {
                        current_file = FatFile::new(self, Some(cluster), is_dir, size);
                    }
                }
                Some(Err(e)) => return Err(e),
                None => return Err(FatError::NotFound),
            }
        }

        Ok(current_file)
    }
}

#[cfg(test)]
#[path = "fat_tests/mod.rs"]
mod tests;
