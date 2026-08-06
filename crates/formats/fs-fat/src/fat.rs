use alloc::string::String;
use core::fmt;

use crate::dir_entry::FatDirEntries;
use crate::error::{FatError, Result};
use crate::file::FatFile;
use crate::io::{Read, Seek};

use fs_common::boot_sector::{
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

    /// Validates that sectors_per_cluster is a power of 2 (1, 2, 4, 8, 16, 32, 64, 128).
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

        let sectors_per_cluster = bpb.sectors_per_cluster as u32;
        let cluster_size = (sector_size as u32)
            .checked_mul(sectors_per_cluster)
            .ok_or(FatError::BpbOverflow)?;
        let reserved_sectors = bpb.reserved_sectors.get() as u32;
        let num_fats = bpb.num_fats as u32;
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

        let size = total_sectors as u64 * sector_size as u64;
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

        let sectors_per_cluster = bpb.sectors_per_cluster as u32;
        let cluster_size = (sector_size as u32)
            .checked_mul(sectors_per_cluster)
            .ok_or(FatError::BpbOverflow)?;
        let reserved_sectors = bpb.reserved_sectors.get() as u32;
        let num_fats = bpb.num_fats as u32;
        let sectors_per_fat = bpb.sectors_per_fat_16.get() as u32;
        let total_sectors = bpb.total_sectors();

        // Calculate root directory sectors (FAT12/16 have a fixed root directory)
        let root_entry_count = bpb.root_entry_count.get() as u32;
        let root_dir_bytes = root_entry_count
            .checked_mul(32)
            .ok_or(FatError::BpbOverflow)?;
        let root_dir_sectors = root_dir_bytes.div_ceil(sector_size as u32);

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

        let size = total_sectors as u64 * sector_size as u64;
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
    pub fn fat_type(&self) -> FatType {
        self.fat_type
    }

    /// Returns the size of a single cluster, in bytes.
    pub fn cluster_size(&self) -> u32 {
        self.cluster_size
    }

    /// Returns the size of a single sector, in bytes.
    pub fn sector_size(&self) -> u16 {
        self.sector_size
    }

    /// Returns the partition size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the number of sectors per FAT.
    pub fn sectors_per_fat(&self) -> u32 {
        self.sectors_per_fat
    }

    /// Returns the first sector of the FAT region.
    pub fn fat_start_sector(&self) -> u32 {
        self.fat_start_sector
    }

    /// Returns the number of sectors in the root directory (FAT12/16 only).
    ///
    /// For FAT32, this returns 0 as the root directory is stored in the data region.
    pub fn root_dir_sectors(&self) -> u32 {
        self.root_dir_sectors
    }

    /// Returns the first data sector (where cluster 2 begins).
    pub fn first_data_sector(&self) -> u32 {
        self.first_data_sector
    }

    /// Returns the total number of data clusters.
    pub fn total_clusters(&self) -> u32 {
        self.total_clusters
    }

    /// Returns the root directory cluster number (FAT32 only).
    ///
    /// For FAT12/16, this returns 0 as the root directory is at a fixed location.
    pub fn root_cluster(&self) -> u32 {
        self.root_cluster
    }

    /// Returns the 32-bit volume serial number.
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
        let cluster_offset = (cluster - 2) as u64 * self.cluster_size as u64;
        Ok(self.first_data_sector as u64 * self.sector_size as u64 + cluster_offset)
    }

    /// Returns the byte offset of the root directory for FAT12/16.
    ///
    /// For FAT32, use `root_cluster()` and `cluster_offset()` instead.
    pub fn root_dir_offset(&self) -> u64 {
        // Root directory is located just before the first data sector
        // Use saturating_sub to prevent underflow on corrupted filesystems
        self.first_data_sector.saturating_sub(self.root_dir_sectors) as u64
            * self.sector_size as u64
    }

    /// Returns the size of the root directory in bytes for FAT12/16.
    ///
    /// For FAT32, the root directory size is not fixed.
    pub fn root_dir_size(&self) -> u32 {
        self.root_dir_sectors * self.sector_size as u32
    }

    /// Reads the next cluster number from the FAT table.
    ///
    /// Returns `Ok(Some(next))` if there is a next cluster in the chain,
    /// `Ok(None)` if this is the end of the chain, or an error if the
    /// cluster is invalid or marked as bad.
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
            self.fat_start_sector as u64 * self.sector_size as u64 + fat_offset as u64;

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
            Ok(Some(value as u32))
        }
    }

    /// Read next cluster for FAT16.
    fn next_cluster_fat16<T>(&self, fs: &mut T, cluster: u32) -> Result<Option<u32>>
    where
        T: Read + Seek,
    {
        let fat_offset = cluster as u64 * 2;
        let fat_byte_offset = self.fat_start_sector as u64 * self.sector_size as u64 + fat_offset;

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
            Ok(Some(value as u32))
        }
    }

    /// Read next cluster for FAT32.
    fn next_cluster_fat32<T>(&self, fs: &mut T, cluster: u32) -> Result<Option<u32>>
    where
        T: Read + Seek,
    {
        let fat_offset = cluster as u64 * 4;
        let fat_byte_offset = self.fat_start_sector as u64 * self.sector_size as u64 + fat_offset;

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
                    .map(|i| i + 1)
                    .unwrap_or(0);

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
mod tests {
    use super::*;
    use alloc::string::ToString;

    // Tests for FatType::from_clusters with boundary values
    // FAT12: < 4085 clusters (0x0FF5)
    // FAT16: >= 4085 and < 65525 clusters (0xFFF5)
    // FAT32: >= 65525 clusters

    #[test]
    fn test_fat_type_from_clusters_fat12() {
        // FAT12 for cluster counts below FAT16_MIN_CLUSTERS (4085)
        assert_eq!(FatType::from_clusters(0), FatType::Fat12);
        assert_eq!(FatType::from_clusters(1), FatType::Fat12);
        assert_eq!(FatType::from_clusters(100), FatType::Fat12);
        assert_eq!(FatType::from_clusters(4084), FatType::Fat12);
    }

    #[test]
    fn test_fat_type_from_clusters_fat12_fat16_boundary() {
        // Boundary: 4084 -> FAT12, 4085 -> FAT16
        assert_eq!(FatType::from_clusters(4084), FatType::Fat12);
        assert_eq!(FatType::from_clusters(4085), FatType::Fat16);
    }

    #[test]
    fn test_fat_type_from_clusters_fat16() {
        // FAT16 for cluster counts >= 4085 and < 65525
        assert_eq!(FatType::from_clusters(4085), FatType::Fat16);
        assert_eq!(FatType::from_clusters(10000), FatType::Fat16);
        assert_eq!(FatType::from_clusters(65524), FatType::Fat16);
    }

    #[test]
    fn test_fat_type_from_clusters_fat16_fat32_boundary() {
        // Boundary: 65524 -> FAT16, 65525 -> FAT32
        assert_eq!(FatType::from_clusters(65524), FatType::Fat16);
        assert_eq!(FatType::from_clusters(65525), FatType::Fat32);
    }

    #[test]
    fn test_fat_type_from_clusters_fat32() {
        // FAT32 for cluster counts >= 65525
        assert_eq!(FatType::from_clusters(65525), FatType::Fat32);
        assert_eq!(FatType::from_clusters(100000), FatType::Fat32);
        assert_eq!(FatType::from_clusters(1000000), FatType::Fat32);
        assert_eq!(FatType::from_clusters(u32::MAX), FatType::Fat32);
    }

    // Tests for FatType Display trait
    #[test]
    fn test_fat_type_display_fat12() {
        assert_eq!(FatType::Fat12.to_string(), "FAT12");
    }

    #[test]
    fn test_fat_type_display_fat16() {
        assert_eq!(FatType::Fat16.to_string(), "FAT16");
    }

    #[test]
    fn test_fat_type_display_fat32() {
        assert_eq!(FatType::Fat32.to_string(), "FAT32");
    }

    // Test FatType equality and copy traits
    #[test]
    fn test_fat_type_equality() {
        assert_eq!(FatType::Fat12, FatType::Fat12);
        assert_eq!(FatType::Fat16, FatType::Fat16);
        assert_eq!(FatType::Fat32, FatType::Fat32);

        assert_ne!(FatType::Fat12, FatType::Fat16);
        assert_ne!(FatType::Fat16, FatType::Fat32);
        assert_ne!(FatType::Fat12, FatType::Fat32);
    }

    #[test]
    fn test_fat_type_copy() {
        let original = FatType::Fat16;
        let copy = original;
        assert_eq!(original, copy);
    }

    #[test]
    fn test_fat_type_debug() {
        // Debug representation
        assert_eq!(format!("{:?}", FatType::Fat12), "Fat12");
        assert_eq!(format!("{:?}", FatType::Fat16), "Fat16");
        assert_eq!(format!("{:?}", FatType::Fat32), "Fat32");
    }

    // Test the constants
    #[test]
    fn test_fat_type_constants() {
        // Verify the constant values match expected FAT specification
        assert_eq!(FatType::FAT16_MIN_CLUSTERS, 0x0FF5); // 4085
        assert_eq!(FatType::FAT32_MIN_CLUSTERS, 0xFFF5); // 65525
    }

    #[test]
    fn test_fat_new_bitlocker_encrypted() {
        let mut buf = [0u8; BOOT_SECTOR_SIZE];
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf[3..11].copy_from_slice(b"-FVE-FS-");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 8;

        let mut cursor = std::io::Cursor::new(&buf[..]);
        let err = Fat::new(&mut cursor).unwrap_err();
        let FatError::BitLockerEncrypted { oem_id } = err else {
            panic!("Expected BitLockerEncrypted, got {err}");
        };
        assert_eq!(&oem_id, b"-FVE-FS-");
    }

    #[test]
    fn test_fat_new_bitlocker_display() {
        let err = FatError::BitLockerEncrypted {
            oem_id: *b"-FVE-FS-",
        };
        let msg = err.to_string();
        assert!(msg.contains("BitLocker"), "should mention BitLocker: {msg}");
        assert!(msg.contains("Decrypt"), "should suggest decryption: {msg}");
    }

    // ----------------------------------------------------------------------
    // Image builders for end-to-end FAT tests (FAT12, FAT16, FAT32).
    // Each fixture uses concrete, distinct values for every BPB field so
    // getter mutants (`-> u32 with 0/1`, etc.) become observable.
    // ----------------------------------------------------------------------

    use alloc::vec;
    use alloc::vec::Vec;
    use std::io::Cursor;

    /// 1.44 MB floppy-style FAT12: 2880 sectors × 512 B, spc=1, 1 reserved
    /// sector, 2 FATs × 9 sectors, 224 root entries = 14 root sectors.
    /// First data sector = 1 + 2*9 + 14 = 33. Data sectors = 2880-33 = 2847.
    /// Clusters = 2847 → FAT12.
    fn build_fat12_image() -> Vec<u8> {
        // Image needs to cover up to cluster 5 (data starts at sector 33;
        // we use 40 sectors to be safe).
        let mut img = vec![0u8; 40 * 512];
        img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        img[3..11].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 1; // spc
        img[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes()); // reserved
        img[0x10] = 2; // num_fats
        img[0x11..0x13].copy_from_slice(&224u16.to_le_bytes());
        img[0x13..0x15].copy_from_slice(&2880u16.to_le_bytes());
        img[0x15] = 0xF0; // 1.44 MB floppy
        img[0x16..0x18].copy_from_slice(&9u16.to_le_bytes()); // spf16
        img[0x18..0x1A].copy_from_slice(&18u16.to_le_bytes());
        img[0x1A..0x1C].copy_from_slice(&2u16.to_le_bytes());
        img[0x24] = 0x00;
        img[0x26] = 0x29;
        img[0x27..0x2B].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        img[0x2B..0x36].copy_from_slice(b"VOLUME12   ");
        img[0x36..0x3E].copy_from_slice(b"FAT12   ");
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;

        // FAT[0..1] reserved (12-bit packed across 3 bytes per entry pair):
        //   FAT[0] = 0xFF0 (media descriptor 0xF0 + 0xFFFs)
        //   FAT[1] = 0xFFF (EOC marker)
        // Bytes 0..3 of FAT region encode (FAT[0], FAT[1]) = packed.
        // Use a simple chain: FAT[2] = 3 (cluster 2 → cluster 3),
        // FAT[3] = EOC (0xFFF).
        let f = 0x200;
        // 12-bit entries: bytes [F0 FF FF | 03 F0 FF | ...]
        // FAT[0] low 8 = 0xF0, FAT[0] high 4 + FAT[1] low 4 = 0xF, FAT[1] high 8 = 0xFF
        img[f] = 0xF0;
        img[f + 1] = 0xFF;
        img[f + 2] = 0xFF;
        // FAT[2] = 0x003 (next = cluster 3): byte[3] = 0x03,
        // byte[4] low 4 = 0; FAT[3] = 0xFFF: byte[4] high 4 = 0xF, byte[5] = 0xFF
        img[f + 3] = 0x03;
        img[f + 4] = 0xF0;
        img[f + 5] = 0xFF;
        img
    }

    /// FAT16 image with 4084 → 4085+ clusters (depending on caller).
    /// total_sectors=4104, spc=1, reserved=1, 1 FAT × 17 sectors,
    /// 16 root entries = 1 sector. first_data=1+17+1=19. Data=4085.
    fn build_fat16_image() -> Vec<u8> {
        let mut img = vec![0u8; 4104 * 512];
        img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        img[3..11].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 1;
        img[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes());
        img[0x10] = 1;
        img[0x11..0x13].copy_from_slice(&16u16.to_le_bytes());
        img[0x13..0x15].copy_from_slice(&4104u16.to_le_bytes());
        img[0x15] = 0xF8;
        img[0x16..0x18].copy_from_slice(&17u16.to_le_bytes());
        img[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
        img[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
        img[0x24] = 0x80;
        img[0x26] = 0x29;
        img[0x27..0x2B].copy_from_slice(&0xCAFE_F00Du32.to_le_bytes());
        img[0x2B..0x36].copy_from_slice(b"VOLUME16   ");
        img[0x36..0x3E].copy_from_slice(b"FAT16   ");
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;

        // FAT[0..1] reserved, FAT[2] = 3, FAT[3] = 0xFFFF (EOC).
        let f = 0x200;
        img[f..f + 2].copy_from_slice(&0xFFF8u16.to_le_bytes());
        img[f + 2..f + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
        img[f + 4..f + 6].copy_from_slice(&3u16.to_le_bytes()); // FAT[2] -> 3
        img[f + 6..f + 8].copy_from_slice(&0xFFFFu16.to_le_bytes()); // FAT[3] EOC
        img
    }

    /// FAT32 image: spc=1, 32 reserved, 1 FAT × 512 sectors, no root entries,
    /// total_sectors_32=66069 → data sectors=65525 → exactly FAT32 threshold.
    fn build_fat32_image() -> Vec<u8> {
        let mut img = vec![0u8; 66069 * 512];
        img[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        img[3..11].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 1;
        img[0x0E..0x10].copy_from_slice(&32u16.to_le_bytes());
        img[0x10] = 1;
        img[0x15] = 0xF8;
        img[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
        img[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
        img[0x20..0x24].copy_from_slice(&66069u32.to_le_bytes());
        img[0x24..0x28].copy_from_slice(&512u32.to_le_bytes()); // sectors_per_fat_32
        img[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes()); // root_cluster=2
        img[0x30..0x32].copy_from_slice(&0xFFFFu16.to_le_bytes()); // no FSInfo
        img[0x40] = 0x80;
        img[0x42] = 0x29;
        img[0x43..0x47].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        img[0x47..0x52].copy_from_slice(b"VOLUME32   ");
        img[0x52..0x5A].copy_from_slice(b"FAT32   ");
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;

        // FAT[0..2] reserved, FAT[2] = 3, FAT[3] = EOC.
        let f = 32 * 512;
        img[f..f + 4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes()); // FAT[0]
        img[f + 4..f + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[1]
        img[f + 8..f + 12].copy_from_slice(&3u32.to_le_bytes()); // FAT[2] -> 3
        img[f + 12..f + 16].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[3] EOC
        img
    }

    // ----------------------------------------------------------------------
    // Getter tests: assert each value at the exact level returned by the
    // crate API. Catches `-> uN with 0/1` mutants for sector_size, size,
    // sectors_per_fat, fat_start_sector, root_dir_sectors,
    // first_data_sector, total_clusters, serial_number, etc.
    // ----------------------------------------------------------------------

    #[test]
    fn fat16_getters_expose_bpb_derived_values() {
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("fat16 image parses");

        assert_eq!(fat.fat_type(), FatType::Fat16);
        assert_eq!(fat.cluster_size(), 512);
        assert_eq!(fat.sector_size(), 512);
        assert_eq!(fat.size(), 4104 * 512);
        assert_eq!(fat.sectors_per_fat(), 17);
        assert_eq!(fat.fat_start_sector(), 1);
        assert_eq!(fat.root_dir_sectors(), 1); // (16*32 + 511)/512 = 1
        assert_eq!(fat.first_data_sector(), 19);
        assert_eq!(fat.total_clusters(), 4085);
        assert_eq!(fat.root_cluster(), 0); // FAT16 has no root cluster
        assert_eq!(fat.serial_number(), 0xCAFE_F00D);

        // FAT12 boundary: 4085 → FAT16 (just into FAT16 territory).
        let img12 = build_fat12_image();
        let mut cur12 = Cursor::new(img12);
        let fat12 = Fat::new(&mut cur12).expect("fat12 image parses");
        assert_eq!(fat12.fat_type(), FatType::Fat12);
        assert_eq!(fat12.serial_number(), 0xDEAD_BEEF);
        // 2880-33 = 2847 clusters → FAT12.
        assert_eq!(fat12.total_clusters(), 2847);

        let img32 = build_fat32_image();
        let mut cur32 = Cursor::new(img32);
        let fat32 = Fat::new(&mut cur32).expect("fat32 image parses");
        assert_eq!(fat32.fat_type(), FatType::Fat32);
        assert_eq!(fat32.root_cluster(), 2);
        assert_eq!(fat32.sectors_per_fat(), 512);
        assert_eq!(fat32.fat_start_sector(), 32);
        assert_eq!(fat32.root_dir_sectors(), 0);
        assert_eq!(fat32.first_data_sector(), 32 + 512);
        assert_eq!(fat32.serial_number(), 0x1234_5678);
    }

    #[test]
    fn cluster_offset_rejects_reserved_and_oob_clusters() {
        // Catches `> with >=/==` at line 388 and `>= with <` etc. on the
        // upper bound: cluster 0, 1 are reserved (always invalid);
        // total_clusters + 1 is the highest valid index;
        // total_clusters + 2 must reject.
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        assert!(matches!(
            fat.cluster_offset(0),
            Err(FatError::InvalidCluster { cluster: 0 })
        ));
        assert!(matches!(
            fat.cluster_offset(1),
            Err(FatError::InvalidCluster { cluster: 1 })
        ));
        // Cluster 2 = first data sector.
        let offset_2 = fat.cluster_offset(2).expect("cluster 2 valid");
        assert_eq!(offset_2, 19 * 512);
        // Cluster 3 = sector 20.
        let offset_3 = fat.cluster_offset(3).expect("cluster 3 valid");
        assert_eq!(offset_3, 20 * 512);
        // Highest valid cluster: total_clusters + 1 = 4086.
        assert!(fat.cluster_offset(4086).is_ok());
        // One past = invalid.
        assert!(matches!(
            fat.cluster_offset(4087),
            Err(FatError::InvalidCluster { cluster: 4087 })
        ));
    }

    #[test]
    fn root_dir_offset_and_size_for_fat16() {
        // Pins `* with +` on root_dir_size and the FAT16 root location.
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        // FAT16 root sits at (first_data_sector - root_dir_sectors) =
        // 19 - 1 = 18, in byte terms 18 * 512 = 9216.
        assert_eq!(fat.root_dir_offset(), 18 * 512);
        // root_dir_size = root_dir_sectors * sector_size = 1 * 512 = 512.
        assert_eq!(fat.root_dir_size(), 512);
    }

    // ----------------------------------------------------------------------
    // next_cluster_fat12 / 16 / 32 — anchor the FAT table indexing math
    // and the end-of-chain / bad-cluster markers.
    // ----------------------------------------------------------------------

    #[test]
    fn next_cluster_fat16_follows_chain_and_returns_none_at_eoc() {
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        // FAT[2] → 3, FAT[3] → EOC (0xFFFF).
        let next2 = fat.next_cluster(&mut cur, 2).expect("read FAT[2]");
        assert_eq!(next2, Some(3));
        let next3 = fat.next_cluster(&mut cur, 3).expect("read FAT[3]");
        assert_eq!(next3, None);
    }

    #[test]
    fn next_cluster_fat16_reports_bad_cluster_marker() {
        // FAT[2] = 0xFFF7 means cluster 2 is BAD.
        let mut img = build_fat16_image();
        let f = 0x200;
        img[f + 4..f + 6].copy_from_slice(&0xFFF7u16.to_le_bytes());

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let err = fat.next_cluster(&mut cur, 2).unwrap_err();
        assert!(matches!(err, FatError::BadCluster { cluster: 2 }));
    }

    #[test]
    fn next_cluster_fat12_follows_chain_and_returns_none_at_eoc() {
        let img = build_fat12_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        // FAT12 stores entries packed 1.5 bytes each:
        //   even cluster N: low 12 bits of u16 at offset N*1.5
        //   odd cluster N:  high 12 bits of u16 at offset N*1.5
        // FAT[2] (even) = 0x003 (next = 3); FAT[3] (odd) = 0xFFF (EOC).
        let next2 = fat.next_cluster(&mut cur, 2).expect("read FAT[2]");
        assert_eq!(next2, Some(3));
        let next3 = fat.next_cluster(&mut cur, 3).expect("read FAT[3]");
        assert_eq!(next3, None);
    }

    #[test]
    fn next_cluster_fat32_masks_high_4_bits_and_follows_chain() {
        let mut img = build_fat32_image();
        // Set FAT[2] = 0xF000_0003 — the high 4 bits should be masked off
        // so the next cluster is 3, not 0xF000_0003.
        let f = 32 * 512;
        img[f + 8..f + 12].copy_from_slice(&0xF000_0003u32.to_le_bytes());

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let next2 = fat.next_cluster(&mut cur, 2).expect("read FAT[2]");
        assert_eq!(next2, Some(3));
        let next3 = fat.next_cluster(&mut cur, 3).expect("read FAT[3]");
        assert_eq!(next3, None);
    }

    #[test]
    fn next_cluster_fat32_reports_bad_cluster_marker() {
        let mut img = build_fat32_image();
        let f = 32 * 512;
        img[f + 8..f + 12].copy_from_slice(&0x0FFF_FFF7u32.to_le_bytes());

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let err = fat.next_cluster(&mut cur, 2).unwrap_err();
        assert!(matches!(err, FatError::BadCluster { cluster: 2 }));
    }

    #[test]
    fn next_cluster_rejects_reserved_and_out_of_range_clusters() {
        // Catches `|| -> &&` and `> with ==/>=` at line 424 plus the
        // wholesale `Ok(None)/Some(0)/Some(1)` return mutants on the
        // generic `next_cluster` dispatcher.
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        assert!(matches!(
            fat.next_cluster(&mut cur, 0),
            Err(FatError::InvalidCluster { cluster: 0 })
        ));
        assert!(matches!(
            fat.next_cluster(&mut cur, 1),
            Err(FatError::InvalidCluster { cluster: 1 })
        ));
        // total_clusters + 1 = 4086 is valid (highest data cluster).
        // total_clusters + 2 = 4087 is out of range.
        assert!(matches!(
            fat.next_cluster(&mut cur, 4087),
            Err(FatError::InvalidCluster { cluster: 4087 })
        ));
    }

    // ----------------------------------------------------------------------
    // volume_name — locate the VOLUME_ID entry in the root directory.
    // ----------------------------------------------------------------------

    #[test]
    fn volume_name_returns_trimmed_label_from_root() {
        // Build an image with a VOLUME_ID entry whose label has trailing
        // spaces. The returned String must strip the trailing spaces
        // (anchors `+ with -/*` arithmetic on the trim-end position).
        let mut img = build_fat16_image();
        // FAT16: first_data_sector = 19, root_dir_sectors = 1, so
        // root_dir_offset = (19 - 1) * 512 = 9216 (sector 18).
        let r = 18 * 512;
        let mut name = *b"MYDISK     ";
        // Pad: MYDISK followed by spaces.
        img[r..r + 11].copy_from_slice(&name);
        // Attributes = VOLUME_ID (0x08).
        img[r + 0x0B] = 0x08;
        // Slot 1: end marker (already zero).

        // Silence the unused-var warning.
        let _ = &mut name;

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let label = fat.volume_name(&mut cur).expect("read");
        assert_eq!(label.as_deref(), Some("MYDISK"));
    }

    #[test]
    fn volume_name_returns_none_when_no_volume_id_entry() {
        // Catches `-> Ok(Some(...))` mutants on the volume_name return
        // path: with no VOLUME_ID entry in the root, the function must
        // return Ok(None).
        let mut img = build_fat16_image();
        let r = 18 * 512;
        // Slot 0: regular file (no VOLUME_ID).
        img[r..r + 11].copy_from_slice(b"DATA    TXT");
        img[r + 0x0B] = 0x20; // ARCHIVE
        // Slot 1: end marker.

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let label = fat.volume_name(&mut cur).expect("read");
        assert_eq!(label, None);
    }

    // ----------------------------------------------------------------------
    // Fat::open — path traversal with `..`, files, missing entries.
    // ----------------------------------------------------------------------

    #[test]
    fn open_returns_root_for_empty_or_slash_path() {
        // Catches the wholesale `Ok(...)` return mutants and the early
        // `components.peek().is_none()` branch.
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let root = fat.open(&mut cur, "").expect("empty path opens root");
        assert!(root.is_directory());
        assert_eq!(root.first_cluster(), None);

        let slash = fat.open(&mut cur, "/").expect("slash opens root");
        assert!(slash.is_directory());

        // Backslash also normalizes.
        let bslash = fat.open(&mut cur, "\\").expect("backslash opens root");
        assert!(bslash.is_directory());
    }

    #[test]
    fn open_not_found_returns_error() {
        // Catches `== with !=` boundary mutations in the open loop's
        // entry-lookup path.
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let err = fat.open(&mut cur, "/MISSING.TXT").unwrap_err();
        assert!(matches!(err, FatError::NotFound));
    }

    #[test]
    fn open_intermediate_non_directory_returns_not_a_directory() {
        // Place a regular file FILE.TXT at the root, then try to open
        // /FILE.TXT/INNER. The intermediate FILE.TXT is not a directory
        // → must return NotADirectory.
        let mut img = build_fat16_image();
        let r = 18 * 512;
        img[r..r + 11].copy_from_slice(b"FILE    TXT");
        img[r + 0x0B] = 0x20; // ARCHIVE
        // first_cluster_low = 0 (no real data needed for this test).

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let err = fat.open(&mut cur, "/FILE.TXT/INNER.TXT").unwrap_err();
        assert!(matches!(err, FatError::NotADirectory));
    }

    #[test]
    fn validate_sectors_per_cluster_rejects_zero_and_non_power_of_two() {
        // Pins both arms of the `|| ` chain: spc=0 trips the first
        // arm, spc=3 trips the second. spc=2 must succeed.
        assert!(matches!(
            Fat::validate_sectors_per_cluster(0),
            Err(FatError::InvalidSectorsPerCluster { actual: 0 })
        ));
        assert!(matches!(
            Fat::validate_sectors_per_cluster(3),
            Err(FatError::InvalidSectorsPerCluster { actual: 3 })
        ));
        assert!(matches!(
            Fat::validate_sectors_per_cluster(5),
            Err(FatError::InvalidSectorsPerCluster { actual: 5 })
        ));
        assert!(Fat::validate_sectors_per_cluster(1).is_ok());
        assert!(Fat::validate_sectors_per_cluster(2).is_ok());
        assert!(Fat::validate_sectors_per_cluster(8).is_ok());
        assert!(Fat::validate_sectors_per_cluster(128).is_ok());
    }

    #[test]
    fn cluster_size_and_total_sectors_for_fat32_use_bpb_arithmetic() {
        // Catches `* with +/-/` mutations on `size = total_sectors * sector_size`
        // (line 231) and `/ with *` on `data_sectors / sectors_per_cluster`
        // (line 226 in new_fat32). The expected size = 66069 * 512 =
        // 33_827_328; mutated `total_sectors + sector_size` = 66069+512 =
        // 66_581, far smaller.
        let img = build_fat32_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        assert_eq!(fat.size(), 66069u64 * 512);

        // FAT32 total_clusters = data_sectors / spc = 65525 / 1 = 65525.
        // Mutated `/ with *`: 65525 * 1 = 65525 (same — equivalent for spc=1).
        // To distinguish, we'd need spc > 1. The fat12 image has spc=1
        // (also indistinguishable). Build an explicit spc=2 image:
        // - bps=512, spc=2 → cluster_size=1024
        // - reserved=2, fats=1, spf16=4, root=16 (=1 sector), total=4112
        // - first_data = 2+4+1 = 7, data = 4105, total_clusters = 4105/2 = 2052 → FAT12
        let mut img = vec![0u8; 4112 * 512];
        img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        img[3..11].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 2; // spc=2
        img[0x0E..0x10].copy_from_slice(&2u16.to_le_bytes());
        img[0x10] = 1;
        img[0x11..0x13].copy_from_slice(&16u16.to_le_bytes());
        img[0x13..0x15].copy_from_slice(&4112u16.to_le_bytes());
        img[0x15] = 0xF8;
        img[0x16..0x18].copy_from_slice(&4u16.to_le_bytes());
        img[0x26] = 0x29;
        img[0x36..0x3E].copy_from_slice(b"FAT12   ");
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("spc=2 image parses");
        // total_clusters = (4112 - 7) / 2 = 4105 / 2 = 2052.
        assert_eq!(fat.cluster_size(), 1024);
        assert_eq!(fat.total_clusters(), 2052);
    }

    #[test]
    fn next_cluster_rejects_top_of_range_boundary() {
        // Catches `> with >=` at line 424 by feeding total_clusters + 1
        // (highest valid) and total_clusters + 2 (just past). Original
        // accepts the highest valid; mutated `>=` rejects it.
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        // Highest valid: total_clusters + 1 = 4086. Without writing FAT
        // table entries that far, reading FAT[4086] will return 0 (free)
        // and the function returns Some(0). The important thing is that
        // it does NOT return Err(InvalidCluster).
        let result = fat.next_cluster(&mut cur, 4086);
        assert!(
            !matches!(result, Err(FatError::InvalidCluster { cluster: 4086 })),
            "cluster 4086 must be accepted as in-range: got {result:?}",
        );
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn arbitrary_fat_type_maps_each_in_range_value_to_a_distinct_variant() {
        // Catches `delete match arm 0` and `delete match arm 1` in the
        // arbitrary impl. Use a buffer with varied bytes so that
        // `int_in_range(0..=2)` cycles through all three possible
        // inputs (0, 1, 2). If a match arm is deleted, the deleted
        // input value collapses into the `_ => Fat32` fall-through,
        // shrinking the set of observed variants from 3 to 2.
        use arbitrary::{Arbitrary, Unstructured};

        let seed: Vec<u8> = (0u8..=255).collect();
        let mut u = Unstructured::new(&seed);
        let mut seen_fat12 = false;
        let mut seen_fat16 = false;
        let mut seen_fat32 = false;
        for _ in 0..255 {
            match FatType::arbitrary(&mut u) {
                Ok(FatType::Fat12) => seen_fat12 = true,
                Ok(FatType::Fat16) => seen_fat16 = true,
                Ok(FatType::Fat32) => seen_fat32 = true,
                Err(_) => break,
            }
        }
        assert!(
            seen_fat12 && seen_fat16 && seen_fat32,
            "arbitrary must yield every FatType variant (got 12={seen_fat12}, 16={seen_fat16}, 32={seen_fat32})",
        );
    }

    #[test]
    fn new_fat32_divides_data_sectors_by_sectors_per_cluster() {
        // Catches `/ with *` at line 245 (`total_clusters = data_sectors /
        // spc`). Build a minimal image syntactically classified as FAT32
        // (sectors_per_fat_16 = 0 and root_entry_count = 0) with spc=2
        // so the divisor differs from 1 and `*` becomes observable.
        // FAT32 routine fires regardless of actual cluster count.
        let mut img = vec![0u8; 50 * 512];
        img[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        img[3..11].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 2; // spc=2
        img[0x0E..0x10].copy_from_slice(&32u16.to_le_bytes());
        img[0x10] = 1;
        img[0x15] = 0xF8;
        img[0x20..0x24].copy_from_slice(&50u32.to_le_bytes());
        img[0x24..0x28].copy_from_slice(&4u32.to_le_bytes()); // sectors_per_fat_32
        img[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes()); // root_cluster
        img[0x30..0x32].copy_from_slice(&0xFFFFu16.to_le_bytes());
        img[0x40] = 0x80;
        img[0x42] = 0x29;
        img[0x52..0x5A].copy_from_slice(b"FAT32   ");
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("parses as FAT32 layout");
        // total_clusters = (50 - 32 - 4) / 2 = 14 / 2 = 7.
        // Mutated `*`: 14 * 2 = 28.
        assert_eq!(fat.total_clusters(), 7);
        assert_eq!(fat.cluster_size(), 1024); // 512 * spc=2
    }

    #[test]
    fn next_cluster_fat12_shifts_odd_entry_right_to_recover_value() {
        // Build a FAT12 image where FAT[3] (odd cluster) points to a
        // specific data cluster. Anchors line 451's `>> 4` against `<< 4`:
        //   - Original `entry >> 4`: extracts the high 12 bits.
        //   - Mutated `entry << 4`: shifts the byte pattern left, often
        //     wrapping into the >=0x0FF8 EOC range and returning None.
        //
        // Layout: FAT[2] = 3, FAT[3] = 0x0A0 (data cluster 160), FAT[160] = EOC.
        // Bytes in the FAT table:
        //   FAT[2..3] occupy bytes 3..6:
        //     byte[3] = 0x03 (low 8 of FAT[2])
        //     byte[4] = (high 4 of FAT[2]) | (low 4 of FAT[3] << 4) = 0x00 | 0x00 = 0x00
        //               Wait — odd-cluster math: FAT[3] low 4 are stored in
        //               byte[4] high 4, FAT[3] high 8 are in byte[5].
        //               For FAT[3] = 0x0A0: low 4 = 0x0, high 8 = 0x0A.
        //               byte[4] = (high 4 of FAT[2]=0) | (low 4 of FAT[3]=0 << 4) = 0
        //               byte[5] = high 8 of FAT[3] = 0x0A
        let mut img = build_fat12_image();
        let f = 0x200;
        // Overwrite FAT[2..3]: FAT[2]=3, FAT[3]=0x0A0.
        img[f + 3] = 0x03; // low 8 of FAT[2]
        img[f + 4] = 0x00; // high 4 of FAT[2] (0) | low 4 of FAT[3] (0) << 4
        img[f + 5] = 0x0A; // high 8 of FAT[3]

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let next3 = fat.next_cluster(&mut cur, 3).expect("read FAT[3]");
        assert_eq!(
            next3,
            Some(0x0A0),
            "FAT[3] must decode to 0x0A0 via `entry >> 4`; mutated `<< 4` would produce 0x0A00 (>=0x0FF8, EOC)",
        );
    }
}
