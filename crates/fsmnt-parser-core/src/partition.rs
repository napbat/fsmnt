//! Partition Table Parsing (MBR and GPT)
//!
//! This module provides parsing for:
//! - MBR (Master Boot Record) partition tables
//! - GPT (GUID Partition Table) partition tables
//!
//! # MBR Structure
//! - 446 bytes: boot code
//! - 64 bytes: partition table (4 entries × 16 bytes)
//! - 2 bytes: boot signature (0x55AA)
//!
//! # GPT Structure
//! - LBA 0: Protective MBR
//! - LBA 1: GPT Header
//! - LBA 2-33: Partition entries (typically 128 entries × 128 bytes)

use alloc::{format, string::String, vec::Vec};

use zerocopy::byteorder::LittleEndian;
use zerocopy::{FromBytes, Immutable, KnownLayout, U16, U32, U64, Unaligned};

/// MBR boot signature
pub const MBR_SIGNATURE: u16 = 0xAA55;

/// GPT signature "EFI PART"
pub const GPT_SIGNATURE: u64 = 0x5452_4150_2049_4645; // "EFI PART" in little-endian

/// Size of an MBR partition entry
pub const MBR_ENTRY_SIZE: usize = 16;

/// Size of a GPT partition entry (minimum)
pub const GPT_ENTRY_SIZE: usize = 128;

/// MBR partition type indicating GPT protective MBR
pub const MBR_TYPE_GPT_PROTECTIVE: u8 = 0xEE;

/// MBR Partition Entry (16 bytes)
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct MbrPartitionEntry {
    /// Boot indicator (0x80 = bootable, 0x00 = not bootable)
    pub boot_indicator: u8,
    /// Starting head (CHS)
    pub start_head: u8,
    /// Starting sector and cylinder (CHS, packed)
    pub start_sector_cylinder: [u8; 2],
    /// Partition type (0x07 = NTFS, 0x0B/0x0C = FAT32, 0xEE = GPT protective)
    pub partition_type: u8,
    /// Ending head (CHS)
    pub end_head: u8,
    /// Ending sector and cylinder (CHS, packed)
    pub end_sector_cylinder: [u8; 2],
    /// Starting LBA (sector offset from start of disk)
    pub start_lba: U32<LittleEndian>,
    /// Number of sectors in partition
    pub sector_count: U32<LittleEndian>,
}

impl MbrPartitionEntry {
    /// Check if this entry is empty/unused
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.partition_type == 0
    }

    /// Check if this is a GPT protective MBR entry
    #[must_use]
    pub fn is_gpt_protective(&self) -> bool {
        self.partition_type == MBR_TYPE_GPT_PROTECTIVE
    }

    /// Get the starting byte offset of this partition
    #[must_use]
    pub fn start_offset(&self, bytes_per_sector: u32) -> u64 {
        u64::from(self.start_lba.get()) * u64::from(bytes_per_sector)
    }

    /// Get the size of this partition in bytes
    #[must_use]
    pub fn size_bytes(&self, bytes_per_sector: u32) -> u64 {
        u64::from(self.sector_count.get()) * u64::from(bytes_per_sector)
    }
}

/// MBR (Master Boot Record) - first 512 bytes of disk
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Mbr {
    /// Boot code (446 bytes)
    pub boot_code: [u8; 446],
    /// Partition table (4 entries × 16 bytes = 64 bytes)
    pub partitions: [MbrPartitionEntry; 4],
    /// Boot signature (should be 0xAA55)
    pub signature: U16<LittleEndian>,
}

impl Mbr {
    /// Parse MBR from a 512-byte sector
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < 512 {
            return None;
        }
        Self::ref_from_bytes(&data[..512]).ok()
    }

    /// Check if this is a valid MBR (has correct signature)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.signature.get() == MBR_SIGNATURE
    }

    /// Check if this MBR indicates a GPT disk (protective MBR)
    #[must_use]
    pub fn is_gpt_protective(&self) -> bool {
        self.is_valid() && self.partitions[0].is_gpt_protective()
    }

    /// Iterator over non-empty partition entries
    pub fn valid_partitions(&self) -> impl Iterator<Item = &MbrPartitionEntry> {
        self.partitions.iter().filter(|p| !p.is_empty())
    }

    /// Whether the four entries look like a table someone wrote rather than
    /// random bytes that happen to end in `55 AA`.
    ///
    /// Two bytes of signature are cheap for arbitrary data to reproduce — a
    /// scan over a multi-gigabyte medium meets one every few megabytes — so
    /// a table is credible only if the entries agree with the rules every
    /// partitioning tool follows: the boot indicator is 0x00 or 0x80 and
    /// nothing else, a used entry names a non-empty extent that does not
    /// begin at sector 0 (which is the table's own sector), and no two
    /// extents overlap. Deliberately not consulted by boot-sector parsing:
    /// a real but damaged table should still be read and reported, whereas
    /// a scan needs to stop inventing partition tables out of file data.
    #[must_use]
    pub fn is_plausible_table(&self) -> bool {
        let mut extents = [None; 4];
        for (index, entry) in self.partitions.iter().enumerate() {
            if entry.is_empty() {
                continue;
            }
            if entry.boot_indicator != 0x00 && entry.boot_indicator != 0x80 {
                return false;
            }
            let start = u64::from(entry.start_lba.get());
            let sectors = u64::from(entry.sector_count.get());
            if start == 0 || sectors == 0 {
                return false;
            }
            let end = start.saturating_add(sectors);
            if extents
                .iter()
                .flatten()
                .any(|&(other_start, other_end)| start < other_end && other_start < end)
            {
                return false;
            }
            extents[index] = Some((start, end));
        }
        true
    }
}

/// GPT Header (LBA 1, 92 bytes minimum)
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct GptHeader {
    /// Signature "EFI PART" (0x5452415020494645)
    pub signature: U64<LittleEndian>,
    /// Revision (typically 0x00010000 for version 1.0)
    pub revision: U32<LittleEndian>,
    /// Header size (usually 92)
    pub header_size: U32<LittleEndian>,
    /// CRC32 of header (with this field zeroed)
    pub header_crc32: U32<LittleEndian>,
    /// Reserved (must be zero)
    pub reserved: U32<LittleEndian>,
    /// Current LBA (location of this header)
    pub current_lba: U64<LittleEndian>,
    /// Backup LBA (location of backup header)
    pub backup_lba: U64<LittleEndian>,
    /// First usable LBA for partitions
    pub first_usable_lba: U64<LittleEndian>,
    /// Last usable LBA for partitions
    pub last_usable_lba: U64<LittleEndian>,
    /// Disk GUID
    pub disk_guid: [u8; 16],
    /// Starting LBA of partition entries
    pub partition_entry_lba: U64<LittleEndian>,
    /// Number of partition entries
    pub num_partition_entries: U32<LittleEndian>,
    /// Size of each partition entry (usually 128)
    pub partition_entry_size: U32<LittleEndian>,
    /// CRC32 of partition entries array
    pub partition_entries_crc32: U32<LittleEndian>,
}

impl GptHeader {
    /// Parse GPT header from bytes (should be from LBA 1)
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < 92 {
            return None;
        }
        Self::ref_from_bytes(&data[..92]).ok()
    }

    /// Check if this is a valid GPT header
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.signature.get() == GPT_SIGNATURE
    }
}

/// GPT Partition Entry (128 bytes)
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct GptPartitionEntry {
    /// Partition type GUID
    pub type_guid: [u8; 16],
    /// Unique partition GUID
    pub partition_guid: [u8; 16],
    /// Starting LBA
    pub start_lba: U64<LittleEndian>,
    /// Ending LBA (inclusive)
    pub end_lba: U64<LittleEndian>,
    /// Attribute flags
    pub attributes: U64<LittleEndian>,
    /// Partition name (UTF-16LE, 36 characters)
    pub name: [u8; 72],
}

/// Null GUID (all zeros) - indicates empty partition entry
const NULL_GUID: [u8; 16] = [0; 16];

impl GptPartitionEntry {
    /// Parse GPT partition entry from bytes
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < 128 {
            return None;
        }
        Self::ref_from_bytes(&data[..128]).ok()
    }

    /// Check if this entry is empty/unused
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.type_guid == NULL_GUID
    }

    /// Get the starting byte offset of this partition
    #[must_use]
    pub fn start_offset(&self, bytes_per_sector: u32) -> u64 {
        self.start_lba.get() * u64::from(bytes_per_sector)
    }

    /// Get the size of this partition in bytes
    #[must_use]
    pub fn size_bytes(&self, bytes_per_sector: u32) -> u64 {
        (self.end_lba.get() - self.start_lba.get() + 1) * u64::from(bytes_per_sector)
    }

    /// Get partition name as string (UTF-16LE to String)
    #[must_use]
    pub fn name_string(&self) -> String {
        let u16_chars: Vec<u16> = self
            .name
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&u16_chars)
    }

    /// Format the type GUID as a standard UUID string
    /// Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    #[must_use]
    pub fn type_guid_string(&self) -> String {
        // GPT GUIDs are stored in mixed-endian format:
        // - First 3 fields are little-endian
        // - Last 2 fields are big-endian
        format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.type_guid[3],
            self.type_guid[2],
            self.type_guid[1],
            self.type_guid[0],
            self.type_guid[5],
            self.type_guid[4],
            self.type_guid[7],
            self.type_guid[6],
            self.type_guid[8],
            self.type_guid[9],
            self.type_guid[10],
            self.type_guid[11],
            self.type_guid[12],
            self.type_guid[13],
            self.type_guid[14],
            self.type_guid[15]
        )
    }

    /// Format the unique partition GUID as a standard UUID string
    #[must_use]
    pub fn partition_guid_string(&self) -> String {
        format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.partition_guid[3],
            self.partition_guid[2],
            self.partition_guid[1],
            self.partition_guid[0],
            self.partition_guid[5],
            self.partition_guid[4],
            self.partition_guid[7],
            self.partition_guid[6],
            self.partition_guid[8],
            self.partition_guid[9],
            self.partition_guid[10],
            self.partition_guid[11],
            self.partition_guid[12],
            self.partition_guid[13],
            self.partition_guid[14],
            self.partition_guid[15]
        )
    }
}

// Common MBR partition type constants
impl MbrPartitionEntry {
    /// Get human-readable name for common partition types
    #[must_use]
    pub fn type_name(&self) -> Option<&'static str> {
        match self.partition_type {
            0x07 => Some("NTFS/HPFS/exFAT"),
            0x0B => Some("FAT32 (CHS)"),
            0x0C => Some("FAT32 (LBA)"),
            0x0E => Some("FAT16 (LBA)"),
            0x0F => Some("Extended (LBA)"),
            0x83 => Some("Linux"),
            0x82 => Some("Linux Swap"),
            0xEE => Some("GPT Protective"),
            0xEF => Some("EFI System"),
            _ => None,
        }
    }
}

// Well-known GPT partition type GUIDs
impl GptPartitionEntry {
    /// EFI System Partition GUID
    pub const EFI_SYSTEM_GUID: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];

    /// Microsoft Basic Data GUID (NTFS, FAT32, etc.)
    pub const MICROSOFT_BASIC_DATA_GUID: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ];

    /// Microsoft Reserved Partition GUID
    pub const MICROSOFT_RESERVED_GUID: [u8; 16] = [
        0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15,
        0xAE,
    ];

    /// Windows Recovery Environment GUID
    pub const WINDOWS_RECOVERY_GUID: [u8; 16] = [
        0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D, 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6,
        0xAC,
    ];

    /// Generic Linux filesystem-data GUID.
    ///
    /// Its canonical UUID is `0FC63DAF-8483-4772-8E79-3D69D8477DE4`;
    /// the bytes below use GPT's mixed-endian on-disk representation.
    pub const LINUX_FILESYSTEM_GUID: [u8; 16] = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ];

    /// Get human-readable name for common GPT partition types
    #[must_use]
    pub fn type_name(&self) -> Option<&'static str> {
        match self.type_guid {
            Self::EFI_SYSTEM_GUID => Some("EFI System"),
            Self::MICROSOFT_BASIC_DATA_GUID => Some("Basic Data (NTFS/FAT)"),
            Self::MICROSOFT_RESERVED_GUID => Some("Microsoft Reserved"),
            Self::WINDOWS_RECOVERY_GUID => Some("Windows Recovery"),
            Self::LINUX_FILESYSTEM_GUID => Some("Linux filesystem"),
            _ => None,
        }
    }
}

/// Read GPT header from a disk (reads LBA 1)
///
/// # Arguments
/// * `reader` - A reader positioned anywhere (will seek to LBA 1)
/// * `sector_size` - Sector size in bytes (typically 512)
///
/// # Errors
///
/// Returns an I/O error when the header cannot be read or its signature is invalid.
#[cfg(feature = "std")]
pub fn read_gpt_header<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    sector_size: u64,
) -> std::io::Result<GptHeader> {
    use std::io::SeekFrom;

    // Seek to LBA 1
    reader.seek(SeekFrom::Start(sector_size))?;

    // Read the GPT header (92 bytes, but read full sector for safety)
    let mut buffer = [0u8; 512];
    reader.read_exact(&mut buffer[..92])?;

    // Parse the header
    let header = GptHeader::ref_from_bytes(&buffer[..92])
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid GPT header"))?;

    if !header.is_valid() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "GPT signature mismatch",
        ));
    }

    Ok(*header)
}

/// Read GPT partition entries from a disk
///
/// # Arguments
/// * `reader` - A reader positioned anywhere (will seek to partition entry LBA)
/// * `header` - The GPT header (to know where partition entries are)
/// * `sector_size` - Sector size in bytes (typically 512)
///
/// # Returns
/// A vector of non-empty partition entries
///
/// # Errors
///
/// Returns an I/O error when seeking or reading the partition array fails.
#[cfg(feature = "std")]
pub fn read_gpt_partitions<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    header: &GptHeader,
    sector_size: u64,
) -> std::io::Result<Vec<GptPartitionEntry>> {
    use std::io::SeekFrom;

    let entry_lba = header.partition_entry_lba.get();
    let num_entries = header.num_partition_entries.get() as usize;
    let entry_size = header.partition_entry_size.get() as usize;

    // Seek to partition entries
    reader.seek(SeekFrom::Start(entry_lba * sector_size))?;

    let mut partitions = Vec::new();
    let mut buffer = vec![0u8; entry_size];

    for _ in 0..num_entries {
        reader.read_exact(&mut buffer)?;

        if buffer.len() >= GPT_ENTRY_SIZE
            && let Ok(entry) = GptPartitionEntry::ref_from_bytes(&buffer[..GPT_ENTRY_SIZE])
            && !entry.is_empty()
        {
            partitions.push(*entry);
        }
    }

    Ok(partitions)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "partition_tests/mod.rs"]
mod tests;
