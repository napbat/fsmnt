//! Partition-table parsing (MBR and GPT).
//!
//! This module provides parsing for:
//! - MBR (Master Boot Record) partition tables
//! - GPT (GUID Partition Table) partition tables
//!
//! # MBR structure
//! - 446 bytes: boot code
//! - 64 bytes: partition table (4 entries x 16 bytes)
//! - 2 bytes: boot signature (0x55, 0xAA)
//!
//! # GPT structure
//! - LBA 0: protective MBR
//! - LBA 1: GPT header
//! - LBA 2-33: partition entries (typically 128 entries x 128 bytes)

use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;

use zerocopy::byteorder::LittleEndian;
use zerocopy::{FromBytes, Immutable, KnownLayout, U16, U32, U64, Unaligned};

/// MBR boot signature.
const MBR_SIGNATURE: u16 = 0xAA55;

/// GPT signature `EFI PART` (as a little-endian integer).
const GPT_SIGNATURE: u64 = 0x5452_4150_2049_4645;

/// Size of an MBR partition entry.
const MBR_ENTRY_SIZE: usize = 16;

/// Size of a GPT partition entry (minimum).
const GPT_ENTRY_SIZE: usize = 128;

/// MBR partition type indicating a GPT protective MBR.
const MBR_TYPE_GPT_PROTECTIVE: u8 = 0xEE;

/// Null GUID (all zeros) — indicates an empty partition entry.
const NULL_GUID: [u8; 16] = [0; 16];

// Compile-time layout checks: these structures are cast directly from raw
// on-disk bytes, so their sizes must match the on-disk layout exactly.
const _: () = assert!(size_of::<MbrPartitionEntry>() == MBR_ENTRY_SIZE);
const _: () = assert!(size_of::<Mbr>() == 512);
const _: () = assert!(size_of::<GptHeader>() == 92);
const _: () = assert!(size_of::<GptPartitionEntry>() == GPT_ENTRY_SIZE);

/// MBR partition entry (16 bytes).
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct MbrPartitionEntry {
    /// Boot indicator (0x80 = bootable, 0x00 = not bootable).
    pub boot_indicator: u8,
    /// Starting head (CHS).
    pub start_head: u8,
    /// Starting sector and cylinder (CHS, packed).
    pub start_sector_cylinder: [u8; 2],
    /// Partition type (0x07 = NTFS, 0x0B/0x0C = FAT32, 0xEE = GPT protective).
    pub partition_type: u8,
    /// Ending head (CHS).
    pub end_head: u8,
    /// Ending sector and cylinder (CHS, packed).
    pub end_sector_cylinder: [u8; 2],
    /// Starting LBA (sector offset from start of disk).
    pub start_lba: U32<LittleEndian>,
    /// Number of sectors in partition.
    pub sector_count: U32<LittleEndian>,
}

impl MbrPartitionEntry {
    /// Check if this entry is empty/unused.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.partition_type == 0
    }

    /// Check if this is a GPT protective MBR entry.
    #[must_use]
    pub fn is_gpt_protective(&self) -> bool {
        self.partition_type == MBR_TYPE_GPT_PROTECTIVE
    }

    /// Get the starting byte offset of this partition.
    #[must_use]
    pub fn start_offset(&self, bytes_per_sector: u32) -> u64 {
        u64::from(self.start_lba.get()) * u64::from(bytes_per_sector)
    }

    /// Get the size of this partition in bytes.
    #[must_use]
    pub fn size_bytes(&self, bytes_per_sector: u32) -> u64 {
        u64::from(self.sector_count.get()) * u64::from(bytes_per_sector)
    }

    /// Get a human-readable name for common partition types.
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

/// MBR (Master Boot Record) — first 512 bytes of a disk.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Mbr {
    /// Boot code (446 bytes).
    pub boot_code: [u8; 446],
    /// Partition table (4 entries x 16 bytes = 64 bytes).
    pub partitions: [MbrPartitionEntry; 4],
    /// Boot signature (should be 0xAA55).
    pub signature: U16<LittleEndian>,
}

impl Mbr {
    /// Parse an MBR from a 512-byte sector.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < 512 {
            return None;
        }
        Self::ref_from_bytes(&data[..512]).ok()
    }

    /// Check if this is a valid MBR (has the correct signature).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.signature.get() == MBR_SIGNATURE
    }

    /// Check if this MBR indicates a GPT disk (protective MBR).
    #[must_use]
    pub fn is_gpt_protective(&self) -> bool {
        self.is_valid() && self.partitions[0].is_gpt_protective()
    }

    /// Iterator over non-empty partition entries.
    pub fn valid_partitions(&self) -> impl Iterator<Item = &MbrPartitionEntry> {
        self.partitions.iter().filter(|p| !p.is_empty())
    }
}

/// GPT header (LBA 1, 92 bytes minimum).
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct GptHeader {
    /// Signature `EFI PART` (`0x5452_4150_2049_4645`).
    pub signature: U64<LittleEndian>,
    /// Revision (typically `0x0001_0000` for version 1.0).
    pub revision: U32<LittleEndian>,
    /// Header size (usually 92).
    pub header_size: U32<LittleEndian>,
    /// CRC32 of the header (with this field zeroed).
    pub header_crc32: U32<LittleEndian>,
    /// Reserved (must be zero).
    pub reserved: U32<LittleEndian>,
    /// Current LBA (location of this header).
    pub current_lba: U64<LittleEndian>,
    /// Backup LBA (location of the backup header).
    pub backup_lba: U64<LittleEndian>,
    /// First usable LBA for partitions.
    pub first_usable_lba: U64<LittleEndian>,
    /// Last usable LBA for partitions.
    pub last_usable_lba: U64<LittleEndian>,
    /// Disk GUID.
    pub disk_guid: [u8; 16],
    /// Starting LBA of the partition entries.
    pub partition_entry_lba: U64<LittleEndian>,
    /// Number of partition entries.
    pub num_partition_entries: U32<LittleEndian>,
    /// Size of each partition entry (usually 128).
    pub partition_entry_size: U32<LittleEndian>,
    /// CRC32 of the partition entries array.
    pub partition_entries_crc32: U32<LittleEndian>,
}

impl GptHeader {
    /// Parse a GPT header from bytes (should be from LBA 1).
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < 92 {
            return None;
        }
        Self::ref_from_bytes(&data[..92]).ok()
    }

    /// Check if this is a valid GPT header.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.signature.get() == GPT_SIGNATURE
    }
}

/// GPT partition entry (128 bytes).
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct GptPartitionEntry {
    /// Partition type GUID.
    pub type_guid: [u8; 16],
    /// Unique partition GUID.
    pub partition_guid: [u8; 16],
    /// Starting LBA.
    pub start_lba: U64<LittleEndian>,
    /// Ending LBA (inclusive).
    pub end_lba: U64<LittleEndian>,
    /// Attribute flags.
    pub attributes: U64<LittleEndian>,
    /// Partition name (UTF-16LE, 36 characters).
    pub name: [u8; 72],
}

/// Format a GPT GUID as a standard UUID string.
///
/// GPT GUIDs are stored in mixed-endian format: the first three fields are
/// little-endian, the last two fields are big-endian.
fn format_guid(guid: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid[3],
        guid[2],
        guid[1],
        guid[0],
        guid[5],
        guid[4],
        guid[7],
        guid[6],
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

impl GptPartitionEntry {
    /// EFI System Partition GUID.
    pub const EFI_SYSTEM_GUID: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];

    /// Microsoft Basic Data GUID (NTFS, FAT32, etc.).
    pub const MICROSOFT_BASIC_DATA_GUID: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ];

    /// Microsoft Reserved Partition GUID.
    pub const MICROSOFT_RESERVED_GUID: [u8; 16] = [
        0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15,
        0xAE,
    ];

    /// Windows Recovery Environment GUID.
    pub const WINDOWS_RECOVERY_GUID: [u8; 16] = [
        0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D, 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6,
        0xAC,
    ];

    /// Parse a GPT partition entry from bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < GPT_ENTRY_SIZE {
            return None;
        }
        Self::ref_from_bytes(&data[..GPT_ENTRY_SIZE]).ok()
    }

    /// Check if this entry is empty/unused.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.type_guid == NULL_GUID
    }

    /// Get the starting byte offset of this partition.
    #[must_use]
    pub fn start_offset(&self, bytes_per_sector: u32) -> u64 {
        self.start_lba.get() * u64::from(bytes_per_sector)
    }

    /// Get the size of this partition in bytes.
    #[must_use]
    pub fn size_bytes(&self, bytes_per_sector: u32) -> u64 {
        (self.end_lba.get() - self.start_lba.get() + 1) * u64::from(bytes_per_sector)
    }

    /// Get the partition name as a string (UTF-16LE decoded).
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
    /// (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX).
    #[must_use]
    pub fn type_guid_string(&self) -> String {
        format_guid(&self.type_guid)
    }

    /// Format the unique partition GUID as a standard UUID string.
    #[must_use]
    pub fn partition_guid_string(&self) -> String {
        format_guid(&self.partition_guid)
    }

    /// Get a human-readable name for common GPT partition types.
    #[must_use]
    pub fn type_name(&self) -> Option<&'static str> {
        match self.type_guid {
            Self::EFI_SYSTEM_GUID => Some("EFI System"),
            Self::MICROSOFT_BASIC_DATA_GUID => Some("Basic Data (NTFS/FAT)"),
            Self::MICROSOFT_RESERVED_GUID => Some("Microsoft Reserved"),
            Self::WINDOWS_RECOVERY_GUID => Some("Windows Recovery"),
            _ => None,
        }
    }
}

/// Read the GPT header from a disk (reads LBA 1).
///
/// The reader may be positioned anywhere; this seeks to LBA 1 using
/// `sector_size` (in bytes, typically 512).
///
/// # Errors
///
/// Returns an error if seeking or reading fails, or if the bytes at LBA 1
/// do not carry a valid `EFI PART` signature.
pub fn read_gpt_header<R: Read + Seek>(
    reader: &mut R,
    sector_size: u64,
) -> std::io::Result<GptHeader> {
    // Seek to LBA 1.
    reader.seek(SeekFrom::Start(sector_size))?;

    // Read the GPT header (92 bytes, but keep a full sector for safety).
    let mut buffer = [0u8; 512];
    reader.read_exact(&mut buffer[..92])?;

    // Parse the header.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ------------------------------------------------------------------
    // Builders
    // ------------------------------------------------------------------

    fn mbr_entry_bytes(
        boot: u8,
        partition_type: u8,
        start_lba: u32,
        sector_count: u32,
    ) -> [u8; MBR_ENTRY_SIZE] {
        let mut bytes = [0u8; MBR_ENTRY_SIZE];
        bytes[0] = boot;
        bytes[4] = partition_type;
        bytes[8..12].copy_from_slice(&start_lba.to_le_bytes());
        bytes[12..16].copy_from_slice(&sector_count.to_le_bytes());
        bytes
    }

    fn build_mbr(entries: [[u8; MBR_ENTRY_SIZE]; 4], signature: u16) -> [u8; 512] {
        let mut buf = [0u8; 512];
        for (i, entry) in entries.iter().enumerate() {
            let offset = 446 + i * MBR_ENTRY_SIZE;
            buf[offset..offset + MBR_ENTRY_SIZE].copy_from_slice(entry);
        }
        buf[510..512].copy_from_slice(&signature.to_le_bytes());
        buf
    }

    fn build_gpt_header_bytes() -> [u8; 92] {
        let mut buf = [0u8; 92];
        buf[0..8].copy_from_slice(&GPT_SIGNATURE.to_le_bytes()); // signature
        buf[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision
        buf[12..16].copy_from_slice(&92u32.to_le_bytes()); // header_size
        buf[16..20].copy_from_slice(&0u32.to_le_bytes()); // header_crc32
        buf[24..32].copy_from_slice(&1u64.to_le_bytes()); // current_lba
        buf[32..40].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes()); // backup_lba
        buf[40..48].copy_from_slice(&34u64.to_le_bytes()); // first_usable_lba
        buf[48..56].copy_from_slice(&0xFFFF_F000u64.to_le_bytes()); // last_usable_lba
        // disk_guid (offset 56-71, 16 bytes) left zero
        buf[72..80].copy_from_slice(&2u64.to_le_bytes()); // partition_entry_lba
        buf[80..84].copy_from_slice(&128u32.to_le_bytes()); // num_partition_entries
        buf[84..88].copy_from_slice(&128u32.to_le_bytes()); // partition_entry_size
        // partition_entries_crc32 (offset 88-91) left zero
        buf
    }

    fn build_gpt_partition_entry(
        type_guid: [u8; 16],
        start_lba: u64,
        end_lba: u64,
        name_utf16: &[u16],
    ) -> [u8; GPT_ENTRY_SIZE] {
        let mut buf = [0u8; GPT_ENTRY_SIZE];
        buf[0..16].copy_from_slice(&type_guid);
        // partition_guid (16..32) left zero
        buf[32..40].copy_from_slice(&start_lba.to_le_bytes());
        buf[40..48].copy_from_slice(&end_lba.to_le_bytes());
        // attributes (48..56) left zero; name starts at 56
        for (i, &c) in name_utf16.iter().enumerate().take(36) {
            let off = 56 + i * 2;
            buf[off..off + 2].copy_from_slice(&c.to_le_bytes());
        }
        buf
    }

    /// A minimal two-sector disk image: zeroed LBA 0 plus a GPT header at
    /// LBA 1.
    fn build_gpt_disk_image() -> Vec<u8> {
        let mut buf = vec![0u8; 1024];
        buf[512..604].copy_from_slice(&build_gpt_header_bytes());
        buf
    }

    // ------------------------------------------------------------------
    // Structure sizes (catches accidental layout changes)
    // ------------------------------------------------------------------

    #[test]
    fn structure_sizes() {
        assert_eq!(size_of::<MbrPartitionEntry>(), MBR_ENTRY_SIZE);
        assert_eq!(size_of::<Mbr>(), 512);
        assert_eq!(size_of::<GptHeader>(), 92);
        assert_eq!(size_of::<GptPartitionEntry>(), GPT_ENTRY_SIZE);
    }

    // ------------------------------------------------------------------
    // MbrPartitionEntry
    // ------------------------------------------------------------------

    #[test]
    fn mbr_entry_is_empty_only_when_type_is_zero() {
        let empty_bytes = mbr_entry_bytes(0, 0, 0, 0);
        let empty = MbrPartitionEntry::ref_from_bytes(&empty_bytes).unwrap();
        assert!(empty.is_empty());

        let ntfs_bytes = mbr_entry_bytes(0, 0x07, 0, 0);
        let ntfs = MbrPartitionEntry::ref_from_bytes(&ntfs_bytes).unwrap();
        assert!(!ntfs.is_empty());

        // Type byte alone (without LBA/size) is enough to be "non-empty".
        let unknown_bytes = mbr_entry_bytes(0, 0xAB, 100, 200);
        let unknown = MbrPartitionEntry::ref_from_bytes(&unknown_bytes).unwrap();
        assert!(!unknown.is_empty());
    }

    #[test]
    fn mbr_entry_is_gpt_protective_matches_0xee_only() {
        let protective_bytes = mbr_entry_bytes(0, MBR_TYPE_GPT_PROTECTIVE, 1, 100);
        let protective = MbrPartitionEntry::ref_from_bytes(&protective_bytes).unwrap();
        assert!(protective.is_gpt_protective());

        let ntfs_bytes = mbr_entry_bytes(0, 0x07, 0, 0);
        let ntfs = MbrPartitionEntry::ref_from_bytes(&ntfs_bytes).unwrap();
        assert!(!ntfs.is_gpt_protective());
    }

    #[test]
    fn mbr_entry_offset_and_size_multiply_by_sector_size() {
        let bytes = mbr_entry_bytes(0, 0x07, 2048, 1024);
        let entry = MbrPartitionEntry::ref_from_bytes(&bytes).unwrap();
        // Distinct sector sizes so + / / cannot accidentally match *.
        assert_eq!(entry.start_offset(512), 2048 * 512);
        assert_eq!(entry.start_offset(4096), 2048 * 4096);
        assert_eq!(entry.size_bytes(512), 1024 * 512);
        assert_eq!(entry.size_bytes(4096), 1024 * 4096);
    }

    #[test]
    fn mbr_entry_type_name_distinct_for_each_known_type() {
        let pairs: &[(u8, &str)] = &[
            (0x07, "NTFS/HPFS/exFAT"),
            (0x0B, "FAT32 (CHS)"),
            (0x0C, "FAT32 (LBA)"),
            (0x0E, "FAT16 (LBA)"),
            (0x0F, "Extended (LBA)"),
            (0x82, "Linux Swap"),
            (0x83, "Linux"),
            (0xEE, "GPT Protective"),
            (0xEF, "EFI System"),
        ];
        for &(byte, label) in pairs {
            let bytes = mbr_entry_bytes(0, byte, 0, 0);
            let entry = MbrPartitionEntry::ref_from_bytes(&bytes).unwrap();
            assert_eq!(entry.type_name(), Some(label), "type 0x{byte:02X}");
        }

        // Unknown type — must return None.
        let unknown_bytes = mbr_entry_bytes(0, 0xAB, 0, 0);
        let unknown = MbrPartitionEntry::ref_from_bytes(&unknown_bytes).unwrap();
        assert_eq!(unknown.type_name(), None);
    }

    // ------------------------------------------------------------------
    // Mbr
    // ------------------------------------------------------------------

    #[test]
    fn mbr_from_bytes_requires_full_sector() {
        // 511 bytes is one short of a full MBR.
        let short = [0u8; 511];
        assert!(Mbr::from_bytes(&short).is_none());

        // 512+ succeeds; only the first 512 bytes are consumed.
        let full = [0u8; 512];
        assert!(Mbr::from_bytes(&full).is_some());

        let oversize = [0u8; 1024];
        assert!(Mbr::from_bytes(&oversize).is_some());
    }

    #[test]
    fn mbr_is_valid_only_when_signature_matches() {
        let entries = [mbr_entry_bytes(0, 0, 0, 0); 4];

        let buf = build_mbr(entries, MBR_SIGNATURE);
        assert!(Mbr::from_bytes(&buf).unwrap().is_valid());

        let bad = build_mbr(entries, 0x1234);
        assert!(!Mbr::from_bytes(&bad).unwrap().is_valid());

        // The 0xAA55 signature is little-endian; the wrong byte order is invalid.
        let swapped = build_mbr(entries, 0x55AA);
        assert!(!Mbr::from_bytes(&swapped).unwrap().is_valid());
    }

    #[test]
    fn mbr_is_gpt_protective_requires_valid_signature_and_protective_first_entry() {
        // Valid signature + first entry is GPT protective: yes.
        let mut entries = [mbr_entry_bytes(0, 0, 0, 0); 4];
        entries[0] = mbr_entry_bytes(0, MBR_TYPE_GPT_PROTECTIVE, 1, 0xFFFF_FFFF);
        let buf = build_mbr(entries, MBR_SIGNATURE);
        assert!(Mbr::from_bytes(&buf).unwrap().is_gpt_protective());

        // Valid signature but first entry NTFS — not GPT.
        let mut entries = [mbr_entry_bytes(0, 0, 0, 0); 4];
        entries[0] = mbr_entry_bytes(0, 0x07, 2048, 1000);
        let buf = build_mbr(entries, MBR_SIGNATURE);
        assert!(!Mbr::from_bytes(&buf).unwrap().is_gpt_protective());

        // Wrong signature, even with protective first entry — not GPT.
        let mut entries = [mbr_entry_bytes(0, 0, 0, 0); 4];
        entries[0] = mbr_entry_bytes(0, MBR_TYPE_GPT_PROTECTIVE, 1, 0xFFFF_FFFF);
        let buf = build_mbr(entries, 0xBEEF);
        assert!(!Mbr::from_bytes(&buf).unwrap().is_gpt_protective());
    }

    #[test]
    fn mbr_valid_partitions_filters_empty_entries() {
        let entries = [
            mbr_entry_bytes(0x80, 0x07, 2048, 1000),
            mbr_entry_bytes(0, 0, 0, 0),
            mbr_entry_bytes(0, 0x83, 3048, 2000),
            mbr_entry_bytes(0, 0, 0, 0),
        ];
        let buf = build_mbr(entries, MBR_SIGNATURE);
        let mbr = Mbr::from_bytes(&buf).unwrap();
        let valid: Vec<u8> = mbr.valid_partitions().map(|p| p.partition_type).collect();
        assert_eq!(valid, vec![0x07, 0x83]);

        // All-empty MBR yields an empty iterator.
        let empty_entries = [mbr_entry_bytes(0, 0, 0, 0); 4];
        let buf = build_mbr(empty_entries, MBR_SIGNATURE);
        let mbr = Mbr::from_bytes(&buf).unwrap();
        assert_eq!(mbr.valid_partitions().count(), 0);
    }

    // ------------------------------------------------------------------
    // GptHeader
    // ------------------------------------------------------------------

    #[test]
    fn gpt_header_from_bytes_requires_at_least_92_bytes() {
        let short = [0u8; 91];
        assert!(GptHeader::from_bytes(&short).is_none());

        let exact = [0u8; 92];
        assert!(GptHeader::from_bytes(&exact).is_some());

        let oversize = [0u8; 512];
        assert!(GptHeader::from_bytes(&oversize).is_some());
    }

    #[test]
    fn gpt_header_is_valid_only_for_efi_part_signature() {
        let buf = build_gpt_header_bytes();
        assert!(GptHeader::from_bytes(&buf).unwrap().is_valid());

        // Flip a byte in the signature — invalid.
        let mut bad = buf;
        bad[0] ^= 0xFF;
        assert!(!GptHeader::from_bytes(&bad).unwrap().is_valid());

        // Zero header (no signature) is not valid.
        let zeros = [0u8; 92];
        assert!(!GptHeader::from_bytes(&zeros).unwrap().is_valid());
    }

    // ------------------------------------------------------------------
    // GptPartitionEntry
    // ------------------------------------------------------------------

    #[test]
    fn gpt_entry_from_bytes_requires_128_bytes() {
        let short = [0u8; 127];
        assert!(GptPartitionEntry::from_bytes(&short).is_none());

        let exact = [0u8; GPT_ENTRY_SIZE];
        assert!(GptPartitionEntry::from_bytes(&exact).is_some());
    }

    #[test]
    fn gpt_entry_is_empty_only_for_null_type_guid() {
        let empty = build_gpt_partition_entry(NULL_GUID, 0, 0, &[]);
        assert!(GptPartitionEntry::from_bytes(&empty).unwrap().is_empty());

        let occupied = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 1, 100, &[]);
        assert!(!GptPartitionEntry::from_bytes(&occupied).unwrap().is_empty());

        // Any non-zero type GUID counts as occupied — flip a single bit.
        let mut almost = NULL_GUID;
        almost[7] = 0x01;
        let entry = build_gpt_partition_entry(almost, 0, 0, &[]);
        assert!(!GptPartitionEntry::from_bytes(&entry).unwrap().is_empty());
    }

    #[test]
    fn gpt_entry_start_offset_multiplies_lba_by_sector_size() {
        let entry = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 34, 2047, &[]);
        let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
        assert_eq!(parsed.start_offset(512), 34 * 512);
        assert_eq!(parsed.start_offset(4096), 34 * 4096);
    }

    #[test]
    fn gpt_entry_size_bytes_uses_inclusive_end_lba() {
        // sectors [start..=end] inclusive — (end - start + 1) sectors.
        let entry = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 100, 199, &[]);
        let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
        // 100 sectors of 512 = 51_200.
        assert_eq!(parsed.size_bytes(512), 100 * 512);

        // Single-sector partition: start == end — 1 sector.
        let single = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 50, 50, &[]);
        let single = GptPartitionEntry::from_bytes(&single).unwrap();
        assert_eq!(single.size_bytes(512), 512);
    }

    #[test]
    fn gpt_entry_name_string_decodes_utf16_until_null() {
        // "EFI" followed by 0 terminator, then a stray 'X'.
        let name = [0x0045u16, 0x0046, 0x0049, 0x0000, 0x0058];
        let entry = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 0, 0, &name);
        let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
        // take_while stops at the first NUL — the trailing 'X' is excluded.
        assert_eq!(parsed.name_string(), "EFI");

        // Empty name (all zeros) decodes to empty string.
        let empty_name = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 0, 0, &[]);
        assert_eq!(
            GptPartitionEntry::from_bytes(&empty_name)
                .unwrap()
                .name_string(),
            ""
        );
    }

    #[test]
    fn gpt_entry_guid_strings_format_mixed_endian_uuid() {
        // EFI System Partition GUID is the canonical mixed-endian test case:
        // bytes 0..4 little-endian, 4..6 LE, 6..8 LE, 8..16 big-endian (raw).
        let entry = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 0, 0, &[]);
        let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
        assert_eq!(
            parsed.type_guid_string(),
            "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
        );

        // First 4 bytes are emitted reversed: stored 0x01,0x02,0x03,0x04
        // formats as "04030201".
        let mut guid = [0u8; 16];
        guid[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        guid[4..6].copy_from_slice(&[0x05, 0x06]);
        guid[6..8].copy_from_slice(&[0x07, 0x08]);
        guid[8..16].copy_from_slice(&[0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);

        let mut entry = [0u8; GPT_ENTRY_SIZE];
        entry[0..16].copy_from_slice(&GptPartitionEntry::EFI_SYSTEM_GUID);
        entry[16..32].copy_from_slice(&guid);
        let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
        assert_eq!(
            parsed.partition_guid_string(),
            "04030201-0605-0807-090A-0B0C0D0E0F10"
        );
    }

    #[test]
    fn gpt_entry_type_name_distinct_for_each_known_guid() {
        let pairs: &[([u8; 16], &str)] = &[
            (GptPartitionEntry::EFI_SYSTEM_GUID, "EFI System"),
            (
                GptPartitionEntry::MICROSOFT_BASIC_DATA_GUID,
                "Basic Data (NTFS/FAT)",
            ),
            (
                GptPartitionEntry::MICROSOFT_RESERVED_GUID,
                "Microsoft Reserved",
            ),
            (GptPartitionEntry::WINDOWS_RECOVERY_GUID, "Windows Recovery"),
        ];
        for &(guid, label) in pairs {
            let entry = build_gpt_partition_entry(guid, 0, 0, &[]);
            let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
            assert_eq!(parsed.type_name(), Some(label));
        }

        // Unknown GUID — type_name must return None.
        let mut unknown = [0u8; 16];
        unknown[0] = 0xDE;
        unknown[1] = 0xAD;
        let entry = build_gpt_partition_entry(unknown, 0, 0, &[]);
        let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
        assert_eq!(parsed.type_name(), None);
    }

    // ------------------------------------------------------------------
    // read_gpt_header
    // ------------------------------------------------------------------

    #[test]
    fn read_gpt_header_seeks_to_lba_1_and_returns_parsed_header() {
        let mut cursor = Cursor::new(build_gpt_disk_image());
        let header = read_gpt_header(&mut cursor, 512).unwrap();
        assert!(header.is_valid());
        assert_eq!(header.partition_entry_lba.get(), 2);
        assert_eq!(header.num_partition_entries.get(), 128);
        assert_eq!(header.partition_entry_size.get(), 128);
    }

    #[test]
    fn read_gpt_header_rejects_signature_mismatch() {
        let mut disk = build_gpt_disk_image();
        // Corrupt the GPT signature at LBA 1.
        disk[512] ^= 0xFF;
        let mut cursor = Cursor::new(disk);
        let err = read_gpt_header(&mut cursor, 512).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_gpt_header_uses_sector_size_for_lba_1_offset() {
        // With 4096-byte sectors, LBA 1 begins at byte 4096.
        let mut buf = vec![0u8; 8192];
        buf[4096..4188].copy_from_slice(&build_gpt_header_bytes());
        let mut cursor = Cursor::new(buf);
        let header = read_gpt_header(&mut cursor, 4096).unwrap();
        assert!(header.is_valid());
    }
}
