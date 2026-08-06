//! Boot Sector and BIOS Parameter Block (BPB) Parsing for IBM-Compatible Filesystems
//!
//! This module provides comprehensive parsing for boot sectors across:
//! - FAT12/FAT16 (DOS 2.0 through DOS 4.0+ EBPB)
//! - FAT32 (DOS 7.1 EBPB)
//! - NTFS (Windows NT/2000/XP+)
//! - exFAT (SDXC cards, large removable media)
//! - HPFS (OS/2, shares DOS 4.0 EBPB structure)
//!
//! References:
//! - Microsoft FAT32 File System Specification (fatgen103.doc)
//! - Microsoft NTFS Technical Reference
//! - Microsoft exFAT Specification
//! - OSDev Wiki FAT/NTFS documentation
//! - Wikipedia BIOS Parameter Block

use zerocopy::byteorder::LittleEndian;
use zerocopy::{FromBytes, Immutable, KnownLayout, U16, U32, U64, Unaligned};

/// Standard boot sector size for IBM PC compatible systems
pub const BOOT_SECTOR_SIZE: usize = 512;

/// Probe length for filesystem-type detection. Large enough to include
/// ext's superblock magic at offset 0x438. Callers that want filesystem
/// detection (not just partition-table detection) should read this many
/// bytes before calling [`DetectedBootSector::from_bytes`].
pub const FS_DETECT_PROBE_SIZE: usize = 2048;

/// Boot signature value (little-endian: 0x55 at offset 510, 0xAA at offset 511)
pub const BOOT_SIGNATURE: u16 = 0xAA55;

const EXT_SUPERBLOCK_OFFSET: usize = 1024;
const SB_S_LOG_BLOCK_SIZE: usize = 0x18;
const SB_S_BLOCKS_PER_GROUP: usize = 0x20;
const SB_S_INODES_PER_GROUP: usize = 0x28;
const SB_S_MAGIC: usize = 0x38;
const EXT_PROBE_MIN_LEN: usize = EXT_SUPERBLOCK_OFFSET + SB_S_MAGIC + 2; // 0x43A
const EXT_MAGIC: u16 = 0xEF53;

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Prefix probe for ext2/ext3/ext4 superblock. Runs cheap sanity checks
/// beyond s_magic to avoid misclassifying GPT partition-entry arrays
/// (where a coincidental 0xEF53 at offset 0x438 would otherwise match).
fn probe_ext(buf: &[u8]) -> bool {
    if buf.len() < EXT_PROBE_MIN_LEN {
        return false;
    }
    if read_u16_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_MAGIC) != EXT_MAGIC {
        return false;
    }
    // s_log_block_size gates 0..=6 (block size 1 KiB .. 64 KiB) per
    // fs-ext's own superblock parser.
    if read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE) > 6 {
        return false;
    }
    if read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCKS_PER_GROUP) == 0 {
        return false;
    }
    if read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_INODES_PER_GROUP) == 0 {
        return false;
    }
    true
}

/// `nx_magic` of an APFS container superblock — the bytes `NXSB`.
const APFS_NX_MAGIC: u32 = u32::from_le_bytes(*b"NXSB");
/// Offset of `nx_magic` within the block-zero container superblock.
const APFS_NX_MAGIC_OFFSET: usize = 0x20;
/// Offset of the object type within an `obj_phys_t` header.
const APFS_OBJECT_TYPE_OFFSET: usize = 0x18;
/// Offset of `nx_block_size`.
const APFS_NX_BLOCK_SIZE_OFFSET: usize = 0x24;
/// `OBJECT_TYPE_NX_SUPERBLOCK`, in the low 16 bits of the object type.
const APFS_OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x0000_0001;
/// Mask selecting the object-type bits from the type/flags word.
const APFS_OBJECT_TYPE_MASK: u32 = 0x0000_FFFF;
/// Minimum probe length to reach `nx_block_size`.
const APFS_PROBE_MIN_LEN: usize = APFS_NX_BLOCK_SIZE_OFFSET + 4;

/// Prefix probe for an APFS container superblock. APFS has no `0xAA55`
/// boot signature, so detection keys on the `NXSB` magic at offset 0x20,
/// confirmed by the block-zero object identifying as an `nx_superblock_t`
/// with a power-of-two block size.
fn probe_apfs(buf: &[u8]) -> bool {
    if buf.len() < APFS_PROBE_MIN_LEN {
        return false;
    }
    if read_u32_le(buf, APFS_NX_MAGIC_OFFSET) != APFS_NX_MAGIC {
        return false;
    }
    if read_u32_le(buf, APFS_OBJECT_TYPE_OFFSET) & APFS_OBJECT_TYPE_MASK
        != APFS_OBJECT_TYPE_NX_SUPERBLOCK
    {
        return false;
    }
    let block_size = read_u32_le(buf, APFS_NX_BLOCK_SIZE_OFFSET);
    block_size.is_power_of_two() && (512..=65536).contains(&block_size)
}

// ============================================================================
// Common Structures (shared across filesystem types)
// ============================================================================

/// Jump instruction and OEM identifier at the start of every boot sector
///
/// Offset 0x00-0x0A (11 bytes)
/// All IBM PC compatible boot sectors start with a jump instruction followed
/// by an 8-byte OEM identifier string.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct BootSectorHeader {
    /// Jump instruction to skip over BPB (typically EB xx 90 or E9 xx xx)
    /// - EB xx 90: JMP SHORT xx; NOP (most common)
    /// - E9 xx xx: JMP NEAR xxxx
    /// - exFAT requires: EB 76 90
    pub jump_instruction: [u8; 3],

    /// OEM identifier (8 bytes, space-padded)
    /// Common values:
    /// - "NTFS    " for NTFS
    /// - "EXFAT   " for exFAT
    /// - "MSDOS5.0" for FAT (various versions exist)
    /// - "mkdosfs " for Linux-formatted FAT
    ///
    /// Note: Microsoft recommends not trusting this for filesystem detection
    pub oem_id: [u8; 8],
}

impl BootSectorHeader {
    /// Check if this appears to be an NTFS volume based on OEM ID
    pub fn is_ntfs(&self) -> bool {
        &self.oem_id == b"NTFS    "
    }

    /// Check if this appears to be an exFAT volume based on OEM ID
    pub fn is_exfat(&self) -> bool {
        &self.oem_id == b"EXFAT   "
    }

    /// Check if this appears to be a BitLocker-encrypted volume based on OEM ID
    pub fn is_bitlocker(&self) -> bool {
        &self.oem_id == b"-FVE-FS-"
    }

    /// Get the OEM ID as a string (trimming trailing spaces/nulls)
    pub fn oem_id_str(&self) -> &str {
        let s = core::str::from_utf8(&self.oem_id).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }
}

/// DOS 3.31 BIOS Parameter Block (25 bytes)
///
/// Offset 0x0B-0x23
/// This is the "standard" BPB shared by FAT12, FAT16, FAT32, NTFS, and HPFS.
/// Some fields have different meanings or are unused in NTFS.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct DosBpb {
    /// Bytes per logical sector (typically 512, 1024, 2048, or 4096)
    /// Offset 0x0B
    pub bytes_per_sector: U16<LittleEndian>,

    /// Logical sectors per cluster (power of 2: 1, 2, 4, 8, 16, 32, 64, 128)
    /// Offset 0x0D
    pub sectors_per_cluster: u8,

    /// Reserved sectors before the first FAT (includes boot sector)
    /// - FAT12/16: typically 1
    /// - FAT32: typically 32
    /// - NTFS: always 0
    ///
    /// Offset 0x0E
    pub reserved_sectors: U16<LittleEndian>,

    /// Number of FAT copies (typically 2 for redundancy)
    /// - NTFS: always 0
    ///
    /// Offset 0x10
    pub num_fats: u8,

    /// Maximum root directory entries (FAT12/16 only)
    /// - FAT32: must be 0
    /// - NTFS: not used (0)
    ///
    /// Offset 0x11
    pub root_entry_count: U16<LittleEndian>,

    /// Total logical sectors (16-bit, for small volumes)
    /// If 0, use total_sectors_32 instead
    /// - NTFS: not used (0)
    ///
    /// Offset 0x13
    pub total_sectors_16: U16<LittleEndian>,

    /// Media descriptor byte
    /// - 0xF8: Fixed disk
    /// - 0xF0: 3.5" 1.44MB floppy
    /// - Other values for various floppy formats
    ///
    /// Offset 0x15
    pub media_descriptor: u8,

    /// Logical sectors per FAT (FAT12/16 only)
    /// - FAT32: must be 0 (use fat_size_32 in EBPB)
    /// - NTFS: always 0
    ///
    /// Offset 0x16
    pub sectors_per_fat_16: U16<LittleEndian>,

    /// Sectors per track (CHS geometry for BIOS INT 13h)
    /// Offset 0x18
    pub sectors_per_track: U16<LittleEndian>,

    /// Number of heads (CHS geometry for BIOS INT 13h)
    /// Offset 0x1A
    pub num_heads: U16<LittleEndian>,

    /// Hidden sectors preceding this partition
    /// (LBA of the partition start for partitioned media)
    ///
    /// Offset 0x1C
    pub hidden_sectors: U32<LittleEndian>,

    /// Total logical sectors (32-bit, for large volumes)
    /// Used when total_sectors_16 is 0
    /// - NTFS: not used (0), uses 64-bit field in EBPB
    ///
    /// Offset 0x20
    pub total_sectors_32: U32<LittleEndian>,
}

impl DosBpb {
    /// Get the total number of sectors (choosing 16 or 32-bit field)
    /// Note: For NTFS/exFAT, use the 64-bit field in the extended BPB
    pub fn total_sectors(&self) -> u32 {
        let ts16 = self.total_sectors_16.get();
        if ts16 != 0 {
            ts16 as u32
        } else {
            self.total_sectors_32.get()
        }
    }

    /// Get cluster size in bytes
    pub fn cluster_size(&self) -> u32 {
        self.bytes_per_sector.get() as u32 * self.sectors_per_cluster as u32
    }

    /// Check if this could be an NTFS volume (certain fields must be 0)
    pub fn looks_like_ntfs(&self) -> bool {
        self.reserved_sectors.get() == 0
            && self.num_fats == 0
            && self.root_entry_count.get() == 0
            && self.sectors_per_fat_16.get() == 0
    }

    /// Check if this could be an exFAT volume (bytes_per_sector field is 0)
    pub fn looks_like_exfat(&self) -> bool {
        self.bytes_per_sector.get() == 0
    }
}

// ============================================================================
// FAT12/FAT16 Extended BIOS Parameter Block
// ============================================================================

/// DOS 4.0 Extended BIOS Parameter Block for FAT12/FAT16 (26 bytes)
///
/// Offset 0x24-0x3D
/// This structure follows the DosBpb for FAT12 and FAT16 volumes.
/// Also used by HPFS (OS/2).
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Fat16Ebpb {
    /// Physical drive number (BIOS INT 13h)
    /// - 0x00: Floppy disk
    /// - 0x80: First hard disk
    ///
    /// Offset 0x24
    pub drive_number: u8,

    /// Reserved (used by Windows NT for flags)
    ///
    /// Offset 0x25
    pub reserved1: u8,

    /// Extended boot signature
    /// - 0x29: All three following fields are valid
    /// - 0x28: Only volume_serial_number is valid
    ///
    /// Offset 0x26
    pub boot_signature: u8,

    /// Volume serial number (random value set at format time)
    ///
    /// Offset 0x27
    pub volume_serial_number: U32<LittleEndian>,

    /// Volume label (11 bytes, space-padded)
    /// Matches the volume label in the root directory
    ///
    /// Offset 0x2B
    pub volume_label: [u8; 11],

    /// Filesystem type label (8 bytes, space-padded)
    /// Typically "FAT12   ", "FAT16   ", or "FAT     "
    /// WARNING: Do not use this for filesystem detection!
    ///
    /// Offset 0x36
    pub filesystem_type: [u8; 8],
}

impl Fat16Ebpb {
    /// Check if the extended fields are valid
    pub fn has_extended_fields(&self) -> bool {
        self.boot_signature == 0x29 || self.boot_signature == 0x28
    }

    /// Get volume label as string (trimming trailing spaces)
    pub fn volume_label_str(&self) -> &str {
        let s = core::str::from_utf8(&self.volume_label).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }

    /// Get filesystem type label as string
    pub fn filesystem_type_str(&self) -> &str {
        let s = core::str::from_utf8(&self.filesystem_type).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }
}

// ============================================================================
// FAT32 Extended BIOS Parameter Block
// ============================================================================

/// DOS 7.1 Extended BIOS Parameter Block for FAT32 (54 bytes)
///
/// Offset 0x24-0x59
/// FAT32 has a completely different extended BPB structure.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Fat32Ebpb {
    /// Sectors per FAT (32-bit, for FAT32's large FAT)
    ///
    /// Offset 0x24
    pub sectors_per_fat_32: U32<LittleEndian>,

    /// Extended flags
    /// - Bits 0-3: Active FAT number (if mirroring disabled)
    /// - Bits 4-6: Reserved
    /// - Bit 7: 0=FAT mirrored, 1=only active FAT used
    /// - Bits 8-15: Reserved
    ///
    /// Offset 0x28
    pub ext_flags: U16<LittleEndian>,

    /// Filesystem version (high byte = major, low byte = minor)
    /// Should be 0x0000 for compatibility
    /// Offset 0x2A
    pub fs_version: U16<LittleEndian>,

    /// Cluster number of root directory start (typically 2)
    /// Offset 0x2C
    pub root_cluster: U32<LittleEndian>,

    /// Sector number of FSInfo structure (typically 1)
    /// Offset 0x30
    pub fs_info_sector: U16<LittleEndian>,

    /// Sector number of backup boot sector (typically 6)
    /// 0 or 0xFFFF means no backup
    /// Offset 0x32
    pub backup_boot_sector: U16<LittleEndian>,

    /// Reserved for future use (should be zero)
    /// Offset 0x34
    pub reserved: [u8; 12],

    /// Physical drive number (same as FAT16)
    /// Offset 0x40
    pub drive_number: u8,

    /// Reserved (Windows NT flags)
    /// Offset 0x41
    pub reserved1: u8,

    /// Extended boot signature (0x29 or 0x28)
    /// Offset 0x42
    pub boot_signature: u8,

    /// Volume serial number
    /// Offset 0x43
    pub volume_serial_number: U32<LittleEndian>,

    /// Volume label (11 bytes, space-padded)
    /// Offset 0x47
    pub volume_label: [u8; 11],

    /// Filesystem type label (always "FAT32   ")
    /// WARNING: Do not use for filesystem detection!
    /// Offset 0x52
    pub filesystem_type: [u8; 8],
}

impl Fat32Ebpb {
    /// Check if FAT mirroring is enabled
    pub fn fat_mirroring_enabled(&self) -> bool {
        (self.ext_flags.get() & 0x0080) == 0
    }

    /// Get the active FAT number (0-15, only meaningful if mirroring disabled)
    pub fn active_fat(&self) -> u8 {
        (self.ext_flags.get() & 0x000F) as u8
    }

    /// Get volume label as string
    pub fn volume_label_str(&self) -> &str {
        let s = core::str::from_utf8(&self.volume_label).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }
}

/// FAT32 FSInfo Structure (512 bytes)
///
/// Located at the sector specified by fs_info_sector in the FAT32 EBPB.
/// Contains hints for free space and allocation.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Fat32FsInfo {
    /// Lead signature (must be 0x41615252 = "RRaA")
    pub lead_signature: U32<LittleEndian>,

    /// Reserved (should be zero)
    pub reserved1: [u8; 480],

    /// Structure signature (must be 0x61417272 = "rrAa")
    pub struct_signature: U32<LittleEndian>,

    /// Last known free cluster count (0xFFFFFFFF = unknown)
    pub free_cluster_count: U32<LittleEndian>,

    /// Hint for next free cluster allocation (0xFFFFFFFF = no hint)
    pub next_free_cluster: U32<LittleEndian>,

    /// Reserved
    pub reserved2: [u8; 12],

    /// Trail signature (must be 0xAA550000)
    pub trail_signature: U32<LittleEndian>,
}

impl Fat32FsInfo {
    pub const LEAD_SIGNATURE: u32 = 0x41615252;
    pub const STRUCT_SIGNATURE: u32 = 0x61417272;
    pub const TRAIL_SIGNATURE: u32 = 0xAA550000;

    /// Validate the FSInfo signatures
    pub fn is_valid(&self) -> bool {
        self.lead_signature.get() == Self::LEAD_SIGNATURE
            && self.struct_signature.get() == Self::STRUCT_SIGNATURE
            && self.trail_signature.get() == Self::TRAIL_SIGNATURE
    }

    /// Get free cluster count if known
    pub fn free_clusters(&self) -> Option<u32> {
        let count = self.free_cluster_count.get();
        if count == 0xFFFFFFFF {
            None
        } else {
            Some(count)
        }
    }

    /// Get next free cluster hint if available
    pub fn next_free(&self) -> Option<u32> {
        let hint = self.next_free_cluster.get();
        if hint == 0xFFFFFFFF || hint < 2 {
            None
        } else {
            Some(hint)
        }
    }
}

// ============================================================================
// NTFS Extended BIOS Parameter Block
// ============================================================================

/// NTFS Extended BIOS Parameter Block (48 bytes)
///
/// Offset 0x24-0x53
/// NTFS uses a modified BPB structure with several fields zeroed and
/// additional NTFS-specific fields.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct NtfsEbpb {
    /// Not used by NTFS (often 0x00800080 or similar)
    /// This was physical drive number + flags in DOS
    /// Offset 0x24
    pub unused_0x24: U32<LittleEndian>,

    /// Total sectors on the volume (64-bit)
    /// Offset 0x28
    pub total_sectors: U64<LittleEndian>,

    /// Logical Cluster Number (LCN) of the $MFT file
    /// Offset 0x30
    pub mft_lcn: U64<LittleEndian>,

    /// Logical Cluster Number (LCN) of the $MFTMirr file
    ///
    /// Offset 0x38
    pub mft_mirror_lcn: U64<LittleEndian>,

    /// Clusters per MFT file record segment (signed)
    /// - Positive: cluster count
    /// - Negative: 2^(-value) bytes (e.g., -10 = 2^10 = 1024 bytes)
    ///
    /// Typically -10 (0xF6) for 1KB records, or -12 (0xF4) for 4KB.
    /// Offset 0x40
    pub clusters_per_mft_record: i8,

    /// Reserved/padding
    ///
    /// Offset 0x41
    pub reserved_0x41: [u8; 3],

    /// Clusters per index buffer (signed, same encoding as above)
    ///
    /// Typically -12 (0xF4) for 4KB index buffers.
    /// Offset 0x44
    pub clusters_per_index_buffer: i8,

    /// Reserved/padding
    /// Offset 0x45
    pub reserved_0x45: [u8; 3],

    /// Volume serial number (64-bit)
    /// Offset 0x48
    pub volume_serial_number: U64<LittleEndian>,

    /// Checksum (not used, typically 0)
    /// Offset 0x50
    pub checksum: U32<LittleEndian>,
}

impl NtfsEbpb {
    /// Decode the clusters_per_mft_record field to bytes
    pub fn mft_record_size(&self, cluster_size: u32) -> u32 {
        Self::decode_cluster_size_field(self.clusters_per_mft_record, cluster_size)
    }

    /// Decode the clusters_per_index_buffer field to bytes
    pub fn index_buffer_size(&self, cluster_size: u32) -> u32 {
        Self::decode_cluster_size_field(self.clusters_per_index_buffer, cluster_size)
    }

    /// Decode a signed cluster/size field
    /// - Positive values: multiply by cluster size
    /// - Negative values: 2^(-value) bytes
    fn decode_cluster_size_field(value: i8, cluster_size: u32) -> u32 {
        if value >= 0 {
            value as u32 * cluster_size
        } else {
            1u32 << ((-value) as u32)
        }
    }
}

// ============================================================================
// exFAT Boot Sector
// ============================================================================

/// exFAT Main Boot Region (first 512 bytes)
///
/// exFAT does NOT use the traditional DOS BPB. Instead, it has a completely
/// redesigned boot sector structure with all fields naturally aligned.
///
/// The OEM ID field (offset 0x03) must contain "EXFAT   " and the traditional
/// BPB area (offset 0x0B-0x3F) must be all zeros.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct ExFatBootSector {
    /// Jump instruction (must be EB 76 90)
    /// Offset 0x00
    pub jump_instruction: [u8; 3],

    /// Filesystem name (must be "EXFAT   ")
    /// Offset 0x03
    pub filesystem_name: [u8; 8],

    /// Must be zero (ensures FAT drivers won't mount this)
    /// This covers the traditional BPB area
    /// Offset 0x0B
    pub must_be_zero: [u8; 53],

    /// Partition offset in sectors from start of media
    /// (typically matches MBR/GPT partition entry)
    /// Offset 0x40
    pub partition_offset: U64<LittleEndian>,

    /// Volume length in sectors
    /// Offset 0x48
    pub volume_length: U64<LittleEndian>,

    /// FAT offset in sectors from start of partition
    /// Offset 0x50
    pub fat_offset: U32<LittleEndian>,

    /// FAT length in sectors
    /// Offset 0x54
    pub fat_length: U32<LittleEndian>,

    /// Cluster heap offset in sectors from start of partition
    /// Offset 0x58
    pub cluster_heap_offset: U32<LittleEndian>,

    /// Total number of clusters in cluster heap
    /// Offset 0x5C
    pub cluster_count: U32<LittleEndian>,

    /// Cluster number of root directory (typically 4+)
    /// Offset 0x60
    pub root_directory_cluster: U32<LittleEndian>,

    /// Volume serial number
    /// Offset 0x64
    pub volume_serial_number: U32<LittleEndian>,

    /// Filesystem revision (high byte = major, low byte = minor)
    /// Currently 0x0100 (version 1.0)
    /// Offset 0x68
    pub filesystem_revision: U16<LittleEndian>,

    /// Volume flags
    /// - Bit 0: Active FAT (0=first, 1=second)
    /// - Bit 1: Volume dirty
    /// - Bit 2: Media failure
    /// - Bit 3: Clear to zero (for future use)
    ///
    /// Offset 0x6A
    pub volume_flags: U16<LittleEndian>,

    /// Bytes per sector as power of 2 (e.g., 9 = 512, 12 = 4096)
    /// Range: 9-12 (512-4096 bytes)
    /// Offset 0x6C
    pub bytes_per_sector_shift: u8,

    /// Sectors per cluster as power of 2 (e.g., 0 = 1, 3 = 8)
    /// Combined with bytes_per_sector_shift, max cluster = 32MB
    /// Offset 0x6D
    pub sectors_per_cluster_shift: u8,

    /// Number of FATs (1 or 2)
    /// Offset 0x6E
    pub number_of_fats: u8,

    /// Physical drive number (BIOS INT 13h)
    /// 0x80 for first hard disk
    /// Offset 0x6F
    pub drive_select: u8,

    /// Percentage of clusters in use (0-100, or 0xFF if unknown)
    /// Offset 0x70
    pub percent_in_use: u8,

    /// Reserved for future use
    /// Offset 0x71
    pub reserved: [u8; 7],

    /// Boot code
    /// Offset 0x78
    pub boot_code: [u8; 390],

    /// Boot signature (must be 0xAA55)
    /// Offset 0x1FE
    pub boot_signature: U16<LittleEndian>,
}

impl ExFatBootSector {
    /// Validate that this is a valid exFAT boot sector
    pub fn is_valid(&self) -> bool {
        // Check filesystem name
        if &self.filesystem_name != b"EXFAT   " {
            return false;
        }

        // Check that BPB area is zeroed
        if !self.must_be_zero.iter().all(|&b| b == 0) {
            return false;
        }

        // Check boot signature
        if self.boot_signature.get() != BOOT_SIGNATURE {
            return false;
        }

        // Check valid sector size shift (9-12)
        if !(9..=12).contains(&self.bytes_per_sector_shift) {
            return false;
        }

        true
    }

    /// Get bytes per sector
    pub fn bytes_per_sector(&self) -> u32 {
        1u32 << self.bytes_per_sector_shift
    }

    /// Get sectors per cluster
    pub fn sectors_per_cluster(&self) -> u32 {
        1u32 << self.sectors_per_cluster_shift
    }

    /// Get cluster size in bytes
    pub fn cluster_size(&self) -> u32 {
        1u32 << (self.bytes_per_sector_shift + self.sectors_per_cluster_shift)
    }

    /// Check if volume is dirty
    pub fn is_dirty(&self) -> bool {
        (self.volume_flags.get() & 0x0002) != 0
    }

    /// Check if media failure flag is set
    pub fn has_media_failure(&self) -> bool {
        (self.volume_flags.get() & 0x0004) != 0
    }

    /// Get the active FAT (0 or 1)
    pub fn active_fat(&self) -> u8 {
        (self.volume_flags.get() & 0x0001) as u8
    }
}

// ============================================================================
// Boot Sector Parsing and Detection
// ============================================================================

/// Detected filesystem type (used internally for FAT type determination)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemType {
    /// FAT12 (< 4085 clusters)
    Fat12,
    /// FAT16 (4085 - 65524 clusters)
    Fat16,
    /// FAT32 (>= 65525 clusters, uses FAT32 EBPB)
    Fat32,
    /// NTFS (Windows NT filesystem)
    Ntfs,
    /// exFAT (Extended FAT for large removable media)
    ExFat,
    /// HPFS (OS/2 High Performance File System)
    /// Note: HPFS uses DOS 4.0 EBPB structure, similar to FAT16
    Hpfs,
    /// Unknown or invalid filesystem
    Unknown,
}

/// Result of detecting what's on a boot sector.
///
/// This enum represents the high-level detection result - either a filesystem
/// type or a partition table type. Use `detect_boot_sector()` to get this
/// from raw boot sector bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedBootSector {
    /// NTFS filesystem
    Ntfs,
    /// FAT12 filesystem
    Fat12,
    /// FAT16 filesystem
    Fat16,
    /// FAT32 filesystem
    Fat32,
    /// exFAT filesystem
    ExFat,
    /// ext2/ext3/ext4 filesystem (version distinguished by fs-ext feature flags)
    Ext,
    /// APFS container (one or more volumes; `NXSB` block-zero superblock)
    Apfs,
    /// BitLocker-encrypted volume (detected container/encrypted-volume type)
    BitLocker,
    /// MBR partitioned disk (need to enumerate partitions)
    MbrPartitioned,
    /// GPT partitioned disk (need to enumerate partitions)
    GptPartitioned,
    /// Unknown or unrecognized
    Unknown,
}

/// Diagnostic result for boot sector detection.
///
/// This API provides additional context for `Unknown` outcomes without
/// changing the fast-path behavior of [`DetectedBootSector::from_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSectorDiagnosis {
    /// A supported filesystem or partition table was detected.
    Detected(DetectedBootSector),
    /// Detection failed with a specific reason.
    Unknown(BootSectorUnknownReason),
}

/// Distinct failure modes when boot sector detection does not produce a
/// supported [`DetectedBootSector`] value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSectorUnknownReason {
    /// Input is smaller than a full boot sector.
    BufferTooSmall,
    /// Input is entirely zero bytes (common on unformatted media).
    AllZeroes,
    /// Signature at 0x1FE is not `0xAA55`.
    InvalidBootSignature,
    /// Structure looked like a known type but failed strict parsing or
    /// validation (e.g., corrupted BPB fields).
    CorruptedStructure,
    /// Parsed as HPFS, which is currently unsupported by `DetectedBootSector`.
    UnsupportedFilesystem(FilesystemType),
    /// Signature is present, but no known/valid filesystem or partition table
    /// could be confirmed.
    UnknownFilesystem {
        /// OEM ID suggests NTFS-like layout (`NTFS    `).
        ntfs_oem_hint: bool,
        /// OEM ID suggests exFAT (`EXFAT   `) or zeroed exFAT BPB region.
        exfat_hint: bool,
        /// OEM ID suggests BitLocker container (`-FVE-FS-`).
        bitlocker_hint: bool,
        /// Boot sector can be parsed as an MBR structure.
        mbr_layout_hint: bool,
    },
}

impl DetectedBootSector {
    /// Detect what's on a boot sector from raw bytes.
    ///
    /// This is a pure function that parses the boot sector and returns
    /// a simplified enum representing the detected type.
    pub fn from_bytes(boot_sector: &[u8]) -> Self {
        match diagnose_boot_sector(boot_sector) {
            BootSectorDiagnosis::Detected(detected) => detected,
            BootSectorDiagnosis::Unknown(_) => DetectedBootSector::Unknown,
        }
    }

    /// Check if this is a filesystem (not a partition table)
    pub fn is_filesystem(&self) -> bool {
        matches!(
            self,
            DetectedBootSector::Ntfs
                | DetectedBootSector::Fat12
                | DetectedBootSector::Fat16
                | DetectedBootSector::Fat32
                | DetectedBootSector::ExFat
                | DetectedBootSector::Ext
                | DetectedBootSector::Apfs
        )
    }

    /// Check if this is a partition table
    pub fn is_partition_table(&self) -> bool {
        matches!(
            self,
            DetectedBootSector::MbrPartitioned | DetectedBootSector::GptPartitioned
        )
    }
}

/// Diagnose a boot sector from raw bytes and retain distinct failure modes.
///
/// Trusts the 512-byte boot signature path first — a disk whose first sector
/// identifies as MBR/GPT/FAT/NTFS/exFAT/BitLocker is not a bare ext image,
/// even if bytes at 0x438 happen to pass the ext sanity checks. Only when
/// the standard classification yields `Unknown` do we fall through to the
/// ext superblock probe (which requires at least
/// [`FS_DETECT_PROBE_SIZE`] bytes).
pub fn diagnose_boot_sector(boot_sector: &[u8]) -> BootSectorDiagnosis {
    let standard = diagnose_boot_sector_standard(boot_sector);
    if matches!(standard, BootSectorDiagnosis::Unknown(_)) {
        // APFS and ext both lack the 0xAA55 boot signature, so they are
        // probed only after standard detection reports Unknown.
        if probe_apfs(boot_sector) {
            return BootSectorDiagnosis::Detected(DetectedBootSector::Apfs);
        }
        if probe_ext(boot_sector) {
            return BootSectorDiagnosis::Detected(DetectedBootSector::Ext);
        }
    }
    standard
}

fn diagnose_boot_sector_standard(boot_sector: &[u8]) -> BootSectorDiagnosis {
    if boot_sector.len() < BOOT_SECTOR_SIZE {
        return BootSectorDiagnosis::Unknown(BootSectorUnknownReason::BufferTooSmall);
    }

    if boot_sector.iter().all(|&b| b == 0) {
        return BootSectorDiagnosis::Unknown(BootSectorUnknownReason::AllZeroes);
    }

    let signature = u16::from_le_bytes([boot_sector[510], boot_sector[511]]);
    if signature != BOOT_SIGNATURE {
        return BootSectorDiagnosis::Unknown(BootSectorUnknownReason::InvalidBootSignature);
    }

    match parse_boot_sector(boot_sector) {
        Ok(parsed) => match parsed {
            ParsedBootSector::Fat12 { .. } => {
                BootSectorDiagnosis::Detected(DetectedBootSector::Fat12)
            }
            ParsedBootSector::Fat16 { .. } => {
                BootSectorDiagnosis::Detected(DetectedBootSector::Fat16)
            }
            ParsedBootSector::Fat32 { .. } => {
                BootSectorDiagnosis::Detected(DetectedBootSector::Fat32)
            }
            ParsedBootSector::Ntfs { .. } => {
                BootSectorDiagnosis::Detected(DetectedBootSector::Ntfs)
            }
            ParsedBootSector::BitLocker { .. } => {
                BootSectorDiagnosis::Detected(DetectedBootSector::BitLocker)
            }
            ParsedBootSector::ExFat { .. } => {
                BootSectorDiagnosis::Detected(DetectedBootSector::ExFat)
            }
            ParsedBootSector::Hpfs { .. } => BootSectorDiagnosis::Unknown(
                BootSectorUnknownReason::UnsupportedFilesystem(FilesystemType::Hpfs),
            ),
            ParsedBootSector::Mbr { .. } => {
                BootSectorDiagnosis::Detected(DetectedBootSector::MbrPartitioned)
            }
            ParsedBootSector::Gpt { .. } => {
                BootSectorDiagnosis::Detected(DetectedBootSector::GptPartitioned)
            }
        },
        Err(ParseError::BufferTooSmall) => {
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::BufferTooSmall)
        }
        Err(ParseError::InvalidBootSignature) => {
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::InvalidBootSignature)
        }
        Err(ParseError::InvalidBytesPerSector | ParseError::ParseFailed) => {
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::CorruptedStructure)
        }
        Err(ParseError::UnknownFilesystem) => {
            let header = BootSectorHeader::ref_from_bytes(&boot_sector[0..11]).ok();
            let ntfs_oem_hint = header.is_some_and(|h| h.is_ntfs());
            let bitlocker_hint = header.is_some_and(|h| h.is_bitlocker());
            let exfat_oem_hint = header.is_some_and(|h| h.is_exfat());
            let exfat_zeroed_bpb_hint = boot_sector[0x0B..0x40].iter().all(|&b| b == 0);
            let mbr_layout_hint = crate::partition::Mbr::from_bytes(boot_sector).is_some();

            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnknownFilesystem {
                ntfs_oem_hint,
                exfat_hint: exfat_oem_hint || exfat_zeroed_bpb_hint,
                bitlocker_hint,
                mbr_layout_hint,
            })
        }
    }
}

/// Parsed boot sector with references to the appropriate structures
#[derive(Debug)]
pub enum ParsedBootSector<'a> {
    /// FAT12 filesystem
    Fat12 {
        header: &'a BootSectorHeader,
        bpb: &'a DosBpb,
        ebpb: &'a Fat16Ebpb,
        boot_code: &'a [u8],
    },
    /// FAT16 filesystem
    Fat16 {
        header: &'a BootSectorHeader,
        bpb: &'a DosBpb,
        ebpb: &'a Fat16Ebpb,
        boot_code: &'a [u8],
    },
    /// FAT32 filesystem
    Fat32 {
        header: &'a BootSectorHeader,
        bpb: &'a DosBpb,
        ebpb: &'a Fat32Ebpb,
        boot_code: &'a [u8],
    },
    /// NTFS filesystem
    Ntfs {
        header: &'a BootSectorHeader,
        bpb: &'a DosBpb,
        ebpb: &'a NtfsEbpb,
        boot_code: &'a [u8],
    },
    /// BitLocker-encrypted volume (FVE)
    ///
    /// The on-disk layout reuses the NTFS boot sector structure, but the OEM ID
    /// is `-FVE-FS-` instead of `NTFS    `. Only volume geometry and selected
    /// metadata are exposed; NTFS-semantic fields (MFT LCN, file record size)
    /// are intentionally excluded.
    ///
    /// `total_sectors` and `volume_serial_number` are read from the NTFS-style
    /// extended BPB at offsets 0x28 and 0x48 respectively. These offsets are
    /// reused by BitLocker volumes.
    BitLocker {
        header: &'a BootSectorHeader,
        bpb: &'a DosBpb,
        total_sectors: u64,
        volume_serial_number: u64,
        boot_code: &'a [u8],
    },
    /// exFAT filesystem
    ExFat { boot_sector: &'a ExFatBootSector },
    /// HPFS filesystem (uses FAT16 EBPB structure)
    Hpfs {
        header: &'a BootSectorHeader,
        bpb: &'a DosBpb,
        ebpb: &'a Fat16Ebpb,
        boot_code: &'a [u8],
    },
    /// MBR partition table (not a filesystem)
    Mbr { mbr: &'a crate::partition::Mbr },
    /// GPT partition table (protective MBR detected)
    Gpt { mbr: &'a crate::partition::Mbr },
}

/// Errors that can occur during boot sector parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Input buffer is too small
    BufferTooSmall,
    /// Missing boot signature (0xAA55)
    InvalidBootSignature,
    /// Invalid bytes per sector value
    InvalidBytesPerSector,
    /// Could not determine filesystem type
    UnknownFilesystem,
    /// Structure parsing failed
    ParseFailed,
}

/// Parse a boot sector and detect the filesystem type
pub fn parse_boot_sector(data: &[u8]) -> Result<ParsedBootSector<'_>, ParseError> {
    if data.len() < BOOT_SECTOR_SIZE {
        return Err(ParseError::BufferTooSmall);
    }

    // Check boot signature at offset 510-511
    let signature = u16::from_le_bytes([data[510], data[511]]);
    if signature != BOOT_SIGNATURE {
        return Err(ParseError::InvalidBootSignature);
    }

    // Try filesystem detection first, fall back to partition table detection
    match try_parse_filesystem(data) {
        Ok(parsed) => Ok(parsed),
        Err(_) => try_parse_partition_table(data),
    }
}

/// Try to parse as a filesystem boot sector
fn try_parse_filesystem(data: &[u8]) -> Result<ParsedBootSector<'_>, ParseError> {
    // Parse header
    let header =
        BootSectorHeader::ref_from_bytes(&data[0..11]).map_err(|_| ParseError::ParseFailed)?;

    // Check for exFAT first (it has a completely different structure).
    //
    // The exFAT spec requires the BPB-region bytes 0x0B..0x40 to be all
    // zero so legacy FAT drivers reject the volume. `ExFatBootSector::is_valid`
    // further anchors the OEM `EXFAT   ` and signature; the cheap zeroed-BPB
    // check alone is sufficient to gate the heavy parse without adding a
    // redundant short-prefix shortcut.
    if data[0x0B..0x40].iter().all(|&b| b == 0) {
        let boot_sector =
            ExFatBootSector::ref_from_bytes(&data[0..512]).map_err(|_| ParseError::ParseFailed)?;
        if boot_sector.is_valid() {
            return Ok(ParsedBootSector::ExFat { boot_sector });
        }
    }

    // Parse DOS BPB (shared by FAT12/16/32, NTFS, HPFS)
    let bpb = DosBpb::ref_from_bytes(&data[0x0B..0x24]).map_err(|_| ParseError::ParseFailed)?;

    // Validate bytes per sector — applies to BitLocker too (reuses NTFS-style BPB)
    let bytes_per_sector = bpb.bytes_per_sector.get();
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(ParseError::InvalidBytesPerSector);
    }

    // Check for BitLocker (FVE) — must precede NTFS check because BitLocker
    // volumes have an NTFS-like BPB that would pass looks_like_ntfs().
    if header.is_bitlocker() {
        let ebpb =
            NtfsEbpb::ref_from_bytes(&data[0x24..0x54]).map_err(|_| ParseError::ParseFailed)?;
        return Ok(ParsedBootSector::BitLocker {
            header,
            bpb,
            total_sectors: ebpb.total_sectors.get(),
            volume_serial_number: ebpb.volume_serial_number.get(),
            boot_code: &data[0x54..510],
        });
    }

    // Check for NTFS
    if header.is_ntfs() || bpb.looks_like_ntfs() {
        let ebpb =
            NtfsEbpb::ref_from_bytes(&data[0x24..0x54]).map_err(|_| ParseError::ParseFailed)?;
        return Ok(ParsedBootSector::Ntfs {
            header,
            bpb,
            ebpb,
            boot_code: &data[0x54..510],
        });
    }

    // Check for FAT32 (sectors_per_fat_16 is 0 and FAT32 EBPB present)
    if bpb.sectors_per_fat_16.get() == 0 && bpb.root_entry_count.get() == 0 {
        let ebpb =
            Fat32Ebpb::ref_from_bytes(&data[0x24..0x5A]).map_err(|_| ParseError::ParseFailed)?;
        return Ok(ParsedBootSector::Fat32 {
            header,
            bpb,
            ebpb,
            boot_code: &data[0x5A..510],
        });
    }

    // FAT12/FAT16 (or HPFS)
    let ebpb = Fat16Ebpb::ref_from_bytes(&data[0x24..0x3E]).map_err(|_| ParseError::ParseFailed)?;

    // Check for HPFS (OEM ID often indicates this)
    if &header.oem_id[0..4] == b"HPFS" || &header.oem_id[0..4] == b"OS2 " {
        return Ok(ParsedBootSector::Hpfs {
            header,
            bpb,
            ebpb,
            boot_code: &data[0x3E..510],
        });
    }

    // Determine FAT12 vs FAT16 based on cluster count
    // FAT type is determined by cluster count, NOT by filesystem type string
    let fs_type = determine_fat_type(bpb);

    match fs_type {
        FilesystemType::Fat12 => Ok(ParsedBootSector::Fat12 {
            header,
            bpb,
            ebpb,
            boot_code: &data[0x3E..510],
        }),
        FilesystemType::Fat16 => Ok(ParsedBootSector::Fat16 {
            header,
            bpb,
            ebpb,
            boot_code: &data[0x3E..510],
        }),
        _ => Err(ParseError::UnknownFilesystem),
    }
}

/// Try to parse as a partition table (MBR or GPT)
fn try_parse_partition_table(data: &[u8]) -> Result<ParsedBootSector<'_>, ParseError> {
    use crate::partition::Mbr;

    // Try to parse as MBR
    let mbr = Mbr::from_bytes(data).ok_or(ParseError::ParseFailed)?;

    if !mbr.is_valid() {
        return Err(ParseError::InvalidBootSignature);
    }

    // Check if it's a GPT protective MBR
    if mbr.is_gpt_protective() {
        return Ok(ParsedBootSector::Gpt { mbr });
    }

    // Check if it has any valid partition entries (genuine MBR)
    if mbr.valid_partitions().next().is_some() {
        return Ok(ParsedBootSector::Mbr { mbr });
    }

    // Has signature but no valid partitions - unknown
    Err(ParseError::UnknownFilesystem)
}

/// Determine FAT type (12/16) based on cluster count
///
/// According to Microsoft FAT specification:
/// - FAT12: cluster count < 4085
/// - FAT16: cluster count >= 4085 and < 65525
/// - FAT32: cluster count >= 65525
fn determine_fat_type(bpb: &DosBpb) -> FilesystemType {
    let bytes_per_sector = bpb.bytes_per_sector.get() as u32;
    let sectors_per_cluster = bpb.sectors_per_cluster as u32;

    if bytes_per_sector == 0 || sectors_per_cluster == 0 {
        return FilesystemType::Unknown;
    }

    // Calculate root directory sectors (FAT12/16)
    let root_entry_count = bpb.root_entry_count.get() as u32;
    let root_dir_sectors = (root_entry_count * 32).div_ceil(bytes_per_sector);

    // Get FAT size
    let fat_size = if bpb.sectors_per_fat_16.get() != 0 {
        bpb.sectors_per_fat_16.get() as u32
    } else {
        // This would be FAT32, but we're checking FAT12/16 here
        return FilesystemType::Unknown;
    };

    // Calculate total sectors
    let total_sectors = bpb.total_sectors();

    // Calculate data sectors
    let reserved = bpb.reserved_sectors.get() as u32;
    let num_fats = bpb.num_fats as u32;
    let first_data_sector = reserved + (num_fats * fat_size) + root_dir_sectors;

    if total_sectors <= first_data_sector {
        return FilesystemType::Unknown;
    }

    let data_sectors = total_sectors - first_data_sector;
    let cluster_count = data_sectors / sectors_per_cluster;

    if cluster_count < 4085 {
        FilesystemType::Fat12
    } else if cluster_count < 65525 {
        FilesystemType::Fat16
    } else {
        FilesystemType::Fat32
    }
}

// ============================================================================
// Helper Types for Complete Boot Sector Layout (optional, for direct casting)
// ============================================================================

/// Complete FAT12/FAT16 boot sector layout (512 bytes)
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Fat16BootSector {
    pub header: BootSectorHeader,          // 0x00-0x0A (11 bytes)
    pub bpb: DosBpb,                       // 0x0B-0x23 (25 bytes)
    pub ebpb: Fat16Ebpb,                   // 0x24-0x3D (26 bytes)
    pub boot_code: [u8; 448],              // 0x3E-0x1FD (448 bytes)
    pub boot_signature: U16<LittleEndian>, // 0x1FE-0x1FF (2 bytes)
}

/// Complete FAT32 boot sector layout (512 bytes)
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Fat32BootSector {
    pub header: BootSectorHeader,          // 0x00-0x0A (11 bytes)
    pub bpb: DosBpb,                       // 0x0B-0x23 (25 bytes)
    pub ebpb: Fat32Ebpb,                   // 0x24-0x59 (54 bytes)
    pub boot_code: [u8; 420],              // 0x5A-0x1FD (420 bytes)
    pub boot_signature: U16<LittleEndian>, // 0x1FE-0x1FF (2 bytes)
}

/// Complete NTFS boot sector layout (512 bytes)
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct NtfsBootSector {
    pub header: BootSectorHeader,          // 0x00-0x0A (11 bytes)
    pub bpb: DosBpb,                       // 0x0B-0x23 (25 bytes)
    pub ebpb: NtfsEbpb,                    // 0x24-0x53 (48 bytes)
    pub boot_code: [u8; 426],              // 0x54-0x1FD (426 bytes)
    pub boot_signature: U16<LittleEndian>, // 0x1FE-0x1FF (2 bytes)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn test_structure_sizes() {
        assert_eq!(size_of::<BootSectorHeader>(), 11);
        assert_eq!(size_of::<DosBpb>(), 25);
        assert_eq!(size_of::<Fat16Ebpb>(), 26);
        assert_eq!(size_of::<Fat32Ebpb>(), 54);
        assert_eq!(size_of::<NtfsEbpb>(), 48);
        assert_eq!(size_of::<ExFatBootSector>(), 512);
        assert_eq!(size_of::<Fat32FsInfo>(), 512);

        // Verify complete boot sector layouts
        assert_eq!(size_of::<Fat16BootSector>(), 512);
        assert_eq!(size_of::<Fat32BootSector>(), 512);
        assert_eq!(size_of::<NtfsBootSector>(), 512);
    }

    #[test]
    fn test_ntfs_cluster_size_decode() {
        let cluster_size = 4096u32;

        // Positive value: multiply by cluster size
        assert_eq!(NtfsEbpb::decode_cluster_size_field(1, cluster_size), 4096);
        assert_eq!(NtfsEbpb::decode_cluster_size_field(2, cluster_size), 8192);

        // Negative value: 2^(-value) bytes
        // -10 (0xF6 as i8) = 2^10 = 1024
        assert_eq!(NtfsEbpb::decode_cluster_size_field(-10, cluster_size), 1024);
        // -12 (0xF4 as i8) = 2^12 = 4096
        assert_eq!(NtfsEbpb::decode_cluster_size_field(-12, cluster_size), 4096);
    }

    #[test]
    fn test_exfat_calculations() {
        // Test shift calculations
        assert_eq!(1u32 << 9, 512); // bytes_per_sector_shift = 9
        assert_eq!(1u32 << 12, 4096); // bytes_per_sector_shift = 12
        assert_eq!(1u32 << (9 + 3), 4096); // 512 byte sectors, 8 sectors per cluster
    }

    // ========================================================================
    // BootSectorHeader tests
    // ========================================================================

    fn create_header(oem_id: &[u8; 8]) -> BootSectorHeader {
        BootSectorHeader {
            jump_instruction: [0xEB, 0x76, 0x90],
            oem_id: *oem_id,
        }
    }

    #[test]
    fn test_boot_sector_header_is_ntfs() {
        let ntfs_header = create_header(b"NTFS    ");
        assert!(ntfs_header.is_ntfs());
        assert!(!ntfs_header.is_exfat());

        let fat_header = create_header(b"MSDOS5.0");
        assert!(!fat_header.is_ntfs());

        let other_header = create_header(b"NTFS    "); // trailing different (for completeness)
        assert!(other_header.is_ntfs());

        let almost_ntfs = create_header(b"NTFS   \0");
        assert!(!almost_ntfs.is_ntfs()); // must be exactly "NTFS    "
    }

    #[test]
    fn test_boot_sector_header_is_exfat() {
        let exfat_header = create_header(b"EXFAT   ");
        assert!(exfat_header.is_exfat());
        assert!(!exfat_header.is_ntfs());

        let fat_header = create_header(b"MSDOS5.0");
        assert!(!fat_header.is_exfat());

        let almost_exfat = create_header(b"EXFAT  \0");
        assert!(!almost_exfat.is_exfat()); // must be exactly "EXFAT   "
    }

    #[test]
    fn test_boot_sector_header_oem_id_str() {
        let ntfs_header = create_header(b"NTFS    ");
        assert_eq!(ntfs_header.oem_id_str(), "NTFS");

        let fat_header = create_header(b"MSDOS5.0");
        assert_eq!(fat_header.oem_id_str(), "MSDOS5.0");

        let mkdosfs_header = create_header(b"mkdosfs ");
        assert_eq!(mkdosfs_header.oem_id_str(), "mkdosfs");

        // Test with null bytes
        let null_header = create_header(b"TEST\0\0\0\0");
        assert_eq!(null_header.oem_id_str(), "TEST");

        // Test with mixed spaces and nulls - trim_end removes consecutive trailing space/null
        let mixed_header = create_header(b"ABC \0 \0\0");
        assert_eq!(mixed_header.oem_id_str(), "ABC"); // all trailing space/null trimmed
    }

    // ========================================================================
    // DosBpb tests
    // ========================================================================

    #[expect(
        clippy::too_many_arguments,
        reason = "test helper mirrors DosBpb fields"
    )]
    fn create_dos_bpb(
        bytes_per_sector: u16,
        sectors_per_cluster: u8,
        reserved_sectors: u16,
        num_fats: u8,
        root_entry_count: u16,
        total_sectors_16: u16,
        sectors_per_fat_16: u16,
        total_sectors_32: u32,
    ) -> DosBpb {
        DosBpb {
            bytes_per_sector: U16::new(bytes_per_sector),
            sectors_per_cluster,
            reserved_sectors: U16::new(reserved_sectors),
            num_fats,
            root_entry_count: U16::new(root_entry_count),
            total_sectors_16: U16::new(total_sectors_16),
            media_descriptor: 0xF8,
            sectors_per_fat_16: U16::new(sectors_per_fat_16),
            sectors_per_track: U16::new(63),
            num_heads: U16::new(255),
            hidden_sectors: U32::new(0),
            total_sectors_32: U32::new(total_sectors_32),
        }
    }

    #[test]
    fn test_dos_bpb_total_sectors_16bit() {
        // When total_sectors_16 is non-zero, use it
        let bpb = create_dos_bpb(512, 1, 1, 2, 512, 2880, 9, 0);
        assert_eq!(bpb.total_sectors(), 2880);
    }

    #[test]
    fn ext_variant_exists_and_is_a_filesystem() {
        let variant = DetectedBootSector::Ext;
        assert!(variant.is_filesystem(), "Ext must classify as a filesystem");
        assert!(!variant.is_partition_table());
    }

    #[test]
    fn test_dos_bpb_total_sectors_32bit() {
        // When total_sectors_16 is 0, use total_sectors_32
        let bpb = create_dos_bpb(512, 8, 32, 2, 0, 0, 0, 4194304);
        assert_eq!(bpb.total_sectors(), 4194304);
    }

    #[test]
    fn test_dos_bpb_cluster_size() {
        // 512 bytes/sector * 1 sector/cluster = 512 bytes/cluster
        let bpb1 = create_dos_bpb(512, 1, 1, 2, 512, 2880, 9, 0);
        assert_eq!(bpb1.cluster_size(), 512);

        // 512 bytes/sector * 8 sectors/cluster = 4096 bytes/cluster
        let bpb2 = create_dos_bpb(512, 8, 32, 2, 0, 0, 0, 4194304);
        assert_eq!(bpb2.cluster_size(), 4096);

        // 4096 bytes/sector * 1 sector/cluster = 4096 bytes/cluster
        let bpb3 = create_dos_bpb(4096, 1, 1, 2, 0, 0, 0, 1000000);
        assert_eq!(bpb3.cluster_size(), 4096);

        // 4096 bytes/sector * 128 sectors/cluster = 524288 bytes/cluster
        let bpb4 = create_dos_bpb(4096, 128, 32, 2, 0, 0, 0, 10000000);
        assert_eq!(bpb4.cluster_size(), 524288);
    }

    #[test]
    fn test_dos_bpb_looks_like_ntfs() {
        // NTFS: reserved_sectors=0, num_fats=0, root_entry_count=0, sectors_per_fat_16=0
        let ntfs_bpb = create_dos_bpb(512, 8, 0, 0, 0, 0, 0, 0);
        assert!(ntfs_bpb.looks_like_ntfs());

        // FAT16: has reserved sectors and FATs
        let fat16_bpb = create_dos_bpb(512, 4, 1, 2, 512, 32000, 128, 0);
        assert!(!fat16_bpb.looks_like_ntfs());

        // FAT32: has reserved sectors and FATs (even though sectors_per_fat_16=0)
        let fat32_bpb = create_dos_bpb(512, 8, 32, 2, 0, 0, 0, 4194304);
        assert!(!fat32_bpb.looks_like_ntfs()); // has reserved_sectors and num_fats
    }

    #[test]
    fn test_dos_bpb_looks_like_exfat() {
        // exFAT: bytes_per_sector=0 (uses shift instead)
        let exfat_bpb = create_dos_bpb(0, 0, 0, 0, 0, 0, 0, 0);
        assert!(exfat_bpb.looks_like_exfat());

        // FAT: has bytes_per_sector
        let fat_bpb = create_dos_bpb(512, 4, 1, 2, 512, 32000, 128, 0);
        assert!(!fat_bpb.looks_like_exfat());
    }

    // ========================================================================
    // Fat16Ebpb tests
    // ========================================================================

    fn create_fat16_ebpb(boot_sig: u8, volume_label: &[u8; 11], fs_type: &[u8; 8]) -> Fat16Ebpb {
        Fat16Ebpb {
            drive_number: 0x80,
            reserved1: 0,
            boot_signature: boot_sig,
            volume_serial_number: U32::new(0x12345678),
            volume_label: *volume_label,
            filesystem_type: *fs_type,
        }
    }

    #[test]
    fn test_fat16_ebpb_has_extended_fields() {
        // 0x29 means all extended fields are valid
        let ebpb_29 = create_fat16_ebpb(0x29, b"NO NAME    ", b"FAT16   ");
        assert!(ebpb_29.has_extended_fields());

        // 0x28 means only serial number is valid
        let ebpb_28 = create_fat16_ebpb(0x28, b"NO NAME    ", b"FAT16   ");
        assert!(ebpb_28.has_extended_fields());

        // Other values mean no extended fields
        let ebpb_other = create_fat16_ebpb(0x00, b"NO NAME    ", b"FAT16   ");
        assert!(!ebpb_other.has_extended_fields());

        let ebpb_27 = create_fat16_ebpb(0x27, b"NO NAME    ", b"FAT16   ");
        assert!(!ebpb_27.has_extended_fields());
    }

    #[test]
    fn test_fat16_ebpb_volume_label_str() {
        let ebpb = create_fat16_ebpb(0x29, b"MY VOLUME  ", b"FAT16   ");
        assert_eq!(ebpb.volume_label_str(), "MY VOLUME");

        let ebpb_no_label = create_fat16_ebpb(0x29, b"NO NAME    ", b"FAT16   ");
        assert_eq!(ebpb_no_label.volume_label_str(), "NO NAME");

        // Test with null bytes
        let ebpb_null = create_fat16_ebpb(0x29, b"LABEL\0\0\0\0\0\0", b"FAT16   ");
        assert_eq!(ebpb_null.volume_label_str(), "LABEL");
    }

    #[test]
    fn test_fat16_ebpb_filesystem_type_str() {
        let ebpb_fat12 = create_fat16_ebpb(0x29, b"NO NAME    ", b"FAT12   ");
        assert_eq!(ebpb_fat12.filesystem_type_str(), "FAT12");

        let ebpb_fat16 = create_fat16_ebpb(0x29, b"NO NAME    ", b"FAT16   ");
        assert_eq!(ebpb_fat16.filesystem_type_str(), "FAT16");

        let ebpb_fat = create_fat16_ebpb(0x29, b"NO NAME    ", b"FAT     ");
        assert_eq!(ebpb_fat.filesystem_type_str(), "FAT");
    }

    // ========================================================================
    // Fat32Ebpb tests
    // ========================================================================

    fn create_fat32_ebpb(ext_flags: u16, volume_label: &[u8; 11]) -> Fat32Ebpb {
        Fat32Ebpb {
            sectors_per_fat_32: U32::new(4096),
            ext_flags: U16::new(ext_flags),
            fs_version: U16::new(0),
            root_cluster: U32::new(2),
            fs_info_sector: U16::new(1),
            backup_boot_sector: U16::new(6),
            reserved: [0; 12],
            drive_number: 0x80,
            reserved1: 0,
            boot_signature: 0x29,
            volume_serial_number: U32::new(0x12345678),
            volume_label: *volume_label,
            filesystem_type: *b"FAT32   ",
        }
    }

    #[test]
    fn test_fat32_ebpb_fat_mirroring_enabled() {
        // Bit 7 clear = mirroring enabled
        let ebpb_mirrored = create_fat32_ebpb(0x0000, b"NO NAME    ");
        assert!(ebpb_mirrored.fat_mirroring_enabled());

        // Bit 7 set = mirroring disabled
        let ebpb_not_mirrored = create_fat32_ebpb(0x0080, b"NO NAME    ");
        assert!(!ebpb_not_mirrored.fat_mirroring_enabled());

        // Other bits shouldn't affect this
        let ebpb_other_bits = create_fat32_ebpb(0x000F, b"NO NAME    ");
        assert!(ebpb_other_bits.fat_mirroring_enabled());
    }

    #[test]
    fn test_fat32_ebpb_active_fat() {
        // Active FAT is in bits 0-3
        let ebpb_fat0 = create_fat32_ebpb(0x0080, b"NO NAME    ");
        assert_eq!(ebpb_fat0.active_fat(), 0);

        let ebpb_fat1 = create_fat32_ebpb(0x0081, b"NO NAME    ");
        assert_eq!(ebpb_fat1.active_fat(), 1);

        let ebpb_fat15 = create_fat32_ebpb(0x008F, b"NO NAME    ");
        assert_eq!(ebpb_fat15.active_fat(), 15);

        // Upper bits shouldn't affect result
        let ebpb_upper_bits = create_fat32_ebpb(0xFF03, b"NO NAME    ");
        assert_eq!(ebpb_upper_bits.active_fat(), 3);
    }

    #[test]
    fn test_fat32_ebpb_volume_label_str() {
        let ebpb = create_fat32_ebpb(0x0000, b"MY DRIVE   ");
        assert_eq!(ebpb.volume_label_str(), "MY DRIVE");

        let ebpb_null = create_fat32_ebpb(0x0000, b"TEST\0\0\0\0\0\0\0");
        assert_eq!(ebpb_null.volume_label_str(), "TEST");
    }

    // ========================================================================
    // Fat32FsInfo tests
    // ========================================================================

    fn create_fat32_fsinfo(
        lead_sig: u32,
        struct_sig: u32,
        trail_sig: u32,
        free_count: u32,
        next_free: u32,
    ) -> Fat32FsInfo {
        Fat32FsInfo {
            lead_signature: U32::new(lead_sig),
            reserved1: [0; 480],
            struct_signature: U32::new(struct_sig),
            free_cluster_count: U32::new(free_count),
            next_free_cluster: U32::new(next_free),
            reserved2: [0; 12],
            trail_signature: U32::new(trail_sig),
        }
    }

    #[test]
    fn test_fat32_fsinfo_is_valid() {
        // All signatures correct
        let valid = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            1000,
            100,
        );
        assert!(valid.is_valid());

        // Invalid lead signature
        let invalid_lead = create_fat32_fsinfo(
            0x00000000,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            1000,
            100,
        );
        assert!(!invalid_lead.is_valid());

        // Invalid struct signature
        let invalid_struct = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            0x00000000,
            Fat32FsInfo::TRAIL_SIGNATURE,
            1000,
            100,
        );
        assert!(!invalid_struct.is_valid());

        // Invalid trail signature
        let invalid_trail = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            0x00000000,
            1000,
            100,
        );
        assert!(!invalid_trail.is_valid());
    }

    #[test]
    fn test_fat32_fsinfo_free_clusters() {
        // Known value
        let fsinfo_known = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            50000,
            100,
        );
        assert_eq!(fsinfo_known.free_clusters(), Some(50000));

        // Unknown (0xFFFFFFFF)
        let fsinfo_unknown = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            0xFFFFFFFF,
            100,
        );
        assert_eq!(fsinfo_unknown.free_clusters(), None);

        // Zero is valid
        let fsinfo_zero = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            0,
            100,
        );
        assert_eq!(fsinfo_zero.free_clusters(), Some(0));
    }

    #[test]
    fn test_fat32_fsinfo_next_free() {
        // Valid hint (>= 2)
        let fsinfo_valid = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            1000,
            100,
        );
        assert_eq!(fsinfo_valid.next_free(), Some(100));

        // Cluster 2 is valid (first data cluster)
        let fsinfo_cluster2 = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            1000,
            2,
        );
        assert_eq!(fsinfo_cluster2.next_free(), Some(2));

        // Unknown (0xFFFFFFFF)
        let fsinfo_unknown = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            1000,
            0xFFFFFFFF,
        );
        assert_eq!(fsinfo_unknown.next_free(), None);

        // Invalid (< 2)
        let fsinfo_zero = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            1000,
            0,
        );
        assert_eq!(fsinfo_zero.next_free(), None);

        let fsinfo_one = create_fat32_fsinfo(
            Fat32FsInfo::LEAD_SIGNATURE,
            Fat32FsInfo::STRUCT_SIGNATURE,
            Fat32FsInfo::TRAIL_SIGNATURE,
            1000,
            1,
        );
        assert_eq!(fsinfo_one.next_free(), None);
    }

    // ========================================================================
    // ExFatBootSector tests
    // ========================================================================

    fn create_exfat_boot_sector(
        bytes_per_sector_shift: u8,
        sectors_per_cluster_shift: u8,
        volume_flags: u16,
    ) -> ExFatBootSector {
        ExFatBootSector {
            jump_instruction: [0xEB, 0x76, 0x90],
            filesystem_name: *b"EXFAT   ",
            must_be_zero: [0; 53],
            partition_offset: U64::new(0),
            volume_length: U64::new(1000000),
            fat_offset: U32::new(24),
            fat_length: U32::new(1024),
            cluster_heap_offset: U32::new(1048),
            cluster_count: U32::new(100000),
            root_directory_cluster: U32::new(4),
            volume_serial_number: U32::new(0x12345678),
            filesystem_revision: U16::new(0x0100),
            volume_flags: U16::new(volume_flags),
            bytes_per_sector_shift,
            sectors_per_cluster_shift,
            number_of_fats: 1,
            drive_select: 0x80,
            percent_in_use: 50,
            reserved: [0; 7],
            boot_code: [0; 390],
            boot_signature: U16::new(BOOT_SIGNATURE),
        }
    }

    #[test]
    fn test_exfat_bytes_per_sector() {
        // Shift 9 = 512 bytes
        let exfat_512 = create_exfat_boot_sector(9, 0, 0);
        assert_eq!(exfat_512.bytes_per_sector(), 512);

        // Shift 10 = 1024 bytes
        let exfat_1024 = create_exfat_boot_sector(10, 0, 0);
        assert_eq!(exfat_1024.bytes_per_sector(), 1024);

        // Shift 11 = 2048 bytes
        let exfat_2048 = create_exfat_boot_sector(11, 0, 0);
        assert_eq!(exfat_2048.bytes_per_sector(), 2048);

        // Shift 12 = 4096 bytes
        let exfat_4096 = create_exfat_boot_sector(12, 0, 0);
        assert_eq!(exfat_4096.bytes_per_sector(), 4096);
    }

    #[test]
    fn test_exfat_sectors_per_cluster() {
        // Shift 0 = 1 sector per cluster
        let exfat_1 = create_exfat_boot_sector(9, 0, 0);
        assert_eq!(exfat_1.sectors_per_cluster(), 1);

        // Shift 3 = 8 sectors per cluster
        let exfat_8 = create_exfat_boot_sector(9, 3, 0);
        assert_eq!(exfat_8.sectors_per_cluster(), 8);

        // Shift 7 = 128 sectors per cluster
        let exfat_128 = create_exfat_boot_sector(9, 7, 0);
        assert_eq!(exfat_128.sectors_per_cluster(), 128);
    }

    #[test]
    fn test_exfat_cluster_size() {
        // 512 bytes/sector * 1 sector/cluster = 512 bytes
        let exfat_512 = create_exfat_boot_sector(9, 0, 0);
        assert_eq!(exfat_512.cluster_size(), 512);

        // 512 bytes/sector * 8 sectors/cluster = 4096 bytes
        let exfat_4k = create_exfat_boot_sector(9, 3, 0);
        assert_eq!(exfat_4k.cluster_size(), 4096);

        // 4096 bytes/sector * 8 sectors/cluster = 32768 bytes
        let exfat_32k = create_exfat_boot_sector(12, 3, 0);
        assert_eq!(exfat_32k.cluster_size(), 32768);

        // 4096 bytes/sector * 128 sectors/cluster = 524288 bytes (max recommended)
        let exfat_max = create_exfat_boot_sector(12, 7, 0);
        assert_eq!(exfat_max.cluster_size(), 524288);
    }

    #[test]
    fn test_exfat_is_dirty() {
        // Bit 1 clear = not dirty
        let exfat_clean = create_exfat_boot_sector(9, 3, 0x0000);
        assert!(!exfat_clean.is_dirty());

        // Bit 1 set = dirty
        let exfat_dirty = create_exfat_boot_sector(9, 3, 0x0002);
        assert!(exfat_dirty.is_dirty());

        // Other bits shouldn't affect dirty flag
        let exfat_other = create_exfat_boot_sector(9, 3, 0xFFFD);
        assert!(!exfat_other.is_dirty());
    }

    #[test]
    fn test_exfat_has_media_failure() {
        // Bit 2 clear = no media failure
        let exfat_ok = create_exfat_boot_sector(9, 3, 0x0000);
        assert!(!exfat_ok.has_media_failure());

        // Bit 2 set = media failure
        let exfat_failure = create_exfat_boot_sector(9, 3, 0x0004);
        assert!(exfat_failure.has_media_failure());

        // Other bits shouldn't affect media failure flag
        let exfat_other = create_exfat_boot_sector(9, 3, 0xFFFB);
        assert!(!exfat_other.has_media_failure());
    }

    #[test]
    fn test_exfat_active_fat() {
        // Bit 0 clear = first FAT (0)
        let exfat_fat0 = create_exfat_boot_sector(9, 3, 0x0000);
        assert_eq!(exfat_fat0.active_fat(), 0);

        // Bit 0 set = second FAT (1)
        let exfat_fat1 = create_exfat_boot_sector(9, 3, 0x0001);
        assert_eq!(exfat_fat1.active_fat(), 1);

        // Other bits shouldn't affect active FAT
        let exfat_other = create_exfat_boot_sector(9, 3, 0xFFFE);
        assert_eq!(exfat_other.active_fat(), 0);
    }

    // ========================================================================
    // FilesystemType enum tests
    // ========================================================================

    #[test]
    fn test_filesystem_type_debug() {
        // Test Debug derivation
        let fat12 = FilesystemType::Fat12;
        let debug_str = format!("{:?}", fat12);
        assert_eq!(debug_str, "Fat12");

        let ntfs = FilesystemType::Ntfs;
        let debug_str = format!("{:?}", ntfs);
        assert_eq!(debug_str, "Ntfs");
    }

    #[test]
    fn test_filesystem_type_clone() {
        let fat16 = FilesystemType::Fat16;
        let cloned = fat16;
        assert_eq!(fat16, cloned);
    }

    #[test]
    fn test_filesystem_type_partial_eq() {
        assert_eq!(FilesystemType::Fat12, FilesystemType::Fat12);
        assert_ne!(FilesystemType::Fat12, FilesystemType::Fat16);
        assert_ne!(FilesystemType::Ntfs, FilesystemType::ExFat);
        assert_eq!(FilesystemType::Unknown, FilesystemType::Unknown);
    }

    #[test]
    fn test_filesystem_type_copy() {
        let fat32 = FilesystemType::Fat32;
        let copied = fat32; // Copy, not move
        assert_eq!(fat32, copied); // Can still use original
    }

    // ========================================================================
    // ParseError enum tests
    // ========================================================================

    #[test]
    fn test_parse_error_debug() {
        let err = ParseError::BufferTooSmall;
        let debug_str = format!("{:?}", err);
        assert_eq!(debug_str, "BufferTooSmall");

        let err2 = ParseError::InvalidBootSignature;
        let debug_str2 = format!("{:?}", err2);
        assert_eq!(debug_str2, "InvalidBootSignature");
    }

    #[test]
    fn test_parse_error_clone() {
        let err = ParseError::InvalidBytesPerSector;
        let cloned = err;
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_parse_error_partial_eq() {
        assert_eq!(ParseError::BufferTooSmall, ParseError::BufferTooSmall);
        assert_ne!(ParseError::BufferTooSmall, ParseError::ParseFailed);
        assert_eq!(ParseError::UnknownFilesystem, ParseError::UnknownFilesystem);
    }

    #[test]
    fn test_parse_error_copy() {
        let err = ParseError::ParseFailed;
        let copied = err; // Copy, not move
        assert_eq!(err, copied); // Can still use original
    }

    // ========================================================================
    // NtfsEbpb additional tests
    // ========================================================================

    #[test]
    fn test_ntfs_ebpb_mft_record_size() {
        let mut ebpb_data = [0u8; 48];
        // clusters_per_mft_record at offset 0x40 - 0x24 = 0x1C (28)
        ebpb_data[28] = 0xF6u8; // -10 as i8 = 1024 bytes

        let ebpb = NtfsEbpb::ref_from_bytes(&ebpb_data).unwrap();
        assert_eq!(ebpb.mft_record_size(4096), 1024);
    }

    #[test]
    fn test_ntfs_ebpb_index_buffer_size() {
        let mut ebpb_data = [0u8; 48];
        // clusters_per_index_buffer at offset 0x44 - 0x24 = 0x20 (32)
        ebpb_data[32] = 0xF4u8; // -12 as i8 = 4096 bytes

        let ebpb = NtfsEbpb::ref_from_bytes(&ebpb_data).unwrap();
        assert_eq!(ebpb.index_buffer_size(4096), 4096);
    }

    #[test]
    fn test_ntfs_ebpb_positive_cluster_values() {
        let mut ebpb_data = [0u8; 48];
        // Test with positive cluster counts
        ebpb_data[28] = 2; // 2 clusters per MFT record
        ebpb_data[32] = 4; // 4 clusters per index buffer

        let ebpb = NtfsEbpb::ref_from_bytes(&ebpb_data).unwrap();
        assert_eq!(ebpb.mft_record_size(4096), 8192); // 2 * 4096
        assert_eq!(ebpb.index_buffer_size(4096), 16384); // 4 * 4096
    }

    // ========================================================================
    // parse_boot_sector function tests
    // ========================================================================

    #[test]
    fn test_parse_boot_sector_buffer_too_small() {
        let small_buffer = [0u8; 100];
        let result = parse_boot_sector(&small_buffer);
        assert_eq!(result.unwrap_err(), ParseError::BufferTooSmall);
    }

    #[test]
    fn test_parse_boot_sector_invalid_signature() {
        let mut buffer = [0u8; 512];
        // No boot signature (0xAA55)
        let result = parse_boot_sector(&buffer);
        assert_eq!(result.unwrap_err(), ParseError::InvalidBootSignature);

        // Wrong signature
        buffer[510] = 0x00;
        buffer[511] = 0x00;
        let result2 = parse_boot_sector(&buffer);
        assert_eq!(result2.unwrap_err(), ParseError::InvalidBootSignature);
    }

    #[test]
    fn test_boot_sector_header_is_bitlocker() {
        let bl_header = create_header(b"-FVE-FS-");
        assert!(bl_header.is_bitlocker());
        assert!(!bl_header.is_ntfs());
        assert!(!bl_header.is_exfat());

        let ntfs_header = create_header(b"NTFS    ");
        assert!(!ntfs_header.is_bitlocker());

        let fat_header = create_header(b"MSDOS5.0");
        assert!(!fat_header.is_bitlocker());

        let almost_bl = create_header(b"-FVE-FS\0");
        assert!(!almost_bl.is_bitlocker());
    }

    #[test]
    fn test_parse_boot_sector_bitlocker() {
        let mut buffer = [0u8; 512];

        // Boot signature
        buffer[510] = 0x55;
        buffer[511] = 0xAA;

        // OEM ID: "-FVE-FS-"
        buffer[3..11].copy_from_slice(b"-FVE-FS-");

        // BPB: valid NTFS-like layout (512 bytes/sector, 8 sectors/cluster)
        buffer[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buffer[0x0D] = 8;

        // NTFS-style EBPB fields reused by BitLocker:
        // total_sectors at offset 0x28
        buffer[0x28..0x30].copy_from_slice(&1048576u64.to_le_bytes());
        // volume_serial_number at offset 0x48
        buffer[0x48..0x50].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());

        let parsed = parse_boot_sector(&buffer).expect("should parse as BitLocker");
        match parsed {
            ParsedBootSector::BitLocker {
                header,
                bpb,
                total_sectors,
                volume_serial_number,
                boot_code,
            } => {
                assert!(header.is_bitlocker());
                assert_eq!(bpb.bytes_per_sector.get(), 512);
                assert_eq!(bpb.sectors_per_cluster, 8);
                assert_eq!(total_sectors, 1048576);
                assert_eq!(volume_serial_number, 0xDEAD_BEEF_CAFE_BABE);
                assert_eq!(boot_code.len(), 510 - 0x54);
            }
            other => panic!("Expected BitLocker, got {other:?}"),
        }
    }

    #[test]
    fn test_detected_boot_sector_bitlocker() {
        let mut buffer = [0u8; 512];
        buffer[510] = 0x55;
        buffer[511] = 0xAA;
        buffer[3..11].copy_from_slice(b"-FVE-FS-");
        buffer[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buffer[0x0D] = 8;
        buffer[0x28..0x30].copy_from_slice(&1048576u64.to_le_bytes());

        let detected = DetectedBootSector::from_bytes(&buffer);
        assert_eq!(detected, DetectedBootSector::BitLocker);
        assert!(!detected.is_filesystem());
        assert!(!detected.is_partition_table());
    }

    #[test]
    fn test_bitlocker_wins_over_ntfs_like_bpb() {
        let mut buffer = [0u8; 512];
        buffer[510] = 0x55;
        buffer[511] = 0xAA;
        buffer[3..11].copy_from_slice(b"-FVE-FS-");
        buffer[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buffer[0x0D] = 8;
        buffer[0x28..0x30].copy_from_slice(&2097152u64.to_le_bytes());

        let parsed = parse_boot_sector(&buffer).expect("should parse");
        let ParsedBootSector::BitLocker { .. } = parsed else {
            panic!("Expected BitLocker, got {parsed:?}");
        };
    }

    #[test]
    fn test_malformed_bitlocker_falls_through_to_partition_table() {
        let mut buffer = [0u8; 512];
        buffer[510] = 0x55;
        buffer[511] = 0xAA;
        buffer[3..11].copy_from_slice(b"-FVE-FS-");
        // bytes_per_sector left at 0 — invalid BPB, so filesystem parse fails
        // and falls through to partition table detection

        let result = parse_boot_sector(&buffer);
        assert_eq!(result.unwrap_err(), ParseError::UnknownFilesystem);
    }

    #[test]
    fn test_diagnose_boot_sector_buffer_too_small() {
        let diagnosis = diagnose_boot_sector(&[0u8; 128]);
        assert_eq!(
            diagnosis,
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::BufferTooSmall)
        );
    }

    #[test]
    fn test_diagnose_boot_sector_all_zeroes() {
        let diagnosis = diagnose_boot_sector(&[0u8; 512]);
        assert_eq!(
            diagnosis,
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::AllZeroes)
        );
    }

    #[test]
    fn test_diagnose_boot_sector_invalid_signature() {
        let mut buffer = [0u8; 512];
        buffer[3..11].copy_from_slice(b"NTFS    ");
        let diagnosis = diagnose_boot_sector(&buffer);
        assert_eq!(
            diagnosis,
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::InvalidBootSignature)
        );
    }

    #[test]
    fn test_diagnose_boot_sector_unknown_with_hints() {
        let mut buffer = [0u8; 512];
        buffer[510] = 0x55;
        buffer[511] = 0xAA;
        buffer[3..11].copy_from_slice(b"NTFS    ");
        // invalid bytes per sector keeps this from parsing as NTFS
        buffer[0x0B..0x0D].copy_from_slice(&123u16.to_le_bytes());

        let diagnosis = diagnose_boot_sector(&buffer);
        assert_eq!(
            diagnosis,
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnknownFilesystem {
                ntfs_oem_hint: true,
                exfat_hint: false,
                bitlocker_hint: false,
                mbr_layout_hint: true,
            })
        );
    }

    #[test]
    fn test_diagnose_boot_sector_unsupported_hpfs() {
        let mut buffer = [0u8; 512];
        buffer[510] = 0x55;
        buffer[511] = 0xAA;
        buffer[3..11].copy_from_slice(b"HPFS    ");
        buffer[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buffer[0x0D] = 1;
        buffer[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes());
        buffer[0x10] = 2;
        buffer[0x11..0x13].copy_from_slice(&512u16.to_le_bytes());
        buffer[0x13..0x15].copy_from_slice(&0u16.to_le_bytes());
        buffer[0x15] = 0xF8;
        buffer[0x16..0x18].copy_from_slice(&9u16.to_le_bytes());
        buffer[0x20..0x24].copy_from_slice(&32768u32.to_le_bytes());

        let diagnosis = diagnose_boot_sector(&buffer);
        assert_eq!(
            diagnosis,
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnsupportedFilesystem(
                FilesystemType::Hpfs
            ))
        );
    }

    // ========================================================================
    // DetectedBootSector ext detection tests
    // ========================================================================

    fn synthesize_ext_superblock(buf: &mut [u8]) {
        // s_magic at offset 1024 + 0x38 = 0x438 (little-endian 0xEF53)
        buf[0x438] = 0x53;
        buf[0x439] = 0xEF;
        // s_log_block_size at offset 1024 + 0x18: set to 2 (4 KiB blocks)
        buf[1024 + 0x18..1024 + 0x18 + 4].copy_from_slice(&2u32.to_le_bytes());
        // s_blocks_per_group at offset 1024 + 0x20: non-zero
        buf[1024 + 0x20..1024 + 0x20 + 4].copy_from_slice(&32_768u32.to_le_bytes());
        // s_inodes_per_group at offset 1024 + 0x28: non-zero
        buf[1024 + 0x28..1024 + 0x28 + 4].copy_from_slice(&8_192u32.to_le_bytes());
    }

    #[test]
    fn from_bytes_detects_ext_with_valid_sanity_fields() {
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        synthesize_ext_superblock(&mut buf);
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Ext
        );
    }

    fn synthesize_apfs_superblock(buf: &mut [u8]) {
        // obj_phys_t object type at 0x18: OBJECT_TYPE_NX_SUPERBLOCK (0x01).
        buf[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        // nx_magic at 0x20: "NXSB".
        buf[0x20..0x24].copy_from_slice(b"NXSB");
        // nx_block_size at 0x24: 4 KiB.
        buf[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
    }

    #[test]
    fn from_bytes_detects_apfs_container() {
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        synthesize_apfs_superblock(&mut buf);
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Apfs
        );
        assert!(DetectedBootSector::Apfs.is_filesystem());
    }

    #[test]
    fn from_bytes_rejects_apfs_with_bad_block_size() {
        // A non-power-of-two nx_block_size must not be classified as APFS.
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        synthesize_apfs_superblock(&mut buf);
        buf[0x24..0x28].copy_from_slice(&5000u32.to_le_bytes());
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }

    #[test]
    fn from_bytes_short_buffer_does_not_detect_ext() {
        // Buffer below EXT_PROBE_MIN_LEN must fall through to the existing
        // 512-byte signature checks and return Unknown for unrecognized
        // bytes. A real ext image's first 512 bytes don't carry the ext
        // magic.
        let buf = vec![0u8; 512];
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }

    #[test]
    fn from_bytes_ext_detection_requires_full_magic_region() {
        // Buffer one byte short of 0x43A must not claim Ext.
        let buf = vec![0u8; EXT_PROBE_MIN_LEN - 1];
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }

    #[test]
    fn from_bytes_prefers_gpt_over_coincidental_ext_magic_in_partition_array() {
        // Construct 2048 bytes of "GPT disk with stray 0xEF53 at 0x438":
        //   bytes 0..512:   protective MBR with type 0xEE + 0xAA55 signature
        //   bytes 512..:    ignored GPT-header region
        //   bytes 1024..:   plant 0xEF53 at 0x438 WITHOUT supporting sanity
        //                   fields, so probe_ext must reject.
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        // MBR partition entry 1 type = 0xEE (protective GPT marker)
        buf[0x1C2] = 0xEE;
        // MBR boot signature
        buf[0x1FE] = 0x55;
        buf[0x1FF] = 0xAA;
        // Bare ext magic — sanity fields remain zero.
        buf[0x438] = 0x53;
        buf[0x439] = 0xEF;

        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::GptPartitioned,
            "probe_ext must reject magic-only; GPT classification must win",
        );
    }

    #[test]
    fn from_bytes_rejects_ext_when_sanity_fields_are_bogus() {
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        // Plant magic and non-zero blocks/inodes per group, but set
        // log_block_size to an out-of-range value.
        buf[0x438] = 0x53;
        buf[0x439] = 0xEF;
        buf[EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE] = 99; // out of 0..=6
        buf[EXT_SUPERBLOCK_OFFSET + SB_S_BLOCKS_PER_GROUP] = 1;
        buf[EXT_SUPERBLOCK_OFFSET + SB_S_INODES_PER_GROUP] = 1;
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }

    // ========================================================================
    // probe_ext / probe_apfs constant and boundary tests
    // ========================================================================

    #[test]
    fn ext_probe_min_len_matches_magic_field_end() {
        // The constant must equal the offset of the last byte of s_magic + 1.
        // Catches arithmetic-operator mutations on the constant expression at
        // line 37 (e.g. `+` → `-` or `*`).
        assert_eq!(EXT_PROBE_MIN_LEN, 0x43A);
    }

    #[test]
    fn ext_probe_short_buffer_at_minimum_minus_one_returns_unknown() {
        // Buffer of size 0x439 has buf[0x438] but not buf[0x439], so the
        // u16 magic read at offset 0x438 would index out of bounds. The
        // size check at probe_ext line 52 must reject this buffer; any
        // mutation that shrinks EXT_PROBE_MIN_LEN below 0x43A makes the
        // check pass, and the magic read then panics.
        let buf = vec![0u8; 0x439];
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }

    #[test]
    fn ext_probe_succeeds_at_exact_minimum_buffer_size() {
        // Buffer of exactly 0x43A bytes — the smallest size that fits the
        // magic field. Catches mutations that grow EXT_PROBE_MIN_LEN
        // (e.g. `SB_S_MAGIC + 2` → `SB_S_MAGIC * 2`) which would push the
        // size threshold above the buffer length.
        let mut buf = vec![0u8; 0x43A];
        synthesize_ext_superblock(&mut buf);
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Ext
        );
    }

    #[test]
    fn ext_probe_rejects_log_block_size_above_six() {
        // s_log_block_size of 7 must reject — anchors the `> 6` boundary
        // against `>= 6` (which would reject the valid 6).
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        synthesize_ext_superblock(&mut buf);
        buf[EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE
            ..EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE + 4]
            .copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }

    #[test]
    fn ext_probe_accepts_log_block_size_exactly_six() {
        // s_log_block_size of 6 must pass — anchors `> 6` against `>= 6`.
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        synthesize_ext_superblock(&mut buf);
        buf[EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE
            ..EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE + 4]
            .copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Ext
        );
    }

    #[test]
    fn apfs_probe_min_len_matches_block_size_field_end() {
        // Catches arithmetic-operator mutations on the constant expression
        // at line 85 (e.g. `+ 4` → `- 4` or `* 4`).
        assert_eq!(APFS_PROBE_MIN_LEN, 0x28);
    }

    #[test]
    fn apfs_probe_succeeds_at_minimum_buffer_size() {
        // 0x28 bytes is the smallest buffer that fits nx_block_size at
        // offset 0x24..0x28. Buffer < 512 short-circuits standard detection
        // to BufferTooSmall, but probe_apfs still runs from the diagnose
        // fall-through, so APFS classification can succeed.
        let mut buf = vec![0u8; 0x28];
        buf[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        buf[0x20..0x24].copy_from_slice(b"NXSB");
        buf[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Apfs
        );
    }

    #[test]
    fn apfs_probe_below_minimum_buffer_size_returns_unknown() {
        // A buffer of 0x27 bytes is one short of fitting nx_block_size.
        // Catches `< with <=` (would reject 0x28, the valid minimum) and
        // any mutation that lets a too-short buffer through (which would
        // then panic reading at 0x24..0x28).
        let mut buf = vec![0u8; 0x27];
        buf[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        buf[0x20..0x24].copy_from_slice(b"NXSB");
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }

    // ========================================================================
    // DosBpb::looks_like_ntfs — each of the four AND-chain branches must
    // independently veto an NTFS classification.
    // ========================================================================

    #[test]
    fn looks_like_ntfs_requires_every_field_zero() {
        // Each row keeps three of the four fields zero and makes the fourth
        // non-zero. The `&&` chain must reject every row; mutating any
        // `&&` to `||` would let three of the four cases through.
        let cases: &[(u16, u8, u16, u16)] =
            &[(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)];
        for &(reserved, num_fats, root_entry, spf16) in cases {
            let bpb = create_dos_bpb(512, 8, reserved, num_fats, root_entry, 0, spf16, 0);
            assert!(
                !bpb.looks_like_ntfs(),
                "fields (reserved={reserved}, num_fats={num_fats}, root_entry={root_entry}, spf16={spf16}) must not classify as NTFS",
            );
        }

        // Sanity baseline: all-zero still classifies as NTFS-like.
        let ntfs = create_dos_bpb(512, 8, 0, 0, 0, 0, 0, 0);
        assert!(ntfs.looks_like_ntfs());
    }

    // ========================================================================
    // DetectedBootSector::is_partition_table — anchor MBR/GPT as true.
    // ========================================================================

    #[test]
    fn is_partition_table_true_for_mbr_and_gpt_only() {
        assert!(DetectedBootSector::MbrPartitioned.is_partition_table());
        assert!(DetectedBootSector::GptPartitioned.is_partition_table());
        // Non-partition-table variants must remain false.
        assert!(!DetectedBootSector::Ntfs.is_partition_table());
        assert!(!DetectedBootSector::Fat32.is_partition_table());
        assert!(!DetectedBootSector::ExFat.is_partition_table());
        assert!(!DetectedBootSector::Ext.is_partition_table());
        assert!(!DetectedBootSector::Apfs.is_partition_table());
        assert!(!DetectedBootSector::BitLocker.is_partition_table());
        assert!(!DetectedBootSector::Unknown.is_partition_table());
    }

    // ========================================================================
    // diagnose_boot_sector_standard hints — exfat_zeroed_bpb / OR logic.
    // ========================================================================

    #[test]
    fn unknown_diagnosis_reports_exfat_zeroed_bpb_hint_when_bpb_is_all_zero() {
        // OEM "NTFS    " (so ntfs_oem_hint=true, exfat_oem_hint=false) plus
        // an all-zero BPB region. Parse fails at bytes_per_sector=0 and
        // falls through to partition-table parsing, which (no valid entries)
        // returns UnknownFilesystem — exposing the hint flags. This catches
        // both `b == 0 → b != 0` (would flip the zeroed-region check) and
        // `|| → &&` in the exfat_hint combination (would AND the two
        // exfat sub-hints, losing the zeroed-region signal).
        let mut buffer = [0u8; 512];
        buffer[510] = 0x55;
        buffer[511] = 0xAA;
        buffer[3..11].copy_from_slice(b"NTFS    ");
        // BPB region [0x0B..0x40] left all-zero on purpose.

        let diagnosis = diagnose_boot_sector(&buffer);
        assert_eq!(
            diagnosis,
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnknownFilesystem {
                ntfs_oem_hint: true,
                exfat_hint: true,
                bitlocker_hint: false,
                mbr_layout_hint: true,
            })
        );
    }

    // ========================================================================
    // ExFatBootSector::is_valid — each guard rejects the corresponding
    // malformation; the well-formed sector must classify as valid.
    // ========================================================================

    #[test]
    fn exfat_is_valid_well_formed_sector() {
        // Pins `-> bool with false` on the function and the boundary shifts
        // 9 and 12 against `!(9..=12).contains(...)`.
        let bs9 = create_exfat_boot_sector(9, 3, 0);
        assert!(bs9.is_valid());
        let bs12 = create_exfat_boot_sector(12, 0, 0);
        assert!(bs12.is_valid());
    }

    #[test]
    fn exfat_is_valid_rejects_each_invariant_violation() {
        // Bad filesystem_name — pins `!= with ==` at line 692:34.
        let mut bs = create_exfat_boot_sector(9, 3, 0);
        bs.filesystem_name = *b"EXFATXY!";
        assert!(!bs.is_valid());

        // Non-zero byte in must_be_zero — pins `delete !` at line 697:12
        // and `== with !=` at line 697:49.
        let mut bs = create_exfat_boot_sector(9, 3, 0);
        bs.must_be_zero[27] = 0xAB;
        assert!(!bs.is_valid());

        // Bad boot_signature — pins `!= with ==` at line 702:38.
        let mut bs = create_exfat_boot_sector(9, 3, 0);
        bs.boot_signature = U16::new(0x1234);
        assert!(!bs.is_valid());

        // bytes_per_sector_shift out of range below — pins `delete !` at
        // line 707:12 (would accept invalid shifts).
        let bs = create_exfat_boot_sector(8, 3, 0);
        assert!(!bs.is_valid());

        // bytes_per_sector_shift out of range above.
        let bs = create_exfat_boot_sector(13, 3, 0);
        assert!(!bs.is_valid());
    }

    // ========================================================================
    // Full-sector parsing for each filesystem type and the partition table
    // fallback. These exercise try_parse_filesystem and determine_fat_type.
    // ========================================================================

    /// Stamp the boot signature into bytes 0x1FE..0x200.
    fn stamp_boot_signature(buf: &mut [u8; 512]) {
        buf[510] = 0x55;
        buf[511] = 0xAA;
    }

    /// Build a DOS BPB-bearing boot sector with the given parameters and OEM.
    /// `total_16` is encoded in the 16-bit `total_sectors_16` slot; if zero,
    /// `total_32` carries the 32-bit slot.
    #[expect(clippy::too_many_arguments, reason = "mirrors the BPB layout")]
    fn build_dos_boot_sector(
        oem: &[u8; 8],
        bytes_per_sector: u16,
        sectors_per_cluster: u8,
        reserved_sectors: u16,
        num_fats: u8,
        root_entry_count: u16,
        total_16: u16,
        spf16: u16,
        total_32: u32,
    ) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        buf[3..11].copy_from_slice(oem);
        buf[0x0B..0x0D].copy_from_slice(&bytes_per_sector.to_le_bytes());
        buf[0x0D] = sectors_per_cluster;
        buf[0x0E..0x10].copy_from_slice(&reserved_sectors.to_le_bytes());
        buf[0x10] = num_fats;
        buf[0x11..0x13].copy_from_slice(&root_entry_count.to_le_bytes());
        buf[0x13..0x15].copy_from_slice(&total_16.to_le_bytes());
        buf[0x15] = 0xF8;
        buf[0x16..0x18].copy_from_slice(&spf16.to_le_bytes());
        buf[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
        buf[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
        buf[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
        buf[0x20..0x24].copy_from_slice(&total_32.to_le_bytes());
        stamp_boot_signature(&mut buf);
        buf
    }

    fn build_fat16_sector(total_sectors_16: u16, sectors_per_fat_16: u16) -> [u8; 512] {
        // FAT16: 4085 ≤ cluster_count < 65525.
        // With 32000 sectors / 4 spc and 128 spf, cluster_count ≈ 7927.
        let mut buf = build_dos_boot_sector(
            b"MSDOS5.0",
            512,
            4,
            1,
            2,
            512,
            total_sectors_16,
            sectors_per_fat_16,
            0,
        );
        // Fat16Ebpb: boot signature at 0x26, fs type label at 0x36.
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT16   ");
        buf
    }

    fn build_fat12_sector() -> [u8; 512] {
        // FAT12: cluster_count < 4085. With 2880 sectors / 1 spc and 9 spf,
        // cluster_count is well below 4085 (matches a 1.44 MB floppy).
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 1, 1, 2, 224, 2880, 9, 0);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
        buf
    }

    fn build_fat32_sector() -> [u8; 512] {
        // FAT32: sectors_per_fat_16 == 0 AND root_entry_count == 0.
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 8, 32, 2, 0, 0, 0, 4_194_304);
        // Fat32Ebpb: sectors_per_fat_32 at 0x24, boot_signature at 0x42,
        // filesystem_type at 0x52.
        buf[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        buf[0x42] = 0x29;
        buf[0x52..0x5A].copy_from_slice(b"FAT32   ");
        buf
    }

    fn build_ntfs_sector() -> [u8; 512] {
        // NTFS via OEM "NTFS    " (looks_like_ntfs() is true for these fields).
        let mut buf = build_dos_boot_sector(b"NTFS    ", 512, 8, 0, 0, 0, 0, 0, 0);
        buf[0x28..0x30].copy_from_slice(&1_048_576u64.to_le_bytes());
        buf
    }

    fn build_hpfs_sector() -> [u8; 512] {
        // HPFS via OEM "HPFS    " — uses Fat16Ebpb layout but a different OEM.
        let mut buf = build_dos_boot_sector(b"HPFS    ", 512, 1, 1, 2, 512, 2880, 9, 0);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
        buf
    }

    fn build_exfat_sector() -> [u8; 512] {
        // exFAT: OEM "EXFAT   " plus the dedicated exFAT layout in bytes
        // 0..512. The BPB region 0x0B..0x40 must be all zero.
        let mut buf = [0u8; 512];
        buf[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        buf[3..11].copy_from_slice(b"EXFAT   ");
        // 0x0B..0x40 stays all-zero (must_be_zero).
        // Partition offset / volume length at 0x40..0x50.
        buf[0x48..0x50].copy_from_slice(&1_048_576u64.to_le_bytes()); // volume_length
        // bytes_per_sector_shift = 9 → 512.
        buf[0x6C] = 9;
        // sectors_per_cluster_shift = 3 → 8.
        buf[0x6D] = 3;
        buf[0x6E] = 1; // number_of_fats
        buf[0x6F] = 0x80; // drive_select
        stamp_boot_signature(&mut buf);
        buf
    }

    fn build_mbr_sector_with_partition() -> [u8; 512] {
        let mut buf = [0u8; 512];
        // Partition entry 1 (offset 446): NTFS partition.
        buf[446] = 0x80; // bootable
        buf[446 + 4] = 0x07; // partition_type NTFS/HPFS/exFAT
        buf[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes()); // start_lba
        buf[446 + 12..446 + 16].copy_from_slice(&1_000_000u32.to_le_bytes()); // sector_count
        stamp_boot_signature(&mut buf);
        buf
    }

    fn build_gpt_protective_sector() -> [u8; 512] {
        let mut buf = [0u8; 512];
        // Partition entry 1: GPT protective marker.
        buf[446 + 4] = crate::partition::MBR_TYPE_GPT_PROTECTIVE;
        buf[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        buf[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        stamp_boot_signature(&mut buf);
        buf
    }

    #[test]
    fn parse_boot_sector_classifies_each_supported_filesystem() {
        // Each variant gets one canonical fixture; we check both the
        // ParsedBootSector variant and DetectedBootSector::from_bytes
        // classification. Together these anchor:
        //  - line 1109 `||` (NTFS detection via OEM ID OR looks_like_ntfs)
        //  - line 1121 `==` & `&&` (FAT32 detection via two zero-field check)
        //  - line 1136 `==` (HPFS detection via OEM prefix)
        //  - line 1150/1156 match arms FAT12/FAT16
        //  - line 1074 `||` & `==` (exFAT detection via OEM OR zeroed BPB)
        //  - line 1076 `==` (exFAT BPB-zeroed all-bytes check)
        //  - the FilesystemType::Fat12 / Fat16 match arms in
        //    try_parse_filesystem.

        let fat12 = build_fat12_sector();
        assert!(matches!(
            parse_boot_sector(&fat12).unwrap(),
            ParsedBootSector::Fat12 { .. }
        ));
        assert_eq!(
            DetectedBootSector::from_bytes(&fat12),
            DetectedBootSector::Fat12
        );

        let fat16 = build_fat16_sector(32000, 128);
        assert!(matches!(
            parse_boot_sector(&fat16).unwrap(),
            ParsedBootSector::Fat16 { .. }
        ));
        assert_eq!(
            DetectedBootSector::from_bytes(&fat16),
            DetectedBootSector::Fat16
        );

        let fat32 = build_fat32_sector();
        assert!(matches!(
            parse_boot_sector(&fat32).unwrap(),
            ParsedBootSector::Fat32 { .. }
        ));
        assert_eq!(
            DetectedBootSector::from_bytes(&fat32),
            DetectedBootSector::Fat32
        );

        let ntfs = build_ntfs_sector();
        assert!(matches!(
            parse_boot_sector(&ntfs).unwrap(),
            ParsedBootSector::Ntfs { .. }
        ));
        assert_eq!(
            DetectedBootSector::from_bytes(&ntfs),
            DetectedBootSector::Ntfs
        );

        let hpfs = build_hpfs_sector();
        assert!(matches!(
            parse_boot_sector(&hpfs).unwrap(),
            ParsedBootSector::Hpfs { .. }
        ));
        // HPFS is unsupported by DetectedBootSector → maps to Unknown.
        assert_eq!(
            DetectedBootSector::from_bytes(&hpfs),
            DetectedBootSector::Unknown
        );

        let exfat = build_exfat_sector();
        assert!(matches!(
            parse_boot_sector(&exfat).unwrap(),
            ParsedBootSector::ExFat { .. }
        ));
        assert_eq!(
            DetectedBootSector::from_bytes(&exfat),
            DetectedBootSector::ExFat
        );

        let mbr = build_mbr_sector_with_partition();
        assert!(matches!(
            parse_boot_sector(&mbr).unwrap(),
            ParsedBootSector::Mbr { .. }
        ));
        assert_eq!(
            DetectedBootSector::from_bytes(&mbr),
            DetectedBootSector::MbrPartitioned
        );

        let gpt = build_gpt_protective_sector();
        assert!(matches!(
            parse_boot_sector(&gpt).unwrap(),
            ParsedBootSector::Gpt { .. }
        ));
        assert_eq!(
            DetectedBootSector::from_bytes(&gpt),
            DetectedBootSector::GptPartitioned
        );
    }

    #[test]
    fn ntfs_detection_via_looks_like_ntfs_when_oem_is_not_ntfs() {
        // Mutating line 1109 `||` → `&&` would break detection of NTFS
        // volumes whose OEM ID was overwritten (still valid on-disk: the
        // spec allows arbitrary OEMs and Microsoft formerly warned against
        // OEM-based detection). This anchors the looks_like_ntfs() branch.
        let mut buf = build_ntfs_sector();
        buf[3..11].copy_from_slice(b"GENERIC ");
        assert!(matches!(
            parse_boot_sector(&buf).unwrap(),
            ParsedBootSector::Ntfs { .. }
        ));
    }

    #[test]
    fn fat32_detection_requires_zero_root_entry_and_zero_sectors_per_fat_16() {
        // Both `sectors_per_fat_16 == 0` AND `root_entry_count == 0` must
        // hold for FAT32; mutating either `==` to `!=`, or the inner `&&`
        // to `||`, would misclassify these adjacent edges.
        let buf = build_fat32_sector();
        assert!(matches!(
            parse_boot_sector(&buf).unwrap(),
            ParsedBootSector::Fat32 { .. }
        ));

        // Non-zero root_entry_count → not FAT32 (lands as FAT16/12).
        let mut buf = build_fat32_sector();
        buf[0x11..0x13].copy_from_slice(&512u16.to_le_bytes());
        // The cluster-count calculation now needs a non-zero spf16 to
        // avoid the "FAT32 here" early-return inside determine_fat_type,
        // so set sectors_per_fat_16 too.
        buf[0x16..0x18].copy_from_slice(&128u16.to_le_bytes());
        buf[0x13..0x15].copy_from_slice(&32000u16.to_le_bytes());
        assert!(!matches!(
            parse_boot_sector(&buf).unwrap(),
            ParsedBootSector::Fat32 { .. }
        ));

        // Non-zero sectors_per_fat_16 → not FAT32.
        let mut buf = build_fat32_sector();
        buf[0x16..0x18].copy_from_slice(&128u16.to_le_bytes());
        buf[0x13..0x15].copy_from_slice(&32000u16.to_le_bytes());
        buf[0x11..0x13].copy_from_slice(&512u16.to_le_bytes());
        assert!(!matches!(
            parse_boot_sector(&buf).unwrap(),
            ParsedBootSector::Fat32 { .. }
        ));
    }

    #[test]
    fn hpfs_detection_via_oem_prefix() {
        // Mutates line 1136 `==` → `!=` would swap HPFS detection. The
        // build_hpfs_sector covers the HPFS arm; an "OS2 " prefix is also
        // valid per the implementation and exercises the second `==`.
        let hpfs = build_hpfs_sector();
        assert!(matches!(
            parse_boot_sector(&hpfs).unwrap(),
            ParsedBootSector::Hpfs { .. }
        ));

        let mut os2 = hpfs;
        os2[3..7].copy_from_slice(b"OS2 ");
        assert!(matches!(
            parse_boot_sector(&os2).unwrap(),
            ParsedBootSector::Hpfs { .. }
        ));

        // Non-HPFS OEM with otherwise-identical layout lands as FAT.
        let mut fat = hpfs;
        fat[3..11].copy_from_slice(b"MSDOS5.0");
        let parsed = parse_boot_sector(&fat).unwrap();
        assert!(
            matches!(
                parsed,
                ParsedBootSector::Fat12 { .. } | ParsedBootSector::Fat16 { .. }
            ),
            "non-HPFS OEM should fall through to FAT12/16, got {parsed:?}",
        );
    }

    // ========================================================================
    // determine_fat_type cluster-count boundaries
    // ========================================================================

    #[test]
    fn fat12_to_fat16_boundary_at_4085_clusters() {
        // FAT16 begins at 4085 clusters. Anchors line 1232 `<` against
        // `<=`, `==`, `>`.  We choose total_sectors_16 to land just above
        // and just below the boundary.

        // 1 spc, 1 reserved sector, 2 FATs, root_entry_count=16 → 1 root-dir
        // sector (16*32=512). spf16 = 1 → fat_size = 1 sector each. So
        // first_data_sector = 1 + 2*1 + 1 = 4. cluster_count = total - 4.
        // To get 4084 (FAT12) clusters: total = 4088.
        let buf = build_dos_boot_sector(b"MSDOS5.0", 512, 1, 1, 2, 16, 4088, 1, 0);
        let mut buf = buf;
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
        assert!(matches!(
            parse_boot_sector(&buf).unwrap(),
            ParsedBootSector::Fat12 { .. }
        ));

        // 4085 clusters → FAT16. total = 4089.
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 1, 1, 2, 16, 4089, 1, 0);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT16   ");
        assert!(matches!(
            parse_boot_sector(&buf).unwrap(),
            ParsedBootSector::Fat16 { .. }
        ));
    }

    #[test]
    fn fat16_to_fat32_boundary_uses_cluster_count_threshold() {
        // The FAT16/FAT32 boundary is at 65525 clusters in determine_fat_type.
        // determine_fat_type only runs when sectors_per_fat_16 != 0, so
        // both fixtures here carry a non-zero spf16. Just under the
        // boundary → FAT16; ≥ 65525 → returned as FAT32 from
        // determine_fat_type, but try_parse_filesystem's outer match would
        // then return UnknownFilesystem (FAT32 path requires spf16 == 0).
        // Anchors line 1234 `<` against `<=`, `==`, `>`.

        // 65524 clusters → FAT16. With 1 spc, 0 root entries, 1 reserved, 1
        // FAT, fat_size=1 → first_data_sector = 1+1+0 = 2. total = 65526.
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 1, 1, 1, 0, 0, 1, 65526);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT16   ");
        assert!(matches!(
            parse_boot_sector(&buf).unwrap(),
            ParsedBootSector::Fat16 { .. }
        ));

        // 65525 clusters → determine_fat_type returns Fat32; the outer
        // match doesn't have a FAT32 arm for FAT16-style layouts, so
        // try_parse_filesystem returns Err(UnknownFilesystem). Falls
        // through to the partition-table path, which also fails (no
        // partition entries), yielding Err(UnknownFilesystem).
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 1, 1, 1, 0, 0, 1, 65527);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
        let err = parse_boot_sector(&buf).unwrap_err();
        assert_eq!(err, ParseError::UnknownFilesystem);
    }

    #[test]
    fn determine_fat_type_rejects_zero_bytes_per_sector_branch() {
        // bytes_per_sector or sectors_per_cluster of 0 makes the FAT12/16
        // path return UnknownFilesystem at the front of determine_fat_type.
        // try_parse_filesystem's early bytes_per_sector validation catches
        // bps=0 first (InvalidBytesPerSector) — so to actually exercise
        // determine_fat_type's `== 0 || == 0` guard we need a path that
        // bypasses that. Setting spc=0 with a valid bps does the job:
        // bps=512 passes the matches!() guard, then determine_fat_type
        // hits its zero-spc check.
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 0, 1, 2, 16, 4096, 1, 0);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
        // determine_fat_type → Unknown → outer match returns UnknownFilesystem.
        // Then partition-table fallback runs; no valid partitions → still
        // Err(UnknownFilesystem).
        let err = parse_boot_sector(&buf).unwrap_err();
        assert_eq!(err, ParseError::UnknownFilesystem);
    }

    #[test]
    fn determine_fat_type_requires_non_zero_sectors_per_fat_16() {
        // sectors_per_fat_16 == 0 makes determine_fat_type return Unknown
        // because the FAT32-style EBPB doesn't carry the value here.
        // Anchors line 1210 `!= with ==` — flipping the inequality would
        // claim the value `0` is valid and proceed to a divide-by-zero
        // shaped calculation.
        //
        // Build a layout that isn't FAT32 (non-zero root_entry_count) but
        // has spf16 == 0 — the outer FAT32 branch is gated by
        // root_entry_count == 0, so we go through the FAT12/16 path,
        // which lands in determine_fat_type with spf16 == 0 and returns
        // Unknown.
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 1, 1, 2, 16, 4096, 0, 0);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
        let err = parse_boot_sector(&buf).unwrap_err();
        assert_eq!(err, ParseError::UnknownFilesystem);
    }

    #[test]
    fn determine_fat_type_rejects_when_total_sectors_at_or_below_first_data() {
        // Anchors line 1225 `<= with >` — when total_sectors equals the
        // first_data_sector, there are zero data sectors, which is
        // pathological. The function returns Unknown rather than 0
        // clusters → FAT12. Mutated `>` would only reject when
        // total_sectors is strictly less than first_data_sector, letting
        // the boundary value through to determine_fat_type returning
        // FAT12 for `0 < 4085`.
        //
        // Layout: 1 spc, 1 reserved, 2 FATs, root=16 (1 sector), spf16=1
        // → first_data_sector = 1 + 2*1 + 1 = 4.
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 1, 1, 2, 16, 4, 1, 0);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
        let err = parse_boot_sector(&buf).unwrap_err();
        assert_eq!(err, ParseError::UnknownFilesystem);
    }

    #[test]
    fn determine_fat_type_multiplies_num_fats_by_fat_size() {
        // first_data_sector = reserved + (num_fats * fat_size) + root_dir_sectors.
        // Mutating `num_fats * fat_size` → `num_fats / fat_size` collapses
        // 2 / 128 to 0, dropping 256 sectors from first_data_sector and
        // shifting cluster_count above the FAT12 threshold. Pick total=4200
        // so the original lands at 3911 clusters (FAT12) and the mutated
        // calculation lands at 4167 (FAT16).
        //
        // Layout: bps=512, spc=1, reserved=1, num_fats=2, root=512 entries
        // (32 root-dir sectors), spf16=128. first_data_orig = 1 + 256 + 32
        // = 289; first_data_mut = 1 + 0 + 32 = 33.
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 1, 1, 2, 512, 4200, 128, 0);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
        assert!(matches!(
            parse_boot_sector(&buf).unwrap(),
            ParsedBootSector::Fat12 { .. }
        ));
    }

    #[test]
    fn determine_fat_type_uses_sectors_per_cluster_to_divide_data_sectors() {
        // Catches `/ with %` and `/ with *` at line 1230 (data_sectors /
        // sectors_per_cluster). With sectors_per_cluster = 8 the original
        // computes cluster_count = data_sectors / 8; `%` would compute
        // data_sectors mod 8 (tiny number, FAT12); `*` would compute
        // data_sectors * 8 (huge, FAT32 territory and the outer match
        // rejects via UnknownFilesystem).
        //
        // Aim for FAT16 territory: spc=8, spf16=64, total=2_000_000.
        // first_data_sector = 1 + 2*64 + 32 = 161. data_sectors = 1_999_839.
        // cluster_count = 1_999_839 / 8 = 249_979 → FAT32 territory →
        // outer FAT16 match rejects → UnknownFilesystem.
        //
        // Mutated `/` → `%`: cluster_count = 1_999_839 % 8 = 7 → FAT12.
        // The fixture asserts the result is NOT FAT12.
        let mut buf = build_dos_boot_sector(b"MSDOS5.0", 512, 8, 1, 2, 512, 0, 64, 2_000_000);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT16   ");
        let parsed = parse_boot_sector(&buf);
        assert!(
            !matches!(parsed, Ok(ParsedBootSector::Fat12 { .. })),
            "data_sectors / sectors_per_cluster must produce FAT32-sized cluster_count (not FAT12); got {parsed:?}",
        );
    }

    #[test]
    fn from_bytes_rejects_crafted_gpt_with_valid_ext_sanity_fields() {
        // A maliciously-crafted GPT partition-entry area where bytes at
        // 0x438 pass ALL four probe_ext sanity checks (magic + log_block_size
        // + non-zero blocks_per_group + non-zero inodes_per_group). With the
        // old detection order (probe_ext first) this would misclassify the
        // disk as Ext and cause detect_layout to skip partition enumeration.
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];

        // Valid protective MBR:
        buf[0x1C2] = 0xEE; // Partition entry 1 type = GPT protective
        buf[0x1FE] = 0x55; // MBR boot signature
        buf[0x1FF] = 0xAA;

        // Full ext-sanity region:
        synthesize_ext_superblock(&mut buf);

        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::GptPartitioned,
            "GPT must win over a probe_ext-passing sanity region",
        );
    }
}
