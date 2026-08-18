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
//! - `OSDev` Wiki FAT/NTFS documentation
//! - Wikipedia BIOS Parameter Block

use zerocopy::byteorder::LittleEndian;
use zerocopy::{FromBytes, Immutable, KnownLayout, U16, U32, U64, Unaligned};

/// Standard boot sector size for IBM PC compatible systems
pub const BOOT_SECTOR_SIZE: usize = 512;

const BTRFS_SUPERBLOCK_MAGIC_OFFSET: usize = 0x40;
const BTRFS_TOTAL_BYTES_OFFSET: usize = 0x70;
const BTRFS_BYTES_USED_OFFSET: usize = 0x78;
const BTRFS_NUM_DEVICES_OFFSET: usize = 0x88;
const BTRFS_SECTOR_SIZE_OFFSET: usize = 0x90;
const BTRFS_NODE_SIZE_OFFSET: usize = 0x94;

/// Byte offset of the primary Btrfs superblock within a volume.
pub const BTRFS_PRIMARY_SUPERBLOCK_OFFSET: u64 = 0x1_0000;

/// Bytes required from a Btrfs superblock to validate its identity and
/// fundamental geometry.
pub const BTRFS_SUPERBLOCK_PROBE_SIZE: usize = BTRFS_NODE_SIZE_OFFSET + 4;

/// Signature stored in every Btrfs superblock.
pub const BTRFS_SUPERBLOCK_MAGIC: [u8; 8] = *b"_BHRfS_M";

/// Probe length for prefix-based filesystem detection.
///
/// This reaches ext's superblock fields at offset 0x438. Btrfs uses a sparse
/// secondary probe at [`BTRFS_PRIMARY_SUPERBLOCK_OFFSET`] instead of forcing
/// every caller to read the intervening 64 KiB.
pub const FS_DETECT_PROBE_SIZE: usize = 2048;

/// Boot signature value (little-endian: 0x55 at offset 510, 0xAA at offset 511)
pub const BOOT_SIGNATURE: u16 = 0xAA55;

mod ext;

use ext::probe_ext;
pub use ext::{
    ExtBackupSuperblock, ExtSuperblockInfo, ext_backup_superblock_group,
    ext_backup_superblock_info, ext_superblock_info,
};

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
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

/// Validate identifying fields from a Btrfs primary superblock.
///
/// The magic is anchored by the superblock's self-address and basic volume
/// geometry so random payload bytes do not classify as a filesystem.
#[must_use]
pub fn is_btrfs_primary_superblock(buf: &[u8]) -> bool {
    if buf.len() < BTRFS_SUPERBLOCK_PROBE_SIZE {
        return false;
    }

    if buf[BTRFS_SUPERBLOCK_MAGIC_OFFSET
        ..BTRFS_SUPERBLOCK_MAGIC_OFFSET + BTRFS_SUPERBLOCK_MAGIC.len()]
        != BTRFS_SUPERBLOCK_MAGIC
    {
        return false;
    }
    if read_u64_le(buf, 0x30) != BTRFS_PRIMARY_SUPERBLOCK_OFFSET {
        return false;
    }

    let total_bytes = read_u64_le(buf, BTRFS_TOTAL_BYTES_OFFSET);
    let bytes_used = read_u64_le(buf, BTRFS_BYTES_USED_OFFSET);
    if total_bytes < BTRFS_PRIMARY_SUPERBLOCK_OFFSET + 0x1000 || bytes_used > total_bytes {
        return false;
    }
    if read_u64_le(buf, BTRFS_NUM_DEVICES_OFFSET) == 0 {
        return false;
    }

    let sector_size = read_u32_le(buf, BTRFS_SECTOR_SIZE_OFFSET);
    if !sector_size.is_power_of_two() || !(4096..=65536).contains(&sector_size) {
        return false;
    }
    let node_size = read_u32_le(buf, BTRFS_NODE_SIZE_OFFSET);
    node_size.is_power_of_two() && (sector_size..=65536).contains(&node_size)
}

fn probe_btrfs_volume(buf: &[u8]) -> bool {
    let Ok(offset) = usize::try_from(BTRFS_PRIMARY_SUPERBLOCK_OFFSET) else {
        return false;
    };
    buf.get(offset..).is_some_and(is_btrfs_primary_superblock)
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
    #[must_use]
    pub fn is_ntfs(&self) -> bool {
        &self.oem_id == b"NTFS    "
    }

    /// Check if this appears to be an exFAT volume based on OEM ID
    #[must_use]
    pub fn is_exfat(&self) -> bool {
        &self.oem_id == b"EXFAT   "
    }

    /// Check if this appears to be a BitLocker-encrypted volume based on OEM ID
    #[must_use]
    pub fn is_bitlocker(&self) -> bool {
        &self.oem_id == b"-FVE-FS-"
    }

    /// Get the OEM ID as a string (trimming trailing spaces/nulls)
    #[must_use]
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
    /// If 0, use `total_sectors_32` instead
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
    /// - FAT32: must be 0 (use `fat_size_32` in EBPB)
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
    /// Used when `total_sectors_16` is 0
    /// - NTFS: not used (0), uses 64-bit field in EBPB
    ///
    /// Offset 0x20
    pub total_sectors_32: U32<LittleEndian>,
}

impl DosBpb {
    /// Get the total number of sectors (choosing 16 or 32-bit field)
    /// Note: For NTFS/exFAT, use the 64-bit field in the extended BPB
    #[must_use]
    pub fn total_sectors(&self) -> u32 {
        let ts16 = self.total_sectors_16.get();
        if ts16 != 0 {
            u32::from(ts16)
        } else {
            self.total_sectors_32.get()
        }
    }

    /// Get cluster size in bytes
    #[must_use]
    pub fn cluster_size(&self) -> u32 {
        u32::from(self.bytes_per_sector.get()) * u32::from(self.sectors_per_cluster)
    }

    /// Check if this could be an NTFS volume (certain fields must be 0)
    #[must_use]
    pub fn looks_like_ntfs(&self) -> bool {
        self.reserved_sectors.get() == 0
            && self.num_fats == 0
            && self.root_entry_count.get() == 0
            && self.sectors_per_fat_16.get() == 0
    }

    /// Check if this could be an exFAT volume (`bytes_per_sector` field is 0)
    #[must_use]
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
/// This structure follows the `DosBpb` for FAT12 and FAT16 volumes.
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
    /// - 0x28: Only `volume_serial_number` is valid
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
    #[must_use]
    pub fn has_extended_fields(&self) -> bool {
        self.boot_signature == 0x29 || self.boot_signature == 0x28
    }

    /// Get volume label as string (trimming trailing spaces)
    #[must_use]
    pub fn volume_label_str(&self) -> &str {
        let s = core::str::from_utf8(&self.volume_label).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }

    /// Get filesystem type label as string
    #[must_use]
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

    /// Sector number of `FSInfo` structure (typically 1)
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
    #[must_use]
    pub fn fat_mirroring_enabled(&self) -> bool {
        (self.ext_flags.get() & 0x0080) == 0
    }

    /// Get the active FAT number (0-15, only meaningful if mirroring disabled)
    #[must_use]
    pub fn active_fat(&self) -> u8 {
        (self.ext_flags.get() & 0x000F) as u8
    }

    /// Get volume label as string
    #[must_use]
    pub fn volume_label_str(&self) -> &str {
        let s = core::str::from_utf8(&self.volume_label).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }
}

/// FAT32 `FSInfo` Structure (512 bytes)
///
/// Located at the sector specified by `fs_info_sector` in the FAT32 EBPB.
/// Contains hints for free space and allocation.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Fat32FsInfo {
    /// Lead signature (must be 0x41615252 = "`RRaA`")
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
    /// Signature at the beginning of a `FAT32` `FSInfo` sector.
    pub const LEAD_SIGNATURE: u32 = 0x4161_5252;
    /// Signature preceding the free-cluster fields.
    pub const STRUCT_SIGNATURE: u32 = 0x6141_7272;
    /// Signature at the end of a `FAT32` `FSInfo` sector.
    pub const TRAIL_SIGNATURE: u32 = 0xAA55_0000;

    /// Validate the `FSInfo` signatures
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.lead_signature.get() == Self::LEAD_SIGNATURE
            && self.struct_signature.get() == Self::STRUCT_SIGNATURE
            && self.trail_signature.get() == Self::TRAIL_SIGNATURE
    }

    /// Get free cluster count if known
    #[must_use]
    pub fn free_clusters(&self) -> Option<u32> {
        let count = self.free_cluster_count.get();
        if count == 0xFFFF_FFFF {
            None
        } else {
            Some(count)
        }
    }

    /// Get next free cluster hint if available
    #[must_use]
    pub fn next_free(&self) -> Option<u32> {
        let hint = self.next_free_cluster.get();
        if hint == 0xFFFF_FFFF || hint < 2 {
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

    /// Logical Cluster Number (LCN) of the $`MFTMirr` file
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
    /// Decode the `clusters_per_mft_record` field to bytes
    #[must_use]
    pub fn mft_record_size(&self, cluster_size: u32) -> u32 {
        Self::decode_cluster_size_field(self.clusters_per_mft_record, cluster_size)
    }

    /// Decode the `clusters_per_index_buffer` field to bytes
    #[must_use]
    pub fn index_buffer_size(&self, cluster_size: u32) -> u32 {
        Self::decode_cluster_size_field(self.clusters_per_index_buffer, cluster_size)
    }

    /// Decode a signed cluster/size field
    /// - Positive values: multiply by cluster size
    /// - Negative values: 2^(-value) bytes
    fn decode_cluster_size_field(value: i8, cluster_size: u32) -> u32 {
        let magnitude = u32::from(value.unsigned_abs());
        if value >= 0 {
            magnitude * cluster_size
        } else {
            1u32.checked_shl(magnitude).unwrap_or(0)
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
    /// Combined with `bytes_per_sector_shift`, max cluster = 32MB
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
    #[must_use]
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
    #[must_use]
    pub fn bytes_per_sector(&self) -> u32 {
        1u32 << self.bytes_per_sector_shift
    }

    /// Get sectors per cluster
    #[must_use]
    pub fn sectors_per_cluster(&self) -> u32 {
        1u32 << self.sectors_per_cluster_shift
    }

    /// Get cluster size in bytes
    #[must_use]
    pub fn cluster_size(&self) -> u32 {
        1u32 << (self.bytes_per_sector_shift + self.sectors_per_cluster_shift)
    }

    /// Check if volume is dirty
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        (self.volume_flags.get() & 0x0002) != 0
    }

    /// Check if media failure flag is set
    #[must_use]
    pub fn has_media_failure(&self) -> bool {
        (self.volume_flags.get() & 0x0004) != 0
    }

    /// Get the active FAT (0 or 1)
    #[must_use]
    pub fn active_fat(&self) -> u8 {
        (self.volume_flags.get() & 0x0001) as u8
    }
}

mod detection;
pub use detection::*;

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[path = "../boot_sector_tests/mod.rs"]
mod tests;
