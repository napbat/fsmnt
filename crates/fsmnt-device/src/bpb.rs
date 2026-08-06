//! Boot sector and BIOS Parameter Block (BPB) parsing for IBM-compatible
//! filesystems: FAT12/16 (DOS 4.0 EBPB), FAT32 (DOS 7.1 EBPB), NTFS,
//! `exFAT`, and HPFS (shares the DOS 4.0 EBPB structure).
//!
//! References: Microsoft FAT32 File System Specification (`fatgen103.doc`),
//! Microsoft NTFS Technical Reference, Microsoft `exFAT` Specification,
//! Wikipedia: BIOS Parameter Block.

use zerocopy::byteorder::LittleEndian;
use zerocopy::{FromBytes, Immutable, KnownLayout, U16, U32, U64, Unaligned};

use crate::detect::{BOOT_SECTOR_SIZE, BOOT_SIGNATURE};
use crate::partition::Mbr;

// Compile-time layout checks: these structures are cast directly from raw
// on-disk bytes, so their sizes must match the on-disk layout exactly.
const _: () = assert!(size_of::<BootSectorHeader>() == 11);
const _: () = assert!(size_of::<DosBpb>() == 25);
const _: () = assert!(size_of::<Fat16Ebpb>() == 26);
const _: () = assert!(size_of::<Fat32Ebpb>() == 54);
const _: () = assert!(size_of::<NtfsEbpb>() == 48);
const _: () = assert!(size_of::<ExFatBootSector>() == 512);

/// Jump instruction and OEM identifier at the start of every boot sector.
///
/// Offset 0x00-0x0A (11 bytes). All IBM PC compatible boot sectors start
/// with a jump instruction followed by an 8-byte OEM identifier string.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct BootSectorHeader {
    /// Jump instruction to skip over the BPB, typically `EB xx 90` or
    /// `E9 xx xx`; `exFAT` requires `EB 76 90`.
    pub jump_instruction: [u8; 3],
    /// OEM identifier (8 bytes, space-padded): `NTFS    `, `EXFAT   `,
    /// `MSDOS5.0`, `mkdosfs `, … — not to be trusted for detection.
    pub oem_id: [u8; 8],
}

impl BootSectorHeader {
    /// Check if this appears to be an NTFS volume based on the OEM ID.
    #[must_use]
    pub fn is_ntfs(&self) -> bool {
        &self.oem_id == b"NTFS    "
    }

    /// Check if this appears to be an `exFAT` volume based on the OEM ID.
    #[must_use]
    pub fn is_exfat(&self) -> bool {
        &self.oem_id == b"EXFAT   "
    }

    /// Check if this appears to be a `BitLocker` volume based on the OEM ID.
    #[must_use]
    pub fn is_bitlocker(&self) -> bool {
        &self.oem_id == b"-FVE-FS-"
    }

    /// Get the OEM ID as a string (trimming trailing spaces/nulls).
    #[must_use]
    pub fn oem_id_str(&self) -> &str {
        let s = std::str::from_utf8(&self.oem_id).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }
}

/// DOS 3.31 BIOS Parameter Block (25 bytes) at offset 0x0B-0x23 — the
/// "standard" BPB shared by FAT12/16/32, NTFS, and HPFS. Some fields have
/// different meanings or are unused in NTFS.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct DosBpb {
    /// Bytes per logical sector (512, 1024, 2048, or 4096). Offset 0x0B.
    pub bytes_per_sector: U16<LittleEndian>,
    /// Sectors per cluster (power of 2: 1 through 128). Offset 0x0D.
    pub sectors_per_cluster: u8,
    /// Reserved sectors before the first FAT, including the boot sector
    /// (FAT12/16: 1; FAT32: 32; NTFS: always 0). Offset 0x0E.
    pub reserved_sectors: U16<LittleEndian>,
    /// Number of FAT copies (typically 2; NTFS: always 0). Offset 0x10.
    pub num_fats: u8,
    /// Max root directory entries (FAT12/16 only; FAT32/NTFS: 0). Offset 0x11.
    pub root_entry_count: U16<LittleEndian>,
    /// Total sectors, 16-bit; if 0 use `total_sectors_32`. Offset 0x13.
    pub total_sectors_16: U16<LittleEndian>,
    /// Media descriptor (0xF8: fixed disk; 0xF0: 1.44 MB floppy). Offset 0x15.
    pub media_descriptor: u8,
    /// Sectors per FAT (FAT12/16 only; FAT32 uses `sectors_per_fat_32` in
    /// its EBPB and sets this to 0; NTFS: always 0). Offset 0x16.
    pub sectors_per_fat_16: U16<LittleEndian>,
    /// Sectors per track (CHS geometry for BIOS INT 13h). Offset 0x18.
    pub sectors_per_track: U16<LittleEndian>,
    /// Number of heads (CHS geometry for BIOS INT 13h). Offset 0x1A.
    pub num_heads: U16<LittleEndian>,
    /// Hidden sectors preceding this partition (its start LBA). Offset 0x1C.
    pub hidden_sectors: U32<LittleEndian>,
    /// Total sectors, 32-bit; used when `total_sectors_16` is 0 (NTFS
    /// instead uses the 64-bit field in its EBPB). Offset 0x20.
    pub total_sectors_32: U32<LittleEndian>,
}

impl DosBpb {
    /// Get the total number of sectors (choosing the 16- or 32-bit field).
    /// Note: for NTFS/`exFAT`, use the 64-bit field in the extended BPB.
    #[must_use]
    pub fn total_sectors(&self) -> u32 {
        let ts16 = self.total_sectors_16.get();
        if ts16 == 0 {
            self.total_sectors_32.get()
        } else {
            u32::from(ts16)
        }
    }

    /// Get the cluster size in bytes.
    #[must_use]
    pub fn cluster_size(&self) -> u32 {
        u32::from(self.bytes_per_sector.get()) * u32::from(self.sectors_per_cluster)
    }

    /// Check if this could be an NTFS volume (certain fields must be 0).
    #[must_use]
    pub fn looks_like_ntfs(&self) -> bool {
        self.reserved_sectors.get() == 0
            && self.num_fats == 0
            && self.root_entry_count.get() == 0
            && self.sectors_per_fat_16.get() == 0
    }

    /// Check if this could be an `exFAT` volume (`bytes_per_sector` is 0).
    #[must_use]
    pub fn looks_like_exfat(&self) -> bool {
        self.bytes_per_sector.get() == 0
    }
}

/// DOS 4.0 Extended BIOS Parameter Block for FAT12/FAT16 (26 bytes) at
/// offset 0x24-0x3D, following the [`DosBpb`]. Also used by HPFS (OS/2).
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Fat16Ebpb {
    /// Physical BIOS INT 13h drive number (0x00: floppy; 0x80: first hard
    /// disk). Offset 0x24.
    pub drive_number: u8,
    /// Reserved (used by Windows NT for flags). Offset 0x25.
    pub reserved1: u8,
    /// Extended boot signature: 0x29 means all following fields are valid,
    /// 0x28 means only `volume_serial_number` is. Offset 0x26.
    pub boot_signature: u8,
    /// Volume serial number (random value set at format time). Offset 0x27.
    pub volume_serial_number: U32<LittleEndian>,
    /// Volume label (11 bytes, space-padded); matches the label in the
    /// root directory. Offset 0x2B.
    pub volume_label: [u8; 11],
    /// Filesystem type label, typically `FAT12   `, `FAT16   `, or
    /// `FAT     ` — never use for detection! Offset 0x36.
    pub filesystem_type: [u8; 8],
}

impl Fat16Ebpb {
    /// Check if the extended fields are valid.
    #[must_use]
    pub fn has_extended_fields(&self) -> bool {
        self.boot_signature == 0x29 || self.boot_signature == 0x28
    }

    /// Get the volume label as a string (trimming trailing spaces).
    #[must_use]
    pub fn volume_label_str(&self) -> &str {
        let s = std::str::from_utf8(&self.volume_label).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }

    /// Get the filesystem type label as a string.
    #[must_use]
    pub fn filesystem_type_str(&self) -> &str {
        let s = std::str::from_utf8(&self.filesystem_type).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }
}

/// DOS 7.1 Extended BIOS Parameter Block for FAT32 (54 bytes) at offset
/// 0x24-0x59 — a completely different structure from the FAT12/16 EBPB.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Fat32Ebpb {
    /// Sectors per FAT (32-bit, for FAT32's large FAT). Offset 0x24.
    pub sectors_per_fat_32: U32<LittleEndian>,
    /// Extended flags: bits 0-3 = active FAT number (when mirroring is
    /// disabled); bit 7: 0 = FAT mirrored, 1 = one active FAT. Offset 0x28.
    pub ext_flags: U16<LittleEndian>,
    /// Filesystem version (major.minor); 0x0000 for compatibility. Offset 0x2A.
    pub fs_version: U16<LittleEndian>,
    /// Cluster number of the root directory start (typically 2). Offset 0x2C.
    pub root_cluster: U32<LittleEndian>,
    /// Sector number of the `FSInfo` structure (typically 1). Offset 0x30.
    pub fs_info_sector: U16<LittleEndian>,
    /// Backup boot sector number (typically 6; 0 or 0xFFFF: none). Offset 0x32.
    pub backup_boot_sector: U16<LittleEndian>,
    /// Reserved for future use (should be zero). Offset 0x34.
    pub reserved: [u8; 12],
    /// Physical drive number (same as FAT16). Offset 0x40.
    pub drive_number: u8,
    /// Reserved (Windows NT flags). Offset 0x41.
    pub reserved1: u8,
    /// Extended boot signature (0x29 or 0x28). Offset 0x42.
    pub boot_signature: u8,
    /// Volume serial number. Offset 0x43.
    pub volume_serial_number: U32<LittleEndian>,
    /// Volume label (11 bytes, space-padded). Offset 0x47.
    pub volume_label: [u8; 11],
    /// Filesystem type label (always `FAT32   `) — never use for
    /// detection! Offset 0x52.
    pub filesystem_type: [u8; 8],
}

impl Fat32Ebpb {
    /// Check if FAT mirroring is enabled.
    #[must_use]
    pub fn fat_mirroring_enabled(&self) -> bool {
        (self.ext_flags.get() & 0x0080) == 0
    }

    /// Get the active FAT number (0-15, meaningful when mirroring is off).
    #[must_use]
    pub fn active_fat(&self) -> u8 {
        // Masked to 4 bits, so the conversion cannot actually fail.
        u8::try_from(self.ext_flags.get() & 0x000F).unwrap_or(0)
    }

    /// Get the volume label as a string.
    #[must_use]
    pub fn volume_label_str(&self) -> &str {
        let s = std::str::from_utf8(&self.volume_label).unwrap_or("");
        s.trim_end_matches([' ', '\0'])
    }
}

/// NTFS Extended BIOS Parameter Block (48 bytes) at offset 0x24-0x53 — a
/// modified BPB with several fields zeroed plus NTFS-specific fields.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct NtfsEbpb {
    /// Not used by NTFS (was drive number + flags in DOS). Offset 0x24.
    pub unused_0x24: U32<LittleEndian>,
    /// Total sectors on the volume (64-bit). Offset 0x28.
    pub total_sectors: U64<LittleEndian>,
    /// Logical Cluster Number (LCN) of the `$MFT` file. Offset 0x30.
    pub mft_lcn: U64<LittleEndian>,
    /// Logical Cluster Number (LCN) of the `$MFTMirr` file. Offset 0x38.
    pub mft_mirror_lcn: U64<LittleEndian>,
    /// Clusters per MFT file record segment (signed): positive = cluster
    /// count; negative = 2^(-value) bytes, typically -10 (0xF6) for 1 KB
    /// records or -12 (0xF4) for 4 KB. Offset 0x40.
    pub clusters_per_mft_record: i8,
    /// Reserved/padding. Offset 0x41.
    pub reserved_0x41: [u8; 3],
    /// Clusters per index buffer (signed, same encoding as
    /// `clusters_per_mft_record`); typically -12 (0xF4). Offset 0x44.
    pub clusters_per_index_buffer: i8,
    /// Reserved/padding. Offset 0x45.
    pub reserved_0x45: [u8; 3],
    /// Volume serial number (64-bit). Offset 0x48.
    pub volume_serial_number: U64<LittleEndian>,
    /// Checksum (not used, typically 0). Offset 0x50.
    pub checksum: U32<LittleEndian>,
}

impl NtfsEbpb {
    /// Decode the `clusters_per_mft_record` field to bytes.
    #[must_use]
    pub fn mft_record_size(&self, cluster_size: u32) -> u32 {
        Self::decode_cluster_size_field(self.clusters_per_mft_record, cluster_size)
    }

    /// Decode the `clusters_per_index_buffer` field to bytes.
    #[must_use]
    pub fn index_buffer_size(&self, cluster_size: u32) -> u32 {
        Self::decode_cluster_size_field(self.clusters_per_index_buffer, cluster_size)
    }

    /// Decode a signed cluster/size field: positive values multiply by
    /// the cluster size; negative values encode 2^(-value) bytes.
    fn decode_cluster_size_field(value: i8, cluster_size: u32) -> u32 {
        if value >= 0 {
            u32::from(value.unsigned_abs()) * cluster_size
        } else {
            1u32 << u32::from(value.unsigned_abs())
        }
    }
}

/// `exFAT` Main Boot Region (first 512 bytes).
///
/// `exFAT` does NOT use the traditional DOS BPB: the OEM ID field (offset
/// 0x03) must contain `EXFAT   ` and the traditional BPB area (offset
/// 0x0B-0x3F) must be all zeros.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct ExFatBootSector {
    /// Jump instruction (must be `EB 76 90`). Offset 0x00.
    pub jump_instruction: [u8; 3],
    /// Filesystem name (must be `EXFAT   `). Offset 0x03.
    pub filesystem_name: [u8; 8],
    /// Must be zero (covers the traditional BPB area so legacy FAT
    /// drivers reject the volume). Offset 0x0B.
    pub must_be_zero: [u8; 53],
    /// Partition offset in sectors from the start of the media. Offset 0x40.
    pub partition_offset: U64<LittleEndian>,
    /// Volume length in sectors. Offset 0x48.
    pub volume_length: U64<LittleEndian>,
    /// FAT offset in sectors from the start of the partition. Offset 0x50.
    pub fat_offset: U32<LittleEndian>,
    /// FAT length in sectors. Offset 0x54.
    pub fat_length: U32<LittleEndian>,
    /// Cluster heap offset in sectors from the partition start. Offset 0x58.
    pub cluster_heap_offset: U32<LittleEndian>,
    /// Total number of clusters in the cluster heap. Offset 0x5C.
    pub cluster_count: U32<LittleEndian>,
    /// Cluster number of the root directory (typically 4+). Offset 0x60.
    pub root_directory_cluster: U32<LittleEndian>,
    /// Volume serial number. Offset 0x64.
    pub volume_serial_number: U32<LittleEndian>,
    /// Filesystem revision (major.minor); currently 0x0100. Offset 0x68.
    pub filesystem_revision: U16<LittleEndian>,
    /// Volume flags: bit 0 = active FAT (0 = first, 1 = second), bit 1 =
    /// volume dirty, bit 2 = media failure, bit 3 = clear to zero. Offset 0x6A.
    pub volume_flags: U16<LittleEndian>,
    /// Bytes per sector as a power of 2 (9 = 512 … 12 = 4096). Offset 0x6C.
    pub bytes_per_sector_shift: u8,
    /// Sectors per cluster as a power of 2 (0 = 1, 3 = 8, …); combined
    /// with `bytes_per_sector_shift`, the max cluster is 32 MB. Offset 0x6D.
    pub sectors_per_cluster_shift: u8,
    /// Number of FATs (1 or 2). Offset 0x6E.
    pub number_of_fats: u8,
    /// Physical BIOS INT 13h drive number (0x80: first disk). Offset 0x6F.
    pub drive_select: u8,
    /// Percentage of clusters in use (0-100, 0xFF if unknown). Offset 0x70.
    pub percent_in_use: u8,
    /// Reserved for future use. Offset 0x71.
    pub reserved: [u8; 7],
    /// Boot code. Offset 0x78.
    pub boot_code: [u8; 390],
    /// Boot signature (must be 0xAA55). Offset 0x1FE.
    pub boot_signature: U16<LittleEndian>,
}

impl ExFatBootSector {
    /// Validate that this is a valid `exFAT` boot sector: filesystem name
    /// `EXFAT   `, zeroed BPB area, boot signature 0xAA55, and a sector
    /// size shift within 9-12.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        &self.filesystem_name == b"EXFAT   "
            && self.must_be_zero.iter().all(|&b| b == 0)
            && self.boot_signature.get() == BOOT_SIGNATURE
            && (9..=12).contains(&self.bytes_per_sector_shift)
    }

    /// Get bytes per sector.
    #[must_use]
    pub fn bytes_per_sector(&self) -> u32 {
        1u32 << self.bytes_per_sector_shift
    }

    /// Get sectors per cluster.
    #[must_use]
    pub fn sectors_per_cluster(&self) -> u32 {
        1u32 << self.sectors_per_cluster_shift
    }

    /// Get the cluster size in bytes.
    #[must_use]
    pub fn cluster_size(&self) -> u32 {
        1u32 << (self.bytes_per_sector_shift + self.sectors_per_cluster_shift)
    }

    /// Check if the volume is dirty.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        (self.volume_flags.get() & 0x0002) != 0
    }

    /// Check if the media failure flag is set.
    #[must_use]
    pub fn has_media_failure(&self) -> bool {
        (self.volume_flags.get() & 0x0004) != 0
    }

    /// Get the active FAT (0 or 1).
    #[must_use]
    pub fn active_fat(&self) -> u8 {
        u8::from((self.volume_flags.get() & 0x0001) != 0)
    }
}

/// Detected filesystem type (used internally for FAT type determination).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemType {
    /// FAT12 (< 4085 clusters).
    Fat12,
    /// FAT16 (4085 - 65524 clusters).
    Fat16,
    /// FAT32 (>= 65525 clusters, uses the FAT32 EBPB).
    Fat32,
    /// NTFS (Windows NT filesystem).
    Ntfs,
    /// `exFAT` (Extended FAT for large removable media).
    ExFat,
    /// HPFS (OS/2; uses the DOS 4.0 EBPB structure like FAT16).
    Hpfs,
    /// Unknown or invalid filesystem.
    Unknown,
}

/// Parsed boot sector with references to the appropriate structures.
#[derive(Debug)]
pub enum ParsedBootSector<'a> {
    /// FAT12 filesystem.
    Fat12 {
        /// Common boot-sector header (jump instruction + OEM ID).
        header: &'a BootSectorHeader,
        /// DOS 3.31 BPB.
        bpb: &'a DosBpb,
        /// FAT12/16 extended BPB.
        ebpb: &'a Fat16Ebpb,
        /// Boot code region following the EBPB.
        boot_code: &'a [u8],
    },
    /// FAT16 filesystem.
    Fat16 {
        /// Common boot-sector header (jump instruction + OEM ID).
        header: &'a BootSectorHeader,
        /// DOS 3.31 BPB.
        bpb: &'a DosBpb,
        /// FAT12/16 extended BPB.
        ebpb: &'a Fat16Ebpb,
        /// Boot code region following the EBPB.
        boot_code: &'a [u8],
    },
    /// FAT32 filesystem.
    Fat32 {
        /// Common boot-sector header (jump instruction + OEM ID).
        header: &'a BootSectorHeader,
        /// DOS 3.31 BPB.
        bpb: &'a DosBpb,
        /// FAT32 extended BPB.
        ebpb: &'a Fat32Ebpb,
        /// Boot code region following the EBPB.
        boot_code: &'a [u8],
    },
    /// NTFS filesystem.
    Ntfs {
        /// Common boot-sector header (jump instruction + OEM ID).
        header: &'a BootSectorHeader,
        /// DOS 3.31 BPB.
        bpb: &'a DosBpb,
        /// NTFS extended BPB.
        ebpb: &'a NtfsEbpb,
        /// Boot code region following the EBPB.
        boot_code: &'a [u8],
    },
    /// `BitLocker`-encrypted volume (FVE). The on-disk layout reuses the
    /// NTFS boot sector structure with OEM ID `-FVE-FS-`; only volume
    /// geometry and selected metadata are exposed (`total_sectors` and
    /// `volume_serial_number` sit at the NTFS EBPB offsets 0x28 / 0x48,
    /// which `BitLocker` volumes reuse).
    BitLocker {
        /// Common boot-sector header (jump instruction + OEM ID).
        header: &'a BootSectorHeader,
        /// DOS 3.31 BPB.
        bpb: &'a DosBpb,
        /// Total sectors on the volume (from offset 0x28).
        total_sectors: u64,
        /// Volume serial number (from offset 0x48).
        volume_serial_number: u64,
        /// Boot code region following the EBPB.
        boot_code: &'a [u8],
    },
    /// `exFAT` filesystem.
    ExFat {
        /// The dedicated `exFAT` boot sector (full 512-byte layout).
        boot_sector: &'a ExFatBootSector,
    },
    /// HPFS filesystem (uses the FAT16 EBPB structure).
    Hpfs {
        /// Common boot-sector header (jump instruction + OEM ID).
        header: &'a BootSectorHeader,
        /// DOS 3.31 BPB.
        bpb: &'a DosBpb,
        /// DOS 4.0 extended BPB (shared with FAT12/16).
        ebpb: &'a Fat16Ebpb,
        /// Boot code region following the EBPB.
        boot_code: &'a [u8],
    },
    /// MBR partition table (not a filesystem).
    Mbr {
        /// The parsed MBR sector.
        mbr: &'a Mbr,
    },
    /// GPT partition table (protective MBR detected).
    Gpt {
        /// The protective MBR sector.
        mbr: &'a Mbr,
    },
}

/// Errors that can occur during boot sector parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Input buffer is too small.
    BufferTooSmall,
    /// Missing boot signature (0xAA55).
    InvalidBootSignature,
    /// Invalid bytes-per-sector value.
    InvalidBytesPerSector,
    /// Could not determine the filesystem type.
    UnknownFilesystem,
    /// Structure parsing failed.
    ParseFailed,
}

/// Parse a boot sector and detect the filesystem type.
///
/// # Errors
///
/// Returns a [`ParseError`] when the buffer is too small, the 0xAA55 boot
/// signature is missing, the structures are malformed, or no known
/// filesystem or partition table can be identified.
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

/// Try to parse as a filesystem boot sector.
fn try_parse_filesystem(data: &[u8]) -> Result<ParsedBootSector<'_>, ParseError> {
    let header =
        BootSectorHeader::ref_from_bytes(&data[0..11]).map_err(|_| ParseError::ParseFailed)?;

    // Check for exFAT first (it has a completely different structure). The
    // exFAT spec requires the BPB-region bytes 0x0B..0x40 to be all zero;
    // that cheap check gates the heavy parse, and `ExFatBootSector::is_valid`
    // further anchors the OEM `EXFAT   ` name and boot signature.
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

    // Check for BitLocker (FVE) — must precede the NTFS check because
    // BitLocker volumes have an NTFS-like BPB that would pass looks_like_ntfs().
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

    // FAT type is determined by cluster count, NOT by the type string.
    match determine_fat_type(bpb) {
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

/// Try to parse as a partition table (MBR or GPT).
fn try_parse_partition_table(data: &[u8]) -> Result<ParsedBootSector<'_>, ParseError> {
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

/// Determine the FAT type (12/16) based on cluster count.
///
/// According to the Microsoft FAT specification:
/// - FAT12: cluster count < 4085
/// - FAT16: cluster count >= 4085 and < 65525
/// - FAT32: cluster count >= 65525
fn determine_fat_type(bpb: &DosBpb) -> FilesystemType {
    let bytes_per_sector = u32::from(bpb.bytes_per_sector.get());
    let sectors_per_cluster = u32::from(bpb.sectors_per_cluster);

    if bytes_per_sector == 0 || sectors_per_cluster == 0 {
        return FilesystemType::Unknown;
    }

    // Root directory sectors (FAT12/16)
    let root_entry_count = u32::from(bpb.root_entry_count.get());
    let root_dir_sectors = (root_entry_count * 32).div_ceil(bytes_per_sector);

    if bpb.sectors_per_fat_16.get() == 0 {
        // That would be FAT32, but we're checking FAT12/16 here.
        return FilesystemType::Unknown;
    }
    let fat_size = u32::from(bpb.sectors_per_fat_16.get());

    let total_sectors = bpb.total_sectors();
    let reserved = u32::from(bpb.reserved_sectors.get());
    let num_fats = u32::from(bpb.num_fats);
    let first_data_sector = reserved + (num_fats * fat_size) + root_dir_sectors;

    if total_sectors <= first_data_sector {
        return FilesystemType::Unknown;
    }

    let data_sectors = total_sectors - first_data_sector;
    let cluster_count = data_sectors / sectors_per_cluster;

    if cluster_count < 4085 {
        FilesystemType::Fat12
    } else if cluster_count < 65_525 {
        FilesystemType::Fat16
    } else {
        FilesystemType::Fat32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stamp the boot signature into bytes 0x1FE..0x200.
    fn stamp_boot_signature(buf: &mut [u8; 512]) {
        buf[510] = 0x55;
        buf[511] = 0xAA;
    }

    /// Build a DOS BPB-bearing boot sector with the given parameters and
    /// OEM. `total_16` is encoded in the 16-bit `total_sectors_16` slot;
    /// if zero, `total_32` carries the 32-bit slot.
    #[expect(clippy::too_many_arguments, reason = "mirrors the BPB layout")]
    fn build_dos_boot_sector(
        oem: [u8; 8],
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
        buf[3..11].copy_from_slice(&oem);
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
        buf[0x20..0x24].copy_from_slice(&total_32.to_le_bytes());
        stamp_boot_signature(&mut buf);
        buf
    }

    fn build_fat12_sector() -> [u8; 512] {
        // FAT12: cluster_count < 4085 (a 1.44 MB floppy layout).
        let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 2, 224, 2880, 9, 0);
        buf[0x26] = 0x29;
        buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
        buf
    }

    fn build_fat32_sector() -> [u8; 512] {
        // FAT32: sectors_per_fat_16 == 0 AND root_entry_count == 0.
        let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 8, 32, 2, 0, 0, 0, 4_194_304);
        buf[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        buf[0x42] = 0x29;
        buf[0x52..0x5A].copy_from_slice(b"FAT32   ");
        buf
    }

    fn build_ntfs_sector() -> [u8; 512] {
        // NTFS via OEM "NTFS    " (looks_like_ntfs() is true for these fields).
        let mut buf = build_dos_boot_sector(*b"NTFS    ", 512, 8, 0, 0, 0, 0, 0, 0);
        buf[0x28..0x30].copy_from_slice(&1_048_576u64.to_le_bytes());
        buf
    }

    fn build_hpfs_sector() -> [u8; 512] {
        // HPFS via OEM "HPFS    " — uses the Fat16Ebpb layout.
        let mut buf = build_fat12_sector();
        buf[3..11].copy_from_slice(b"HPFS    ");
        buf
    }

    fn build_exfat_sector() -> [u8; 512] {
        // exFAT: OEM "EXFAT   " with the BPB region 0x0B..0x40 all zero.
        let mut buf = [0u8; 512];
        buf[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        buf[3..11].copy_from_slice(b"EXFAT   ");
        buf[0x48..0x50].copy_from_slice(&1_048_576u64.to_le_bytes()); // volume_length
        buf[0x6C] = 9; // bytes_per_sector_shift (512)
        buf[0x6D] = 3; // sectors_per_cluster_shift (8)
        buf[0x6E] = 1; // number_of_fats
        buf[0x6F] = 0x80; // drive_select
        stamp_boot_signature(&mut buf);
        buf
    }

    fn bpb_of(buf: &[u8; 512]) -> &DosBpb {
        DosBpb::ref_from_bytes(&buf[0x0B..0x24]).unwrap()
    }

    fn exfat_of(buf: &[u8; 512]) -> &ExFatBootSector {
        ExFatBootSector::ref_from_bytes(buf).unwrap()
    }

    #[test]
    fn header_oem_id_checks_require_exact_match() {
        fn header(oem_id: [u8; 8]) -> BootSectorHeader {
            BootSectorHeader {
                jump_instruction: [0xEB, 0x76, 0x90],
                oem_id,
            }
        }

        let ntfs = header(*b"NTFS    ");
        assert!(ntfs.is_ntfs());
        assert!(!ntfs.is_exfat());
        assert!(!ntfs.is_bitlocker());
        assert!(header(*b"EXFAT   ").is_exfat());
        assert!(header(*b"-FVE-FS-").is_bitlocker());

        // Padding must match exactly; oem_id_str trims trailing space/nulls.
        assert!(!header(*b"NTFS   \0").is_ntfs());
        assert!(!header(*b"EXFAT  \0").is_exfat());
        assert!(!header(*b"-FVE-FS\0").is_bitlocker());
        assert_eq!(header(*b"NTFS    ").oem_id_str(), "NTFS");
        assert_eq!(header(*b"TEST\0\0\0\0").oem_id_str(), "TEST");
    }

    #[test]
    fn dos_bpb_geometry_helpers() {
        let fat12 = build_fat12_sector();
        assert_eq!(bpb_of(&fat12).total_sectors(), 2880); // 16-bit slot wins
        assert_eq!(bpb_of(&fat12).cluster_size(), 512);

        // When total_sectors_16 is 0, use total_sectors_32.
        let fat32 = build_fat32_sector();
        assert_eq!(bpb_of(&fat32).total_sectors(), 4_194_304);
        assert_eq!(bpb_of(&fat32).cluster_size(), 4096);
    }

    #[test]
    fn looks_like_ntfs_requires_every_field_zero() {
        // Each row keeps three of the four gating fields zero and makes
        // the fourth non-zero; the `&&` chain must reject every row.
        let cases: &[(u16, u8, u16, u16)] =
            &[(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)];
        for &(rs, nf, re, spf) in cases {
            let buf = build_dos_boot_sector(*b"GENERIC ", 512, 8, rs, nf, re, 0, spf, 0);
            assert!(
                !bpb_of(&buf).looks_like_ntfs(),
                "fields ({rs}, {nf}, {re}, {spf}) must not classify as NTFS",
            );
        }

        // Sanity baseline: all-zero still classifies as NTFS-like, and
        // looks_like_exfat keys on bytes_per_sector == 0.
        assert!(bpb_of(&build_ntfs_sector()).looks_like_ntfs());
        assert!(bpb_of(&build_exfat_sector()).looks_like_exfat());
        assert!(!bpb_of(&build_fat12_sector()).looks_like_exfat());
    }

    #[test]
    fn ntfs_cluster_size_decode() {
        let cluster_size = 4096u32;

        // Positive value: multiply by cluster size
        assert_eq!(NtfsEbpb::decode_cluster_size_field(1, cluster_size), 4096);
        assert_eq!(NtfsEbpb::decode_cluster_size_field(2, cluster_size), 8192);

        // Negative value: 2^(-value) bytes
        assert_eq!(NtfsEbpb::decode_cluster_size_field(-10, cluster_size), 1024);
        assert_eq!(NtfsEbpb::decode_cluster_size_field(-12, cluster_size), 4096);
    }

    #[test]
    fn exfat_is_valid_accepts_well_formed_and_rejects_violations() {
        // Well-formed, with boundary shifts 9 and 12 both accepted.
        let good = build_exfat_sector();
        assert!(exfat_of(&good).is_valid());
        let mut shift12 = good;
        shift12[0x6C] = 12;
        assert!(exfat_of(&shift12).is_valid());

        // Bad filesystem name.
        let mut bad_name = good;
        bad_name[3..11].copy_from_slice(b"EXFATXY!");
        assert!(!exfat_of(&bad_name).is_valid());

        // Non-zero byte in the must_be_zero BPB region.
        let mut bad_zero = good;
        bad_zero[0x0B + 27] = 0xAB;
        assert!(!exfat_of(&bad_zero).is_valid());

        // Bad boot signature.
        let mut bad_sig = good;
        bad_sig[510] = 0x34;
        bad_sig[511] = 0x12;
        assert!(!exfat_of(&bad_sig).is_valid());

        // bytes_per_sector_shift out of range (below and above).
        let mut shift8 = good;
        shift8[0x6C] = 8;
        assert!(!exfat_of(&shift8).is_valid());
        let mut shift13 = good;
        shift13[0x6C] = 13;
        assert!(!exfat_of(&shift13).is_valid());
    }

    #[test]
    fn parse_boot_sector_rejects_small_buffer_and_missing_signature() {
        let small = parse_boot_sector(&[0u8; 100]).unwrap_err();
        assert_eq!(small, ParseError::BufferTooSmall);
        let unsigned = parse_boot_sector(&[0u8; 512]).unwrap_err();
        assert_eq!(unsigned, ParseError::InvalidBootSignature);
    }

    #[test]
    fn parse_boot_sector_classifies_each_supported_filesystem() {
        assert!(matches!(
            parse_boot_sector(&build_fat12_sector()).unwrap(),
            ParsedBootSector::Fat12 { .. }
        ));
        assert!(matches!(
            parse_boot_sector(&build_fat32_sector()).unwrap(),
            ParsedBootSector::Fat32 { .. }
        ));
        assert!(matches!(
            parse_boot_sector(&build_ntfs_sector()).unwrap(),
            ParsedBootSector::Ntfs { .. }
        ));
        assert!(matches!(
            parse_boot_sector(&build_hpfs_sector()).unwrap(),
            ParsedBootSector::Hpfs { .. }
        ));
        assert!(matches!(
            parse_boot_sector(&build_exfat_sector()).unwrap(),
            ParsedBootSector::ExFat { .. }
        ));
    }

    #[test]
    fn parse_boot_sector_bitlocker_extracts_geometry() {
        let mut buffer = build_dos_boot_sector(*b"-FVE-FS-", 512, 8, 0, 0, 0, 0, 0, 0);
        // NTFS-style EBPB fields reused by BitLocker:
        buffer[0x28..0x30].copy_from_slice(&1_048_576u64.to_le_bytes()); // total_sectors
        buffer[0x48..0x50].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes()); // serial

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
                assert_eq!(total_sectors, 1_048_576);
                assert_eq!(volume_serial_number, 0xDEAD_BEEF_CAFE_BABE);
                assert_eq!(boot_code.len(), 510 - 0x54);
            }
            other => panic!("Expected BitLocker, got {other:?}"),
        }
    }

    #[test]
    fn hpfs_detection_via_oem_prefix() {
        // An "OS2 " prefix is also valid for HPFS.
        let mut os2 = build_hpfs_sector();
        os2[3..7].copy_from_slice(b"OS2 ");
        assert!(matches!(
            parse_boot_sector(&os2).unwrap(),
            ParsedBootSector::Hpfs { .. }
        ));

        // A non-HPFS OEM with an otherwise-identical layout lands as FAT.
        let mut fat = build_hpfs_sector();
        fat[3..11].copy_from_slice(b"MSDOS5.0");
        assert!(matches!(
            parse_boot_sector(&fat).unwrap(),
            ParsedBootSector::Fat12 { .. } | ParsedBootSector::Fat16 { .. }
        ));
    }

    #[test]
    fn fat16_to_fat32_boundary_yields_unknown_for_fat16_shaped_layouts() {
        // 1 spc, 1 reserved, 1 FAT of 1 sector, 0 root entries: total
        // 65527 → 65525 clusters → FAT32 territory, which a FAT16-shaped
        // layout cannot express → UnknownFilesystem. (The FAT12/16/32
        // thresholds are pinned by the boundary tests in `detect`.)
        let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 1, 0, 0, 1, 65_527);
        buf[0x26] = 0x29;
        assert_eq!(
            parse_boot_sector(&buf).unwrap_err(),
            ParseError::UnknownFilesystem
        );
    }
}
