use super::{
    BOOT_SECTOR_SIZE, BOOT_SIGNATURE, BootSectorHeader, DosBpb, ExFatBootSector, Fat16Ebpb,
    Fat32Ebpb, NtfsEbpb, probe_apfs, probe_btrfs_volume, probe_ext,
};
use zerocopy::byteorder::LittleEndian;
use zerocopy::{FromBytes, Immutable, KnownLayout, U16, Unaligned};

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
    /// Btrfs filesystem (primary superblock at 64 KiB)
    Btrfs,
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
        /// OEM ID suggests `BitLocker` container (`-FVE-FS-`).
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
    #[must_use]
    pub fn from_bytes(boot_sector: &[u8]) -> Self {
        match diagnose_boot_sector(boot_sector) {
            BootSectorDiagnosis::Detected(detected) => detected,
            BootSectorDiagnosis::Unknown(_) => DetectedBootSector::Unknown,
        }
    }

    /// Check if this is a filesystem (not a partition table)
    #[must_use]
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
                | DetectedBootSector::Btrfs
        )
    }

    /// Check if this is a partition table
    #[must_use]
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
/// identifies as MBR/GPT/FAT/NTFS/exFAT/BitLocker wins over later filesystem
/// probes. Only when the standard classification yields `Unknown` do we test
/// APFS, Btrfs, and ext superblocks.
#[must_use]
pub fn diagnose_boot_sector(boot_sector: &[u8]) -> BootSectorDiagnosis {
    let standard = diagnose_boot_sector_standard(boot_sector);
    if matches!(standard, BootSectorDiagnosis::Unknown(_)) {
        // These formats lack the 0xAA55 boot signature, so they are probed
        // only after standard detection reports Unknown.
        if probe_apfs(boot_sector) {
            return BootSectorDiagnosis::Detected(DetectedBootSector::Apfs);
        }
        if probe_btrfs_volume(boot_sector) {
            return BootSectorDiagnosis::Detected(DetectedBootSector::Btrfs);
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
            let ntfs_oem_hint = header.is_some_and(BootSectorHeader::is_ntfs);
            let bitlocker_hint = header.is_some_and(BootSectorHeader::is_bitlocker);
            let exfat_oem_hint = header.is_some_and(BootSectorHeader::is_exfat);
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
        /// Common jump and OEM header.
        header: &'a BootSectorHeader,
        /// DOS BIOS parameter block.
        bpb: &'a DosBpb,
        /// FAT12/16 extended parameter block.
        ebpb: &'a Fat16Ebpb,
        /// Boot-loader code following the parameter blocks.
        boot_code: &'a [u8],
    },
    /// FAT16 filesystem
    Fat16 {
        /// Common jump and OEM header.
        header: &'a BootSectorHeader,
        /// DOS BIOS parameter block.
        bpb: &'a DosBpb,
        /// FAT12/16 extended parameter block.
        ebpb: &'a Fat16Ebpb,
        /// Boot-loader code following the parameter blocks.
        boot_code: &'a [u8],
    },
    /// FAT32 filesystem
    Fat32 {
        /// Common jump and OEM header.
        header: &'a BootSectorHeader,
        /// DOS BIOS parameter block.
        bpb: &'a DosBpb,
        /// FAT32 extended parameter block.
        ebpb: &'a Fat32Ebpb,
        /// Boot-loader code following the parameter blocks.
        boot_code: &'a [u8],
    },
    /// NTFS filesystem
    Ntfs {
        /// Common jump and OEM header.
        header: &'a BootSectorHeader,
        /// DOS-compatible BIOS parameter block.
        bpb: &'a DosBpb,
        /// NTFS extended parameter block.
        ebpb: &'a NtfsEbpb,
        /// Boot-loader code following the parameter blocks.
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
    /// reused by `BitLocker` volumes.
    BitLocker {
        /// Common jump and FVE OEM header.
        header: &'a BootSectorHeader,
        /// DOS-compatible BIOS parameter block.
        bpb: &'a DosBpb,
        /// Volume length in sectors.
        total_sectors: u64,
        /// On-disk volume serial number.
        volume_serial_number: u64,
        /// Boot-loader code following the parameter blocks.
        boot_code: &'a [u8],
    },
    /// exFAT filesystem
    ExFat {
        /// Complete exFAT main boot-sector structure.
        boot_sector: &'a ExFatBootSector,
    },
    /// HPFS filesystem (uses FAT16 EBPB structure)
    Hpfs {
        /// Common jump and OEM header.
        header: &'a BootSectorHeader,
        /// DOS BIOS parameter block.
        bpb: &'a DosBpb,
        /// DOS 4 extended parameter block used by HPFS.
        ebpb: &'a Fat16Ebpb,
        /// Boot-loader code following the parameter blocks.
        boot_code: &'a [u8],
    },
    /// MBR partition table (not a filesystem)
    Mbr {
        /// Parsed master boot record.
        mbr: &'a crate::partition::Mbr,
    },
    /// GPT partition table (protective MBR detected)
    Gpt {
        /// Protective master boot record preceding the GPT.
        mbr: &'a crate::partition::Mbr,
    },
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
///
/// # Errors
///
/// Returns [`ParseError`] when the buffer is short, malformed, or has an
/// unsupported filesystem signature.
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
    let bytes_per_sector = u32::from(bpb.bytes_per_sector.get());
    let sectors_per_cluster = u32::from(bpb.sectors_per_cluster);

    if bytes_per_sector == 0 || sectors_per_cluster == 0 {
        return FilesystemType::Unknown;
    }

    // Calculate root directory sectors (FAT12/16)
    let root_entry_count = u32::from(bpb.root_entry_count.get());
    let root_dir_sectors = (root_entry_count * 32).div_ceil(bytes_per_sector);

    // Get FAT size
    let fat_size = if bpb.sectors_per_fat_16.get() != 0 {
        u32::from(bpb.sectors_per_fat_16.get())
    } else {
        // This would be FAT32, but we're checking FAT12/16 here
        return FilesystemType::Unknown;
    };

    // Calculate total sectors
    let total_sectors = bpb.total_sectors();

    // Calculate data sectors
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
    /// Common jump and OEM header at offset `0x00`.
    pub header: BootSectorHeader, // 0x00-0x0A (11 bytes)
    /// DOS BIOS parameter block at offset `0x0B`.
    pub bpb: DosBpb, // 0x0B-0x23 (25 bytes)
    /// FAT12/16 extended parameter block at offset `0x24`.
    pub ebpb: Fat16Ebpb, // 0x24-0x3D (26 bytes)
    /// Boot-loader code between the parameter block and signature.
    pub boot_code: [u8; 448], // 0x3E-0x1FD (448 bytes)
    /// Terminal `0xAA55` boot signature.
    pub boot_signature: U16<LittleEndian>, // 0x1FE-0x1FF (2 bytes)
}

/// Complete FAT32 boot sector layout (512 bytes)
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct Fat32BootSector {
    /// Common jump and OEM header at offset `0x00`.
    pub header: BootSectorHeader, // 0x00-0x0A (11 bytes)
    /// DOS BIOS parameter block at offset `0x0B`.
    pub bpb: DosBpb, // 0x0B-0x23 (25 bytes)
    /// FAT32 extended parameter block at offset `0x24`.
    pub ebpb: Fat32Ebpb, // 0x24-0x59 (54 bytes)
    /// Boot-loader code between the parameter block and signature.
    pub boot_code: [u8; 420], // 0x5A-0x1FD (420 bytes)
    /// Terminal `0xAA55` boot signature.
    pub boot_signature: U16<LittleEndian>, // 0x1FE-0x1FF (2 bytes)
}

/// Complete NTFS boot sector layout (512 bytes)
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct NtfsBootSector {
    /// Common jump and OEM header at offset `0x00`.
    pub header: BootSectorHeader, // 0x00-0x0A (11 bytes)
    /// DOS-compatible BIOS parameter block at offset `0x0B`.
    pub bpb: DosBpb, // 0x0B-0x23 (25 bytes)
    /// NTFS extended parameter block at offset `0x24`.
    pub ebpb: NtfsEbpb, // 0x24-0x53 (48 bytes)
    /// Boot-loader code between the parameter block and signature.
    pub boot_code: [u8; 426], // 0x54-0x1FD (426 bytes)
    /// Terminal `0xAA55` boot signature.
    pub boot_signature: U16<LittleEndian>, // 0x1FE-0x1FF (2 bytes)
}
