//! Boot-sector detection: classify raw boot-sector bytes as a filesystem
//! or a partition table.
//!
//! The standard classification path trusts the 512-byte boot-signature
//! structures (FAT/NTFS/`exFAT`/`BitLocker`/MBR/GPT). Filesystems without
//! an 0xAA55 boot signature (ext2/3/4 and APFS) are handled by dedicated
//! prefix probes that only run after standard classification reports
//! `Unknown`.

use zerocopy::FromBytes;

use crate::bpb::{
    BootSectorHeader, FilesystemType, ParseError, ParsedBootSector, parse_boot_sector,
};
use crate::partition::Mbr;

/// Standard boot sector size for IBM PC compatible systems.
pub const BOOT_SECTOR_SIZE: usize = 512;

/// Probe length for filesystem-type detection. Large enough to include
/// ext's superblock magic at offset 0x438. Callers that want filesystem
/// detection (not just partition-table detection) should read this many
/// bytes before calling [`DetectedBootSector::from_bytes`].
pub const FS_DETECT_PROBE_SIZE: usize = 2048;

/// Boot signature value (little-endian: 0x55 at offset 510, 0xAA at
/// offset 511).
pub(crate) const BOOT_SIGNATURE: u16 = 0xAA55;

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

/// Prefix probe for the ext2/ext3/ext4 superblock. Runs cheap sanity
/// checks beyond `s_magic` to avoid misclassifying GPT partition-entry
/// arrays (where a coincidental 0xEF53 at offset 0x438 would otherwise
/// match).
fn probe_ext(buf: &[u8]) -> bool {
    if buf.len() < EXT_PROBE_MIN_LEN {
        return false;
    }
    if read_u16_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_MAGIC) != EXT_MAGIC {
        return false;
    }
    // s_log_block_size gates 0..=6 (block size 1 KiB .. 64 KiB), matching
    // ext's own superblock rules.
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

/// Prefix probe for an APFS container superblock. APFS has no 0xAA55
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
    block_size.is_power_of_two() && (512..=65_536).contains(&block_size)
}

/// Result of detecting what's on a boot sector.
///
/// This enum represents the high-level detection result — either a
/// filesystem type or a partition table type. Use
/// [`DetectedBootSector::from_bytes`] to get this from raw boot sector
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedBootSector {
    /// NTFS filesystem.
    Ntfs,
    /// FAT12 filesystem.
    Fat12,
    /// FAT16 filesystem.
    Fat16,
    /// FAT32 filesystem.
    Fat32,
    /// `exFAT` filesystem.
    ExFat,
    /// ext2/ext3/ext4 filesystem.
    Ext,
    /// APFS container (one or more volumes; `NXSB` block-zero superblock).
    Apfs,
    /// `BitLocker`-encrypted volume (detected container/encrypted-volume
    /// type).
    BitLocker,
    /// MBR partitioned disk (need to enumerate partitions).
    MbrPartitioned,
    /// GPT partitioned disk (need to enumerate partitions).
    GptPartitioned,
    /// Unknown or unrecognized.
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
    /// Signature at 0x1FE is not 0xAA55.
    InvalidBootSignature,
    /// Structure looked like a known type but failed strict parsing or
    /// validation (e.g., corrupted BPB fields).
    CorruptedStructure,
    /// Parsed as HPFS, which is currently unsupported by
    /// [`DetectedBootSector`].
    UnsupportedFilesystem(FilesystemType),
    /// Signature is present, but no known/valid filesystem or partition
    /// table could be confirmed.
    UnknownFilesystem {
        /// OEM ID suggests an NTFS-like layout (`NTFS    `).
        ntfs_oem_hint: bool,
        /// OEM ID suggests `exFAT` (`EXFAT   `) or a zeroed `exFAT` BPB
        /// region.
        exfat_hint: bool,
        /// OEM ID suggests a `BitLocker` container (`-FVE-FS-`).
        bitlocker_hint: bool,
        /// Boot sector can be parsed as an MBR structure.
        mbr_layout_hint: bool,
    },
}

impl DetectedBootSector {
    /// Detect what's on a boot sector from raw bytes.
    ///
    /// This is a pure function that parses the boot sector and returns a
    /// simplified enum representing the detected type.
    #[must_use]
    pub fn from_bytes(boot_sector: &[u8]) -> Self {
        match diagnose_boot_sector(boot_sector) {
            BootSectorDiagnosis::Detected(detected) => detected,
            BootSectorDiagnosis::Unknown(_) => DetectedBootSector::Unknown,
        }
    }

    /// Check if this is a filesystem (not a partition table).
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
        )
    }

    /// Check if this is a partition table.
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
/// Trusts the 512-byte boot signature path first — a disk whose first
/// sector identifies as MBR/GPT/FAT/NTFS/`exFAT`/`BitLocker` is not a
/// bare ext image, even if bytes at 0x438 happen to pass the ext sanity
/// checks. Only when the standard classification yields `Unknown` do we
/// fall through to the APFS and ext superblock probes (the latter
/// requires at least [`FS_DETECT_PROBE_SIZE`] bytes).
#[must_use]
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
            let ntfs_oem_hint = header.is_some_and(BootSectorHeader::is_ntfs);
            let bitlocker_hint = header.is_some_and(BootSectorHeader::is_bitlocker);
            let exfat_oem_hint = header.is_some_and(BootSectorHeader::is_exfat);
            let exfat_zeroed_bpb_hint = boot_sector[0x0B..0x40].iter().all(|&b| b == 0);
            let mbr_layout_hint = Mbr::from_bytes(boot_sector).is_some();

            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnknownFilesystem {
                ntfs_oem_hint,
                exfat_hint: exfat_oem_hint || exfat_zeroed_bpb_hint,
                bitlocker_hint,
                mbr_layout_hint,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    fn stamp_boot_signature(buf: &mut [u8; 512]) {
        buf[510] = 0x55;
        buf[511] = 0xAA;
    }

    fn build_ntfs_sector() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 8; // sectors per cluster
        buf[0x28..0x30].copy_from_slice(&1_048_576u64.to_le_bytes()); // total sectors
        stamp_boot_signature(&mut buf);
        buf
    }

    fn build_fat12_sector() -> [u8; 512] {
        // A 1.44 MB floppy layout: 2880 sectors, 1 spc, 9 spf, 224 root
        // entries — cluster count is well below 4085.
        let mut buf = [0u8; 512];
        buf[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        buf[3..11].copy_from_slice(b"MSDOS5.0");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 1; // sectors per cluster
        buf[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes()); // reserved sectors
        buf[0x10] = 2; // number of FATs
        buf[0x11..0x13].copy_from_slice(&224u16.to_le_bytes()); // root entries
        buf[0x13..0x15].copy_from_slice(&2880u16.to_le_bytes()); // total sectors
        buf[0x15] = 0xF8;
        buf[0x16..0x18].copy_from_slice(&9u16.to_le_bytes()); // sectors per FAT
        buf[0x26] = 0x29; // extended boot signature
        stamp_boot_signature(&mut buf);
        buf
    }

    fn build_fat32_sector() -> [u8; 512] {
        // FAT32: sectors_per_fat_16 == 0 AND root_entry_count == 0.
        let mut buf = [0u8; 512];
        buf[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        buf[3..11].copy_from_slice(b"MSDOS5.0");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 8; // sectors per cluster
        buf[0x0E..0x10].copy_from_slice(&32u16.to_le_bytes()); // reserved sectors
        buf[0x10] = 2; // number of FATs
        buf[0x15] = 0xF8;
        buf[0x20..0x24].copy_from_slice(&4_194_304u32.to_le_bytes()); // total sectors
        buf[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes()); // sectors per FAT
        buf[0x42] = 0x29; // extended boot signature
        stamp_boot_signature(&mut buf);
        buf
    }

    fn build_hpfs_sector() -> [u8; 512] {
        let mut buf = build_fat12_sector();
        buf[3..11].copy_from_slice(b"HPFS    ");
        buf
    }

    /// Minimal FAT12/16 layout: 1 spc, 1 reserved sector, 2 FATs of 1
    /// sector each, 16 root entries (1 root-dir sector) — so
    /// `first_data_sector` = 4 and `cluster_count` = total - 4.
    fn build_small_fat_sector(total_sectors_16: u16) -> [u8; 512] {
        let mut buf = build_fat12_sector();
        buf[0x11..0x13].copy_from_slice(&16u16.to_le_bytes()); // root entries
        buf[0x13..0x15].copy_from_slice(&total_sectors_16.to_le_bytes());
        buf[0x16..0x18].copy_from_slice(&1u16.to_le_bytes()); // sectors per FAT
        buf
    }

    fn build_bitlocker_sector() -> [u8; 512] {
        let mut buf = build_ntfs_sector();
        buf[3..11].copy_from_slice(b"-FVE-FS-");
        buf
    }

    fn build_exfat_sector() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        buf[3..11].copy_from_slice(b"EXFAT   ");
        // BPB region 0x0B..0x40 stays all-zero (must_be_zero).
        buf[0x48..0x50].copy_from_slice(&1_048_576u64.to_le_bytes()); // volume_length
        buf[0x6C] = 9; // bytes_per_sector_shift
        buf[0x6D] = 3; // sectors_per_cluster_shift
        buf[0x6E] = 1; // number_of_fats
        buf[0x6F] = 0x80; // drive_select
        stamp_boot_signature(&mut buf);
        buf
    }

    fn build_mbr_sector_with_partition() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[446] = 0x80; // bootable
        buf[446 + 4] = 0x07; // partition_type NTFS/HPFS/exFAT
        buf[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        buf[446 + 12..446 + 16].copy_from_slice(&1_000_000u32.to_le_bytes());
        stamp_boot_signature(&mut buf);
        buf
    }

    fn build_gpt_protective_sector() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[446 + 4] = 0xEE; // GPT protective marker
        buf[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        buf[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        stamp_boot_signature(&mut buf);
        buf
    }

    fn synthesize_ext_superblock(buf: &mut [u8]) {
        // s_magic at offset 1024 + 0x38 = 0x438 (little-endian 0xEF53)
        buf[0x438] = 0x53;
        buf[0x439] = 0xEF;
        // s_log_block_size at 1024 + 0x18: 2 (4 KiB blocks)
        buf[1024 + 0x18..1024 + 0x18 + 4].copy_from_slice(&2u32.to_le_bytes());
        // s_blocks_per_group at 1024 + 0x20: non-zero
        buf[1024 + 0x20..1024 + 0x20 + 4].copy_from_slice(&32_768u32.to_le_bytes());
        // s_inodes_per_group at 1024 + 0x28: non-zero
        buf[1024 + 0x28..1024 + 0x28 + 4].copy_from_slice(&8_192u32.to_le_bytes());
    }

    fn synthesize_apfs_superblock(buf: &mut [u8]) {
        // obj_phys_t object type at 0x18: OBJECT_TYPE_NX_SUPERBLOCK (0x01).
        buf[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        // nx_magic at 0x20: "NXSB".
        buf[0x20..0x24].copy_from_slice(b"NXSB");
        // nx_block_size at 0x24: 4 KiB.
        buf[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
    }

    // ------------------------------------------------------------------
    // Diagnosis failure modes
    // ------------------------------------------------------------------

    #[test]
    fn diagnose_buffer_too_small() {
        assert_eq!(
            diagnose_boot_sector(&[0u8; 128]),
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::BufferTooSmall)
        );
    }

    #[test]
    fn diagnose_all_zeroes() {
        assert_eq!(
            diagnose_boot_sector(&[0u8; 512]),
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::AllZeroes)
        );
    }

    #[test]
    fn diagnose_invalid_signature() {
        let mut buffer = [0u8; 512];
        buffer[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(
            diagnose_boot_sector(&buffer),
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::InvalidBootSignature)
        );
    }

    #[test]
    fn diagnose_unknown_filesystem_reports_hints() {
        let mut buffer = [0u8; 512];
        stamp_boot_signature(&mut buffer);
        buffer[3..11].copy_from_slice(b"NTFS    ");
        // An invalid bytes-per-sector keeps this from parsing as NTFS.
        buffer[0x0B..0x0D].copy_from_slice(&123u16.to_le_bytes());

        assert_eq!(
            diagnose_boot_sector(&buffer),
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnknownFilesystem {
                ntfs_oem_hint: true,
                exfat_hint: false,
                bitlocker_hint: false,
                mbr_layout_hint: true,
            })
        );
    }

    #[test]
    fn unknown_diagnosis_reports_exfat_zeroed_bpb_hint_when_bpb_is_all_zero() {
        // OEM "NTFS    " (so ntfs_oem_hint=true, exfat_oem_hint=false)
        // plus an all-zero BPB region: parsing fails at bytes_per_sector=0
        // and the zeroed-region signal must still set exfat_hint.
        let mut buffer = [0u8; 512];
        stamp_boot_signature(&mut buffer);
        buffer[3..11].copy_from_slice(b"NTFS    ");
        // BPB region [0x0B..0x40] left all-zero on purpose.

        assert_eq!(
            diagnose_boot_sector(&buffer),
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnknownFilesystem {
                ntfs_oem_hint: true,
                exfat_hint: true,
                bitlocker_hint: false,
                mbr_layout_hint: true,
            })
        );
    }

    #[test]
    fn diagnose_unsupported_hpfs() {
        assert_eq!(
            diagnose_boot_sector(&build_hpfs_sector()),
            BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnsupportedFilesystem(
                FilesystemType::Hpfs
            ))
        );
        // HPFS maps to Unknown at the from_bytes level.
        assert_eq!(
            DetectedBootSector::from_bytes(&build_hpfs_sector()),
            DetectedBootSector::Unknown
        );
    }

    // ------------------------------------------------------------------
    // Standard classification
    // ------------------------------------------------------------------

    #[test]
    fn from_bytes_classifies_standard_boot_sectors() {
        assert_eq!(
            DetectedBootSector::from_bytes(&build_ntfs_sector()),
            DetectedBootSector::Ntfs
        );
        assert_eq!(
            DetectedBootSector::from_bytes(&build_fat12_sector()),
            DetectedBootSector::Fat12
        );
        assert_eq!(
            DetectedBootSector::from_bytes(&build_fat32_sector()),
            DetectedBootSector::Fat32
        );
        assert_eq!(
            DetectedBootSector::from_bytes(&build_exfat_sector()),
            DetectedBootSector::ExFat
        );
        assert_eq!(
            DetectedBootSector::from_bytes(&build_mbr_sector_with_partition()),
            DetectedBootSector::MbrPartitioned
        );
        assert_eq!(
            DetectedBootSector::from_bytes(&build_gpt_protective_sector()),
            DetectedBootSector::GptPartitioned
        );
    }

    #[test]
    fn from_bytes_detects_bitlocker() {
        let detected = DetectedBootSector::from_bytes(&build_bitlocker_sector());
        assert_eq!(detected, DetectedBootSector::BitLocker);
        assert!(!detected.is_filesystem());
        assert!(!detected.is_partition_table());
    }

    #[test]
    fn classification_predicates() {
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

        for fs in [
            DetectedBootSector::Ntfs,
            DetectedBootSector::Fat12,
            DetectedBootSector::Fat16,
            DetectedBootSector::Fat32,
            DetectedBootSector::ExFat,
            DetectedBootSector::Ext,
            DetectedBootSector::Apfs,
        ] {
            assert!(fs.is_filesystem(), "{fs:?} must classify as a filesystem");
        }
        assert!(!DetectedBootSector::MbrPartitioned.is_filesystem());
        assert!(!DetectedBootSector::Unknown.is_filesystem());
    }

    #[test]
    fn ntfs_detection_via_bpb_shape_when_oem_is_overwritten() {
        // NTFS volumes whose OEM ID was overwritten must still classify
        // via the looks_like_ntfs() BPB shape (all four gate fields zero).
        let mut buf = build_ntfs_sector();
        buf[3..11].copy_from_slice(b"GENERIC ");
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Ntfs
        );
    }

    #[test]
    fn fat32_detection_requires_zero_root_entry_and_zero_sectors_per_fat_16() {
        // Non-zero root_entry_count and sectors_per_fat_16 — not FAT32:
        // the layout lands as FAT16 through the cluster-count calculation.
        let mut buf = build_fat32_sector();
        buf[0x11..0x13].copy_from_slice(&512u16.to_le_bytes()); // root_entry_count
        buf[0x16..0x18].copy_from_slice(&128u16.to_le_bytes()); // sectors_per_fat_16
        buf[0x13..0x15].copy_from_slice(&32_000u16.to_le_bytes()); // total_sectors_16
        buf[0x0D] = 4; // sectors per cluster → FAT16-sized cluster count
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Fat16
        );
    }

    // ------------------------------------------------------------------
    // FAT cluster-count thresholds (drive FAT12/16/32 classification)
    // ------------------------------------------------------------------

    #[test]
    fn fat12_to_fat16_boundary_at_4085_clusters() {
        // cluster_count = total - 4: total 4088 → 4084 clusters (FAT12);
        // total 4089 → 4085 clusters (FAT16).
        assert_eq!(
            DetectedBootSector::from_bytes(&build_small_fat_sector(4088)),
            DetectedBootSector::Fat12
        );
        assert_eq!(
            DetectedBootSector::from_bytes(&build_small_fat_sector(4089)),
            DetectedBootSector::Fat16
        );
    }

    #[test]
    fn fat16_to_fat32_boundary_uses_cluster_count_threshold() {
        // A FAT16-shaped layout (spf16 != 0) with 1 spc, 1 reserved
        // sector, 1 FAT of 1 sector, and 0 root entries: the total goes
        // in the 32-bit slot and first_data_sector = 2.
        fn sector(total_32: u32) -> [u8; 512] {
            let mut buf = build_fat12_sector();
            buf[0x10] = 1; // one FAT
            buf[0x11..0x13].copy_from_slice(&0u16.to_le_bytes()); // root entries
            buf[0x13..0x15].copy_from_slice(&0u16.to_le_bytes()); // ts16 = 0
            buf[0x16..0x18].copy_from_slice(&1u16.to_le_bytes()); // sectors per FAT
            buf[0x20..0x24].copy_from_slice(&total_32.to_le_bytes());
            buf
        }

        // total 65526 → 65524 clusters → FAT16.
        assert_eq!(
            DetectedBootSector::from_bytes(&sector(65_526)),
            DetectedBootSector::Fat16
        );
        // total 65527 → 65525 clusters → FAT32 territory, which the
        // FAT16-shaped parse rejects → Unknown.
        assert_eq!(
            DetectedBootSector::from_bytes(&sector(65_527)),
            DetectedBootSector::Unknown
        );
    }

    // ------------------------------------------------------------------
    // ext probe
    // ------------------------------------------------------------------

    #[test]
    fn from_bytes_detects_ext_with_valid_sanity_fields() {
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        synthesize_ext_superblock(&mut buf);
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Ext
        );
    }

    #[test]
    fn from_bytes_short_buffer_does_not_detect_ext() {
        // A buffer below EXT_PROBE_MIN_LEN must fall through to the
        // 512-byte signature checks; a real ext image's first 512 bytes
        // don't carry the ext magic.
        let buf = vec![0u8; 512];
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }

    #[test]
    fn ext_probe_min_len_matches_magic_field_end() {
        // The constant must equal the offset of the last s_magic byte + 1.
        assert_eq!(EXT_PROBE_MIN_LEN, 0x43A);
    }

    #[test]
    fn ext_probe_short_buffer_at_minimum_minus_one_returns_unknown() {
        // A buffer of 0x439 bytes has buf[0x438] but not buf[0x439]; the
        // probe's size check must reject it before the u16 magic read.
        let buf = vec![0u8; 0x439];
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }

    #[test]
    fn ext_probe_succeeds_at_exact_minimum_buffer_size() {
        // Exactly 0x43A bytes — the smallest size that fits the magic.
        let mut buf = vec![0u8; 0x43A];
        synthesize_ext_superblock(&mut buf);
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Ext
        );
    }

    #[test]
    fn ext_probe_rejects_log_block_size_above_six() {
        // s_log_block_size of 7 must reject — anchors the `> 6` boundary.
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

    #[test]
    fn from_bytes_prefers_gpt_over_coincidental_ext_magic_in_partition_array() {
        // A GPT disk with a stray 0xEF53 at 0x438 but no supporting
        // sanity fields: probe_ext must reject; GPT classification wins.
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        buf[0x1C2] = 0xEE; // MBR partition entry 1 type = protective GPT
        buf[0x1FE] = 0x55; // MBR boot signature
        buf[0x1FF] = 0xAA;
        buf[0x438] = 0x53; // bare ext magic, sanity fields remain zero
        buf[0x439] = 0xEF;

        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::GptPartitioned,
            "probe_ext must reject magic-only; GPT classification must win",
        );
    }

    #[test]
    fn from_bytes_rejects_crafted_gpt_with_valid_ext_sanity_fields() {
        // A maliciously-crafted GPT partition-entry area where bytes at
        // 0x438 pass ALL four probe_ext sanity checks. Standard detection
        // runs first, so GPT must still win.
        let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
        buf[0x1C2] = 0xEE;
        buf[0x1FE] = 0x55;
        buf[0x1FF] = 0xAA;
        synthesize_ext_superblock(&mut buf);

        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::GptPartitioned,
            "GPT must win over a probe_ext-passing sanity region",
        );
    }

    // ------------------------------------------------------------------
    // APFS probe
    // ------------------------------------------------------------------

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
    fn apfs_probe_min_len_matches_block_size_field_end() {
        assert_eq!(APFS_PROBE_MIN_LEN, 0x28);
    }

    #[test]
    fn apfs_probe_succeeds_at_minimum_buffer_size() {
        // 0x28 bytes is the smallest buffer that fits nx_block_size at
        // 0x24..0x28. Standard detection short-circuits to BufferTooSmall,
        // but probe_apfs still runs from the diagnose fall-through.
        let mut buf = vec![0u8; 0x28];
        synthesize_apfs_superblock(&mut buf);
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Apfs
        );
    }

    #[test]
    fn apfs_probe_below_minimum_buffer_size_returns_unknown() {
        // A buffer of 0x27 bytes is one short of fitting nx_block_size.
        let mut buf = vec![0u8; 0x27];
        buf[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        buf[0x20..0x24].copy_from_slice(b"NXSB");
        assert_eq!(
            DetectedBootSector::from_bytes(&buf),
            DetectedBootSector::Unknown
        );
    }
}
