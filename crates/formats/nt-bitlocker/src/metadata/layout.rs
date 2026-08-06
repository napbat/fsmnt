//! On-disk layout structures for `BitLocker` FVE metadata.
//!
//! All structs use `zerocopy` for safe, zero-copy parsing from raw bytes.
//! Field names and offsets are cross-referenced against:
//! - dislocker `metadata.priv.h` (`bitlocker_information_t`, `bitlocker_dataset_t`)
//! - dislocker `datums.h` (`datum_header_safe_t`)
//! - libbde format documentation

use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// `BitLocker` volume header (boot sector, 512 bytes).
///
/// This is the standard NTFS-style BPB with BitLocker-specific fields.
/// The OEM ID is `-FVE-FS-` and the FVE metadata offsets are at 0xB0.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct BitLockerVolumeHeader {
    /// Jump instruction (3 bytes: 0xEB 0x58 0x90).
    pub jump: [u8; 3],
    /// OEM identifier — must be `-FVE-FS-`.
    pub oem_id: [u8; 8],
    /// Bytes per sector (typically 512).
    pub bytes_per_sector: U16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Reserved / BPB fields (0x0E–0x27, 26 bytes).
    pub _bpb_reserved: [u8; 26],
    /// Total sectors on the volume (offset 0x28).
    pub total_sectors: U64,
    /// MFT cluster number (offset 0x30, not used by `BitLocker`).
    pub _mft_cluster: U64,
    /// MFT mirror cluster (offset 0x38, not used by `BitLocker`).
    pub _mft_mirror: U64,
    /// Clusters per file record segment (offset 0x40).
    pub _clusters_per_frs: U32,
    /// Clusters per index block (offset 0x44).
    pub _clusters_per_index: U32,
    /// Volume serial number (offset 0x48).
    pub volume_serial: U64,
    /// Reserved (offset 0x50–0xAF, 96 bytes).
    pub _reserved_50: [u8; 96],
    /// FVE metadata block offsets (3 × u64, offset 0xB0).
    pub fve_metadata_offsets: [U64; 3],
    /// Remaining bytes up to the boot signature (0xC8–0x1FD, 310 bytes).
    pub _remaining: [u8; 310],
    /// Boot signature (0x55, 0xAA at offset 0x1FE).
    pub boot_signature: [u8; 2],
}

const _: () = assert!(size_of::<BitLockerVolumeHeader>() == 512);

/// FVE metadata block header (64 bytes, offset 0 of each FVE block).
///
/// Corresponds to the first 0x40 bytes of dislocker's `bitlocker_information_t`.
/// Starts with the `-FVE-FS-` signature.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct FveBlockHeader {
    /// `-FVE-FS-` magic signature.
    pub signature: [u8; 8],
    /// Size field. For version ≥ 2 (Windows 7+), the actual block size in
    /// bytes is `size << 4`. For version 1 (Vista), this is the raw byte count.
    pub size: U16,
    /// Block version (1 = Vista, 2 = Windows 7+).
    pub version: U16,
    /// Current encryption state.
    pub curr_state: U16,
    /// Next encryption state (target).
    pub next_state: U16,
    /// Size of the encrypted volume in bytes.
    pub encrypted_volume_size: U64,
    /// Conversion size (4 bytes).
    pub convert_size: U32,
    /// Number of backup sectors.
    pub nb_backup_sectors: U32,
    /// Redundant copies of the three FVE metadata block offsets.
    pub fve_metadata_offsets: [U64; 3],
    /// Offset to the backup sectors on disk.
    pub boot_sectors_backup: U64,
}

const _: () = assert!(size_of::<FveBlockHeader>() == 64);

/// FVE metadata dataset header (48 bytes, offset 0x40 of each FVE block).
///
/// Corresponds to dislocker's `bitlocker_dataset_t` (the `dataset` field
/// inside `bitlocker_information_t`).
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct FveDatasetHeader {
    /// Total size of the dataset (this header + all datum entries), in bytes.
    pub size: U32,
    /// Dataset version.
    pub version: U32,
    /// Header size (always 48 for known versions).
    pub header_size: U32,
    /// Copy of `size` (redundant).
    pub size_copy: U32,
    /// Volume GUID.
    pub volume_guid: [u8; 16],
    /// Next counter value (nonce generation).
    pub next_counter: U32,
    /// Encryption algorithm / method (2 bytes, not 4).
    pub algorithm: U16,
    /// Padding / trash (2 bytes after the algorithm field).
    pub _algorithm_pad: U16,
    /// Timestamp (Windows FILETIME).
    pub timestamp: U64,
}

const _: () = assert!(size_of::<FveDatasetHeader>() == 48);

/// Validation structure (8 bytes) that immediately follows the metadata block.
///
/// Corresponds to dislocker's `bitlocker_validations_t`.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct FveValidation {
    /// Size of this validation structure (always 8).
    pub size: U16,
    /// Validation version.
    pub version: U16,
    /// CRC-32 computed over the entire metadata block (from offset 0 to
    /// `total_block_size`).
    pub crc32: U32,
}

const _: () = assert!(size_of::<FveValidation>() == 8);

/// Datum header (8 bytes), the common prefix of every FVE datum entry.
///
/// Corresponds to dislocker's `datum_header_safe_t`.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct DatumHeaderRaw {
    /// Total size of this datum (header + payload).
    pub size: U16,
    /// Entry type (e.g. 0x0002 = VMK, 0x0003 = FVEK).
    pub entry_type: U16,
    /// Value type (e.g. 0x0005 = AES-CCM, 0x0008 = VMK, 0x0009 = external key).
    pub value_type: U16,
    /// Status flags.
    pub status: U16,
}

const _: () = assert!(size_of::<DatumHeaderRaw>() == 8);

/// VMK datum fixed-size body (28 bytes, immediately after the datum header).
///
/// Corresponds to the fixed portion of dislocker's `datum_vmk_t`.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct VmkBody {
    /// VMK identifier GUID.
    pub guid: [u8; 16],
    /// Last modification timestamp (Windows FILETIME).
    pub last_modify: U64,
    /// Unknown field.
    pub unknown: U16,
    /// Protection type (e.g. 0x0000 = clear key, 0x0100 = TPM, 0x0800 = password).
    pub protection_type: U16,
}

const _: () = assert!(size_of::<VmkBody>() == 28);

/// Stretch key datum body (20 bytes, after the datum header).
///
/// Contains the algorithm identifier and 16-byte salt used for
/// `BitLocker`'s custom SHA-256 key stretching.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct StretchKeyBody {
    /// Key stretching algorithm identifier.
    pub algorithm: U16,
    /// Reserved / padding.
    pub _reserved: U16,
    /// 16-byte salt.
    pub salt: [u8; 16],
}

const _: () = assert!(size_of::<StretchKeyBody>() == 20);

/// AES-CCM encrypted datum body (28-byte fixed prefix, after the datum header).
///
/// The remaining bytes after this prefix are the encrypted key material.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct AesCcmBody {
    /// 12-byte nonce / IV.
    pub nonce: [u8; 12],
    /// 16-byte MAC tag.
    pub mac: [u8; 16],
}

const _: () = assert!(size_of::<AesCcmBody>() == 28);

/// External key datum body (24-byte fixed prefix, after the datum header).
///
/// The remaining bytes after this prefix are nested datum entries.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct ExternalKeyBody {
    /// External key identifier GUID.
    pub guid: [u8; 16],
    /// Reserved / unknown (8 bytes).
    pub _reserved: U64,
}

const _: () = assert!(size_of::<ExternalKeyBody>() == 24);

/// Optional 2-byte algorithm ID prefix on an FVEK blob.
///
/// When the decrypted FVEK is longer than the encryption method requires,
/// the first two bytes are an algorithm identifier (0x8000–0x8005) that
/// should be stripped before using the key material.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct FvekAlgoPrefix {
    /// Algorithm identifier (e.g. 0x8004 = AES-128-XTS).
    pub algo_id: U16,
}

const _: () = assert!(size_of::<FvekAlgoPrefix>() == 2);

impl FvekAlgoPrefix {
    /// Returns `true` if this is a recognised `BitLocker` algorithm ID
    /// (0x8000 through 0x8005).
    #[must_use]
    pub fn is_known(self) -> bool {
        matches!(self.algo_id.get(), 0x8000..=0x8005)
    }
}
