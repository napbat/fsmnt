pub mod entry;
pub mod fve_block;
pub mod header;
pub mod layout;
pub mod vmk;

use std::io::{Read, Seek, SeekFrom};

use crate::{BitLockerError, MetadataFailure, Result};
use entry::{DatumIter, ENTRY_TYPE_VMK, VALUE_TYPE_VMK};
use fve_block::FveBlock;
use header::VolumeHeader;
use vmk::VmkDatum;

/// Per-block validation result.
#[derive(Debug, Clone)]
pub enum BlockStatus {
    /// The redundant metadata block passed signature, bounds, and CRC checks.
    Valid,
    /// The redundant metadata block was rejected for the recorded reason.
    Invalid(MetadataFailure),
}

/// Diagnostics from parsing all three FVE metadata blocks.
#[derive(Debug, Clone)]
pub struct MetadataDiagnostics {
    block_statuses: [BlockStatus; 3],
    selected_block: u8,
    has_disagreements: bool,
}

impl MetadataDiagnostics {
    /// Returns validation results for all three metadata copies.
    #[must_use]
    pub fn block_statuses(&self) -> &[BlockStatus; 3] {
        &self.block_statuses
    }

    /// Returns the zero-based index of the authoritative metadata copy.
    #[must_use]
    pub fn selected_block(&self) -> u8 {
        self.selected_block
    }

    /// Returns whether valid copies disagree on security-relevant fields.
    #[must_use]
    pub fn has_disagreements(&self) -> bool {
        self.has_disagreements
    }

    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self {
            block_statuses: [BlockStatus::Valid, BlockStatus::Valid, BlockStatus::Valid],
            selected_block: 0,
            has_disagreements: false,
        }
    }
}

/// Estimated maximum size for a single FVE metadata block read (1 MiB).
const MAX_FVE_BLOCK_READ: usize = 1024 * 1024;

/// Read a single FVE metadata block from the given offset.
fn read_fve_block<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    block_index: u8,
) -> std::result::Result<FveBlock, MetadataFailure> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|_| MetadataFailure::ParseFailed {
            offset,
            detail: "seek to FVE block offset failed",
        })?;

    let mut buf = vec![0u8; MAX_FVE_BLOCK_READ];
    let bytes_read = read_fill(reader, &mut buf).map_err(|_| MetadataFailure::ParseFailed {
        offset,
        detail: "I/O error reading FVE block",
    })?;

    FveBlock::from_bytes(&buf[..bytes_read], block_index).map_err(|e| match e {
        BitLockerError::InvalidMetadata { reason, .. } => reason,
        _ => MetadataFailure::ParseFailed {
            offset,
            detail: "unexpected error parsing FVE block",
        },
    })
}

/// Read as many bytes as possible into the buffer, returning the count.
fn read_fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Validate all three FVE metadata blocks and select the authoritative copy.
///
/// # Errors
///
/// Returns `AllMetadataBlocksCorrupt` if none of the three blocks are valid.
pub fn validate_all_blocks<R: Read + Seek>(
    reader: &mut R,
    volume_header: &VolumeHeader,
) -> Result<(FveBlock, MetadataDiagnostics)> {
    let offsets = volume_header.fve_metadata_offsets();
    let mut blocks: [Option<FveBlock>; 3] = [None, None, None];
    let mut statuses: [Option<BlockStatus>; 3] = [None, None, None];
    let mut failures: [Option<MetadataFailure>; 3] = [None, None, None];

    for (i, &offset) in offsets.iter().enumerate() {
        let idx = u8::try_from(i).map_err(|_| BitLockerError::InvalidMetadata {
            block_index: u8::MAX,
            reason: MetadataFailure::ParseFailed {
                offset,
                detail: "metadata block index exceeds u8",
            },
        })?;
        match read_fve_block(reader, offset, idx) {
            Ok(block) => {
                statuses[i] = Some(BlockStatus::Valid);
                blocks[i] = Some(block);
            }
            Err(failure) => {
                statuses[i] = Some(BlockStatus::Invalid(failure.clone()));
                failures[i] = Some(failure);
            }
        }
    }

    let block_statuses = [
        statuses[0]
            .take()
            .unwrap_or(BlockStatus::Invalid(MetadataFailure::InvalidSignature)),
        statuses[1]
            .take()
            .unwrap_or(BlockStatus::Invalid(MetadataFailure::InvalidSignature)),
        statuses[2]
            .take()
            .unwrap_or(BlockStatus::Invalid(MetadataFailure::InvalidSignature)),
    ];

    // Collect valid block indices
    let valid_indices: Vec<usize> = blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| b.is_some())
        .map(|(i, _)| i)
        .collect();

    if valid_indices.is_empty() {
        return Err(BitLockerError::AllMetadataBlocksCorrupt {
            failures: [
                failures[0]
                    .take()
                    .unwrap_or(MetadataFailure::InvalidSignature),
                failures[1]
                    .take()
                    .unwrap_or(MetadataFailure::InvalidSignature),
                failures[2]
                    .take()
                    .unwrap_or(MetadataFailure::InvalidSignature),
            ],
        });
    }

    // Select by metadata version (highest wins), then by first-valid as tiebreaker
    // Following dislocker's approach (first-valid) with version as selector
    let selected_idx = valid_indices
        .iter()
        .copied()
        .max_by_key(|&i| blocks[i].as_ref().map_or(0, FveBlock::metadata_version))
        .unwrap_or(valid_indices[0]);

    // Check for disagreements among valid blocks
    let has_disagreements = if valid_indices.len() > 1 {
        let reference = blocks[selected_idx].as_ref();
        valid_indices.iter().any(|&i| {
            let block = blocks[i].as_ref();
            match (reference, block) {
                (Some(r), Some(b)) => {
                    r.encryption_method_raw() != b.encryption_method_raw()
                        || r.volume_guid() != b.volume_guid()
                }
                _ => false,
            }
        })
    } else {
        false
    };

    // Safety: selected_idx comes from valid_indices, which only contains
    // indices where blocks[i].is_some(), so take() always returns Some.
    let Some(selected_block) = blocks[selected_idx].take() else {
        return Err(BitLockerError::AllMetadataBlocksCorrupt {
            failures: [
                MetadataFailure::InvalidSignature,
                MetadataFailure::InvalidSignature,
                MetadataFailure::InvalidSignature,
            ],
        });
    };

    Ok((
        selected_block,
        MetadataDiagnostics {
            block_statuses,
            selected_block: u8::try_from(selected_idx).map_err(|_| {
                BitLockerError::InvalidMetadata {
                    block_index: u8::MAX,
                    reason: MetadataFailure::ParseFailed {
                        offset: 0,
                        detail: "selected metadata block index exceeds u8",
                    },
                }
            })?,
            has_disagreements,
        },
    ))
}

/// Encryption method from FVE metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    /// AES-128 in CBC mode with Elephant diffusion.
    Aes128CbcDiffuser, // 0x8000
    /// AES-256 in CBC mode with Elephant diffusion.
    Aes256CbcDiffuser, // 0x8001
    /// AES-128 in CBC mode without diffusion.
    Aes128Cbc, // 0x8002
    /// AES-256 in CBC mode without diffusion.
    Aes256Cbc, // 0x8003
    /// AES-128 in XTS mode.
    Aes128Xts, // 0x8004
    /// AES-256 in XTS mode.
    Aes256Xts, // 0x8005
}

impl EncryptionMethod {
    fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0x8000 => Some(Self::Aes128CbcDiffuser),
            0x8001 => Some(Self::Aes256CbcDiffuser),
            0x8002 => Some(Self::Aes128Cbc),
            0x8003 => Some(Self::Aes256Cbc),
            0x8004 => Some(Self::Aes128Xts),
            0x8005 => Some(Self::Aes256Xts),
            _ => None,
        }
    }
}

/// Key protector type from VMK datum `protection_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectorType {
    /// VMK is stored under an unencrypted clear-key protector.
    ClearKey, // 0x0000
    /// VMK is protected by the platform TPM.
    Tpm, // 0x0100
    /// VMK is protected by an external startup-key file.
    StartupKey, // 0x0200
    /// VMK requires both TPM state and a user PIN.
    TpmPin, // 0x0500
    /// VMK is protected by a numerical recovery password.
    RecoveryPassword, // 0x0800
    /// VMK is protected by a user password.
    Password, // 0x2000
    /// An unrecognized on-disk protector identifier.
    Unknown(u16),
}

impl ProtectorType {
    /// Decodes an on-disk protector identifier without rejecting unknown IDs.
    #[must_use]
    pub fn from_raw(raw: u16) -> Self {
        match raw {
            0x0000 => Self::ClearKey,
            0x0100 => Self::Tpm,
            0x0200 => Self::StartupKey,
            0x0500 => Self::TpmPin,
            0x0800 => Self::RecoveryPassword,
            0x2000 => Self::Password,
            other => Self::Unknown(other),
        }
    }
}

/// Encryption state derived from FVE metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionState {
    /// All protected volume sectors are encrypted.
    FullyEncrypted,
    /// The volume data is currently decrypted.
    Decrypted,
    /// An encryption or decryption conversion is in progress.
    SwitchingEncryption,
    /// A conversion operation is paused.
    SwitchPaused,
    /// An unrecognized on-disk conversion state.
    Unknown(u16),
}

impl EncryptionState {
    /// Decodes an on-disk encryption-state identifier.
    #[must_use]
    pub fn from_raw(raw: u16) -> Self {
        match raw {
            1 => Self::Decrypted,
            2 => Self::SwitchingEncryption,
            3 => Self::SwitchPaused,
            4 => Self::FullyEncrypted,
            other => Self::Unknown(other),
        }
    }
}

/// Summary of a key protector (type + GUID) without secrets.
#[derive(Debug, Clone)]
pub struct KeyProtectorInfo {
    protector_type: ProtectorType,
    guid: [u8; 16],
}

impl KeyProtectorInfo {
    /// Returns the mechanism used to protect this VMK.
    #[must_use]
    pub fn protector_type(&self) -> ProtectorType {
        self.protector_type
    }

    /// Returns the key protector's persistent identifier.
    #[must_use]
    pub fn guid(&self) -> &[u8; 16] {
        &self.guid
    }
}

/// Parsed `BitLocker` volume metadata.
///
/// Aggregates data from the volume header and the selected FVE metadata block.
/// Exposes forensic-safe information (no secrets).
#[derive(Debug)]
pub struct BitLockerMetadata {
    encryption_method: EncryptionMethod,
    encryption_state: EncryptionState,
    volume_guid: [u8; 16],
    volume_serial_number: u64,
    encrypted_volume_size: u64,
    bytes_per_sector: u16,
    total_sectors: u64,
    nb_backup_sectors: u32,
    boot_sectors_backup: u64,
    fve_version: u16,
    key_protectors: Vec<KeyProtectorInfo>,
    diagnostics: MetadataDiagnostics,
    datum_data: Vec<u8>,
}

impl BitLockerMetadata {
    /// Returns the sector encryption algorithm selected for the volume.
    #[must_use]
    pub fn encryption_method(&self) -> EncryptionMethod {
        self.encryption_method
    }

    /// Returns the volume's current encryption or conversion state.
    #[must_use]
    pub fn encryption_state(&self) -> EncryptionState {
        self.encryption_state
    }

    /// Returns the volume serial number from its FVE boot sector.
    #[must_use]
    pub fn volume_serial_number(&self) -> u64 {
        self.volume_serial_number
    }

    /// Returns summaries of the VMK protectors advertised by the volume.
    #[must_use]
    pub fn key_protectors(&self) -> &[KeyProtectorInfo] {
        &self.key_protectors
    }

    /// Returns the persistent `BitLocker` volume identifier.
    #[must_use]
    pub fn volume_guid(&self) -> &[u8; 16] {
        &self.volume_guid
    }

    /// Returns the number of volume bytes covered by encryption.
    #[must_use]
    pub fn encrypted_volume_size(&self) -> u64 {
        self.encrypted_volume_size
    }

    /// Returns the volume's logical sector size.
    #[must_use]
    pub fn bytes_per_sector(&self) -> u16 {
        self.bytes_per_sector
    }

    /// Returns the total number of logical sectors reported by the volume.
    #[must_use]
    pub fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    /// Number of sectors at the start of the volume that have been relocated
    /// to the backup area.
    #[must_use]
    pub fn nb_backup_sectors(&self) -> u32 {
        self.nb_backup_sectors
    }

    /// Byte offset on disk where the original boot sectors are backed up.
    #[must_use]
    pub fn boot_sectors_backup_offset(&self) -> u64 {
        self.boot_sectors_backup
    }

    /// Returns the FVE metadata format version.
    #[must_use]
    pub fn bitlocker_version(&self) -> u16 {
        self.fve_version
    }

    /// Returns validation and selection details for redundant metadata copies.
    #[must_use]
    pub fn metadata_diagnostics(&self) -> &MetadataDiagnostics {
        &self.diagnostics
    }

    /// Raw datum bytes for use during unlock-time parsing.
    #[must_use]
    pub fn datum_data(&self) -> &[u8] {
        &self.datum_data
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        encryption_method: EncryptionMethod,
        encrypted_volume_size: u64,
        bytes_per_sector: u16,
        total_sectors: u64,
    ) -> Self {
        Self {
            encryption_method,
            encryption_state: EncryptionState::FullyEncrypted,
            volume_guid: [0; 16],
            volume_serial_number: 0,
            encrypted_volume_size,
            bytes_per_sector,
            total_sectors,
            nb_backup_sectors: 0,
            boot_sectors_backup: 0,
            fve_version: 2,
            key_protectors: Vec::new(),
            diagnostics: MetadataDiagnostics::new_for_test(),
            datum_data: Vec::new(),
        }
    }
}

/// Builds volume metadata from a header and the selected FVE metadata block.
///
/// # Errors
///
/// Returns [`BitLockerError::UnsupportedEncryptionMethod`] when the FVE
/// dataset selects an encryption algorithm this crate cannot decrypt.
pub fn build_metadata(
    volume_header: &VolumeHeader,
    block: &FveBlock,
    diagnostics: MetadataDiagnostics,
) -> Result<BitLockerMetadata> {
    let method_raw = block.encryption_method_raw();
    let method_bytes = method_raw.to_le_bytes();
    let method_u16 = u16::from_le_bytes([method_bytes[0], method_bytes[1]]);
    let encryption_method = EncryptionMethod::from_raw(method_raw)
        .ok_or(BitLockerError::UnsupportedEncryptionMethod { method: method_u16 })?;

    // Extract key protectors from VMK datum entries
    let mut key_protectors = Vec::new();
    for datum in DatumIter::new(block.datum_data()) {
        if datum.entry_type() == ENTRY_TYPE_VMK
            && datum.value_type() == VALUE_TYPE_VMK
            && let Ok(vmk) = VmkDatum::from_bytes(datum.raw_data())
        {
            key_protectors.push(KeyProtectorInfo {
                protector_type: ProtectorType::from_raw(vmk.protection_type()),
                guid: *vmk.guid(),
            });
        }
    }

    Ok(BitLockerMetadata {
        encryption_method,
        encryption_state: EncryptionState::from_raw(block.encryption_state_raw()),
        volume_guid: *block.volume_guid(),
        volume_serial_number: volume_header.volume_serial_number(),
        encrypted_volume_size: block.encrypted_volume_size(),
        bytes_per_sector: volume_header.bytes_per_sector(),
        total_sectors: volume_header.total_sectors(),
        nb_backup_sectors: block.nb_backup_sectors(),
        boot_sectors_backup: block.boot_sectors_backup_offset(),
        fve_version: block.block_version(),
        key_protectors,
        diagnostics,
        datum_data: block.datum_data().to_vec(),
    })
}

/// Parsed `BitLocker` volume — metadata parsed, not yet unlocked.
#[derive(Debug)]
pub struct BitLockerVolume<R> {
    reader: R,
    metadata: BitLockerMetadata,
}

impl<R: Read + Seek> BitLockerVolume<R> {
    /// Parse FVE metadata from a `BitLocker` volume.
    ///
    /// Reads the volume header, validates all three FVE metadata blocks,
    /// selects the authoritative copy, and builds the metadata.
    ///
    /// # Errors
    ///
    /// Returns errors for non-`BitLocker` volumes, corrupt metadata, or
    /// unsupported encryption methods.
    pub fn open(mut reader: R) -> Result<Self> {
        // Read volume header (first 512 bytes)
        let mut header_buf = [0u8; 512];
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut header_buf)?;
        let volume_header = VolumeHeader::from_bytes(&header_buf)?;

        // Validate all three FVE blocks
        let (block, diagnostics) = validate_all_blocks(&mut reader, &volume_header)?;

        // Build metadata from selected block
        let metadata = build_metadata(&volume_header, &block, diagnostics)?;

        Ok(Self { reader, metadata })
    }

    /// Returns the validated, non-secret volume metadata.
    #[must_use]
    pub fn metadata(&self) -> &BitLockerMetadata {
        &self.metadata
    }

    /// Consume the volume, returning the inner reader and metadata.
    pub fn into_parts(self) -> (R, BitLockerMetadata) {
        (self.reader, self.metadata)
    }

    /// Reconstruct from parts (used after `unlock()` failure).
    pub fn from_parts(reader: R, metadata: BitLockerMetadata) -> Self {
        Self { reader, metadata }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_volume_header_bytes(offsets: [u64; 3]) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0] = 0xEB;
        buf[1] = 0x58;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"-FVE-FS-");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 8;
        buf[0x28..0x30].copy_from_slice(&2_097_152u64.to_le_bytes());
        buf[0xB0..0xB8].copy_from_slice(&offsets[0].to_le_bytes());
        buf[0xB8..0xC0].copy_from_slice(&offsets[1].to_le_bytes());
        buf[0xC0..0xC8].copy_from_slice(&offsets[2].to_le_bytes());
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf
    }

    fn make_fve_block_bytes(version: u32, encryption_method: u32) -> Vec<u8> {
        let metadata_size: u32 = 128;
        let total_block_size = 64
            + usize::try_from(metadata_size)
                .expect("the test metadata size fits in the host address space");
        // Buffer = block + 8-byte validations structure
        let mut buf = vec![0u8; total_block_size + 8];
        buf[0..8].copy_from_slice(b"-FVE-FS-");
        // Block header size field at offset 8 (V2: total_block_size >> 4)
        let size_field = u16::try_from(total_block_size >> 4)
            .expect("the test block's 16-byte unit count fits in u16");
        buf[0x08..0x0A].copy_from_slice(&size_field.to_le_bytes());
        buf[0x0A..0x0C].copy_from_slice(&2u16.to_le_bytes());
        buf[0x10..0x18].copy_from_slice(&1_048_576u64.to_le_bytes());
        buf[64..68].copy_from_slice(&metadata_size.to_le_bytes());
        buf[68..72].copy_from_slice(&version.to_le_bytes());
        buf[72..76].copy_from_slice(&48u32.to_le_bytes());
        buf[76..80].copy_from_slice(&metadata_size.to_le_bytes());
        buf[100..104].copy_from_slice(&encryption_method.to_le_bytes());
        // CRC over entire block, stored at total_block_size + 4
        let crc = crc32fast::hash(&buf[..total_block_size]);
        let crc_offset = total_block_size + 4;
        buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    fn make_corrupt_block() -> Vec<u8> {
        vec![0u8; 256]
    }

    fn build_volume(offsets: [u64; 3], block0: &[u8], block1: &[u8], block2: &[u8]) -> Vec<u8> {
        let max_end = offsets
            .iter()
            .enumerate()
            .map(|(i, &offset)| {
                usize::try_from(offset).expect("the test volume offset fits in usize")
                    + [block0, block1, block2][i].len()
            })
            .max()
            .unwrap_or(512);
        let total = max_end.max(512);
        let mut vol = vec![0u8; total];
        let header = make_volume_header_bytes(offsets);
        vol[..512].copy_from_slice(&header);
        for (i, &offset) in offsets.iter().enumerate() {
            let block = [block0, block1, block2][i];
            let start = usize::try_from(offset).expect("the test volume offset fits in usize");
            vol[start..start + block.len()].copy_from_slice(block);
        }
        vol
    }

    #[test]
    fn selects_valid_block_when_others_corrupt() {
        let b0 = make_corrupt_block();
        let b1 = make_fve_block_bytes(1, 0x8004);
        let b2 = make_corrupt_block();
        let offsets = [0x1000, 0x2000, 0x3000];
        let vol = build_volume(offsets, &b0, &b1, &b2);
        let vh = VolumeHeader::from_bytes(&vol[..512]).unwrap();
        let (block, diag) = validate_all_blocks(&mut Cursor::new(vol), &vh).unwrap();
        assert_eq!(diag.selected_block(), 1);
        assert_eq!(block.encryption_method_raw(), 0x8004);
        assert!(matches!(diag.block_statuses()[0], BlockStatus::Invalid(_)));
        assert!(matches!(diag.block_statuses()[1], BlockStatus::Valid));
        assert!(matches!(diag.block_statuses()[2], BlockStatus::Invalid(_)));
    }

    #[test]
    fn selects_highest_version_when_multiple_valid() {
        let b0 = make_fve_block_bytes(1, 0x8004);
        let b1 = make_fve_block_bytes(2, 0x8004);
        let b2 = make_fve_block_bytes(1, 0x8004);
        let offsets = [0x1000, 0x2000, 0x3000];
        let vol = build_volume(offsets, &b0, &b1, &b2);
        let vh = VolumeHeader::from_bytes(&vol[..512]).unwrap();
        let (_, diag) = validate_all_blocks(&mut Cursor::new(vol), &vh).unwrap();
        assert_eq!(diag.selected_block(), 1);
    }

    #[test]
    fn reports_all_corrupt_when_none_valid() {
        let b0 = make_corrupt_block();
        let b1 = make_corrupt_block();
        let b2 = make_corrupt_block();
        let offsets = [0x1000, 0x2000, 0x3000];
        let vol = build_volume(offsets, &b0, &b1, &b2);
        let vh = VolumeHeader::from_bytes(&vol[..512]).unwrap();
        let err = validate_all_blocks(&mut Cursor::new(vol), &vh).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::AllMetadataBlocksCorrupt { .. }
        ));
    }

    #[test]
    fn diagnostics_reports_disagreement() {
        let b0 = make_fve_block_bytes(1, 0x8004);
        let b1 = make_fve_block_bytes(1, 0x8005); // Different encryption method
        let b2 = make_corrupt_block();
        let offsets = [0x1000, 0x2000, 0x3000];
        let vol = build_volume(offsets, &b0, &b1, &b2);
        let vh = VolumeHeader::from_bytes(&vol[..512]).unwrap();
        let (_, diag) = validate_all_blocks(&mut Cursor::new(vol), &vh).unwrap();
        assert!(diag.has_disagreements());
    }

    #[test]
    fn diagnostics_reports_per_block_status() {
        let b0 = make_fve_block_bytes(1, 0x8004);
        let b1 = make_corrupt_block();
        let b2 = make_fve_block_bytes(1, 0x8004);
        let offsets = [0x1000, 0x2000, 0x3000];
        let vol = build_volume(offsets, &b0, &b1, &b2);
        let vh = VolumeHeader::from_bytes(&vol[..512]).unwrap();
        let (_, diag) = validate_all_blocks(&mut Cursor::new(vol), &vh).unwrap();
        assert_eq!(diag.block_statuses().len(), 3);
        assert!(matches!(diag.block_statuses()[0], BlockStatus::Valid));
        assert!(matches!(diag.block_statuses()[1], BlockStatus::Invalid(_)));
        assert!(matches!(diag.block_statuses()[2], BlockStatus::Valid));
        assert!(!diag.has_disagreements());
    }

    // --- Test helper for FVE blocks with VMK datums ---

    fn make_vmk_datum_bytes(protection_type: u16) -> Vec<u8> {
        let total_size: u16 = 36; // header(8) + guid(16) + time(8) + unk(2) + prot(2)
        let mut buf = vec![0u8; usize::from(total_size)];
        buf[0..2].copy_from_slice(&total_size.to_le_bytes());
        buf[2..4].copy_from_slice(&ENTRY_TYPE_VMK.to_le_bytes());
        buf[4..6].copy_from_slice(&VALUE_TYPE_VMK.to_le_bytes());
        buf[8..24].copy_from_slice(&[0xCC; 16]); // GUID
        buf[34..36].copy_from_slice(&protection_type.to_le_bytes());
        buf
    }

    fn make_fve_block_with_vmk(encryption_method: u32, protection_type: u16) -> Vec<u8> {
        let vmk = make_vmk_datum_bytes(protection_type);
        let metadata_size =
            48 + u32::try_from(vmk.len()).expect("the test VMK datum length fits in u32");
        // Round up to 16-byte alignment (V2 size field loses low 4 bits)
        let total_block_size = ((64
            + usize::try_from(metadata_size)
                .expect("the test metadata size fits in the host address space"))
            + 15)
            & !15;
        // Buffer = block + 8-byte validations structure
        let mut buf = vec![0u8; total_block_size + 8];
        buf[0..8].copy_from_slice(b"-FVE-FS-");
        // Block header size field at offset 8 (V2: total_block_size >> 4)
        let size_field = u16::try_from(total_block_size >> 4)
            .expect("the test block's 16-byte unit count fits in u16");
        buf[0x08..0x0A].copy_from_slice(&size_field.to_le_bytes());
        buf[0x0A..0x0C].copy_from_slice(&2u16.to_le_bytes());
        buf[0x10..0x18].copy_from_slice(&1_048_576u64.to_le_bytes());
        buf[64..68].copy_from_slice(&metadata_size.to_le_bytes());
        buf[68..72].copy_from_slice(&1u32.to_le_bytes()); // version
        buf[72..76].copy_from_slice(&48u32.to_le_bytes()); // header size
        buf[76..80].copy_from_slice(&metadata_size.to_le_bytes());
        buf[100..104].copy_from_slice(&encryption_method.to_le_bytes());
        // Place VMK datum after metadata header (offset 112 = 64+48)
        buf[112..112 + vmk.len()].copy_from_slice(&vmk);
        // CRC over entire block, stored at total_block_size + 4
        let crc = crc32fast::hash(&buf[..total_block_size]);
        let crc_offset = total_block_size + 4;
        buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    #[test]
    fn open_parses_metadata() {
        let b = make_fve_block_with_vmk(0x8004, 0x0800);
        let offsets = [0x1000, 0x2000, 0x3000];
        let vol = build_volume(offsets, &b, &b, &b);
        let bv = BitLockerVolume::open(Cursor::new(vol)).unwrap();
        let meta = bv.metadata();
        assert_eq!(meta.encryption_method(), EncryptionMethod::Aes128Xts);
        assert_eq!(meta.bytes_per_sector(), 512);
        assert_eq!(meta.total_sectors(), 2_097_152);
        assert_eq!(meta.encrypted_volume_size(), 1_048_576);
        assert_eq!(meta.bitlocker_version(), 2);
    }

    #[test]
    fn open_exposes_protectors() {
        let b = make_fve_block_with_vmk(0x8004, 0x0800);
        let offsets = [0x1000, 0x2000, 0x3000];
        let vol = build_volume(offsets, &b, &b, &b);
        let bv = BitLockerVolume::open(Cursor::new(vol)).unwrap();
        let protectors = bv.metadata().key_protectors();
        assert_eq!(protectors.len(), 1);
        assert_eq!(
            protectors[0].protector_type(),
            ProtectorType::RecoveryPassword
        );
        assert_eq!(protectors[0].guid(), &[0xCC; 16]);
    }

    #[test]
    fn open_exposes_diagnostics() {
        let b = make_fve_block_with_vmk(0x8004, 0x0800);
        let offsets = [0x1000, 0x2000, 0x3000];
        let vol = build_volume(offsets, &b, &b, &b);
        let bv = BitLockerVolume::open(Cursor::new(vol)).unwrap();
        // All three blocks are identical; max_by_key returns the last match
        assert!(bv.metadata().metadata_diagnostics().selected_block() < 3);
    }

    #[test]
    fn open_rejects_non_bitlocker() {
        let b = make_fve_block_with_vmk(0x8004, 0x0800);
        let offsets = [0x1000, 0x2000, 0x3000];
        let mut vol = build_volume(offsets, &b, &b, &b);
        vol[3..11].copy_from_slice(b"NTFS    ");
        let err = BitLockerVolume::open(Cursor::new(vol)).unwrap_err();
        assert!(matches!(err, BitLockerError::InvalidMetadata { .. }));
    }

    #[test]
    fn open_rejects_unsupported_encryption_method() {
        let b = make_fve_block_with_vmk(0x9999, 0x0800);
        let offsets = [0x1000, 0x2000, 0x3000];
        let vol = build_volume(offsets, &b, &b, &b);
        let err = BitLockerVolume::open(Cursor::new(vol)).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::UnsupportedEncryptionMethod { .. }
        ));
    }
}
