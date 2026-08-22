use std::io::{Read, Seek, SeekFrom};

use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::Decryptor;
use crate::crypto::cbc::{AesCbcDecryptor, AesCbcDiffuserDecryptor};
use crate::crypto::xts::AesXtsDecryptor;
use zerocopy::FromBytes;

use crate::keys::bek::BekFile;
use crate::keys::protector::unwrap_aes_ccm;
use crate::keys::recovery::parse_recovery_password;
use crate::keys::stretch::stretch_key;
use crate::metadata::entry::{
    DatumIter, ENTRY_TYPE_FVEK, ENTRY_TYPE_VMK, VALUE_TYPE_AES_CCM, VALUE_TYPE_VMK,
};
use crate::metadata::layout::{DatumHeaderRaw, FvekAlgoPrefix};
use crate::metadata::vmk::{AesCcmDatum, VmkDatum};
use crate::metadata::{BitLockerMetadata, BitLockerVolume, EncryptionMethod, ProtectorType};
use crate::{BitLockerError, Credential, Result, UnlockMethod};

/// Error returned when `unlock()` fails, preserving the volume for retry.
#[derive(Debug)]
pub struct UnlockError<R> {
    /// Locked volume returned intact so another credential can be attempted.
    pub volume: BitLockerVolume<R>,
    /// Error raised while validating the attempted credential.
    pub source: BitLockerError,
}

impl<R> std::fmt::Display for UnlockError<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unlock failed: {}", self.source)
    }
}

impl<R: std::fmt::Debug> std::error::Error for UnlockError<R> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Unlocked `BitLocker` volume — implements `Read + Seek` over decrypted data.
///
/// Sector-aligned decryption with a single-sector plaintext cache.
/// The buffer is zeroized on eviction and on drop.
pub struct UnlockedVolume<R> {
    pub(crate) reader: R,
    pub(crate) metadata: BitLockerMetadata,
    pub(crate) decryptor: Decryptor,
    pub(crate) sector_size: u16,
    /// Logical cursor position in decrypted view (0 = start of volume data).
    position: u64,
    /// Lazily grown multi-sector read buffer. Holds up to
    /// [`MAX_CHUNK_SECTORS`] sectors of decrypted data and retains capacity
    /// after sequential read-ahead expands it.
    buf: Zeroizing<Vec<u8>>,
    /// First logical sector number currently in `buf`, or `None` if empty.
    buf_start_sector: Option<u64>,
    /// Number of valid sectors currently in `buf` (may be < `chunk_sectors`
    /// near the end of the volume).
    buf_valid_sectors: usize,
    /// Current adaptive chunk size (number of sectors per fill).
    /// Grows on sequential access, resets on random seeks.
    chunk_sectors: usize,
}

/// Minimum sectors per fill (8 sectors × 512 = 4 KiB).
/// Small enough that random-access MFT lookups don't waste time
/// decrypting sectors that will be discarded.
const MIN_CHUNK_SECTORS: usize = 8;

/// Maximum sectors per fill (256 sectors × 512 = 128 KiB).
/// Large enough to saturate USB/SATA throughput on sequential reads.
const MAX_CHUNK_SECTORS: usize = 256;

impl<R> UnlockedVolume<R> {
    /// Returns the validated metadata associated with the unlocked view.
    #[must_use]
    pub fn metadata(&self) -> &BitLockerMetadata {
        &self.metadata
    }

    /// Returns the logical sector size used for decryption and seeking.
    #[must_use]
    pub fn sector_size(&self) -> u16 {
        self.sector_size
    }

    /// Consume the unlocked volume, returning its parts.
    pub fn into_parts(self) -> (R, BitLockerMetadata, Decryptor) {
        (self.reader, self.metadata, self.decryptor)
    }

    /// Effective volume size in bytes.
    fn volume_size(&self) -> u64 {
        let ss = u64::from(self.sector_size);
        (self.metadata.total_sectors() * ss).max(self.metadata.encrypted_volume_size())
    }
}

impl<R: Read + Seek> UnlockedVolume<R> {
    /// Fill the internal buffer starting at `start_sector`.
    ///
    /// Reads up to `self.chunk_sectors` sectors from disk in one call, then
    /// decrypts each sector in-place.  Handles boot-sector relocation and
    /// the encrypted/plaintext boundary.
    fn fill_buf(&mut self, start_sector: u64) -> std::io::Result<()> {
        let ss = u64::from(self.sector_size);
        let ss_usize = usize::from(self.sector_size);
        let volume_size = self.volume_size();
        let encrypted_size = self.metadata.encrypted_volume_size();
        let nb_backup = u64::from(self.metadata.nb_backup_sectors());
        let backup_addr = self.metadata.boot_sectors_backup_offset();

        // How many sectors can we read from start_sector?
        let remaining_sectors = (volume_size.saturating_sub(start_sector * ss)) / ss;
        let target = self.chunk_sectors;
        let count = target.min(usize::try_from(remaining_sectors).unwrap_or(usize::MAX));
        if count == 0 {
            self.buf_start_sector = None;
            self.buf_valid_sectors = 0;
            return Ok(());
        }
        let required_bytes = count.checked_mul(ss_usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decryption buffer size overflow",
            )
        })?;
        if self.buf.len() < required_bytes {
            self.buf.resize(required_bytes, 0);
        }

        // Check if any sectors in this chunk are in the backup region.
        // If so, we must read them individually (they're at a different
        // disk offset).  Otherwise we can do one big sequential read.
        let first_is_backup = start_sector < nb_backup;
        let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
        let all_contiguous = !first_is_backup || start_sector + count_u64 <= nb_backup;

        if all_contiguous {
            // Fast path: one seek + one read for the whole chunk.
            let disk_offset = if first_is_backup {
                backup_addr + start_sector * ss
            } else {
                start_sector * ss
            };
            self.reader.seek(SeekFrom::Start(disk_offset))?;
            self.reader.read_exact(&mut self.buf[..required_bytes])?;
        } else {
            // Slow path: per-sector reads (only for backup region boundary).
            for i in 0..count {
                let sector = start_sector + u64::try_from(i).unwrap_or(u64::MAX);
                let disk_offset = if sector < nb_backup {
                    backup_addr + sector * ss
                } else {
                    sector * ss
                };
                let buf_off = i * ss_usize;
                self.reader.seek(SeekFrom::Start(disk_offset))?;
                self.reader
                    .read_exact(&mut self.buf[buf_off..buf_off + ss_usize])?;
            }
        }

        // Decrypt each sector in-place.
        for i in 0..count {
            let sector = start_sector + u64::try_from(i).unwrap_or(u64::MAX);
            let buf_off = i * ss_usize;
            let data = &mut self.buf[buf_off..buf_off + ss_usize];

            // Compute the disk offset for the tweak.
            let decrypt_offset = if sector < nb_backup {
                backup_addr + sector * ss
            } else {
                sector * ss
            };

            if decrypt_offset < encrypted_size {
                let tweak_sector = decrypt_offset / ss;
                self.decryptor.decrypt_sector_in_place(tweak_sector, data);
            }
            // else: plaintext — already in the buffer, nothing to do.
        }

        self.buf_start_sector = Some(start_sector);
        self.buf_valid_sectors = count;
        Ok(())
    }

    /// Ensure the sector containing `self.position` is in the buffer.
    ///
    /// Implements adaptive read-ahead: when sequential access is detected
    /// (the requested sector is exactly at the end of the current buffer),
    /// the chunk size doubles (up to [`MAX_CHUNK_SECTORS`]).  On random
    /// seeks the chunk size resets to [`MIN_CHUNK_SECTORS`].
    fn ensure_buffered(&mut self) -> std::io::Result<()> {
        let ss = u64::from(self.sector_size);
        let sector = self.position / ss;

        if let Some(start) = self.buf_start_sector {
            let end = start + u64::try_from(self.buf_valid_sectors).unwrap_or(u64::MAX);
            if sector >= start && sector < end {
                return Ok(()); // already buffered
            }

            // Adaptive: if the next read is exactly contiguous, we're
            // in a sequential pattern → grow the chunk size.
            if sector == end {
                self.chunk_sectors = (self.chunk_sectors * 2).min(MAX_CHUNK_SECTORS);
            } else {
                // Random seek — reset to minimum.
                self.chunk_sectors = MIN_CHUNK_SECTORS;
            }
        }

        self.fill_buf(sector)
    }
}

impl<R: Read + Seek> Read for UnlockedVolume<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let volume_size = self.volume_size();
        if self.position >= volume_size {
            return Ok(0);
        }

        let ss = u64::from(self.sector_size);
        let mut filled = 0;

        while filled < buf.len() && self.position < volume_size {
            self.ensure_buffered()?;

            let start = self.buf_start_sector.unwrap_or(0);
            let buf_byte_start = start * ss;
            let valid_sectors = u64::try_from(self.buf_valid_sectors).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "decryption buffer sector count exceeds u64",
                )
            })?;
            let buf_byte_end = buf_byte_start + (valid_sectors * ss);

            // These differences are bounded by the buffer size (MAX_CHUNK_SECTORS
            // × sector_size), which fits in usize on any supported platform.
            let pos_in_buf = usize::try_from(self.position - buf_byte_start).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "decryption-buffer offset exceeds usize",
                )
            })?;
            let remaining_in_buf = usize::try_from(buf_byte_end - self.position).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "decryption-buffer length exceeds usize",
                )
            })?;
            let remaining_in_output = buf.len() - filled;
            let volume_remaining = volume_size - self.position;
            let volume_cap = usize::try_from(volume_remaining).unwrap_or(usize::MAX);

            let to_copy = remaining_in_buf.min(remaining_in_output).min(volume_cap);

            buf[filled..filled + to_copy]
                .copy_from_slice(&self.buf[pos_in_buf..pos_in_buf + to_copy]);
            filled += to_copy;
            self.position += u64::try_from(to_copy).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "read length exceeds the volume position range",
                )
            })?;
        }

        Ok(filled)
    }
}

impl<R: Read + Seek> Seek for UnlockedVolume<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let volume_size = self.volume_size();

        let new_pos: i128 = match pos {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(offset) => i128::from(volume_size) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };

        let Ok(pos) = u64::try_from(new_pos) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek to invalid position",
            ));
        };

        // Don't invalidate the buffer here — `ensure_buffered` handles
        // cache misses and uses the old buffer position to detect whether
        // the access is sequential (for adaptive chunk sizing).
        self.position = pos;
        Ok(self.position)
    }
}

impl<R: Read + Seek> BitLockerVolume<R> {
    /// Unlock the volume with the given credentials.
    ///
    /// On success, returns `UnlockedVolume` with a sector decryptor.
    /// On failure, returns the volume back via `UnlockError` for retry.
    ///
    /// # Errors
    ///
    /// Returns `UnlockError` if credential processing, key unwrapping,
    /// or FVEK extraction fails.
    #[expect(
        clippy::result_large_err,
        reason = "the error deliberately returns the intact volume so callers can retry another credential"
    )]
    pub fn unlock(
        self,
        method: &UnlockMethod,
    ) -> std::result::Result<UnlockedVolume<R>, UnlockError<R>> {
        let fvek_result = derive_fvek(self.metadata(), method);
        match fvek_result {
            Ok(fvek) => {
                let enc_method = self.metadata().encryption_method();
                match build_decryptor(enc_method, &fvek) {
                    Ok(decryptor) => {
                        let sector_size = self.metadata().bytes_per_sector();
                        let (reader, metadata) = self.into_parts();
                        Ok(UnlockedVolume {
                            reader,
                            metadata,
                            decryptor,
                            sector_size,
                            position: 0,
                            buf: Zeroizing::new(Vec::new()),
                            buf_start_sector: None,
                            buf_valid_sectors: 0,
                            chunk_sectors: MIN_CHUNK_SECTORS,
                        })
                    }
                    Err(source) => {
                        let (reader, metadata) = self.into_parts();
                        Err(UnlockError {
                            volume: BitLockerVolume::from_parts(reader, metadata),
                            source,
                        })
                    }
                }
            }
            Err(source) => {
                let (reader, metadata) = self.into_parts();
                Err(UnlockError {
                    volume: BitLockerVolume::from_parts(reader, metadata),
                    source,
                })
            }
        }
    }
}

/// Derive the FVEK from the unlock method and metadata.
fn derive_fvek(metadata: &BitLockerMetadata, method: &UnlockMethod) -> Result<Zeroizing<Vec<u8>>> {
    match method {
        UnlockMethod::Fvek(secret_bytes) => {
            Ok(Zeroizing::new(secret_bytes.expose_secret().to_vec()))
        }
        UnlockMethod::Vmk(secret_bytes) => {
            let vmk_key = secret_bytes.expose_secret();
            unwrap_fvek_with_vmk(metadata, vmk_key)
        }
        UnlockMethod::Credential(credential) => {
            let vmk = derive_vmk_from_credential(metadata, credential)?;
            unwrap_fvek_with_vmk(metadata, &vmk)
        }
    }
}

/// Derive the VMK by processing a credential against metadata.
fn derive_vmk_from_credential(
    metadata: &BitLockerMetadata,
    credential: &Credential,
) -> Result<Zeroizing<Vec<u8>>> {
    match credential {
        Credential::ClearKey => extract_clear_key_vmk(metadata),
        Credential::RecoveryPassword(secret_pw) => {
            let pw = secret_pw.expose_secret();
            recover_vmk_from_password(metadata, pw)
        }
        Credential::UserPassword(secret_pw) => {
            let pw = secret_pw.expose_secret();
            recover_vmk_from_user_password(metadata, pw)
        }
        Credential::BekFile(secret_bek) => {
            let bek_bytes = secret_bek.expose_secret();
            recover_vmk_from_bek(metadata, bek_bytes)
        }
    }
}

/// Extract VMK from a clear key protector (type 0x0000).
fn extract_clear_key_vmk(metadata: &BitLockerMetadata) -> Result<Zeroizing<Vec<u8>>> {
    let datum_data = metadata.datum_data();
    for datum in DatumIter::new(datum_data) {
        if datum.entry_type() != ENTRY_TYPE_VMK || datum.value_type() != VALUE_TYPE_VMK {
            continue;
        }
        let vmk = VmkDatum::from_bytes(datum.raw_data())?;
        if ProtectorType::from_raw(vmk.protection_type()) != ProtectorType::ClearKey {
            continue;
        }
        let Some(ext_key) = vmk.find_external_key() else {
            continue;
        };
        let Some(aes_ccm) = vmk.find_aes_ccm() else {
            continue;
        };
        // The nested data inside an external key datum contains a key datum
        // with a standard 8-byte datum header followed by the raw key bytes.
        let nested = ext_key.nested_data();
        let kek = if let Ok((inner_hdr, _)) = DatumHeaderRaw::read_from_prefix(nested) {
            let inner_size = usize::from(inner_hdr.size.get());
            let hdr_size = size_of::<DatumHeaderRaw>();
            if inner_size <= nested.len() && inner_size >= hdr_size {
                &nested[hdr_size..inner_size]
            } else {
                nested
            }
        } else {
            nested
        };
        let wrapped = build_ccm_payload(&aes_ccm);

        // Try SHA-256 hashed key first
        let hash = Sha256::digest(kek);
        let kek_sized = &hash[..kek.len().min(32)];
        if let Ok(decrypted) = unwrap_aes_ccm(kek_sized, aes_ccm.nonce(), &wrapped) {
            return strip_datum_key_header(&decrypted);
        }
        // Try raw key if hash didn't work
        if (kek.len() == 16 || kek.len() == 32)
            && let Ok(decrypted) = unwrap_aes_ccm(kek, aes_ccm.nonce(), &wrapped)
        {
            return strip_datum_key_header(&decrypted);
        }
    }
    Err(BitLockerError::AuthenticationFailed)
}

/// Recover VMK from a recovery password (protector type 0x0800).
fn recover_vmk_from_password(
    metadata: &BitLockerMetadata,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let groups = parse_recovery_password(password)?;

    let mut key_bytes = Zeroizing::new([0u8; 16]);
    for (i, &group) in groups.iter().enumerate() {
        key_bytes[i * 2..i * 2 + 2].copy_from_slice(&group.to_le_bytes());
    }

    let password_hash: [u8; 32] = Sha256::digest(*key_bytes).into();

    unwrap_vmk_with_hash(metadata, &password_hash, ProtectorType::RecoveryPassword)
}

/// Recover VMK from a user password (protector type 0x2000).
fn recover_vmk_from_user_password(
    metadata: &BitLockerMetadata,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let password_hash = crate::keys::password::hash_user_password(password);
    unwrap_vmk_with_hash(metadata, &password_hash, ProtectorType::Password)
}

/// Recover VMK from a BEK startup key file (protector type 0x0200).
fn recover_vmk_from_bek(
    metadata: &BitLockerMetadata,
    bek_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let bek = BekFile::from_bytes(bek_bytes)?;
    let key = bek.key_data();

    let datum_data = metadata.datum_data();
    for datum in DatumIter::new(datum_data) {
        if datum.entry_type() != ENTRY_TYPE_VMK || datum.value_type() != VALUE_TYPE_VMK {
            continue;
        }
        let vmk = VmkDatum::from_bytes(datum.raw_data())?;
        if ProtectorType::from_raw(vmk.protection_type()) != ProtectorType::StartupKey {
            continue;
        }

        let aes_ccm = vmk.find_aes_ccm().ok_or(BitLockerError::InvalidMetadata {
            block_index: 0,
            reason: crate::MetadataFailure::ParseFailed {
                offset: 0,
                detail: "VMK datum missing AES-CCM sub-entry for BEK",
            },
        })?;

        let wrapped = build_ccm_payload(&aes_ccm);

        // BEK key is hashed with SHA-256 to derive the KEK
        let hash = Sha256::digest(key);
        let kek = &hash[..key.len().min(32)];

        if let Ok(decrypted) = unwrap_aes_ccm(kek, aes_ccm.nonce(), &wrapped) {
            return strip_datum_key_header(&decrypted);
        }

        // Try raw key if hash didn't work
        if (key.len() == 16 || key.len() == 32)
            && let Ok(decrypted) = unwrap_aes_ccm(key, aes_ccm.nonce(), &wrapped)
        {
            return strip_datum_key_header(&decrypted);
        }
    }

    Err(BitLockerError::AuthenticationFailed)
}

/// Common flow: find VMK with matching protector type, stretch key, unwrap.
fn unwrap_vmk_with_hash(
    metadata: &BitLockerMetadata,
    password_hash: &[u8; 32],
    expected_type: ProtectorType,
) -> Result<Zeroizing<Vec<u8>>> {
    let datum_data = metadata.datum_data();
    for datum in DatumIter::new(datum_data) {
        if datum.entry_type() != ENTRY_TYPE_VMK || datum.value_type() != VALUE_TYPE_VMK {
            continue;
        }

        let vmk = VmkDatum::from_bytes(datum.raw_data())?;
        if ProtectorType::from_raw(vmk.protection_type()) != expected_type {
            continue;
        }

        let stretch = vmk
            .find_stretch_key()
            .ok_or(BitLockerError::InvalidMetadata {
                block_index: 0,
                reason: crate::MetadataFailure::ParseFailed {
                    offset: 0,
                    detail: "VMK datum missing stretch key sub-entry",
                },
            })?;

        let salt: &[u8; 16] = stretch.salt();

        // Iteration count is not stored in the stretch key datum — it is
        // implied by the algorithm (0x1000). All known BitLocker versions
        // use 0x100000 (1,048,576) iterations. Verified against dislocker
        // `stretch_user_key()` in accesses/stretch_key.c.
        let iterations = 0x10_0000u32;
        let stretched = stretch_key(password_hash, salt, iterations);

        let aes_ccm = vmk.find_aes_ccm().ok_or(BitLockerError::InvalidMetadata {
            block_index: 0,
            reason: crate::MetadataFailure::ParseFailed {
                offset: 0,
                detail: "VMK datum missing AES-CCM sub-entry",
            },
        })?;

        let wrapped = build_ccm_payload(&aes_ccm);

        let decrypted = unwrap_aes_ccm(&*stretched, aes_ccm.nonce(), &wrapped)
            .map_err(|_| BitLockerError::AuthenticationFailed)?;
        return strip_datum_key_header(&decrypted);
    }

    Err(BitLockerError::AuthenticationFailed)
}

/// Strip the `datum_key_t` header from a decrypted key blob.
///
/// AES-CCM decryption of VMK and FVEK blobs produces a `datum_key_t`
/// structure: `datum_header(8) + algo(2) + padding(2) + key_bytes`.
/// This function returns just the key bytes after the 12-byte header.
///
/// Verified against dislocker's `get_payload_safe()` which skips the
/// `datum_key_t` header (size 12) to extract the raw key material.
fn strip_datum_key_header(decrypted: &Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    const DATUM_KEY_HEADER_SIZE: usize = 12; // 8 (datum_header) + 2 (algo) + 2 (padding)
    if decrypted.len() <= DATUM_KEY_HEADER_SIZE {
        return Err(BitLockerError::InvalidCredentialFormat {
            detail: "decrypted key blob too short for datum_key_t header",
        });
    }
    Ok(Zeroizing::new(decrypted[DATUM_KEY_HEADER_SIZE..].to_vec()))
}

/// Build the CCM crate's expected `ciphertext || mac` payload from a parsed
/// [`AesCcmDatum`].
///
/// On disk the layout is `nonce(12) || mac(16) || encrypted_data`, but the
/// `ccm` crate's `decrypt` expects `ciphertext || tag`.  The nonce is passed
/// separately; this function concatenates the remaining two pieces in the
/// order the crate needs.
fn build_ccm_payload(aes_ccm: &AesCcmDatum<'_>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(aes_ccm.encrypted_data().len() + aes_ccm.mac().len());
    payload.extend_from_slice(aes_ccm.encrypted_data());
    payload.extend_from_slice(aes_ccm.mac());
    payload
}

/// Unwrap FVEK using the VMK key.
///
/// The FVEK is stored as a top-level datum with `entry_type` = 3 (FVEK) and
/// `value_type` = 5 (AES-CCM).  The datum itself is the AES-CCM encrypted
/// blob — there are no nested datums inside it.
fn unwrap_fvek_with_vmk(
    metadata: &BitLockerMetadata,
    vmk_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let datum_data = metadata.datum_data();
    for datum in DatumIter::new(datum_data) {
        if datum.entry_type() != ENTRY_TYPE_FVEK || datum.value_type() != VALUE_TYPE_AES_CCM {
            continue;
        }

        let aes_ccm = AesCcmDatum::from_header(&datum).ok_or(BitLockerError::InvalidMetadata {
            block_index: 0,
            reason: crate::MetadataFailure::ParseFailed {
                offset: 0,
                detail: "FVEK datum has AES-CCM value type but failed to parse body",
            },
        })?;

        let wrapped = build_ccm_payload(&aes_ccm);

        let kek_len = if vmk_key.len() >= 32 { 32 } else { 16 };
        let kek = &vmk_key[..kek_len.min(vmk_key.len())];

        let decrypted = unwrap_aes_ccm(kek, aes_ccm.nonce(), &wrapped)
            .map_err(|_| BitLockerError::AuthenticationFailed)?;
        return strip_datum_key_header(&decrypted);
    }

    Err(BitLockerError::InvalidMetadata {
        block_index: 0,
        reason: crate::MetadataFailure::ParseFailed {
            offset: 0,
            detail: "no FVEK datum found in metadata",
        },
    })
}

/// Build the correct sector decryptor from the encryption method and FVEK.
///
/// The FVEK bytes may include a 2-byte algorithm ID prefix.
fn build_decryptor(method: EncryptionMethod, fvek: &[u8]) -> Result<Decryptor> {
    // The decrypted FVEK may carry a 2-byte algorithm ID prefix.  Strip it
    // when the prefix is a recognised ID and the remaining bytes are still
    // long enough for the encryption method.
    let key_data = if let Ok((prefix, rest)) = FvekAlgoPrefix::read_from_prefix(fvek) {
        if prefix.is_known() && fvek.len() > required_key_size(method) {
            rest
        } else {
            fvek
        }
    } else {
        fvek
    };

    match method {
        EncryptionMethod::Aes128Cbc => {
            if key_data.len() < 16 {
                return Err(BitLockerError::SectorLayoutError {
                    detail: "AES-128-CBC FVEK too short (need 16 bytes)",
                });
            }
            Ok(Decryptor::Cbc(AesCbcDecryptor::new(
                key_data[..16].to_vec(),
            )?))
        }
        EncryptionMethod::Aes256Cbc => {
            if key_data.len() < 32 {
                return Err(BitLockerError::SectorLayoutError {
                    detail: "AES-256-CBC FVEK too short (need 32 bytes)",
                });
            }
            Ok(Decryptor::Cbc(AesCbcDecryptor::new(
                key_data[..32].to_vec(),
            )?))
        }
        EncryptionMethod::Aes128CbcDiffuser => {
            if key_data.len() < 64 {
                return Err(BitLockerError::SectorLayoutError {
                    detail: "AES-128-CBC+Elephant FVEK too short (need 64 bytes)",
                });
            }
            // AES-128-CBC+Elephant: 16B CBC key, 16B unused, 32B tweak key.
            // Verified against dislocker decrypt_cbc_with_diffuser().
            let cbc_key = key_data[..16].to_vec();
            let tweak_key = key_data[32..64].to_vec();
            Ok(Decryptor::CbcDiffuser(AesCbcDiffuserDecryptor::new(
                cbc_key, tweak_key,
            )?))
        }
        EncryptionMethod::Aes256CbcDiffuser => {
            if key_data.len() < 64 {
                return Err(BitLockerError::SectorLayoutError {
                    detail: "AES-256-CBC+Elephant FVEK too short (need 64 bytes)",
                });
            }
            let cbc_key = key_data[..32].to_vec();
            let tweak_key = key_data[32..64].to_vec();
            Ok(Decryptor::CbcDiffuser(AesCbcDiffuserDecryptor::new(
                cbc_key, tweak_key,
            )?))
        }
        EncryptionMethod::Aes128Xts => {
            if key_data.len() < 32 {
                return Err(BitLockerError::SectorLayoutError {
                    detail: "AES-128-XTS FVEK too short (need 32 bytes)",
                });
            }
            Ok(Decryptor::Xts(AesXtsDecryptor::new(
                key_data[..32].to_vec(),
            )?))
        }
        EncryptionMethod::Aes256Xts => {
            if key_data.len() < 64 {
                return Err(BitLockerError::SectorLayoutError {
                    detail: "AES-256-XTS FVEK too short (need 64 bytes)",
                });
            }
            Ok(Decryptor::Xts(AesXtsDecryptor::new(
                key_data[..64].to_vec(),
            )?))
        }
    }
}

/// Required key size for a given encryption method.
fn required_key_size(method: EncryptionMethod) -> usize {
    match method {
        EncryptionMethod::Aes128Cbc => 16,
        EncryptionMethod::Aes256Cbc | EncryptionMethod::Aes128Xts => 32,
        EncryptionMethod::Aes128CbcDiffuser
        | EncryptionMethod::Aes256CbcDiffuser
        | EncryptionMethod::Aes256Xts => 64,
    }
}

#[cfg(test)]
#[path = "unlock_tests/mod.rs"]
mod tests;
