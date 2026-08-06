//! EFSRPC Metadata Version 1 (EFS versions 1-3).
//!
//! A flat layout: an 84-byte header followed by a DDF key list and an
//! optional DRF key list. Each key list entry pairs an opaque encrypted
//! FEK blob with the X.509 certificate that wraps it.
//!
//! Reference: MS-EFSR §2.2.2.1 (`docs/ms-efsr/01-metadata-v1.md`).

use alloc::string::String;
use alloc::vec::Vec;

use super::{decode_utf16le, read_guid, read_slice, read_u32};
use crate::error::{NtfsError, Result};
use crate::guid::NtfsGuid;
use crate::structured_values::NtfsSid;
use crate::types::NtfsPosition;

/// Size of the V1 metadata header; the key lists begin at or after this.
const V1_HEADER_LEN: usize = 0x54;
/// Offset of the `EFS_ID` GUID in the V1 header (§2.2.2.1).
const EFS_ID_OFFSET: usize = 0x10;
/// Offset of the `DDF_Offset` field in the V1 header.
const DDF_OFFSET_FIELD: usize = 0x40;
/// Offset of the `DRF_Offset` field in the V1 header.
const DRF_OFFSET_FIELD: usize = 0x44;

/// Minimum size of a key list entry header (§2.2.2.1.2): five `u32` fields.
const ENTRY_HEADER_LEN: usize = 0x14;
/// Minimum size of a Public Key Information header (§2.2.2.1.3).
const PKI_HEADER_LEN: usize = 0x1C;
/// Minimum size of a Certificate Data header (§2.2.2.1.4): five `u32` fields.
const CERT_HEADER_LEN: usize = 0x14;

fn read_usize(data: &[u8], offset: usize, position: NtfsPosition) -> Result<usize> {
    let value = read_u32(data, offset, position)?;
    usize::try_from(value).map_err(|_| NtfsError::InvalidEfsMetadata {
        position,
        reason: "32-bit EFS offset or length does not fit the target address space",
    })
}

/// How the FEK in a key list entry is wrapped (§2.2.2.1.2, `Flags`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FekEncryptionMethod {
    /// `Flags` 0x00000000 — the FEK is RSA-encrypted with a user/DRA key.
    Rsa,
    /// `Flags` 0x00000001 — the FEK is AES-256-encrypted (smart-card path).
    Aes256,
    /// An unrecognized `Flags` value.
    Unknown(u32),
}

impl FekEncryptionMethod {
    fn from_flags(flags: u32) -> Self {
        match flags {
            0 => Self::Rsa,
            1 => Self::Aes256,
            other => Self::Unknown(other),
        }
    }
}

/// X.509 certificate hints for a key list entry (§2.2.2.1.4).
#[derive(Clone, Debug)]
pub struct EfsCertificateData {
    thumbprint: Vec<u8>,
    container_name: Option<String>,
    provider_name: Option<String>,
    display_name: Option<String>,
}

impl EfsCertificateData {
    /// Parses Certificate Data; offsets are relative to `cert`'s start.
    fn parse(cert: &[u8], position: NtfsPosition) -> Result<Self> {
        if cert.len() < CERT_HEADER_LEN {
            return Err(NtfsError::InvalidEfsMetadata {
                position,
                reason: "certificate data smaller than its header",
            });
        }
        let thumb_off = read_usize(cert, 0x00, position)?;
        let thumb_len = read_usize(cert, 0x04, position)?;
        let container_off = read_usize(cert, 0x08, position)?;
        let provider_off = read_usize(cert, 0x0C, position)?;
        let display_off = read_usize(cert, 0x10, position)?;

        let thumbprint = read_slice(cert, thumb_off, thumb_len, position)?.to_vec();

        Ok(Self {
            thumbprint,
            container_name: read_optional_name(cert, container_off, position)?,
            provider_name: read_optional_name(cert, provider_off, position)?,
            display_name: read_optional_name(cert, display_off, position)?,
        })
    }

    /// The SHA-1 hash of the DER-encoded certificate (`Certificate Thumbprint`).
    #[must_use]
    pub fn thumbprint(&self) -> &[u8] {
        &self.thumbprint
    }

    /// Hint for the key container holding the private key, if recorded.
    #[must_use]
    pub fn container_name(&self) -> Option<&str> {
        self.container_name.as_deref()
    }

    /// Hint for the CSP/KSP provider name, if recorded.
    #[must_use]
    pub fn provider_name(&self) -> Option<&str> {
        self.provider_name.as_deref()
    }

    /// Friendly display name for the certificate, if recorded.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
}

/// Reads a NUL-terminated UTF-16LE name at `offset`, or `None` if absent.
fn read_optional_name(
    data: &[u8],
    offset: usize,
    position: NtfsPosition,
) -> Result<Option<String>> {
    if offset == 0 {
        return Ok(None);
    }
    let tail = data.get(offset..).ok_or(NtfsError::InvalidEfsMetadata {
        position,
        reason: "name offset outside the certificate data",
    })?;
    Ok(Some(decode_utf16le(tail)))
}

/// Public Key Information for a key list entry (§2.2.2.1.3).
#[derive(Clone, Debug)]
pub struct EfsPublicKeyInfo {
    owner_sid: Option<NtfsSid>,
    certificate: EfsCertificateData,
}

impl EfsPublicKeyInfo {
    /// Parses Public Key Information; `pki_offset` is relative to `entry`.
    fn parse(entry: &[u8], pki_offset: usize, position: NtfsPosition) -> Result<Self> {
        let pki_len = read_usize(entry, pki_offset, position)?;
        let pki = read_slice(entry, pki_offset, pki_len, position)?;
        if pki.len() < PKI_HEADER_LEN {
            return Err(NtfsError::InvalidEfsMetadata {
                position,
                reason: "public key information smaller than its header",
            });
        }

        let owner_hint_off = read_usize(pki, 0x04, position)?;
        let cert_data_len = read_usize(pki, 0x0C, position)?;
        let cert_data_off = read_usize(pki, 0x10, position)?;

        let owner_sid = if owner_hint_off == 0 {
            None
        } else {
            let sid_bytes = pki
                .get(owner_hint_off..)
                .ok_or(NtfsError::InvalidEfsMetadata {
                    position,
                    reason: "owner hint offset outside the public key info",
                })?;
            Some(NtfsSid::from_bytes(sid_bytes, position)?)
        };

        let cert = read_slice(pki, cert_data_off, cert_data_len, position)?;
        Ok(Self {
            owner_sid,
            certificate: EfsCertificateData::parse(cert, position)?,
        })
    }

    /// SID hinting at the identity of the key owner, if present.
    #[must_use]
    pub fn owner_sid(&self) -> Option<&NtfsSid> {
        self.owner_sid.as_ref()
    }

    /// Certificate hints (thumbprint, container/provider/display names).
    #[must_use]
    pub fn certificate(&self) -> &EfsCertificateData {
        &self.certificate
    }
}

/// A single DDF or DRF key list entry (§2.2.2.1.2).
#[derive(Clone, Debug)]
pub struct EfsKeyListEntry {
    fek_encryption: FekEncryptionMethod,
    encrypted_fek: Vec<u8>,
    public_key_info: EfsPublicKeyInfo,
}

impl EfsKeyListEntry {
    /// Parses a key list entry; `entry_offset` is relative to the metadata.
    fn parse(data: &[u8], entry_offset: usize, position: NtfsPosition) -> Result<(Self, usize)> {
        let entry_len = read_usize(data, entry_offset, position)?;
        if entry_len < ENTRY_HEADER_LEN {
            return Err(NtfsError::InvalidEfsMetadata {
                position,
                reason: "key list entry smaller than its header",
            });
        }
        let entry = read_slice(data, entry_offset, entry_len, position)?;

        let pki_offset = read_usize(entry, 0x04, position)?;
        let fek_len = read_usize(entry, 0x08, position)?;
        let fek_offset = read_usize(entry, 0x0C, position)?;
        let flags = read_u32(entry, 0x10, position)?;

        let encrypted_fek = read_slice(entry, fek_offset, fek_len, position)?.to_vec();
        let public_key_info = EfsPublicKeyInfo::parse(entry, pki_offset, position)?;

        Ok((
            Self {
                fek_encryption: FekEncryptionMethod::from_flags(flags),
                encrypted_fek,
                public_key_info,
            },
            entry_len,
        ))
    }

    /// How the FEK blob in this entry is wrapped.
    #[must_use]
    pub fn fek_encryption(&self) -> FekEncryptionMethod {
        self.fek_encryption
    }

    /// The opaque wrapped FEK ciphertext for offline key recovery.
    ///
    /// Decrypting it yields the §2.2.2.1.5 `Encrypted FEK` plaintext
    /// structure; that requires the private key and is out of scope here.
    #[must_use]
    pub fn encrypted_fek(&self) -> &[u8] {
        &self.encrypted_fek
    }

    /// Certificate and owner information for the wrapping key.
    #[must_use]
    pub fn public_key_info(&self) -> &EfsPublicKeyInfo {
        &self.public_key_info
    }
}

/// A DDF or DRF key list (§2.2.2.1.1).
#[derive(Clone, Debug)]
pub struct EfsKeyList {
    entries: Vec<EfsKeyListEntry>,
}

impl EfsKeyList {
    /// Parses a key list starting at `list_offset` within the metadata.
    fn parse(data: &[u8], list_offset: usize, position: NtfsPosition) -> Result<Self> {
        let count = read_usize(data, list_offset, position)?;
        // Each entry is at least ENTRY_HEADER_LEN bytes, so a count larger
        // than the buffer itself is corrupt — reject before iterating.
        if count > data.len() {
            return Err(NtfsError::InvalidEfsMetadata {
                position,
                reason: "key list entry count exceeds the metadata size",
            });
        }

        let mut entries = Vec::new();
        let mut cursor = list_offset + 4;
        for _ in 0..count {
            let (entry, entry_len) = EfsKeyListEntry::parse(data, cursor, position)?;
            cursor = cursor
                .checked_add(entry_len)
                .ok_or(NtfsError::InvalidEfsMetadata {
                    position,
                    reason: "key list entry offset arithmetic overflowed",
                })?;
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    /// The key list entries, one per authorized user (DDF) or DRA (DRF).
    #[must_use]
    pub fn entries(&self) -> &[EfsKeyListEntry] {
        &self.entries
    }
}

/// Parsed EFSRPC Metadata Version 1 (§2.2.2.1).
#[derive(Clone, Debug)]
pub struct EfsMetadataV1 {
    efs_version: u32,
    efs_id: NtfsGuid,
    ddf: EfsKeyList,
    drf: Option<EfsKeyList>,
    position: NtfsPosition,
}

impl EfsMetadataV1 {
    /// Parses Version 1 metadata. `efs_version` is the already-read header
    /// field (1-3); the caller in [`super::NtfsEfsMetadata::parse`] dispatches on it.
    pub(super) fn parse(data: &[u8], position: NtfsPosition, efs_version: u32) -> Result<Self> {
        if data.len() < V1_HEADER_LEN {
            return Err(NtfsError::InvalidEfsMetadata {
                position,
                reason: "buffer smaller than the 84-byte V1 header",
            });
        }

        let efs_id = read_guid(data, EFS_ID_OFFSET, position)?;
        let ddf_offset = read_usize(data, DDF_OFFSET_FIELD, position)?;
        let drf_offset = read_usize(data, DRF_OFFSET_FIELD, position)?;

        let ddf_offset = validate_list_offset(ddf_offset, data, position)?;
        let ddf = EfsKeyList::parse(data, ddf_offset, position)?;
        let drf = if drf_offset == 0 {
            None
        } else {
            let drf_offset = validate_list_offset(drf_offset, data, position)?;
            Some(EfsKeyList::parse(data, drf_offset, position)?)
        };

        Ok(Self {
            efs_version,
            efs_id,
            ddf,
            drf,
            position,
        })
    }

    /// The `EFS_Version` header field (1-3 for Version 1 metadata).
    #[must_use]
    pub fn efs_version(&self) -> u32 {
        self.efs_version
    }

    /// The `EFS_ID` GUID of the machine that created the metadata.
    #[must_use]
    pub fn efs_id(&self) -> &NtfsGuid {
        &self.efs_id
    }

    /// The Data Decryption Field — FEKs wrapped for authorized users.
    #[must_use]
    pub fn ddf(&self) -> &EfsKeyList {
        &self.ddf
    }

    /// The Data Recovery Field — FEKs wrapped for Data Recovery Agents,
    /// or `None` when no DRA has been applied to the file.
    #[must_use]
    pub fn drf(&self) -> Option<&EfsKeyList> {
        self.drf.as_ref()
    }

    /// The absolute byte position of the `$EFS` attribute, if known.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position
    }
}

/// Bounds-checks a key list offset taken from the V1 header.
fn validate_list_offset(offset: usize, data: &[u8], position: NtfsPosition) -> Result<usize> {
    if offset < V1_HEADER_LEN || offset >= data.len() {
        return Err(NtfsError::InvalidEfsMetadata {
            position,
            reason: "key list offset outside the metadata buffer",
        });
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured_values::NtfsEfsMetadata;

    /// Little-endian `u32` bytes.
    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    /// Builds Certificate Data: header + thumbprint + optional display name.
    fn build_cert(thumbprint: &[u8], display: Option<&str>) -> Vec<u8> {
        let mut buf = Vec::new();
        let thumb_off = u32::try_from(CERT_HEADER_LEN).expect("test value fits u32");
        let display_off = match display {
            Some(_) => thumb_off + u32::try_from(thumbprint.len()).expect("test value fits u32"),
            None => 0,
        };
        buf.extend_from_slice(&le32(thumb_off));
        buf.extend_from_slice(&le32(
            u32::try_from(thumbprint.len()).expect("test value fits u32"),
        ));
        buf.extend_from_slice(&le32(0)); // container
        buf.extend_from_slice(&le32(0)); // provider
        buf.extend_from_slice(&le32(display_off));
        buf.extend_from_slice(thumbprint);
        if let Some(name) = display {
            for unit in name.encode_utf16() {
                buf.extend_from_slice(&unit.to_le_bytes());
            }
            buf.extend_from_slice(&[0, 0]);
        }
        buf
    }

    /// Builds Public Key Information wrapping `cert`, with no owner hint.
    fn build_pki(cert: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let cert_off = u32::try_from(PKI_HEADER_LEN).expect("test value fits u32");
        let total = PKI_HEADER_LEN + cert.len();
        buf.extend_from_slice(&le32(u32::try_from(total).expect("test value fits u32")));
        buf.extend_from_slice(&le32(0)); // owner hint offset
        buf.extend_from_slice(&le32(3)); // credential type
        buf.extend_from_slice(&le32(
            u32::try_from(cert.len()).expect("test value fits u32"),
        ));
        buf.extend_from_slice(&le32(cert_off));
        buf.extend_from_slice(&[0u8; 8]); // reserved
        buf.extend_from_slice(cert);
        buf
    }

    /// Builds a key list entry wrapping `pki` with FEK blob `fek`.
    fn build_entry(pki: &[u8], fek: &[u8], flags: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        let pki_off = u32::try_from(ENTRY_HEADER_LEN).expect("test value fits u32");
        let fek_off = ENTRY_HEADER_LEN + pki.len();
        let total = fek_off + fek.len();
        buf.extend_from_slice(&le32(u32::try_from(total).expect("test value fits u32")));
        buf.extend_from_slice(&le32(pki_off));
        buf.extend_from_slice(&le32(
            u32::try_from(fek.len()).expect("test value fits u32"),
        ));
        buf.extend_from_slice(&le32(u32::try_from(fek_off).expect("test value fits u32")));
        buf.extend_from_slice(&le32(flags));
        buf.extend_from_slice(pki);
        buf.extend_from_slice(fek);
        buf
    }

    /// Builds full V1 metadata with a single DDF entry and no DRF.
    fn build_v1(fek: &[u8], thumbprint: &[u8], display: Option<&str>, flags: u32) -> Vec<u8> {
        let cert = build_cert(thumbprint, display);
        let pki = build_pki(&cert);
        let entry = build_entry(&pki, fek, flags);

        let mut buf = alloc::vec![0u8; V1_HEADER_LEN];
        buf[0x08..0x0C].copy_from_slice(&le32(2)); // EFS_Version 2
        buf[0x40..0x44].copy_from_slice(&le32(
            u32::try_from(V1_HEADER_LEN).expect("test value fits u32"),
        )); // DDF offset
        // DRF offset stays 0 (absent).
        buf.extend_from_slice(&le32(1)); // DDF key list: one entry
        buf.extend_from_slice(&entry);
        buf
    }

    #[test]
    fn parses_single_ddf_entry() {
        let fek = [0xAAu8; 256];
        let thumb = [0x11u8; 20];
        let buf = build_v1(&fek, &thumb, Some("Alice"), 0);

        let meta = match NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).unwrap() {
            NtfsEfsMetadata::V1(m) => m,
            NtfsEfsMetadata::V2(_) => panic!("expected V1 metadata"),
        };
        assert_eq!(meta.efs_version(), 2);
        assert!(meta.drf().is_none());

        let entries = meta.ddf().entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.fek_encryption(), FekEncryptionMethod::Rsa);
        assert_eq!(entry.encrypted_fek(), &fek);

        let cert = entry.public_key_info().certificate();
        assert_eq!(cert.thumbprint(), &thumb);
        assert_eq!(cert.display_name(), Some("Alice"));
        assert_eq!(cert.container_name(), None);
        assert!(entry.public_key_info().owner_sid().is_none());
    }

    #[test]
    fn aes256_flag_maps_to_aes256() {
        let buf = build_v1(&[0xBB; 32], &[0x22; 20], None, 1);
        let meta = match NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).unwrap() {
            NtfsEfsMetadata::V1(m) => m,
            NtfsEfsMetadata::V2(_) => panic!("expected V1 metadata"),
        };
        assert_eq!(
            meta.ddf().entries()[0].fek_encryption(),
            FekEncryptionMethod::Aes256,
        );
    }

    #[test]
    fn unknown_flag_preserved() {
        assert_eq!(
            FekEncryptionMethod::from_flags(0x99),
            FekEncryptionMethod::Unknown(0x99),
        );
    }

    #[test]
    fn rejects_ddf_offset_inside_header() {
        let mut buf = build_v1(&[0; 16], &[0; 20], None, 0);
        buf[0x40..0x44].copy_from_slice(&le32(0x10)); // points into the header
        assert!(NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).is_err());
    }

    #[test]
    fn rejects_truncated_entry() {
        let mut buf = build_v1(&[0xCC; 16], &[0x33; 20], None, 0);
        buf.truncate(buf.len() - 8); // chop the tail of the FEK blob
        assert!(NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).is_err());
    }

    #[test]
    fn rejects_buffer_shorter_than_header() {
        let buf = alloc::vec![0u8; 0x20];
        assert!(EfsMetadataV1::parse(&buf, NtfsPosition::none(), 1).is_err());
    }

    #[test]
    fn rejects_absurd_entry_count() {
        let mut buf = build_v1(&[0; 16], &[0; 20], None, 0);
        // Overwrite the DDF key list entry count with a huge value.
        buf[V1_HEADER_LEN..V1_HEADER_LEN + 4].copy_from_slice(&le32(u32::MAX));
        assert!(NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).is_err());
    }

    /// Builds Certificate Data with thumbprint, container, provider, and
    /// display names all present (each NUL-terminated UTF-16LE).
    fn build_cert_full(
        thumbprint: &[u8],
        container: &str,
        provider: &str,
        display: &str,
    ) -> Vec<u8> {
        fn utf16(s: &str) -> Vec<u8> {
            let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            v.extend_from_slice(&[0, 0]);
            v
        }
        let thumb_off = u32::try_from(CERT_HEADER_LEN).expect("test value fits u32");
        let container_bytes = utf16(container);
        let provider_bytes = utf16(provider);
        let display_bytes = utf16(display);

        let container_off =
            thumb_off + u32::try_from(thumbprint.len()).expect("test value fits u32");
        let provider_off =
            container_off + u32::try_from(container_bytes.len()).expect("test value fits u32");
        let display_off =
            provider_off + u32::try_from(provider_bytes.len()).expect("test value fits u32");

        let mut buf = Vec::new();
        buf.extend_from_slice(&le32(thumb_off));
        buf.extend_from_slice(&le32(
            u32::try_from(thumbprint.len()).expect("test value fits u32"),
        ));
        buf.extend_from_slice(&le32(container_off));
        buf.extend_from_slice(&le32(provider_off));
        buf.extend_from_slice(&le32(display_off));
        buf.extend_from_slice(thumbprint);
        buf.extend_from_slice(&container_bytes);
        buf.extend_from_slice(&provider_bytes);
        buf.extend_from_slice(&display_bytes);
        buf
    }

    /// Builds Public Key Information wrapping `cert` with an owner SID hint.
    fn build_pki_with_sid(cert: &[u8], sid: &[u8]) -> Vec<u8> {
        let owner_off = u32::try_from(PKI_HEADER_LEN).expect("test value fits u32");
        let cert_off = owner_off + u32::try_from(sid.len()).expect("test value fits u32");
        let total = PKI_HEADER_LEN + sid.len() + cert.len();

        let mut buf = Vec::new();
        buf.extend_from_slice(&le32(u32::try_from(total).expect("test value fits u32")));
        buf.extend_from_slice(&le32(owner_off)); // owner hint offset (non-zero)
        buf.extend_from_slice(&le32(3)); // credential type
        buf.extend_from_slice(&le32(
            u32::try_from(cert.len()).expect("test value fits u32"),
        ));
        buf.extend_from_slice(&le32(cert_off));
        buf.extend_from_slice(&[0u8; 8]); // reserved
        buf.extend_from_slice(sid);
        buf.extend_from_slice(cert);
        buf
    }

    /// A minimal valid SID: revision 1, 1 sub-authority, NT authority.
    fn minimal_sid() -> Vec<u8> {
        let mut sid = Vec::new();
        sid.push(1); // revision
        sid.push(1); // sub-authority count
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // NT authority (S-1-5-...)
        sid.extend_from_slice(&18u32.to_le_bytes()); // sub-authority = 18 (LocalSystem)
        sid
    }

    #[test]
    fn parses_container_and_provider_names() {
        // A cert carrying container/provider/display names; the accessors must
        // return the genuine strings (not None, not "" / "xyzzy").
        let cert = build_cert_full(&[0x55; 20], "MyContainer", "MyProvider", "MyDisplay");
        let pki = build_pki(&cert);
        let entry = build_entry(&pki, &[0xCC; 32], 0);

        let mut buf = alloc::vec![0u8; V1_HEADER_LEN];
        buf[0x08..0x0C].copy_from_slice(&le32(2));
        buf[0x40..0x44].copy_from_slice(&le32(
            u32::try_from(V1_HEADER_LEN).expect("test value fits u32"),
        ));
        buf.extend_from_slice(&le32(1)); // one DDF entry
        buf.extend_from_slice(&entry);

        let meta = match NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).unwrap() {
            NtfsEfsMetadata::V1(m) => m,
            NtfsEfsMetadata::V2(_) => panic!("expected V1 metadata"),
        };
        let cert = meta.ddf().entries()[0].public_key_info().certificate();
        assert_eq!(cert.container_name(), Some("MyContainer"));
        assert_eq!(cert.provider_name(), Some("MyProvider"));
        assert_eq!(cert.display_name(), Some("MyDisplay"));
    }

    #[test]
    fn parses_owner_sid() {
        // A PKI carrying an owner SID hint: owner_sid() must be Some, not None.
        let cert = build_cert(&[0x11; 20], None);
        let sid = minimal_sid();
        let pki = build_pki_with_sid(&cert, &sid);
        let entry = build_entry(&pki, &[0xAA; 32], 0);

        let mut buf = alloc::vec![0u8; V1_HEADER_LEN];
        buf[0x08..0x0C].copy_from_slice(&le32(2));
        buf[0x40..0x44].copy_from_slice(&le32(
            u32::try_from(V1_HEADER_LEN).expect("test value fits u32"),
        ));
        buf.extend_from_slice(&le32(1));
        buf.extend_from_slice(&entry);

        let meta = match NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).unwrap() {
            NtfsEfsMetadata::V1(m) => m,
            NtfsEfsMetadata::V2(_) => panic!("expected V1 metadata"),
        };
        let pki = meta.ddf().entries()[0].public_key_info();
        let owner = pki.owner_sid().expect("owner SID present");
        assert_eq!(owner.to_sid_string(), "S-1-5-18");
    }

    #[test]
    fn parses_drf_key_list() {
        // V1 metadata with both a DDF and a DRF key list: drf() must be Some
        // with one entry, not None. Pins `drf_offset == 0` branch and the
        // EfsMetadataV1::drf accessor.
        let cert = build_cert(&[0x33; 20], None);
        let pki = build_pki(&cert);
        let decryptor_entry = build_entry(&pki, &[0x44; 32], 0);
        let recovery_entry = build_entry(&pki, &[0x66; 16], 1);

        let mut buf = alloc::vec![0u8; V1_HEADER_LEN];
        buf[0x08..0x0C].copy_from_slice(&le32(2));
        let decryptors_offset = u32::try_from(V1_HEADER_LEN).expect("test value fits u32");
        buf[0x40..0x44].copy_from_slice(&le32(decryptors_offset));

        // Append DDF key list: count + entry.
        buf.extend_from_slice(&le32(1));
        buf.extend_from_slice(&decryptor_entry);

        // DRF key list starts here.
        let recovery_offset = u32::try_from(buf.len()).expect("test value fits u32");
        buf[0x44..0x48].copy_from_slice(&le32(recovery_offset));
        buf.extend_from_slice(&le32(1));
        buf.extend_from_slice(&recovery_entry);

        let meta = match NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).unwrap() {
            NtfsEfsMetadata::V1(m) => m,
            NtfsEfsMetadata::V2(_) => panic!("expected V1 metadata"),
        };
        let drf = meta.drf().expect("DRF key list present");
        assert_eq!(drf.entries().len(), 1);
        assert_eq!(
            drf.entries()[0].fek_encryption(),
            FekEncryptionMethod::Aes256
        );
        // DDF still parses to one entry.
        assert_eq!(meta.ddf().entries().len(), 1);
    }

    #[test]
    fn cert_exactly_header_size_has_empty_thumbprint() {
        // A cert of exactly CERT_HEADER_LEN bytes (all offsets 0) is accepted
        // (boundary for `cert.len() < CERT_HEADER_LEN`) and yields an empty
        // thumbprint with no names.
        let cert = alloc::vec![0u8; CERT_HEADER_LEN];
        let parsed = EfsCertificateData::parse(&cert, NtfsPosition::none()).unwrap();
        assert!(parsed.thumbprint().is_empty());
        assert_eq!(parsed.container_name(), None);
        assert_eq!(parsed.provider_name(), None);
        assert_eq!(parsed.display_name(), None);
    }

    #[test]
    fn cert_one_byte_short_is_rejected() {
        // CERT_HEADER_LEN - 1 bytes must be rejected (other side of the
        // `cert.len() < CERT_HEADER_LEN` boundary).
        let cert = alloc::vec![0u8; CERT_HEADER_LEN - 1];
        assert!(EfsCertificateData::parse(&cert, NtfsPosition::none()).is_err());
    }

    /// Builds a PKI of exactly `pki_len` bytes whose cert sub-slice occupies
    /// the tail. The cert must be at least `CERT_HEADER_LEN` bytes, so place it
    /// so that `cert_off + CERT_HEADER_LEN == pki_len`.
    fn build_pki_exact(pki_len: usize) -> Vec<u8> {
        assert!(pki_len >= PKI_HEADER_LEN + CERT_HEADER_LEN || pki_len >= CERT_HEADER_LEN + 8);
        let cert_len = CERT_HEADER_LEN;
        let cert_off = pki_len - cert_len;
        let mut buf = alloc::vec![0u8; pki_len];
        buf[0x00..0x04]
            .copy_from_slice(&le32(u32::try_from(pki_len).expect("test value fits u32"))); // StructureSize
        buf[0x04..0x08].copy_from_slice(&le32(0)); // owner hint offset = 0
        buf[0x0C..0x10]
            .copy_from_slice(&le32(u32::try_from(cert_len).expect("test value fits u32"))); // cert_data_len
        buf[0x10..0x14]
            .copy_from_slice(&le32(u32::try_from(cert_off).expect("test value fits u32"))); // cert_data_off
        buf
    }

    #[test]
    fn pki_exactly_header_len_is_accepted() {
        // pki.len() == PKI_HEADER_LEN (28): the `<` check is false, so the PKI
        // is accepted and parses to a valid (empty-cert) PKI. A `< -> <=`
        // mutant would reject len == PKI_HEADER_LEN. The cert sub-slice
        // ([8..28]) overlaps the header bytes but is a valid all-zero cert.
        let pki = build_pki_exact(PKI_HEADER_LEN);
        assert_eq!(pki.len(), PKI_HEADER_LEN);
        let result = EfsPublicKeyInfo::parse(&pki, 0, NtfsPosition::none());
        assert!(
            result.is_ok(),
            "len == PKI_HEADER_LEN must parse: {result:?}"
        );
        assert!(result.unwrap().owner_sid().is_none());
    }

    #[test]
    fn pki_shorter_than_header_is_rejected() {
        // pki_len = PKI_HEADER_LEN - 1 -> `<` true, rejected with the
        // header-size reason. A `< -> ==` mutant (27 == 28 is false) would not
        // reject here; it would proceed and fail later with a DIFFERENT reason.
        // Asserting the header-size reason kills `< -> ==`.
        let short_len = PKI_HEADER_LEN - 1;
        let mut pki = alloc::vec![0u8; short_len];
        pki[0x00..0x04].copy_from_slice(&le32(
            u32::try_from(short_len).expect("test value fits u32"),
        ));
        let err = EfsPublicKeyInfo::parse(&pki, 0, NtfsPosition::none());
        assert!(matches!(
            err,
            Err(NtfsError::InvalidEfsMetadata { reason, .. })
                if reason.contains("public key information smaller than its header")
        ));
    }

    #[test]
    fn entry_exactly_header_size_passes_guard() {
        // entry_len == ENTRY_HEADER_LEN is the `>=` side of
        // `entry_len < ENTRY_HEADER_LEN`. At exactly the header size the entry
        // slice holds only the header, so the original passes the size guard
        // and then fails reading the (absent) PKI/FEK with "field extends past
        // the metadata buffer". A `< -> <=` mutant would instead reject at the
        // guard with "smaller than its header". Asserting the later reason
        // kills `< -> <=`.
        let mut data = alloc::vec![0u8; ENTRY_HEADER_LEN];
        data[0x00..0x04].copy_from_slice(&le32(
            u32::try_from(ENTRY_HEADER_LEN).expect("test value fits u32"),
        )); // entry_len == header
        // pki/fek offsets point past the 20-byte entry slice -> read fails.
        data[0x04..0x08].copy_from_slice(&le32(
            u32::try_from(ENTRY_HEADER_LEN).expect("test value fits u32"),
        )); // pki_offset
        data[0x0C..0x10].copy_from_slice(&le32(
            u32::try_from(ENTRY_HEADER_LEN).expect("test value fits u32"),
        )); // fek_offset
        let err = EfsKeyListEntry::parse(&data, 0, NtfsPosition::none());
        assert!(
            matches!(
                &err,
                Err(NtfsError::InvalidEfsMetadata { reason, .. })
                    if reason.contains("extends past the metadata buffer")
            ),
            "entry_len == header must pass the guard, got: {err:?}"
        );
    }

    #[test]
    fn entry_shorter_than_header_is_rejected() {
        // entry_len = ENTRY_HEADER_LEN - 1 -> `<` true (reject). Kills `< -> ==`.
        let short_len = ENTRY_HEADER_LEN - 1;
        let mut data = alloc::vec![0u8; short_len];
        data[0x00..0x04].copy_from_slice(&le32(
            u32::try_from(short_len).expect("test value fits u32"),
        ));
        assert!(EfsKeyListEntry::parse(&data, 0, NtfsPosition::none()).is_err());
    }

    #[test]
    fn key_list_count_equal_to_buffer_len_passes_guard() {
        // EfsKeyList::parse rejects `count > data.len()`. With count exactly
        // equal to data.len(), the `>` guard is false and must NOT reject;
        // the original then enters the entry loop and fails with a DIFFERENT
        // error ("extends past the metadata buffer" from read_slice). The
        // `> -> >=` mutant would instead reject here with "exceeds the metadata
        // size". Asserting the error reason distinguishes them.
        let n = 8usize;
        let mut data = alloc::vec![0u8; n];
        data[0..4].copy_from_slice(&le32(u32::try_from(n).expect("test value fits u32"))); // count == data.len() == 8
        let err = EfsKeyList::parse(&data, 0, NtfsPosition::none());
        match err {
            Err(NtfsError::InvalidEfsMetadata { reason, .. }) => {
                assert!(
                    !reason.contains("exceeds the metadata size"),
                    "count == len must pass the size guard, got: {reason}"
                );
            }
            other => panic!("expected entry-loop error, got {other:?}"),
        }
    }

    #[test]
    fn key_list_count_just_over_buffer_len_is_rejected() {
        // count == data.len() + 1 -> `>` true (reject). Kills `> -> ==`/`>=`
        // by exercising the strictly-greater side of the boundary.
        let n = 4usize;
        let mut data = alloc::vec![0u8; n];
        data[0..4].copy_from_slice(&le32(u32::try_from(n + 1).expect("test value fits u32"))); // count = 5 > 4
        let err = EfsKeyList::parse(&data, 0, NtfsPosition::none());
        assert!(matches!(
            err,
            Err(NtfsError::InvalidEfsMetadata { reason, .. })
                if reason.contains("exceeds the metadata size")
        ));
    }

    #[test]
    fn v1_buffer_exactly_header_len_passes_size_check() {
        // data.len() == V1_HEADER_LEN is the `>=` side of
        // `data.len() < V1_HEADER_LEN`. The ddf_offset (0x40) is left 0, so
        // validate_list_offset rejects it AFTER the header-size check passes.
        // Kills `< -> <=` (which would reject len == V1_HEADER_LEN).
        let buf = alloc::vec![0u8; V1_HEADER_LEN];
        let err = EfsMetadataV1::parse(&buf, NtfsPosition::none(), 1);
        assert!(matches!(
            err,
            Err(NtfsError::InvalidEfsMetadata { reason, .. })
                if reason.contains("key list offset")
        ));
    }

    #[test]
    fn v1_buffer_one_byte_short_is_rejected_by_size_check() {
        // data.len() == V1_HEADER_LEN - 1 -> `<` true (reject). Kills `< -> ==`.
        let buf = alloc::vec![0u8; V1_HEADER_LEN - 1];
        let err = EfsMetadataV1::parse(&buf, NtfsPosition::none(), 1);
        assert!(matches!(
            err,
            Err(NtfsError::InvalidEfsMetadata { reason, .. })
                if reason.contains("84-byte V1 header")
        ));
    }
}
