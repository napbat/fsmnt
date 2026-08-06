use zerocopy::FromBytes;

use crate::{BitLockerError, MetadataFailure, Result};

use super::entry::{
    DATUM_HEADER_SIZE, DatumHeader, DatumIter, VALUE_TYPE_AES_CCM, VALUE_TYPE_EXTERNAL_KEY,
    VALUE_TYPE_STRETCH_KEY,
};
use super::layout::{AesCcmBody, StretchKeyBody, VmkBody};

/// VMK datum fixed-size portion (after the 8-byte datum header).
const VMK_FIXED_SIZE: usize = size_of::<VmkBody>();

/// Parsed VMK datum (`entry_type` 2, `value_type` 8).
#[derive(Debug)]
pub struct VmkDatum<'a> {
    body: VmkBody,
    nested_data: &'a [u8],
}

impl<'a> VmkDatum<'a> {
    /// Parse a VMK datum from the full datum bytes (including header).
    ///
    /// # Errors
    ///
    /// Returns `InvalidMetadata` if the payload is too short.
    pub fn from_bytes(buf: &'a [u8]) -> Result<Self> {
        let header = DatumHeader::from_bytes(buf)?;
        let payload = header.payload();

        let (body, rest) =
            VmkBody::read_from_prefix(payload).map_err(|_| BitLockerError::InvalidMetadata {
                block_index: 0,
                reason: MetadataFailure::SizeBoundsExceeded {
                    declared: u64::try_from(DATUM_HEADER_SIZE + VMK_FIXED_SIZE).unwrap_or(u64::MAX),
                    available: u64::try_from(buf.len()).unwrap_or(u64::MAX),
                },
            })?;

        Ok(Self {
            body,
            nested_data: rest,
        })
    }

    #[must_use]
    /// Returns the VMK protector's persistent identifier.
    pub fn guid(&self) -> &[u8; 16] {
        &self.body.guid
    }

    #[must_use]
    /// Returns the raw key-protector type stored in the VMK datum.
    pub fn protection_type(&self) -> u16 {
        self.body.protection_type.get()
    }

    /// Find the stretch key datum (`value_type` 3) in nested entries.
    #[must_use]
    pub fn find_stretch_key(&self) -> Option<StretchKeyDatum> {
        DatumIter::new(self.nested_data)
            .find(|d| d.value_type() == VALUE_TYPE_STRETCH_KEY)
            .and_then(|d| StretchKeyDatum::from_datum(&d))
    }

    /// Find the AES-CCM datum (`value_type` 5) in nested entries.
    #[must_use]
    pub fn find_aes_ccm(&self) -> Option<AesCcmDatum<'a>> {
        DatumIter::new(self.nested_data)
            .find(|d| d.value_type() == VALUE_TYPE_AES_CCM)
            .and_then(|d| AesCcmDatum::from_datum(&d))
    }

    /// Find the external key datum (`value_type` 9) in nested entries.
    #[must_use]
    pub fn find_external_key(&self) -> Option<ExternalKeyDatum<'a>> {
        DatumIter::new(self.nested_data)
            .find(|d| d.value_type() == VALUE_TYPE_EXTERNAL_KEY)
            .and_then(|d| ExternalKeyDatum::from_datum(&d))
    }

    /// Iterate over all nested datum entries.
    #[must_use]
    pub fn nested_entries(&self) -> DatumIter<'a> {
        DatumIter::new(self.nested_data)
    }
}

/// Parsed stretch key datum (`value_type` 3).
///
/// Contains the salt used for `BitLocker`'s custom SHA-256 key stretching.
#[derive(Debug)]
pub struct StretchKeyDatum {
    body: StretchKeyBody,
}

impl StretchKeyDatum {
    fn from_datum(header: &DatumHeader<'_>) -> Option<Self> {
        let payload = header.payload();
        let (body, _) = StretchKeyBody::read_from_prefix(payload).ok()?;
        Some(Self { body })
    }

    #[must_use]
    /// Returns the key-stretching algorithm identifier.
    pub fn algorithm(&self) -> u16 {
        self.body.algorithm.get()
    }

    #[must_use]
    /// Returns the salt used to derive this protector key.
    pub fn salt(&self) -> &[u8; 16] {
        &self.body.salt
    }
}

/// Parsed AES-CCM datum (`value_type` 5).
///
/// Contains nonce, MAC tag, and encrypted key material.
#[derive(Debug)]
pub struct AesCcmDatum<'a> {
    body: AesCcmBody,
    encrypted_data: &'a [u8],
}

impl<'a> AesCcmDatum<'a> {
    /// Parse an AES-CCM datum from a datum header.
    #[must_use]
    pub fn from_header(header: &DatumHeader<'a>) -> Option<Self> {
        Self::from_datum(header)
    }

    fn from_datum(header: &DatumHeader<'a>) -> Option<Self> {
        let payload = header.payload();
        let (body, rest) = AesCcmBody::read_from_prefix(payload).ok()?;
        Some(Self {
            body,
            encrypted_data: rest,
        })
    }

    #[must_use]
    /// Returns the AES-CCM nonce associated with the encrypted key material.
    pub fn nonce(&self) -> &[u8; 12] {
        &self.body.nonce
    }

    #[must_use]
    /// Returns the AES-CCM authentication tag.
    pub fn mac(&self) -> &[u8; 16] {
        &self.body.mac
    }

    #[must_use]
    /// Returns the AES-CCM ciphertext following the fixed datum fields.
    pub fn encrypted_data(&self) -> &[u8] {
        self.encrypted_data
    }
}

/// Parsed external key datum (`value_type` 9).
///
/// Contains a GUID and nested key data (used for BEK/startup key).
#[derive(Debug)]
pub struct ExternalKeyDatum<'a> {
    body: super::layout::ExternalKeyBody,
    nested_data: &'a [u8],
}

impl<'a> ExternalKeyDatum<'a> {
    fn from_datum(header: &DatumHeader<'a>) -> Option<Self> {
        let payload = header.payload();
        let (body, rest) = super::layout::ExternalKeyBody::read_from_prefix(payload).ok()?;
        Some(Self {
            body,
            nested_data: rest,
        })
    }

    #[must_use]
    /// Returns the identifier of the referenced external startup key.
    pub fn guid(&self) -> &[u8; 16] {
        &self.body.guid
    }

    #[must_use]
    /// Returns the encoded datum sequence carried by the external key.
    pub fn nested_data(&self) -> &[u8] {
        self.nested_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vmk_datum(protection_type: u16) -> Vec<u8> {
        let total_size: u16 = 64;
        let mut buf = vec![0u8; usize::from(total_size)];
        buf[0..2].copy_from_slice(&total_size.to_le_bytes());
        buf[2..4].copy_from_slice(&2u16.to_le_bytes());
        buf[4..6].copy_from_slice(&8u16.to_le_bytes());
        buf[8..24].copy_from_slice(&[0xAA; 16]);
        buf[34..36].copy_from_slice(&protection_type.to_le_bytes());
        buf[36..38].copy_from_slice(&28u16.to_le_bytes());
        buf[38..40].copy_from_slice(&0u16.to_le_bytes());
        buf[40..42].copy_from_slice(&3u16.to_le_bytes());
        buf[44..46].copy_from_slice(&0x1000u16.to_le_bytes());
        buf[48..64].copy_from_slice(&[0xBB; 16]);
        buf
    }

    #[test]
    fn parse_vmk_protection_type() {
        let buf = make_vmk_datum(0x0800);
        let vmk = VmkDatum::from_bytes(&buf).unwrap();
        assert_eq!(vmk.protection_type(), 0x0800);
    }

    #[test]
    fn parse_vmk_guid() {
        let buf = make_vmk_datum(0x0800);
        let vmk = VmkDatum::from_bytes(&buf).unwrap();
        assert_eq!(vmk.guid(), &[0xAA; 16]);
    }

    #[test]
    fn parse_vmk_nested_stretch_key() {
        let buf = make_vmk_datum(0x0800);
        let vmk = VmkDatum::from_bytes(&buf).unwrap();
        let stretch = vmk.find_stretch_key().unwrap();
        assert_eq!(stretch.salt(), &[0xBB; 16]);
        assert_eq!(stretch.algorithm(), 0x1000);
    }

    #[test]
    fn vmk_too_short_rejected() {
        let buf = vec![8, 0, 2, 0, 8, 0, 0, 0];
        let err = VmkDatum::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::SizeBoundsExceeded { .. },
                ..
            }
        ));
    }
}
