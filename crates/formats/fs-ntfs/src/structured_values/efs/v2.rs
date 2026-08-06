//! EFSRPC Metadata Version 2 (EFS versions 4-5, Windows Vista and later).
//!
//! A 52-byte header followed by DDF/DRF protector lists and a FekInfo
//! datum. Everything below the header is built from tagged **EFSX datum**
//! structures (§2.2.2.2.2): an 8-byte header carrying a `StructureSize`,
//! `Role`, `Type`, and `Flags`, optionally containing nested datums.
//!
//! Reference: MS-EFSR §2.2.2.2 (`docs/ms-efsr/02-metadata-v2.md`).

use alloc::vec::Vec;

use super::{EfsAlgorithm, read_guid, read_u16, read_u32};
use crate::error::{NtfsError, Result};
use crate::guid::NtfsGuid;
use crate::types::NtfsPosition;

/// Size of the V2 metadata header (§2.2.2.2).
const V2_HEADER_LEN: usize = 0x34;
/// Offset of the `EFS_ID` GUID in the V2 header.
const EFS_ID_OFFSET: usize = 0x10;
/// Offset of the `DDF_Offset` field in the V2 header.
const DDF_OFFSET_FIELD: usize = 0x20;
/// Offset of the `DRF_Offset` field in the V2 header.
const DRF_OFFSET_FIELD: usize = 0x24;
/// Offset where the FekInfo datum begins in the V2 header.
const FEK_INFO_OFFSET: usize = 0x28;

/// Size of an EFSX datum header (`StructureSize`, `Role`, `Type`, `Flags`).
const EFSX_HEADER_LEN: usize = 8;
/// `Flags` bit marking a datum that contains nested datum structures.
const EFSX_FLAG_COMPLEX: u16 = 0x0002;
/// Upper bound on EFSX datum nesting, to bound recursion on corrupt input.
const MAX_DATUM_DEPTH: usize = 16;
/// Size of a protector list header (`StructureSize` + `ProtectorsCount`).
const PROTECTOR_LIST_HEADER_LEN: usize = 6;

/// EFSX datum type: opaque binary blob (§2.2.2.2.3).
const TYPE_BLOB: u16 = 0x0001;
/// EFSX datum type: key protector (§2.2.2.2.5).
const TYPE_KEY_PROTECTOR: u16 = 0x0003;
/// EFSX datum type: protector info (§2.2.2.2.6).
const TYPE_PROTECTOR_INFO: u16 = 0x0004;
/// EFSX datum type: key agreement data (§2.2.2.2.7).
const TYPE_KEY_AGMT_DATA: u16 = 0x0005;
/// EFSX datum type: FekInfo (§2.2.2.2.8).
const TYPE_FEK_INFO: u16 = 0x0006;

/// EFSX `Role` for the datum holding the encrypted FEK (§2.2.2.2.2).
const ROLE_ENCRYPTED_FEK: u16 = 0x000A;
/// EFSX `Role` for the datum holding the file initialization vector.
const ROLE_FILE_IV: u16 = 0x000B;

/// A tagged EFSX datum (§2.2.2.2.2), with any nested datums parsed.
///
/// `payload` is every byte after the 8-byte header. For complex container
/// datums it begins with a small type-specific prefix (e.g. the FekInfo
/// `AlgorithmID`); [`Self::children`] holds the datums that follow it.
#[derive(Clone, Debug)]
pub struct EfsxDatum {
    structure_size: u16,
    role: u16,
    datum_type: u16,
    flags: u16,
    payload: Vec<u8>,
    children: Vec<EfsxDatum>,
}

impl EfsxDatum {
    /// The `Role` tag describing what this datum is used for.
    pub fn role(&self) -> u16 {
        self.role
    }

    /// The `Type` tag describing this datum's structure.
    pub fn datum_type(&self) -> u16 {
        self.datum_type
    }

    /// The raw `Flags` field.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Whether this datum advertises nested datum structures.
    pub fn is_complex(&self) -> bool {
        self.flags & EFSX_FLAG_COMPLEX != 0
    }

    /// Every byte after the 8-byte EFSX header.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The nested datums of a complex container datum.
    pub fn children(&self) -> &[EfsxDatum] {
        &self.children
    }

    /// For a Blob datum (§2.2.2.2.3), the opaque `Blob_Data` after the
    /// `BlobType`/`BlobFlags` prefix; `None` for any other datum type.
    pub fn blob_data(&self) -> Option<&[u8]> {
        if self.datum_type == TYPE_BLOB {
            self.payload.get(4..)
        } else {
            None
        }
    }

    /// For a Key Protector datum (§2.2.2.2.5), the `ProtectorType` value;
    /// `None` for any other datum type.
    pub fn protector_type(&self) -> Option<u16> {
        if self.datum_type == TYPE_KEY_PROTECTOR && self.payload.len() >= 2 {
            Some(u16::from_le_bytes([self.payload[0], self.payload[1]]))
        } else {
            None
        }
    }

    /// Recursively finds the first descendant datum with the given `Role`.
    pub fn find_by_role(&self, role: u16) -> Option<&EfsxDatum> {
        for child in &self.children {
            if child.role == role {
                return Some(child);
            }
            if let Some(found) = child.find_by_role(role) {
                return Some(found);
            }
        }
        None
    }
}

/// Returns the type-specific prefix length for a complex container datum,
/// or `None` for datum types that never carry nested datums.
///
/// The prefix is the fixed fields between the EFSX header and the nested
/// datums: FekInfo `AlgorithmID` (4), Key Protector `ProtectorType` +
/// `ProtectorFlags` (4), Key Agreement `KeyAgmtFlags` (2).
fn container_prefix_len(datum_type: u16) -> Option<usize> {
    match datum_type {
        TYPE_FEK_INFO | TYPE_KEY_PROTECTOR => Some(4),
        TYPE_KEY_AGMT_DATA => Some(2),
        TYPE_PROTECTOR_INFO => Some(0),
        _ => None,
    }
}

/// Parses a single EFSX datum starting at `offset` within `data`.
fn parse_datum(
    data: &[u8],
    offset: usize,
    depth: usize,
    position: NtfsPosition,
) -> Result<EfsxDatum> {
    if depth > MAX_DATUM_DEPTH {
        return Err(NtfsError::InvalidEfsMetadata {
            position,
            reason: "EFSX datum nesting exceeds the supported depth",
        });
    }

    let structure_size = read_u16(data, offset, position)? as usize;
    if structure_size < EFSX_HEADER_LEN {
        return Err(NtfsError::InvalidEfsMetadata {
            position,
            reason: "EFSX datum smaller than its 8-byte header",
        });
    }
    let role = read_u16(data, offset + 2, position)?;
    let datum_type = read_u16(data, offset + 4, position)?;
    let flags = read_u16(data, offset + 6, position)?;

    let end = offset
        .checked_add(structure_size)
        .ok_or(NtfsError::InvalidEfsMetadata {
            position,
            reason: "EFSX datum offset arithmetic overflowed",
        })?;
    let payload = data
        .get(offset + EFSX_HEADER_LEN..end)
        .ok_or(NtfsError::InvalidEfsMetadata {
            position,
            reason: "EFSX datum extends past the metadata buffer",
        })?
        .to_vec();

    // Only walk nested datums for container types: a Blob/Descriptor with
    // a stray complex flag would otherwise be misparsed (§2.2.2.2.3).
    let mut children = Vec::new();
    if flags & EFSX_FLAG_COMPLEX != 0
        && let Some(prefix) = container_prefix_len(datum_type)
    {
        children = parse_datum_list(&payload, prefix, depth + 1, position)?;
    }

    Ok(EfsxDatum {
        structure_size: structure_size as u16,
        role,
        datum_type,
        flags,
        payload,
        children,
    })
}

/// Parses a run of sibling EFSX datums beginning at `start` within `data`.
///
/// MS-EFSR §2.2.2.1 permits a trailing unused area, but only one spanning
/// at most 8 contiguous bytes. A sub-header-sized `StructureSize` is
/// therefore benign padding only when it is the final ≤8-byte tail; a
/// larger leftover region is corruption and is rejected so a malformed
/// child header cannot silently truncate the datum subtree.
fn parse_datum_list(
    data: &[u8],
    start: usize,
    depth: usize,
    position: NtfsPosition,
) -> Result<Vec<EfsxDatum>> {
    let mut out = Vec::new();
    let mut cursor = start;
    while cursor + EFSX_HEADER_LEN <= data.len() {
        let structure_size = read_u16(data, cursor, position)? as usize;
        if structure_size < EFSX_HEADER_LEN {
            if data.len() - cursor > EFSX_HEADER_LEN {
                return Err(NtfsError::InvalidEfsMetadata {
                    position,
                    reason: "EFSX datum has an invalid structure size",
                });
            }
            break;
        }
        let datum = parse_datum(data, cursor, depth, position)?;
        cursor = cursor
            .checked_add(structure_size)
            .ok_or(NtfsError::InvalidEfsMetadata {
                position,
                reason: "EFSX datum list offset arithmetic overflowed",
            })?;
        out.push(datum);
    }
    Ok(out)
}

/// Parses a DDF or DRF protector list (§2.2.2.2.1) at `offset`.
fn parse_protector_list(
    data: &[u8],
    offset: usize,
    position: NtfsPosition,
) -> Result<Vec<EfsxDatum>> {
    let struct_size = read_u32(data, offset, position)? as usize;
    let count = read_u16(data, offset + 4, position)?;
    let list_end = offset
        .checked_add(struct_size)
        .ok_or(NtfsError::InvalidEfsMetadata {
            position,
            reason: "protector list offset arithmetic overflowed",
        })?;
    if struct_size < PROTECTOR_LIST_HEADER_LEN || list_end > data.len() {
        return Err(NtfsError::InvalidEfsMetadata {
            position,
            reason: "protector list extends past the metadata buffer",
        });
    }
    // MS-EFSR §2.2.2.2: a present DDF/DRF protector list must hold at
    // least one entry. A zero count is structurally invalid metadata.
    if count == 0 {
        return Err(NtfsError::InvalidEfsMetadata {
            position,
            reason: "protector list has no entries",
        });
    }

    let mut entries = Vec::new();
    let mut cursor = offset + PROTECTOR_LIST_HEADER_LEN;
    for _ in 0..count {
        let datum = parse_datum(data, cursor, 0, position)?;
        cursor = cursor.checked_add(datum.structure_size as usize).ok_or(
            NtfsError::InvalidEfsMetadata {
                position,
                reason: "protector list entry offset arithmetic overflowed",
            },
        )?;
        if cursor > list_end {
            return Err(NtfsError::InvalidEfsMetadata {
                position,
                reason: "protector list entry extends past the list",
            });
        }
        entries.push(datum);
    }
    Ok(entries)
}

/// Parsed EFSRPC Metadata Version 2 (§2.2.2.2).
#[derive(Clone, Debug)]
pub struct EfsMetadataV2 {
    efs_version: u32,
    efs_id: NtfsGuid,
    fek_algorithm: EfsAlgorithm,
    fek_info: EfsxDatum,
    ddf_protectors: Vec<EfsxDatum>,
    drf_protectors: Vec<EfsxDatum>,
    position: NtfsPosition,
}

impl EfsMetadataV2 {
    /// Parses Version 2 metadata. `efs_version` is the already-read header
    /// field (4 or the version-5 DPAPI-NG variant).
    pub(super) fn parse(data: &[u8], position: NtfsPosition, efs_version: u32) -> Result<Self> {
        if data.len() < V2_HEADER_LEN {
            return Err(NtfsError::InvalidEfsMetadata {
                position,
                reason: "buffer smaller than the 52-byte V2 header",
            });
        }

        let efs_id = read_guid(data, EFS_ID_OFFSET, position)?;
        let ddf_offset = read_u32(data, DDF_OFFSET_FIELD, position)? as usize;
        let drf_offset = read_u32(data, DRF_OFFSET_FIELD, position)? as usize;

        let fek_info = parse_datum(data, FEK_INFO_OFFSET, 0, position)?;
        // The FekInfo container prefix is the 4-byte AlgorithmID (§2.2.2.2.8).
        let fek_algorithm = match fek_info.payload.get(0..4) {
            Some(b) => EfsAlgorithm::from_alg_id(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            None => EfsAlgorithm::Unknown(0),
        };

        let ddf_protectors = parse_protector_list(data, ddf_offset, position)?;
        let drf_protectors = if drf_offset == 0 {
            Vec::new()
        } else {
            parse_protector_list(data, drf_offset, position)?
        };

        Ok(Self {
            efs_version,
            efs_id,
            fek_algorithm,
            fek_info,
            ddf_protectors,
            drf_protectors,
            position,
        })
    }

    /// The `EFS_Version` header field (4, or 5 for the DPAPI-NG variant).
    pub fn efs_version(&self) -> u32 {
        self.efs_version
    }

    /// The `EFS_ID` GUID of the machine that created the metadata.
    pub fn efs_id(&self) -> &NtfsGuid {
        &self.efs_id
    }

    /// The symmetric algorithm used to encrypt file content with the FEK.
    pub fn fek_algorithm(&self) -> EfsAlgorithm {
        self.fek_algorithm
    }

    /// The FekInfo datum (§2.2.2.2.8): `AlgorithmID` plus the wrapped FEK
    /// and file IV blobs.
    pub fn fek_info(&self) -> &EfsxDatum {
        &self.fek_info
    }

    /// The AES-keywrapped FEK blob, if present in the FekInfo datum.
    ///
    /// This is ciphertext; recovering the plaintext FEK requires the File
    /// Master Key and is out of scope for this read-only parser.
    pub fn encrypted_fek(&self) -> Option<&[u8]> {
        self.fek_info
            .find_by_role(ROLE_ENCRYPTED_FEK)
            .and_then(EfsxDatum::blob_data)
    }

    /// The wrapped file initialization vector blob, if present.
    pub fn file_iv(&self) -> Option<&[u8]> {
        self.fek_info
            .find_by_role(ROLE_FILE_IV)
            .and_then(EfsxDatum::blob_data)
    }

    /// The DDF protector list — key protectors for authorized users.
    pub fn ddf_protectors(&self) -> &[EfsxDatum] {
        &self.ddf_protectors
    }

    /// The DRF protector list — key protectors for Data Recovery Agents.
    pub fn drf_protectors(&self) -> &[EfsxDatum] {
        &self.drf_protectors
    }

    /// The absolute byte position of the `$EFS` attribute, if known.
    pub fn position(&self) -> NtfsPosition {
        self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured_values::NtfsEfsMetadata;

    /// Builds an EFSX datum: 8-byte header + `payload`.
    fn datum(role: u16, datum_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let size = (EFSX_HEADER_LEN + payload.len()) as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&role.to_le_bytes());
        buf.extend_from_slice(&datum_type.to_le_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// Builds a Blob datum (§2.2.2.2.3) carrying `blob_data`.
    fn blob(role: u16, blob_data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u16.to_le_bytes()); // BlobType
        payload.extend_from_slice(&0u16.to_le_bytes()); // BlobFlags
        payload.extend_from_slice(blob_data);
        datum(role, TYPE_BLOB, 0, &payload)
    }

    /// Builds a FekInfo datum holding the encrypted FEK and file IV blobs.
    fn fek_info_datum(alg_id: u32, fek: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&alg_id.to_le_bytes()); // AlgorithmID prefix
        payload.extend_from_slice(&blob(ROLE_ENCRYPTED_FEK, fek));
        payload.extend_from_slice(&blob(ROLE_FILE_IV, iv));
        datum(0, TYPE_FEK_INFO, EFSX_FLAG_COMPLEX, &payload)
    }

    /// Builds a protector list (§2.2.2.2.1) wrapping one key protector.
    fn protector_list() -> Vec<u8> {
        let mut prot_payload = Vec::new();
        prot_payload.extend_from_slice(&0x0002u16.to_le_bytes()); // ProtectorType
        prot_payload.extend_from_slice(&0u16.to_le_bytes()); // ProtectorFlags
        let entry = datum(0, TYPE_KEY_PROTECTOR, EFSX_FLAG_COMPLEX, &prot_payload);

        let mut buf = Vec::new();
        let struct_size = (PROTECTOR_LIST_HEADER_LEN + entry.len()) as u32;
        buf.extend_from_slice(&struct_size.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // ProtectorsCount
        buf.extend_from_slice(&entry);
        buf
    }

    /// Builds full V2 metadata with a FekInfo datum and a DDF protector list.
    fn build_v2(alg_id: u32, fek: &[u8], iv: &[u8]) -> Vec<u8> {
        let fek_info = fek_info_datum(alg_id, fek, iv);
        let ddf = protector_list();

        let mut buf = alloc::vec![0u8; V2_HEADER_LEN];
        buf[0x08..0x0C].copy_from_slice(&4u32.to_le_bytes()); // EFS_Version 4
        // The FekInfo datum starts inside the header at 0x28 and runs past
        // it; the DDF protector list follows it.
        let ddf_offset = (FEK_INFO_OFFSET + fek_info.len()) as u32;
        buf[0x20..0x24].copy_from_slice(&ddf_offset.to_le_bytes());
        // DRF offset stays 0 (absent).
        buf.truncate(FEK_INFO_OFFSET);
        buf.extend_from_slice(&fek_info);
        buf.extend_from_slice(&ddf);
        buf
    }

    #[test]
    fn parses_fek_info_and_protectors() {
        let fek = [0xAAu8; 32];
        let iv = [0xBBu8; 16];
        let buf = build_v2(0x6610, &fek, &iv);

        let meta = match NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).unwrap() {
            NtfsEfsMetadata::V2(m) => m,
            NtfsEfsMetadata::V1(_) => panic!("expected V2 metadata"),
        };
        assert_eq!(meta.efs_version(), 4);
        assert_eq!(meta.fek_algorithm(), EfsAlgorithm::Aes256);
        assert_eq!(meta.encrypted_fek(), Some(&fek[..]));
        assert_eq!(meta.file_iv(), Some(&iv[..]));
        assert!(meta.drf_protectors().is_empty());

        let protectors = meta.ddf_protectors();
        assert_eq!(protectors.len(), 1);
        assert_eq!(protectors[0].datum_type(), TYPE_KEY_PROTECTOR);
        assert_eq!(protectors[0].protector_type(), Some(0x0002));
    }

    #[test]
    fn datum_smaller_than_header_is_rejected() {
        let data = [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(parse_datum(&data, 0, 0, NtfsPosition::none()).is_err());
    }

    #[test]
    fn datum_past_buffer_is_rejected() {
        // StructureSize claims 64 bytes but only 8 are present.
        let data = datum(0, TYPE_BLOB, 0, &[]);
        let mut data = data;
        data[0..2].copy_from_slice(&64u16.to_le_bytes());
        assert!(parse_datum(&data, 0, 0, NtfsPosition::none()).is_err());
    }

    #[test]
    fn datum_list_stops_at_trailing_padding() {
        let mut buf = blob(ROLE_FILE_IV, &[0x01, 0x02]);
        buf.extend_from_slice(&[0u8; 4]); // < 8 bytes of trailing padding
        let list = parse_datum_list(&buf, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn datum_list_rejects_corrupt_header_with_excess_bytes() {
        // A blob followed by 12 bytes whose StructureSize field reads < 8:
        // too large to be permitted padding, so it must be rejected rather
        // than silently truncating the datum subtree.
        let mut buf = blob(ROLE_FILE_IV, &[0x01, 0x02]);
        buf.extend_from_slice(&[0u8; 12]);
        assert!(parse_datum_list(&buf, 0, 0, NtfsPosition::none()).is_err());
    }

    #[test]
    fn rejects_empty_protector_list() {
        let mut buf = build_v2(0x6610, &[0; 16], &[0; 16]);
        // Overwrite the DDF protector list's ProtectorsCount with zero.
        let ddf_offset = u32::from_le_bytes([buf[0x20], buf[0x21], buf[0x22], buf[0x23]]) as usize;
        buf[ddf_offset + 4..ddf_offset + 6].copy_from_slice(&0u16.to_le_bytes());
        assert!(NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).is_err());
    }

    #[test]
    fn blob_data_only_for_blob_type() {
        let payload = [0u8; 8];
        let non_blob = parse_datum(
            &datum(0, TYPE_PROTECTOR_INFO, 0, &payload),
            0,
            0,
            NtfsPosition::none(),
        )
        .unwrap();
        assert!(non_blob.blob_data().is_none());
    }

    #[test]
    fn rejects_protector_list_past_buffer() {
        let mut buf = build_v2(0x6610, &[0; 16], &[0; 16]);
        // Point the DDF offset one byte before the end of the buffer.
        let bad = (buf.len() - 1) as u32;
        buf[0x20..0x24].copy_from_slice(&bad.to_le_bytes());
        assert!(NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).is_err());
    }

    #[test]
    fn unknown_algorithm_is_preserved() {
        let buf = build_v2(0x1234, &[0; 16], &[0; 16]);
        let meta = match NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).unwrap() {
            NtfsEfsMetadata::V2(m) => m,
            NtfsEfsMetadata::V1(_) => panic!("expected V2 metadata"),
        };
        assert_eq!(meta.fek_algorithm(), EfsAlgorithm::Unknown(0x1234));
    }

    #[test]
    fn datum_accessors_return_genuine_fields() {
        // Build a single datum with a distinct role (0x000B), type (TYPE_BLOB),
        // no complex flag, and a recognizable payload. Each accessor must
        // return the genuine value, not 0/1/empty.
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let raw = datum(ROLE_FILE_IV, TYPE_BLOB, 0, &payload);
        let parsed = parse_datum(&raw, 0, 0, NtfsPosition::none()).unwrap();

        assert_eq!(parsed.role(), ROLE_FILE_IV);
        assert_eq!(parsed.datum_type(), TYPE_BLOB);
        assert_eq!(parsed.flags(), 0);
        assert!(!parsed.is_complex());
        assert_eq!(parsed.payload(), &payload);
        assert!(parsed.children().is_empty());
    }

    #[test]
    fn complex_flag_drives_is_complex_and_children() {
        // A FekInfo datum has the complex flag set and contains nested datums.
        // is_complex must be true, flags must carry EFSX_FLAG_COMPLEX, and the
        // children vector must be non-empty. Pins the `& EFSX_FLAG_COMPLEX != 0`
        // bit test (vs |/^) and the children accessor.
        let raw = fek_info_datum(0x6610, &[0xAA; 8], &[0xBB; 8]);
        let parsed = parse_datum(&raw, 0, 0, NtfsPosition::none()).unwrap();

        assert!(parsed.is_complex());
        assert_eq!(parsed.flags() & EFSX_FLAG_COMPLEX, EFSX_FLAG_COMPLEX);
        // The FekInfo container holds two nested blobs (encrypted FEK + IV).
        assert_eq!(parsed.children().len(), 2);
        assert_eq!(parsed.children()[0].role(), ROLE_ENCRYPTED_FEK);
        assert_eq!(parsed.children()[1].role(), ROLE_FILE_IV);
    }

    #[test]
    fn non_complex_datum_has_no_children() {
        // A KEY_PROTECTOR datum WITHOUT the complex flag whose payload, if it
        // were wrongly walked, contains a 4-byte prefix followed by a valid
        // nested blob. The `flags & EFSX_FLAG_COMPLEX != 0` guard (flags=0)
        // must keep children empty. A `& -> |` mutation would make
        // `0 | 2 = 2 != 0` true and parse the nested blob, so this kills it.
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // ProtectorType + Flags prefix
        payload.extend_from_slice(&blob(ROLE_FILE_IV, &[0x01, 0x02])); // would-be child
        let raw = datum(0x0001, TYPE_KEY_PROTECTOR, 0, &payload);
        let parsed = parse_datum(&raw, 0, 0, NtfsPosition::none()).unwrap();
        assert!(!parsed.is_complex());
        assert!(
            parsed.children().is_empty(),
            "non-complex datum must not parse children"
        );
    }

    /// Builds a chain of `depth` nested complex KEY_PROTECTOR datums, the
    /// innermost carrying `leaf` as a child. Each level adds the 4-byte
    /// KEY_PROTECTOR prefix before its single nested datum.
    fn nested_protectors(depth: usize, leaf: &[u8]) -> Vec<u8> {
        let mut current = leaf.to_vec();
        for _ in 0..depth {
            let mut payload = Vec::new();
            payload.extend_from_slice(&[0u8, 0, 0, 0]); // ProtectorType + Flags (4-byte prefix)
            payload.extend_from_slice(&current);
            current = datum(0, TYPE_KEY_PROTECTOR, EFSX_FLAG_COMPLEX, &payload);
        }
        current
    }

    #[test]
    fn nesting_at_depth_limit_is_accepted() {
        // MAX_DATUM_DEPTH is 16. With 16 nested containers the innermost
        // parse_datum call receives depth == 16; `16 > 16` is false, so the
        // original ACCEPTS it. A `> -> >=`/`> -> ==` mutant rejects at depth 16,
        // so accepting this fixture kills both boundary mutants at line 155.
        // It also requires `depth + 1` to actually advance (a `* 1` mutation
        // would keep depth at 0 and also accept — but the deeper-nest test
        // below catches that).
        let leaf = blob(ROLE_FILE_IV, &[0x07, 0x08]);
        let raw = nested_protectors(16, &leaf);
        let parsed = parse_datum(&raw, 0, 0, NtfsPosition::none()).unwrap();
        assert!(parsed.find_by_role(ROLE_FILE_IV).is_some());
    }

    #[test]
    fn nesting_beyond_depth_limit_is_rejected() {
        // A nest deeper than MAX_DATUM_DEPTH (16) must be rejected by the
        // `depth > MAX_DATUM_DEPTH` guard. 20 levels overflows it. This kills
        // `depth + 1 -> depth * 1` (which would keep depth at 0 forever and
        // never trip the guard, wrongly accepting).
        let leaf = blob(ROLE_FILE_IV, &[0x07, 0x08]);
        let raw = nested_protectors(20, &leaf);
        let err = parse_datum(&raw, 0, 0, NtfsPosition::none());
        assert!(matches!(
            err,
            Err(NtfsError::InvalidEfsMetadata { reason, .. })
                if reason.contains("nesting exceeds")
        ));
    }

    #[test]
    fn datum_list_rejects_excess_after_sub_header_size() {
        // parse_datum_list: a leading valid datum followed by a region whose
        // structure_size reads < EFSX_HEADER_LEN, where the leftover exceeds
        // EFSX_HEADER_LEN (8). `data.len() - cursor > EFSX_HEADER_LEN` must be
        // true -> reject. 9 trailing bytes (odd, but parse_datum_list reads a
        // u16) — use 10 trailing bytes so the leftover is 10 > 8.
        let mut buf = blob(ROLE_FILE_IV, &[0x01, 0x02]);
        buf.extend_from_slice(&[0u8; 10]); // structure_size reads 0 (< 8), 10 > 8 leftover
        assert!(parse_datum_list(&buf, 0, 0, NtfsPosition::none()).is_err());
    }

    #[test]
    fn datum_list_parses_header_only_datum() {
        // A list whose first datum has structure_size == EFSX_HEADER_LEN (8)
        // followed by another datum. structure_size == 8 is NOT < 8, so it is
        // parsed as a genuine (empty-payload) datum, not skipped as padding.
        // Kills `< -> ==`/`<=` at line 223 (which would treat size-8 as a
        // sub-header and break / reject).
        let mut buf = Vec::new();
        buf.extend_from_slice(&datum(0x0001, TYPE_BLOB, 0, &[])); // size == 8
        buf.extend_from_slice(&datum(0x0002, TYPE_BLOB, 0, &[0xAA, 0xBB])); // size == 10
        let list = parse_datum_list(&buf, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].role(), 0x0001);
        assert!(list[0].payload().is_empty());
        assert_eq!(list[1].role(), 0x0002);
    }

    #[test]
    fn datum_list_allows_exactly_header_size_trailing() {
        // Trailing region of exactly EFSX_HEADER_LEN (8) bytes with a
        // sub-header structure_size: `data.len() - cursor > EFSX_HEADER_LEN`
        // is false (8 > 8 is false) -> benign padding, break. Kills `> -> >=`
        // (which would reject) and `- -> +` (which would compute a huge value
        // and reject).
        let mut buf = blob(ROLE_FILE_IV, &[0x01, 0x02]);
        buf.extend_from_slice(&[0u8; 8]); // exactly 8 trailing bytes
        let list = parse_datum_list(&buf, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn protector_list_struct_size_at_header_boundary() {
        // struct_size == PROTECTOR_LIST_HEADER_LEN (6): the `<` size-check is
        // false, so the original proceeds to the count/entry logic and fails in
        // the entry loop with "extends past the list". A `< -> <=` mutant would
        // reject HERE with "extends past the metadata buffer". Asserting the
        // loop reason kills `< -> <=`. The data buffer is long enough that
        // list_end (6) <= data.len(), isolating the struct_size operand.
        let mut at_boundary = Vec::new();
        at_boundary.extend_from_slice(&6u32.to_le_bytes()); // struct_size == 6
        at_boundary.extend_from_slice(&1u16.to_le_bytes()); // count = 1
        at_boundary.extend_from_slice(&datum(0, TYPE_KEY_PROTECTOR, 0, &[0u8; 4]));
        let err = parse_protector_list(&at_boundary, 0, NtfsPosition::none());
        assert!(
            matches!(
                &err,
                Err(NtfsError::InvalidEfsMetadata { reason, .. })
                    if reason.contains("extends past the list")
            ),
            "struct_size == header len must pass the size check, got: {err:?}"
        );

        // struct_size = 5 (< 6): rejected by the size check itself. Kills
        // `< -> ==` (5 != 6 so `==` would wrongly accept).
        let mut below = Vec::new();
        below.extend_from_slice(&5u32.to_le_bytes()); // struct_size = 5
        below.extend_from_slice(&1u16.to_le_bytes());
        below.extend_from_slice(&[0u8; 16]);
        let err = parse_protector_list(&below, 0, NtfsPosition::none());
        assert!(matches!(
            err,
            Err(NtfsError::InvalidEfsMetadata { reason, .. })
                if reason.contains("extends past the metadata buffer")
        ));
    }

    #[test]
    fn protector_list_end_past_buffer_is_rejected() {
        // list_end > data.len() must reject (the second `||` operand). A valid
        // struct_size but a buffer one byte too short forces list_end past the
        // end. Kills `> -> <` (258:60) and the `|| -> &&` mutation (with a
        // valid struct_size, `&&` would require BOTH true and wrongly accept).
        let mut buf = Vec::new();
        let struct_size = 6 + 16u32; // header + one 16-byte entry
        buf.extend_from_slice(&struct_size.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // count = 1
        buf.extend_from_slice(&datum(0, TYPE_KEY_PROTECTOR, 0, &[0u8; 8]));
        buf.truncate(buf.len() - 1); // chop one byte so list_end > data.len()
        let err = parse_protector_list(&buf, 0, NtfsPosition::none());
        assert!(matches!(
            err,
            Err(NtfsError::InvalidEfsMetadata { reason, .. })
                if reason.contains("extends past the metadata buffer")
        ));
    }

    #[test]
    fn protector_list_entry_past_list_end_is_rejected() {
        // An entry whose advance pushes cursor beyond list_end must be rejected
        // by `cursor > list_end`. struct_size declares a list shorter than the
        // single entry actually consumes. Kills `> -> <` at line 283.
        let entry = datum(0, TYPE_KEY_PROTECTOR, 0, &[0u8; 8]); // 16-byte entry
        let declared_list = PROTECTOR_LIST_HEADER_LEN + 4; // shorter than 6 + 16
        let mut buf = Vec::new();
        buf.extend_from_slice(&(declared_list as u32).to_le_bytes()); // struct_size
        buf.extend_from_slice(&1u16.to_le_bytes()); // count = 1
        buf.extend_from_slice(&entry);
        // list_end = declared_list (10). After parsing the 16-byte entry,
        // cursor = 6 + 16 = 22 > 10 -> reject.
        let err = parse_protector_list(&buf, 0, NtfsPosition::none());
        assert!(matches!(
            err,
            Err(NtfsError::InvalidEfsMetadata { reason, .. })
                if reason.contains("extends past the list")
        ));
    }

    #[test]
    fn v2_buffer_one_byte_short_is_rejected() {
        // data.len() == V2_HEADER_LEN - 1 -> `<` true (reject). Together with
        // v2_buffer_exactly_header_size_parses_header (the `>=` side), this
        // pins both directions of `data.len() < V2_HEADER_LEN`. Calls the inner
        // parser directly so the dispatch on EFS_Version is bypassed.
        let buf = alloc::vec![0u8; V2_HEADER_LEN - 1];
        let err = EfsMetadataV2::parse(&buf, NtfsPosition::none(), 4);
        assert!(matches!(
            err,
            Err(NtfsError::InvalidEfsMetadata { reason, .. })
                if reason.contains("52-byte V2 header")
        ));
    }

    #[test]
    fn protector_type_reads_two_byte_prefix() {
        // A Key Protector datum exposes its ProtectorType from the first two
        // payload bytes; other types return None. Pins the
        // `datum_type == TYPE_KEY_PROTECTOR && payload.len() >= 2` predicate.
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u16.to_le_bytes()); // ProtectorType
        payload.extend_from_slice(&0u16.to_le_bytes()); // ProtectorFlags
        let raw = datum(0, TYPE_KEY_PROTECTOR, 0, &payload);
        let parsed = parse_datum(&raw, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(parsed.protector_type(), Some(0x1234));

        // A non-protector type returns None even with a >= 2-byte payload.
        let other = datum(0, TYPE_BLOB, 0, &payload);
        let other = parse_datum(&other, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(other.protector_type(), None);
    }

    #[test]
    fn protector_type_none_when_payload_too_short() {
        // TYPE_KEY_PROTECTOR but only a 1-byte payload (< 2): the
        // `payload.len() >= 2` half of the `&&` must reject. If `&&` became
        // `||` this would wrongly index the payload.
        let raw = datum(0, TYPE_KEY_PROTECTOR, 0, &[0x07]);
        let parsed = parse_datum(&raw, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(parsed.protector_type(), None);
    }

    #[test]
    fn key_agreement_container_prefix_is_two() {
        // A complex KEY_AGMT_DATA datum has a 2-byte KeyAgmtFlags prefix; a
        // nested datum follows it. The single child must be parsed at offset 2.
        // Pins the `TYPE_KEY_AGMT_DATA => Some(2)` match arm.
        let child = blob(ROLE_FILE_IV, &[0x01, 0x02]);
        let mut payload = Vec::new();
        payload.extend_from_slice(&0xABCDu16.to_le_bytes()); // KeyAgmtFlags prefix (2 bytes)
        payload.extend_from_slice(&child);
        let raw = datum(0, TYPE_KEY_AGMT_DATA, EFSX_FLAG_COMPLEX, &payload);
        let parsed = parse_datum(&raw, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(parsed.children().len(), 1);
        assert_eq!(parsed.children()[0].role(), ROLE_FILE_IV);
    }

    #[test]
    fn protector_info_container_prefix_is_zero() {
        // A complex PROTECTOR_INFO datum has a 0-byte prefix; nested datums
        // begin immediately. Pins the `TYPE_PROTECTOR_INFO => Some(0)` arm.
        let child = blob(ROLE_FILE_IV, &[0x09, 0x0A]);
        let raw = datum(0, TYPE_PROTECTOR_INFO, EFSX_FLAG_COMPLEX, &child);
        let parsed = parse_datum(&raw, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(parsed.children().len(), 1);
        assert_eq!(parsed.children()[0].role(), ROLE_FILE_IV);
    }

    #[test]
    fn parses_drf_protector_list() {
        // V2 metadata with both DDF and DRF protector lists: drf_protectors()
        // must be non-empty. Pins the `drf_offset == 0` branch and the
        // drf_protectors accessor.
        let fek_info = fek_info_datum(0x6610, &[0xAA; 16], &[0xBB; 16]);
        let ddf = protector_list();
        let drf = protector_list();

        let mut buf = alloc::vec![0u8; V2_HEADER_LEN];
        buf[0x08..0x0C].copy_from_slice(&4u32.to_le_bytes());
        let ddf_offset = (FEK_INFO_OFFSET + fek_info.len()) as u32;
        let drf_offset = ddf_offset + ddf.len() as u32;
        buf[0x20..0x24].copy_from_slice(&ddf_offset.to_le_bytes());
        buf[0x24..0x28].copy_from_slice(&drf_offset.to_le_bytes());
        buf.truncate(FEK_INFO_OFFSET);
        buf.extend_from_slice(&fek_info);
        buf.extend_from_slice(&ddf);
        buf.extend_from_slice(&drf);

        let meta = match NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).unwrap() {
            NtfsEfsMetadata::V2(m) => m,
            NtfsEfsMetadata::V1(_) => panic!("expected V2 metadata"),
        };
        assert_eq!(meta.ddf_protectors().len(), 1);
        assert_eq!(meta.drf_protectors().len(), 1);
    }

    #[test]
    fn datum_exactly_header_size_is_accepted() {
        // structure_size == EFSX_HEADER_LEN (8) is the minimum valid datum
        // (boundary for `structure_size < EFSX_HEADER_LEN`). Payload is empty.
        let raw = datum(ROLE_FILE_IV, TYPE_BLOB, 0, &[]);
        assert_eq!(raw.len(), EFSX_HEADER_LEN);
        let parsed = parse_datum(&raw, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(parsed.role(), ROLE_FILE_IV);
        assert!(parsed.payload().is_empty());
    }

    #[test]
    fn datum_list_two_siblings() {
        // Two adjacent datums must both be parsed; pins the cursor advance
        // `cursor + structure_size` in parse_datum_list (vs - or *).
        let mut buf = Vec::new();
        buf.extend_from_slice(&datum(0x0001, TYPE_BLOB, 0, &[0x01, 0x02, 0x03, 0x04]));
        buf.extend_from_slice(&datum(0x0002, TYPE_BLOB, 0, &[0x05, 0x06]));
        let list = parse_datum_list(&buf, 0, 0, NtfsPosition::none()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].role(), 0x0001);
        assert_eq!(list[1].role(), 0x0002);
    }

    #[test]
    fn rejects_protector_list_struct_size_too_small() {
        // struct_size below PROTECTOR_LIST_HEADER_LEN (6) must be rejected.
        // Pins `struct_size < PROTECTOR_LIST_HEADER_LEN`.
        let mut data = Vec::new();
        data.extend_from_slice(&4u32.to_le_bytes()); // struct_size = 4 (< 6)
        data.extend_from_slice(&1u16.to_le_bytes()); // count
        data.extend_from_slice(&[0u8; 16]); // padding so list_end <= data.len
        assert!(parse_protector_list(&data, 0, NtfsPosition::none()).is_err());
    }

    #[test]
    fn v2_buffer_exactly_header_size_parses_header() {
        // data.len() == V2_HEADER_LEN: the `<` size check is false, so the
        // original PROCEEDS past it and fails later parsing the FekInfo /
        // protector list with a DIFFERENT reason. A `< -> <=` mutant would
        // reject HERE with "52-byte V2 header". Asserting the error reason is
        // NOT the header-size one kills `< -> <=`.
        let mut buf = alloc::vec![0u8; V2_HEADER_LEN];
        // FekInfo datum header at 0x28: structure_size = 8, no payload.
        buf[FEK_INFO_OFFSET..FEK_INFO_OFFSET + 2].copy_from_slice(&8u16.to_le_bytes());
        // ddf_offset (0x20) left as 0 -> protector list parse over a zero-size
        // struct -> error, but only reached because the header check passed.
        let err = EfsMetadataV2::parse(&buf, NtfsPosition::none(), 4);
        match err {
            Err(NtfsError::InvalidEfsMetadata { reason, .. }) => {
                assert!(
                    !reason.contains("52-byte V2 header"),
                    "len == V2_HEADER_LEN must pass the size check, got: {reason}"
                );
            }
            other => panic!("expected a post-header parse error, got {other:?}"),
        }
    }
}
