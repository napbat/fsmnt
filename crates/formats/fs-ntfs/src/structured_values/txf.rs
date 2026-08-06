//! Transactional NTFS (TxF) per-file metadata (`$TXF_DATA`).
//!
//! When a file or directory takes part in a TxF transaction, NTFS
//! attaches a `$TXF_DATA` attribute — a `$LOGGED_UTILITY_STREAM` (0x100)
//! named `$TXF_DATA`. The attribute is a fixed 56-byte structure that
//! identifies the transaction and points, via three Common Log File
//! System (CLFS) Log Sequence Numbers, at the records describing the
//! file's data, metadata, and directory-index changes.
//!
//! TxF is deprecated, but the attribute survives on modern NTFS volumes
//! and is forensically useful: its presence shows a file participated in
//! a transaction, and the LSN fields reveal which CLFS streams hold the
//! corresponding records. This module parses the attribute only — the
//! CLFS log (`$TxfLog.blf`) is a separate container outside
//! `$LOGGED_UTILITY_STREAM` and is not read here.
//!
//! Layout reference: libyal `libfsntfs` NTFS documentation; CLFS LSN
//! format from the `ionescu007/clfs-docs` reverse-engineering notes.

use crate::error::{NtfsError, Result};
use crate::file_reference::NtfsFileReference;
use crate::types::NtfsPosition;

/// Size of a `$TXF_DATA` attribute; it is always exactly this long.
const TXF_DATA_LEN: usize = 56;

/// A Common Log File System (CLFS) Log Sequence Number.
///
/// A 64-bit value addressing a record in the TxF CLFS log. The low 32
/// bits split into a record number (bits 0-8) and the block offset
/// within the container (bits 9-31); the high 32 bits are the logical
/// container identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClfsLsn(u64);

impl ClfsLsn {
    /// The CLFS null LSN — the stream has no associated record.
    pub const NULL: ClfsLsn = ClfsLsn(0);
    /// The CLFS invalid LSN sentinel.
    pub const INVALID: ClfsLsn = ClfsLsn(0x0000_0000_FFFF_FFFF);

    /// Wraps a raw 64-bit LSN value.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw 64-bit LSN value.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Whether this is the null LSN (no record).
    pub fn is_null(self) -> bool {
        self.0 == Self::NULL.0
    }

    /// Whether this is the invalid-LSN sentinel.
    pub fn is_invalid(self) -> bool {
        self.0 == Self::INVALID.0
    }

    /// Whether this LSN references an actual CLFS log record.
    pub fn is_present(self) -> bool {
        !self.is_null() && !self.is_invalid()
    }

    /// The record number within the block (bits 0-8).
    pub fn record_number(self) -> u16 {
        (self.0 & 0x1FF) as u16
    }

    /// The byte offset of the containing CLFS block within its container.
    ///
    /// The LSN encodes the block as a 23-bit index (bits 9-31) of
    /// 512-byte CLFS blocks; this returns that index scaled to a byte
    /// address, which is the form CLFS uses to locate records in a
    /// container such as `$TxfLog.blf`.
    pub fn block_offset(self) -> u32 {
        (((self.0 >> 9) & 0x7F_FFFF) << 9) as u32
    }

    /// The logical container identifier (high 32 bits).
    pub fn container_id(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

/// Parsed `$TXF_DATA` per-file TxF metadata.
///
/// Obtain via [`NtfsLoggedUtilityStream::parse_txf`].
///
/// [`NtfsLoggedUtilityStream::parse_txf`]:
/// crate::structured_values::NtfsLoggedUtilityStream::parse_txf
#[derive(Clone, Debug)]
pub struct NtfsTxfData {
    rm_root_reference: NtfsFileReference,
    txf_id: u64,
    data_lsn: ClfsLsn,
    metadata_lsn: ClfsLsn,
    directory_index_lsn: ClfsLsn,
    flags: u16,
    position: NtfsPosition,
}

impl NtfsTxfData {
    /// Parses a `$TXF_DATA` attribute from the bytes of its
    /// `$LOGGED_UTILITY_STREAM`.
    pub fn parse(data: &[u8], position: NtfsPosition) -> Result<Self> {
        if data.len() < TXF_DATA_LEN {
            return Err(NtfsError::InvalidTxfData {
                position,
                reason: "$TXF_DATA attribute is shorter than 56 bytes",
            });
        }

        let mut ref_bytes = [0u8; 8];
        ref_bytes.copy_from_slice(&data[6..14]);

        Ok(Self {
            rm_root_reference: NtfsFileReference::new(ref_bytes),
            txf_id: le_u64(data, 22),
            data_lsn: ClfsLsn::from_raw(le_u64(data, 30)),
            metadata_lsn: ClfsLsn::from_raw(le_u64(data, 38)),
            directory_index_lsn: ClfsLsn::from_raw(le_u64(data, 46)),
            flags: le_u16(data, 54),
            position,
        })
    }

    /// File reference of the resource manager root that owns this
    /// transaction (typically `$Extend\$RmMetadata`).
    pub fn rm_root_reference(&self) -> NtfsFileReference {
        self.rm_root_reference
    }

    /// The TxF transaction identifier (`TxID`) for this file.
    pub fn txf_id(&self) -> u64 {
        self.txf_id
    }

    /// CLFS LSN of the records describing this file's data changes.
    pub fn data_lsn(&self) -> ClfsLsn {
        self.data_lsn
    }

    /// CLFS LSN of the records describing this file's metadata changes.
    pub fn metadata_lsn(&self) -> ClfsLsn {
        self.metadata_lsn
    }

    /// CLFS LSN of the records describing directory-index changes.
    pub fn directory_index_lsn(&self) -> ClfsLsn {
        self.directory_index_lsn
    }

    /// The raw `Flags` field.
    ///
    /// Observed values are 0x0000 and 0x0002; the semantics are not
    /// publicly documented, so the field is exposed verbatim.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// The absolute byte position of the `$TXF_DATA` attribute, if known.
    pub fn position(&self) -> NtfsPosition {
        self.position
    }
}

/// Reads a little-endian `u64` at `offset`; the caller guarantees range.
fn le_u64(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        d[o],
        d[o + 1],
        d[o + 2],
        d[o + 3],
        d[o + 4],
        d[o + 5],
        d[o + 6],
        d[o + 7],
    ])
}

/// Reads a little-endian `u16` at `offset`; the caller guarantees range.
fn le_u16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a 56-byte `$TXF_DATA` attribute with the given field values.
    fn build_txf_data(
        rm_ref: u64,
        txf_id: u64,
        data_lsn: u64,
        metadata_lsn: u64,
        dir_lsn: u64,
        flags: u16,
    ) -> [u8; TXF_DATA_LEN] {
        let mut buf = [0u8; TXF_DATA_LEN];
        buf[6..14].copy_from_slice(&rm_ref.to_le_bytes());
        buf[22..30].copy_from_slice(&txf_id.to_le_bytes());
        buf[30..38].copy_from_slice(&data_lsn.to_le_bytes());
        buf[38..46].copy_from_slice(&metadata_lsn.to_le_bytes());
        buf[46..54].copy_from_slice(&dir_lsn.to_le_bytes());
        buf[54..56].copy_from_slice(&flags.to_le_bytes());
        buf
    }

    #[test]
    fn parses_all_fields() {
        // RM root file reference: record 27, sequence 1.
        let rm_ref = 27u64 | (1u64 << 48);
        let buf = build_txf_data(
            rm_ref,
            0xABCD_1234,
            0x0000_0001_0000_0042,
            0,
            ClfsLsn::INVALID.raw(),
            0x0002,
        );

        let txf = NtfsTxfData::parse(&buf, NtfsPosition::new(0x500)).unwrap();
        assert_eq!(txf.rm_root_reference().file_record_number(), 27);
        assert_eq!(txf.rm_root_reference().sequence_number(), 1);
        assert_eq!(txf.txf_id(), 0xABCD_1234);
        assert!(txf.data_lsn().is_present());
        assert!(txf.metadata_lsn().is_null());
        assert!(txf.directory_index_lsn().is_invalid());
        assert_eq!(txf.flags(), 0x0002);
        assert_eq!(txf.position(), NtfsPosition::new(0x500));
    }

    #[test]
    fn rejects_short_attribute() {
        let buf = [0u8; 40];
        assert!(NtfsTxfData::parse(&buf, NtfsPosition::none()).is_err());
    }

    #[test]
    fn accepts_buffer_longer_than_56_bytes() {
        let mut buf = alloc::vec::Vec::from(build_txf_data(0, 7, 0, 0, 0, 0));
        buf.extend_from_slice(&[0xFFu8; 8]);
        let txf = NtfsTxfData::parse(&buf, NtfsPosition::none()).unwrap();
        assert_eq!(txf.txf_id(), 7);
    }

    #[test]
    fn clfs_lsn_field_extraction() {
        // record number 0x1AB (bits 0-8), block index 0x55 (bits 9-31),
        // container id 0x1234 (high 32 bits).
        let raw = 0x1ABu64 | (0x55u64 << 9) | (0x1234u64 << 32);
        let lsn = ClfsLsn::from_raw(raw);
        assert_eq!(lsn.record_number(), 0x1AB);
        // block_offset is the block index scaled to a byte address.
        assert_eq!(lsn.block_offset(), 0x55 << 9);
        assert_eq!(lsn.container_id(), 0x1234);
        assert!(lsn.is_present());
    }

    #[test]
    fn le_helpers_read_each_byte_position() {
        // Sixteen distinct bytes read at offset 7 so every `o + k` index lands
        // on a unique byte (and any `+` -> `-` flip reads a different,
        // in-range byte rather than panicking).
        let bytes: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ];
        assert_eq!(le_u64(&bytes, 7), 0x1E1D_1C1B_1A19_1817);

        // le_u16 reads d[o] and d[o + 1]; offset 7 selects bytes 7 and 8.
        assert_eq!(le_u16(&bytes, 7), 0x1817);
    }

    #[test]
    fn clfs_lsn_special_values() {
        assert!(ClfsLsn::NULL.is_null());
        assert!(!ClfsLsn::NULL.is_present());
        assert!(ClfsLsn::INVALID.is_invalid());
        assert!(!ClfsLsn::INVALID.is_present());
        assert!(!ClfsLsn::from_raw(1).is_null());
    }
}
