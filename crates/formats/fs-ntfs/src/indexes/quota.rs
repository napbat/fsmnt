use core::fmt;

use crate::error::{NtfsError, Result};
use crate::indexes::{NtfsIndexEntryData, NtfsIndexEntryHasData, NtfsIndexEntryType};
use crate::structured_values::NtfsSid;
use crate::types::NtfsPosition;

use super::NtfsIndexEntryKey;

/// Minimum size of a QUOTA_CONTROL_ENTRY before the variable-length SID:
/// version(4) + flags(4) + quota_used(8) + change_time(8)
/// + quota_threshold(8) + quota_limit(8) + exceeded_time(8) = 48 bytes.
const QUOTA_CONTROL_FIXED_SIZE: usize = 48;

/// Defines the [`NtfsIndexEntryType`] for $Q (Quota) index entries
/// in the `$Quota` system file.
#[derive(Clone, Copy, Debug)]
pub struct NtfsQuotaQIndex;

impl NtfsIndexEntryType for NtfsQuotaQIndex {
    type KeyType = NtfsQuotaOwnerIdKey;
}

impl NtfsIndexEntryHasData for NtfsQuotaQIndex {
    type DataType = NtfsQuotaControlData;
}

/// The key type for $Q index entries: a u32 owner ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsQuotaOwnerIdKey {
    owner_id: u32,
}

impl NtfsQuotaOwnerIdKey {
    /// Returns the owner ID.
    pub fn owner_id(&self) -> u32 {
        self.owner_id
    }
}

impl NtfsIndexEntryKey for NtfsQuotaOwnerIdKey {
    impl_fixed_size_key_ref!();

    fn key_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        if slice.len() < 4 {
            return Err(NtfsError::InvalidQuotaEntry {
                position,
                reason: "$Q key too short (expected 4 bytes)",
            });
        }
        let owner_id = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        Ok(Self { owner_id })
    }
}

impl fmt::Display for NtfsQuotaOwnerIdKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OwnerId({})", self.owner_id)
    }
}

/// The data type for $Q index entries: a QUOTA_CONTROL_ENTRY
/// containing version, flags, usage, timestamps, thresholds,
/// and the owner SID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsQuotaControlData {
    version: u32,
    flags: u32,
    quota_used: u64,
    change_time: i64,
    quota_threshold: i64,
    quota_limit: i64,
    exceeded_time: i64,
    sid: NtfsSid,
}

impl NtfsQuotaControlData {
    /// Returns the version of the quota entry (expected to be 2).
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the quota flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the number of bytes charged against this quota.
    pub fn quota_used(&self) -> u64 {
        self.quota_used
    }

    /// Returns the change time as a raw NTFS timestamp (100-ns
    /// intervals since 1601-01-01).
    pub fn change_time(&self) -> i64 {
        self.change_time
    }

    /// Returns the warning threshold in bytes (-1 means no limit).
    pub fn quota_threshold(&self) -> i64 {
        self.quota_threshold
    }

    /// Returns the hard limit in bytes (-1 means no limit).
    pub fn quota_limit(&self) -> i64 {
        self.quota_limit
    }

    /// Returns the time at which the quota was last exceeded
    /// (0 if never exceeded).
    pub fn exceeded_time(&self) -> i64 {
        self.exceeded_time
    }

    /// Returns the SID of the quota owner.
    pub fn sid(&self) -> &NtfsSid {
        &self.sid
    }
}

impl NtfsIndexEntryData for NtfsQuotaControlData {
    fn data_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        if slice.len() < QUOTA_CONTROL_FIXED_SIZE {
            return Err(NtfsError::InvalidQuotaEntry {
                position,
                reason: "$Q data too short for fixed fields \
                         (expected at least 48 bytes)",
            });
        }

        let version = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        let flags = u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
        let quota_used = u64::from_le_bytes([
            slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14], slice[15],
        ]);
        let change_time = i64::from_le_bytes([
            slice[16], slice[17], slice[18], slice[19], slice[20], slice[21], slice[22], slice[23],
        ]);
        let quota_threshold = i64::from_le_bytes([
            slice[24], slice[25], slice[26], slice[27], slice[28], slice[29], slice[30], slice[31],
        ]);
        let quota_limit = i64::from_le_bytes([
            slice[32], slice[33], slice[34], slice[35], slice[36], slice[37], slice[38], slice[39],
        ]);
        let exceeded_time = i64::from_le_bytes([
            slice[40], slice[41], slice[42], slice[43], slice[44], slice[45], slice[46], slice[47],
        ]);

        let sid = NtfsSid::from_bytes(&slice[QUOTA_CONTROL_FIXED_SIZE..], position)?;

        Ok(Self {
            version,
            flags,
            quota_used,
            change_time,
            quota_threshold,
            quota_limit,
            exceeded_time,
            sid,
        })
    }
}

impl fmt::Display for NtfsQuotaControlData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Quota(ver={}, flags={:#x}, used={}, threshold={}, \
             limit={}, sid={})",
            self.version,
            self.flags,
            self.quota_used,
            self.quota_threshold,
            self.quota_limit,
            self.sid,
        )
    }
}

/// Defines the [`NtfsIndexEntryType`] for $O (Owner) index entries
/// in the `$Quota` system file. The $O index maps SIDs to owner IDs.
#[derive(Clone, Copy, Debug)]
pub struct NtfsQuotaOIndex;

impl NtfsIndexEntryType for NtfsQuotaOIndex {
    type KeyType = NtfsQuotaSidKey;
}

impl NtfsIndexEntryHasData for NtfsQuotaOIndex {
    type DataType = NtfsQuotaOwnerIdData;
}

/// The key type for $O index entries: a variable-length SID
/// identifying the quota owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsQuotaSidKey {
    sid: NtfsSid,
}

impl NtfsQuotaSidKey {
    /// Returns the SID of the quota owner.
    pub fn sid(&self) -> &NtfsSid {
        &self.sid
    }
}

impl NtfsIndexEntryKey for NtfsQuotaSidKey {
    impl_fixed_size_key_ref!();

    fn key_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        let sid = NtfsSid::from_bytes(slice, position)?;
        Ok(Self { sid })
    }
}

impl fmt::Display for NtfsQuotaSidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuotaSid({})", self.sid)
    }
}

/// The data type for $O index entries: a u32 owner ID that maps
/// back to the corresponding $Q index entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsQuotaOwnerIdData {
    owner_id: u32,
}

impl NtfsQuotaOwnerIdData {
    /// Returns the owner ID.
    pub fn owner_id(&self) -> u32 {
        self.owner_id
    }
}

impl NtfsIndexEntryData for NtfsQuotaOwnerIdData {
    fn data_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        if slice.len() < 4 {
            return Err(NtfsError::InvalidQuotaEntry {
                position,
                reason: "$O data too short (expected 4 bytes)",
            });
        }
        let owner_id = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        Ok(Self { owner_id })
    }
}

impl fmt::Display for NtfsQuotaOwnerIdData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OwnerId({})", self.owner_id)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// Builds the 12-byte binary SID for S-1-5-18 (SYSTEM).
    fn system_sid_bytes() -> [u8; 12] {
        [
            0x01, 0x01, // revision=1, sub_authority_count=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority=5
            0x12, 0x00, 0x00, 0x00, // sub_authority=18
        ]
    }

    /// Assembles a complete QUOTA_CONTROL_ENTRY with the given SID
    /// appended after the 48-byte fixed header.
    fn build_quota_control_data(sid: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(QUOTA_CONTROL_FIXED_SIZE + sid.len());
        // version = 2
        buf.extend_from_slice(&2u32.to_le_bytes());
        // flags = 0x0000_0001
        buf.extend_from_slice(&1u32.to_le_bytes());
        // quota_used = 1024
        buf.extend_from_slice(&1024u64.to_le_bytes());
        // change_time = 132_500_000_000_000_000
        buf.extend_from_slice(&132_500_000_000_000_000i64.to_le_bytes());
        // quota_threshold = -1 (no limit)
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        // quota_limit = -1 (no limit)
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        // exceeded_time = 0 (never exceeded)
        buf.extend_from_slice(&0i64.to_le_bytes());
        // SID
        buf.extend_from_slice(sid);
        buf
    }

    #[test]
    fn q_key_parse_valid() {
        let bytes = 42u32.to_le_bytes();
        let key = NtfsQuotaOwnerIdKey::key_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(key.owner_id(), 42);
    }

    #[test]
    fn q_key_reject_truncated() {
        let bytes = [0xAA, 0xBB, 0xCC]; // only 3 bytes
        let result = NtfsQuotaOwnerIdKey::key_from_slice(&bytes, NtfsPosition::none());
        assert!(result.is_err());
    }

    #[test]
    fn q_data_parse_valid() {
        let sid = system_sid_bytes();
        let buf = build_quota_control_data(&sid);
        let data = NtfsQuotaControlData::data_from_slice(&buf, NtfsPosition::none()).unwrap();

        assert_eq!(data.version(), 2);
        assert_eq!(data.flags(), 1);
        assert_eq!(data.quota_used(), 1024);
        assert_eq!(data.change_time(), 132_500_000_000_000_000);
        assert_eq!(data.quota_threshold(), -1);
        assert_eq!(data.quota_limit(), -1);
        assert_eq!(data.exceeded_time(), 0);
        assert_eq!(data.sid().to_sid_string(), "S-1-5-18");
    }

    #[test]
    fn q_data_reject_truncated() {
        let bytes = [0u8; 20]; // well under 48 bytes
        let result = NtfsQuotaControlData::data_from_slice(&bytes, NtfsPosition::none());
        assert!(result.is_err());
    }

    #[test]
    fn o_key_parse_valid() {
        let sid_bytes = system_sid_bytes();
        let key = NtfsQuotaSidKey::key_from_slice(&sid_bytes, NtfsPosition::none())
            .expect("should parse valid $O key");
        assert_eq!(key.sid().to_sid_string(), "S-1-5-18");
    }

    #[test]
    fn o_key_reject_truncated() {
        let bytes = [0x01, 0x01, 0x00];
        let result = NtfsQuotaSidKey::key_from_slice(&bytes, NtfsPosition::new(0x300));
        assert!(result.is_err());
    }

    #[test]
    fn o_data_parse_valid() {
        let bytes = 99u32.to_le_bytes();
        let data = NtfsQuotaOwnerIdData::data_from_slice(&bytes, NtfsPosition::none())
            .expect("should parse valid $O data");
        assert_eq!(data.owner_id(), 99);
    }

    #[test]
    fn o_data_reject_truncated() {
        let bytes = [0u8; 3];
        let result = NtfsQuotaOwnerIdData::data_from_slice(&bytes, NtfsPosition::new(0x400));
        assert!(result.is_err());
    }

    #[test]
    fn q_data_reject_missing_sid() {
        // Exactly 48 bytes (fixed header) with no SID data
        let bytes = [0u8; QUOTA_CONTROL_FIXED_SIZE];
        let result = NtfsQuotaControlData::data_from_slice(&bytes, NtfsPosition::none());
        assert!(result.is_err());
    }

    #[test]
    fn q_data_boundary_length_passes_fixed_check() {
        // A slice of exactly the fixed size passes the `len() < 48` check
        // (so the failure is in SID parsing — InvalidSid — not the length
        // guard). With `<=` the guard would fire first (InvalidQuotaEntry),
        // pinning the boundary comparison.
        let bytes = [0u8; QUOTA_CONTROL_FIXED_SIZE];
        let err = NtfsQuotaControlData::data_from_slice(&bytes, NtfsPosition::none()).unwrap_err();
        match err {
            NtfsError::InvalidSid { .. } => {}
            other => panic!("expected InvalidSid (length guard passed), got {other:?}"),
        }

        // One byte short must fail the fixed-size guard itself.
        let short = [0u8; QUOTA_CONTROL_FIXED_SIZE - 1];
        let err = NtfsQuotaControlData::data_from_slice(&short, NtfsPosition::none()).unwrap_err();
        match err {
            NtfsError::InvalidQuotaEntry { .. } => {}
            other => panic!("expected InvalidQuotaEntry for too-short slice, got {other:?}"),
        }
    }

    #[test]
    fn q_data_distinct_field_values() {
        // Distinct, non-default values so per-accessor return-value
        // replacements (flags->1, threshold->-1, limit->-1, exceeded->0)
        // are observably wrong.
        let sid = system_sid_bytes();
        let mut buf = Vec::with_capacity(QUOTA_CONTROL_FIXED_SIZE + sid.len());
        buf.extend_from_slice(&2u32.to_le_bytes()); // version = 2
        buf.extend_from_slice(&0x0000_0202u32.to_le_bytes()); // flags = 0x202 (!= 0/1)
        buf.extend_from_slice(&4096u64.to_le_bytes()); // quota_used
        buf.extend_from_slice(&100i64.to_le_bytes()); // change_time
        buf.extend_from_slice(&8_000_000i64.to_le_bytes()); // quota_threshold (!= -1)
        buf.extend_from_slice(&16_000_000i64.to_le_bytes()); // quota_limit (!= -1)
        buf.extend_from_slice(&999i64.to_le_bytes()); // exceeded_time (!= 0)
        buf.extend_from_slice(&sid);

        let data = NtfsQuotaControlData::data_from_slice(&buf, NtfsPosition::none()).unwrap();
        assert_eq!(data.flags(), 0x0000_0202);
        assert_eq!(data.quota_threshold(), 8_000_000);
        assert_eq!(data.quota_limit(), 16_000_000);
        assert_eq!(data.exceeded_time(), 999);
    }

    #[test]
    fn display_impls() {
        let q_key = NtfsQuotaOwnerIdKey::key_from_slice(&42u32.to_le_bytes(), NtfsPosition::none())
            .unwrap();
        assert_eq!(format!("{q_key}"), "OwnerId(42)");

        let sid_bytes = system_sid_bytes();
        let q_data = NtfsQuotaControlData::data_from_slice(
            &build_quota_control_data(&sid_bytes),
            NtfsPosition::none(),
        )
        .unwrap();
        let display = format!("{q_data}");
        assert!(display.contains("S-1-5-18"));

        let o_key = NtfsQuotaSidKey::key_from_slice(&sid_bytes, NtfsPosition::none()).unwrap();
        assert!(format!("{o_key}").contains("S-1-5-18"));

        let o_data =
            NtfsQuotaOwnerIdData::data_from_slice(&99u32.to_le_bytes(), NtfsPosition::none())
                .unwrap();
        assert_eq!(format!("{o_data}"), "OwnerId(99)");
    }
}
