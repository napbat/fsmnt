use alloc::format;
use alloc::string::String;
use core::fmt;
use core::fmt::Write;

use arrayvec::ArrayVec;

use crate::error::{NtfsError, Result};
use crate::types::NtfsPosition;

/// Maximum number of sub-authority values in a SID.
const SID_MAX_SUB_AUTHORITIES: usize = 15;

/// Minimum SID size: 1 (revision) + 1 (count) + 6 (authority) = 8 bytes.
const SID_MIN_SIZE: usize = 8;

/// An NTFS Security Identifier (SID).
///
/// SIDs uniquely identify security principals (users, groups, computers) and are stored
/// in security descriptors on NTFS volumes.
///
/// The binary format uses **mixed endianness**: the identifier authority is big-endian
/// (network byte order) while sub-authority values are little-endian.
///
/// The string representation follows the format: `S-{revision}-{authority}-{sub1}-{sub2}-...`
///
/// Spec reference: MS-DTYP Section 2.4.2 (SID).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsSid {
    revision: u8,
    identifier_authority: [u8; 6],
    sub_authorities: ArrayVec<u32, SID_MAX_SUB_AUTHORITIES>,
}

impl NtfsSid {
    /// Parse a SID from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the SID header or declared sub-authorities are
    /// truncated, or if the SID revision is unsupported.
    pub fn from_bytes(data: &[u8], position: NtfsPosition) -> Result<Self> {
        if data.len() < SID_MIN_SIZE {
            return Err(NtfsError::InvalidSid {
                position,
                reason: "data too short for SID header",
            });
        }

        let revision = data[0];
        let sub_authority_count = usize::from(data[1]);

        if sub_authority_count > SID_MAX_SUB_AUTHORITIES {
            return Err(NtfsError::InvalidSid {
                position,
                reason: "sub-authority count exceeds maximum of 15",
            });
        }

        let expected_size = SID_MIN_SIZE + sub_authority_count * 4;
        if data.len() < expected_size {
            return Err(NtfsError::InvalidSid {
                position,
                reason: "data too short for declared sub-authorities",
            });
        }

        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&data[2..8]);

        let mut sub_authorities = ArrayVec::new();
        for i in 0..sub_authority_count {
            let offset = SID_MIN_SIZE + i * 4;
            let value = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            sub_authorities.push(value);
        }

        Ok(Self {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }

    /// Returns the SID revision (always 1 for current Windows versions).
    #[must_use]
    pub fn revision(&self) -> u8 {
        self.revision
    }

    /// Returns the identifier authority as a u64.
    ///
    /// The on-disk format stores this as a 6-byte big-endian value.
    // mutants::skip: each byte is shifted by a distinct multiple of 8, so the
    // six terms occupy disjoint bit ranges. For disjoint operands `|`, `^` and
    // `+` are identical, making the `| -> ^` swaps on this expression provably
    // equivalent mutants. The shift amounts and the assembled value are pinned
    // by `authority_big_endian_assembly` and the well-known-SID tests.
    #[cfg_attr(test, mutants::skip)]
    #[must_use]
    pub fn authority(&self) -> u64 {
        let a = &self.identifier_authority;
        (u64::from(a[0]) << 40)
            | (u64::from(a[1]) << 32)
            | (u64::from(a[2]) << 24)
            | (u64::from(a[3]) << 16)
            | (u64::from(a[4]) << 8)
            | u64::from(a[5])
    }

    /// Returns the sub-authority values.
    #[must_use]
    pub fn sub_authorities(&self) -> &[u32] {
        &self.sub_authorities
    }

    /// Returns the total size of this SID in bytes.
    #[must_use]
    pub fn byte_size(&self) -> usize {
        SID_MIN_SIZE + self.sub_authorities.len() * 4
    }

    /// Returns a well-known name if this is a recognized SID, or `None`.
    #[must_use]
    pub fn well_known_name(&self) -> Option<&'static str> {
        let auth = self.authority();
        let subs = self.sub_authorities();

        match (auth, subs) {
            (0, &[0]) => Some("Null SID"),
            (1, &[0]) => Some("Everyone"),
            (5, &[18]) => Some("SYSTEM"),
            (5, &[19]) => Some("LOCAL SERVICE"),
            (5, &[20]) => Some("NETWORK SERVICE"),
            (5, &[32, 544]) => Some("Administrators"),
            (5, &[32, 545]) => Some("Users"),
            (5, &[32, 546]) => Some("Guests"),
            (5, &[32, 547]) => Some("Power Users"),
            _ => None,
        }
    }

    /// Formats the SID as a string: `S-{revision}-{authority}-{sub1}-{sub2}-...`
    #[must_use]
    pub fn to_sid_string(&self) -> String {
        let mut s = format!("S-{}", self.revision);

        let auth = self.authority();
        if auth >= (1u64 << 32) {
            // Display as hex with 0x prefix for large authorities (theoretical)
            let _ = write!(s, "-0x{auth:012x}");
        } else {
            let _ = write!(s, "-{auth}");
        }

        for sub in &self.sub_authorities {
            let _ = write!(s, "-{sub}");
        }

        s
    }
}

impl fmt::Display for NtfsSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let auth = self.authority();
        if auth >= (1u64 << 32) {
            write!(f, "S-{}-0x{auth:012x}", self.revision)?;
        } else {
            write!(f, "S-{}-{auth}", self.revision)?;
        }
        for sub in &self.sub_authorities {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsSid {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let revision: u8 = u.arbitrary()?;
        let identifier_authority: [u8; 6] = u.arbitrary()?;
        let count: usize = u.int_in_range(0..=SID_MAX_SUB_AUTHORITIES)?;
        let mut sub_authorities = ArrayVec::new();
        for _ in 0..count {
            sub_authorities.push(u.arbitrary::<u32>()?);
        }
        Ok(Self {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sid_system() {
        // S-1-5-18 (SYSTEM)
        // revision=1, count=1, authority=5 (big-endian: 00 00 00 00 00 05), sub=18 (LE: 12 00 00 00)
        let bytes = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ];
        let sid = NtfsSid::from_bytes(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(sid.revision(), 1);
        assert_eq!(sid.authority(), 5);
        assert_eq!(sid.sub_authorities(), &[18]);
        assert_eq!(sid.byte_size(), 12);
        assert_eq!(sid.to_sid_string(), "S-1-5-18");
        assert_eq!(format!("{sid}"), "S-1-5-18");
        assert_eq!(sid.well_known_name(), Some("SYSTEM"));
    }

    #[test]
    fn test_sid_everyone() {
        // S-1-1-0 (Everyone)
        let bytes = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let sid = NtfsSid::from_bytes(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(sid.to_sid_string(), "S-1-1-0");
        assert_eq!(sid.well_known_name(), Some("Everyone"));
    }

    #[test]
    fn test_sid_administrators() {
        // S-1-5-32-544 (Administrators)
        let bytes = [
            0x01, 0x02, // revision=1, count=2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority=5
            0x20, 0x00, 0x00, 0x00, // sub=32
            0x20, 0x02, 0x00, 0x00, // sub=544
        ];
        let sid = NtfsSid::from_bytes(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(sid.to_sid_string(), "S-1-5-32-544");
        assert_eq!(sid.well_known_name(), Some("Administrators"));
    }

    #[test]
    fn test_sid_domain_user() {
        // S-1-5-21-123456789-987654321-111222333-500 (domain Administrator)
        let bytes = [
            0x01, 0x04, // revision=1, count=4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority=5
            0x15, 0x00, 0x00, 0x00, // sub=21
            0x15, 0xCD, 0x5B, 0x07, // sub=123456789
            0xB1, 0x68, 0xDE, 0x3A, // sub=987654321
            0x3D, 0x1E, 0xA1, 0x06, // sub=111222333
        ];
        let sid = NtfsSid::from_bytes(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(
            sid.to_sid_string(),
            "S-1-5-21-123456789-987654321-111222333"
        );
        assert_eq!(sid.well_known_name(), None);
    }

    #[test]
    fn test_sid_too_short() {
        let bytes = [0x01, 0x01, 0x00, 0x00];
        assert!(NtfsSid::from_bytes(&bytes, NtfsPosition::none()).is_err());
    }

    #[test]
    fn test_sid_count_exceeds_data() {
        // Says 2 sub-authorities but only has data for 1
        let bytes = [
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ];
        assert!(NtfsSid::from_bytes(&bytes, NtfsPosition::none()).is_err());
    }

    #[test]
    fn from_bytes_min_size_boundary() {
        // Exactly SID_MIN_SIZE (8) with zero sub-authorities must parse;
        // anchors the `data.len() < SID_MIN_SIZE` boundary at line 37.
        let exactly_min = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        let sid = NtfsSid::from_bytes(&exactly_min, NtfsPosition::none()).unwrap();
        assert_eq!(sid.byte_size(), 8);
        assert!(sid.sub_authorities().is_empty());

        // One byte short (7) must be rejected.
        let one_short = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(NtfsSid::from_bytes(&one_short, NtfsPosition::none()).is_err());
    }

    #[test]
    fn from_bytes_sub_authority_count_boundary() {
        // Exactly SID_MAX_SUB_AUTHORITIES (15) must parse, anchoring the
        // `> SID_MAX_SUB_AUTHORITIES` boundary at line 47 (count == 15 is OK).
        let mut at_max = vec![0x01, 15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        at_max.extend(core::iter::repeat_n(0x00, 15 * 4));
        let sid = NtfsSid::from_bytes(&at_max, NtfsPosition::none()).unwrap();
        assert_eq!(sid.sub_authorities().len(), 15);

        // 16 sub-authorities must be rejected (one over the max).
        let mut over_max = vec![0x01, 16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        over_max.extend(core::iter::repeat_n(0x00, 16 * 4));
        assert!(NtfsSid::from_bytes(&over_max, NtfsPosition::none()).is_err());
    }

    #[test]
    fn revision_is_parsed_verbatim() {
        // revision byte = 2 (distinct from the common value 1) so a
        // `revision -> 1` replacement is observable.
        let bytes = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        let sid = NtfsSid::from_bytes(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(sid.revision(), 2);
    }

    #[test]
    fn authority_big_endian_assembly() {
        // 6-byte big-endian authority with a distinct nonzero byte in every
        // position: 0x01 0x02 0x03 0x04 0x05 0x06 -> 0x010203040506.
        // Every byte lands in a different position, so a wrong shift amount,
        // a dropped `<<`, or an `&` in place of `|` changes the result.
        let bytes = [0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut data = bytes.to_vec();
        data.extend(core::iter::repeat_n(0x00, 6 * 4)); // 6 sub-authorities
        let sid = NtfsSid::from_bytes(&data, NtfsPosition::none()).unwrap();
        assert_eq!(sid.authority(), 0x0000_0102_0304_0506);
    }

    #[test]
    fn well_known_name_each_arm() {
        // One fixture per well_known_name match arm so deleting any arm
        // changes the returned name. Each tuple is (authority, sub-auths).
        fn make_sid(authority: u8, subs: &[u32]) -> NtfsSid {
            let mut data = vec![
                0x01,
                u8::try_from(subs.len()).expect("test value fits u8"),
                0,
                0,
                0,
                0,
                0,
                authority,
            ];
            for sub in subs {
                data.extend_from_slice(&sub.to_le_bytes());
            }
            NtfsSid::from_bytes(&data, NtfsPosition::none()).unwrap()
        }

        assert_eq!(make_sid(0, &[0]).well_known_name(), Some("Null SID"));
        assert_eq!(make_sid(1, &[0]).well_known_name(), Some("Everyone"));
        assert_eq!(make_sid(5, &[18]).well_known_name(), Some("SYSTEM"));
        assert_eq!(make_sid(5, &[19]).well_known_name(), Some("LOCAL SERVICE"));
        assert_eq!(
            make_sid(5, &[20]).well_known_name(),
            Some("NETWORK SERVICE")
        );
        assert_eq!(
            make_sid(5, &[32, 544]).well_known_name(),
            Some("Administrators")
        );
        assert_eq!(make_sid(5, &[32, 545]).well_known_name(), Some("Users"));
        assert_eq!(make_sid(5, &[32, 546]).well_known_name(), Some("Guests"));
        assert_eq!(
            make_sid(5, &[32, 547]).well_known_name(),
            Some("Power Users")
        );
        // An unrecognized tuple returns None.
        assert_eq!(make_sid(5, &[99]).well_known_name(), None);
    }
}
