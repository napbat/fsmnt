use core::fmt;

use bitflags::bitflags;

use crate::error::{NtfsError, Result};
use crate::types::NtfsPosition;

use super::sid::NtfsSid;

/// Minimum ACL header size: revision(1) + padding(1) + size(2) + `ace_count(2)` + padding(2) = 8.
const ACL_HEADER_SIZE: usize = 8;

/// Minimum ACE header size: type(1) + flags(1) + size(2) = 4.
const ACE_HEADER_SIZE: usize = 4;

/// A parsed NTFS Access Control List (ACL).
///
/// An ACL contains a list of Access Control Entries (ACEs) that define permissions
/// for a security principal on an NTFS object.
///
/// Spec reference: MS-DTYP Section 2.4.5 (ACL).
#[derive(Clone, Debug)]
pub struct NtfsAcl<'s> {
    data: &'s [u8],
    position: NtfsPosition,
}

impl<'s> NtfsAcl<'s> {
    /// Parse an ACL from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the ACL header is truncated or its declared size is
    /// smaller than the header or exceeds `data`.
    pub fn from_bytes(data: &'s [u8], position: NtfsPosition) -> Result<Self> {
        if data.len() < ACL_HEADER_SIZE {
            return Err(NtfsError::InvalidAcl {
                position,
                reason: "data too short for ACL header",
            });
        }

        let acl_size = usize::from(u16::from_le_bytes([data[2], data[3]]));
        if acl_size < ACL_HEADER_SIZE {
            return Err(NtfsError::InvalidAcl {
                position,
                reason: "declared ACL size is smaller than ACL header",
            });
        }
        if acl_size > data.len() {
            return Err(NtfsError::InvalidAcl {
                position,
                reason: "declared ACL size exceeds available data",
            });
        }

        Ok(Self {
            data: &data[..acl_size],
            position,
        })
    }

    /// Returns the ACL revision (2 for standard ACLs, 4 for ACLs with object-specific ACE types).
    #[must_use]
    pub fn revision(&self) -> u8 {
        self.data[0]
    }

    /// Returns the total size of the ACL in bytes (including the header).
    #[must_use]
    pub fn size(&self) -> u16 {
        u16::from_le_bytes([self.data[2], self.data[3]])
    }

    /// Returns the number of ACEs in this ACL.
    #[must_use]
    pub fn ace_count(&self) -> u16 {
        u16::from_le_bytes([self.data[4], self.data[5]])
    }

    /// Returns an iterator over the ACEs in this ACL.
    #[must_use]
    pub fn entries(&self) -> NtfsAceIterator<'s> {
        NtfsAceIterator {
            data: self.data,
            position: self.position,
            offset: ACL_HEADER_SIZE,
            remaining: self.ace_count(),
        }
    }
}

/// An iterator over Access Control Entries (ACEs) in an ACL.
#[derive(Clone, Debug)]
pub struct NtfsAceIterator<'s> {
    data: &'s [u8],
    position: NtfsPosition,
    offset: usize,
    remaining: u16,
}

impl<'s> Iterator for NtfsAceIterator<'s> {
    type Item = Result<NtfsAce<'s>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        self.remaining -= 1;

        if self.offset + ACE_HEADER_SIZE > self.data.len() {
            self.remaining = 0;
            return Some(Err(NtfsError::InvalidAce {
                position: self.position,
                reason: "ACE header extends beyond ACL data",
            }));
        }

        let ace_size = usize::from(u16::from_le_bytes([
            self.data[self.offset + 2],
            self.data[self.offset + 3],
        ]));

        if ace_size < ACE_HEADER_SIZE {
            self.remaining = 0;
            return Some(Err(NtfsError::InvalidAce {
                position: self.position,
                reason: "ACE size smaller than header",
            }));
        }

        if self.offset + ace_size > self.data.len() {
            self.remaining = 0;
            return Some(Err(NtfsError::InvalidAce {
                position: self.position,
                reason: "ACE extends beyond ACL data",
            }));
        }

        let ace_data = &self.data[self.offset..self.offset + ace_size];
        self.offset += ace_size;

        Some(Ok(NtfsAce {
            data: ace_data,
            position: self.position,
        }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(usize::from(self.remaining)))
    }
}

/// A parsed NTFS Access Control Entry (ACE).
///
/// An ACE defines a single permission grant or denial for a specific security principal (SID).
///
/// Spec reference: MS-DTYP Section 2.4.4 (ACE).
#[derive(Clone, Debug)]
pub struct NtfsAce<'s> {
    data: &'s [u8],
    position: NtfsPosition,
}

impl NtfsAce<'_> {
    /// Returns the ACE type.
    #[must_use]
    pub fn ace_type(&self) -> NtfsAceType {
        NtfsAceType::n(self.data[0]).unwrap_or(NtfsAceType::Unknown)
    }

    /// Returns the raw ACE type byte (useful when the type is not recognized).
    #[must_use]
    pub fn ace_type_raw(&self) -> u8 {
        self.data[0]
    }

    /// Returns the ACE flags.
    #[must_use]
    pub fn flags(&self) -> NtfsAceFlags {
        NtfsAceFlags::from_bits_truncate(self.data[1])
    }

    /// Returns the total size of this ACE in bytes.
    #[must_use]
    pub fn size(&self) -> u16 {
        u16::from_le_bytes([self.data[2], self.data[3]])
    }

    /// Returns the access mask (permission bits).
    ///
    /// Only valid for basic ACE types (`AccessAllowed`, `AccessDenied`, `SystemAudit`, `SystemAlarm`).
    /// For other ACE types, the body layout differs.
    ///
    /// # Errors
    ///
    /// Returns an error if the ACE is too short to contain an access mask.
    pub fn access_mask(&self) -> Result<u32> {
        if self.data.len() < ACE_HEADER_SIZE + 4 {
            return Err(NtfsError::InvalidAce {
                position: self.position,
                reason: "ACE too short for access mask",
            });
        }
        Ok(u32::from_le_bytes([
            self.data[4],
            self.data[5],
            self.data[6],
            self.data[7],
        ]))
    }

    /// Returns the SID that this ACE applies to.
    ///
    /// Only valid for basic ACE types (`AccessAllowed`, `AccessDenied`, `SystemAudit`, `SystemAlarm`).
    /// The SID starts immediately after the 4-byte access mask.
    ///
    /// # Errors
    ///
    /// Returns an error if the ACE is too short to contain a SID or the SID is
    /// malformed.
    pub fn sid(&self) -> Result<NtfsSid> {
        let sid_offset = ACE_HEADER_SIZE + 4; // header + access_mask
        if self.data.len() < sid_offset + 8 {
            return Err(NtfsError::InvalidAce {
                position: self.position,
                reason: "ACE too short for SID",
            });
        }
        NtfsSid::from_bytes(&self.data[sid_offset..], self.position)
    }
}

/// The type of an Access Control Entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NtfsAceType {
    /// Grants the rights encoded in the access mask.
    AccessAllowed = 0,
    /// Denies the rights encoded in the access mask.
    AccessDenied = 1,
    /// Requests auditing when the encoded access is attempted.
    SystemAudit = 2,
    /// Represents the legacy system-alarm ACE form.
    SystemAlarm = 3,
    /// Represents a compound allow ACE carrying server and client identities.
    AccessAllowedCompound = 4,
    /// Grants rights to a specific object type.
    AccessAllowedObject = 5,
    /// Denies rights to a specific object type.
    AccessDeniedObject = 6,
    /// Audits access to a specific object type.
    SystemAuditObject = 7,
    /// Represents the object-specific system-alarm ACE form.
    SystemAlarmObject = 8,
    /// Grants rights and carries application callback data.
    AccessAllowedCallback = 9,
    /// Denies rights and carries application callback data.
    AccessDeniedCallback = 10,
    /// Grants object-specific rights and carries callback data.
    AccessAllowedCallbackObject = 11,
    /// Denies object-specific rights and carries callback data.
    AccessDeniedCallbackObject = 12,
    /// Audits access and carries application callback data.
    SystemAuditCallback = 13,
    /// Represents a callback-capable system-alarm ACE.
    SystemAlarmCallback = 14,
    /// Audits object-specific access and carries callback data.
    SystemAuditCallbackObject = 15,
    /// Represents an object-specific callback system-alarm ACE.
    SystemAlarmCallbackObject = 16,
    /// Carries an integrity level used by mandatory access control.
    SystemMandatoryLabel = 17,
    /// Carries resource claims used by conditional access checks.
    SystemResourceAttribute = 18,
    /// Associates the object with a central access policy.
    SystemScopedPolicyId = 19,
    /// Carries a process trust level.
    SystemProcessTrustLabel = 20,
    /// Applies a conditional access filter.
    SystemAccessFilter = 21,
    /// Placeholder for unrecognized ACE types.
    Unknown = 255,
}

impl NtfsAceType {
    /// Converts an on-disk ACE type byte into a known variant.
    ///
    /// Returns `None` for values that NTFS has not assigned. Callers that
    /// need to preserve an unknown value can map that result to
    /// [`Self::Unknown`].
    #[must_use]
    pub fn n(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::AccessAllowed),
            1 => Some(Self::AccessDenied),
            2 => Some(Self::SystemAudit),
            3 => Some(Self::SystemAlarm),
            4 => Some(Self::AccessAllowedCompound),
            5 => Some(Self::AccessAllowedObject),
            6 => Some(Self::AccessDeniedObject),
            7 => Some(Self::SystemAuditObject),
            8 => Some(Self::SystemAlarmObject),
            9 => Some(Self::AccessAllowedCallback),
            10 => Some(Self::AccessDeniedCallback),
            11 => Some(Self::AccessAllowedCallbackObject),
            12 => Some(Self::AccessDeniedCallbackObject),
            13 => Some(Self::SystemAuditCallback),
            14 => Some(Self::SystemAlarmCallback),
            15 => Some(Self::SystemAuditCallbackObject),
            16 => Some(Self::SystemAlarmCallbackObject),
            17 => Some(Self::SystemMandatoryLabel),
            18 => Some(Self::SystemResourceAttribute),
            19 => Some(Self::SystemScopedPolicyId),
            20 => Some(Self::SystemProcessTrustLabel),
            21 => Some(Self::SystemAccessFilter),
            255 => Some(Self::Unknown),
            _ => None,
        }
    }
}

impl fmt::Display for NtfsAceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessAllowed => write!(f, "ACCESS_ALLOWED"),
            Self::AccessDenied => write!(f, "ACCESS_DENIED"),
            Self::SystemAudit => write!(f, "SYSTEM_AUDIT"),
            Self::SystemAlarm => write!(f, "SYSTEM_ALARM"),
            Self::AccessAllowedObject => write!(f, "ACCESS_ALLOWED_OBJECT"),
            Self::AccessDeniedObject => write!(f, "ACCESS_DENIED_OBJECT"),
            Self::SystemMandatoryLabel => write!(f, "SYSTEM_MANDATORY_LABEL"),
            _ => write!(f, "{self:?}"),
        }
    }
}

bitflags! {
    /// Flags on an Access Control Entry.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsAceFlags: u8 {
        /// ACE is inherited by child objects (non-container).
        const OBJECT_INHERIT = 0x01;
        /// ACE is inherited by child containers.
        const CONTAINER_INHERIT = 0x02;
        /// Do not propagate the inherit flags to child ACEs.
        const NO_PROPAGATE_INHERIT = 0x04;
        /// Only inherit, do not apply to this object.
        const INHERIT_ONLY = 0x08;
        /// ACE was inherited from a parent object.
        const INHERITED = 0x10;
        /// For audit ACEs: generate audit on successful access.
        const SUCCESSFUL_ACCESS = 0x40;
        /// For audit ACEs: generate audit on failed access.
        const FAILED_ACCESS = 0x80;
    }
}

impl fmt::Display for NtfsAceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsAceFlags {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bits: u8 = u.arbitrary()?;
        Ok(Self::from_bits_truncate(bits))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsAceType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let variants = [
            NtfsAceType::AccessAllowed,
            NtfsAceType::AccessDenied,
            NtfsAceType::SystemAudit,
            NtfsAceType::SystemAlarm,
            NtfsAceType::AccessAllowedCompound,
            NtfsAceType::AccessAllowedObject,
            NtfsAceType::AccessDeniedObject,
            NtfsAceType::SystemAuditObject,
            NtfsAceType::SystemAlarmObject,
            NtfsAceType::AccessAllowedCallback,
            NtfsAceType::AccessDeniedCallback,
            NtfsAceType::AccessAllowedCallbackObject,
            NtfsAceType::AccessDeniedCallbackObject,
            NtfsAceType::SystemAuditCallback,
            NtfsAceType::SystemAlarmCallback,
            NtfsAceType::SystemAuditCallbackObject,
            NtfsAceType::SystemAlarmCallbackObject,
            NtfsAceType::SystemMandatoryLabel,
            NtfsAceType::SystemResourceAttribute,
            NtfsAceType::SystemScopedPolicyId,
            NtfsAceType::SystemProcessTrustLabel,
            NtfsAceType::SystemAccessFilter,
            NtfsAceType::Unknown,
        ];
        Ok(*u.choose(&variants)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_acl_with_one_ace() -> Vec<u8> {
        // ACL header: revision=2, padding=0, size=36, ace_count=1, padding=0
        // ACE: type=0 (AccessAllowed), flags=0, size=28
        //   access_mask=0x001F01FF (GENERIC_ALL for files)
        //   SID: S-1-5-18 (SYSTEM) = 12 bytes
        let mut data = vec![
            // ACL header (8 bytes)
            0x02, 0x00, // revision, padding
            0x24, 0x00, // size = 36
            0x01, 0x00, // ace_count = 1
            0x00, 0x00, // padding
            // ACE header (4 bytes)
            0x00, // type = AccessAllowed
            0x00, // flags = 0
            0x1C, 0x00, // size = 28
            // ACE body: access_mask (4 bytes)
            0xFF, 0x01, 0x1F, 0x00, // ACE body: SID S-1-5-18 (12 bytes)
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ];
        // Pad to declared ACE size (28 bytes total for ACE = 4 header + 4 mask + 12 SID + 8 pad)
        while data.len() < 36 {
            data.push(0x00);
        }
        data
    }

    #[test]
    fn test_acl_basics() {
        let data = make_acl_with_one_ace();
        let acl = NtfsAcl::from_bytes(&data, NtfsPosition::none()).unwrap();
        assert_eq!(acl.revision(), 2);
        assert_eq!(acl.ace_count(), 1);
        assert_eq!(acl.size(), 36);
    }

    #[test]
    fn test_ace_access_allowed() {
        let data = make_acl_with_one_ace();
        let acl = NtfsAcl::from_bytes(&data, NtfsPosition::none()).unwrap();
        let ace = acl.entries().next().unwrap().unwrap();
        assert_eq!(ace.ace_type(), NtfsAceType::AccessAllowed);
        assert_eq!(ace.flags(), NtfsAceFlags::empty());
        assert_eq!(ace.access_mask().unwrap(), 0x001F_01FF);
        let sid = ace.sid().unwrap();
        assert_eq!(sid.to_sid_string(), "S-1-5-18");
    }

    #[test]
    fn test_acl_too_short() {
        let data = [0x02, 0x00, 0x04, 0x00]; // only 4 bytes
        assert!(NtfsAcl::from_bytes(&data, NtfsPosition::none()).is_err());
    }

    /// Builds one basic ACE: 4-byte header (type, flags, size) + 4-byte
    /// access mask + a SID S-1-5-`subs...`. The declared ACE size matches the
    /// produced length.
    fn make_basic_ace(ace_type: u8, flags: u8, access_mask: u32, subs: &[u32]) -> Vec<u8> {
        let mut ace = vec![ace_type, flags, 0x00, 0x00]; // size patched below
        ace.extend_from_slice(&access_mask.to_le_bytes());
        // SID: revision 1, len(subs) sub-authorities, authority 5.
        ace.extend_from_slice(&[
            0x01,
            u8::try_from(subs.len()).expect("test value fits u8"),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x05,
        ]);
        for sub in subs {
            ace.extend_from_slice(&sub.to_le_bytes());
        }
        let size = u16::try_from(ace.len()).expect("test value fits u16");
        ace[2..4].copy_from_slice(&size.to_le_bytes());
        ace
    }

    /// Wraps `aces` in an ACL header (revision 2) with the given `ace_count`.
    fn make_acl(revision: u8, ace_count: u16, aces: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = aces.iter().flatten().copied().collect();
        let size = u16::try_from(ACL_HEADER_SIZE + body.len()).expect("test value fits u16");
        let mut acl = vec![revision, 0x00];
        acl.extend_from_slice(&size.to_le_bytes());
        acl.extend_from_slice(&ace_count.to_le_bytes());
        acl.extend_from_slice(&[0x00, 0x00]); // padding
        acl.extend_from_slice(&body);
        acl
    }

    #[test]
    fn from_bytes_size_within_and_exceeding_data() {
        // Declared size equals the buffer length: accepted, and the ACL is
        // truncated to exactly that size.
        let ace = make_basic_ace(0, 0, 0x1F_01FF, &[18]);
        let acl_bytes = make_acl(2, 1, &[ace]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        assert_eq!(usize::from(acl.size()), acl_bytes.len());

        // Declared size larger than the buffer: rejected (anchors `>` at 46).
        let mut oversized = acl_bytes.clone();
        let bigger = u16::try_from(acl_bytes.len()).expect("test value fits u16") + 4;
        oversized[2..4].copy_from_slice(&bigger.to_le_bytes());
        assert!(NtfsAcl::from_bytes(&oversized, NtfsPosition::none()).is_err());

        // Declared size smaller than the buffer is accepted and truncates.
        let mut padded = acl_bytes.clone();
        padded.extend_from_slice(&[0xEE; 8]);
        let acl2 = NtfsAcl::from_bytes(&padded, NtfsPosition::none()).unwrap();
        assert_eq!(usize::from(acl2.size()), acl_bytes.len());
    }

    #[test]
    fn iterator_walks_two_aces_of_different_sizes() {
        // Two ACEs with distinct types, sizes, masks and SIDs. Correct
        // offset/remaining arithmetic is required to read both and to stop.
        // ace0 has one sub-authority, ace1 has two, so their sizes differ and
        // correct offset arithmetic is required to land on the second ACE.
        let ace0 = make_basic_ace(0, 0x01, 0x0011_2233, &[18]); // AccessAllowed
        let ace1 = make_basic_ace(1, 0x02, 0x4455_6677, &[32, 544]); // AccessDenied
        let ace0_len = ace0.len();
        let ace1_len = ace1.len();
        assert_ne!(ace0_len, ace1_len, "fixture sizes must differ");
        let acl_bytes = make_acl(2, 2, &[ace0, ace1]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();

        let mut it = acl.entries();
        // size_hint reports the remaining count as an upper bound.
        assert_eq!(it.size_hint(), (0, Some(2)));

        let a0 = it.next().unwrap().unwrap();
        assert_eq!(a0.ace_type(), NtfsAceType::AccessAllowed);
        assert_eq!(a0.ace_type_raw(), 0);
        assert_eq!(a0.flags(), NtfsAceFlags::OBJECT_INHERIT);
        assert_eq!(usize::from(a0.size()), ace0_len);
        assert_eq!(a0.access_mask().unwrap(), 0x0011_2233);
        assert_eq!(a0.sid().unwrap().to_sid_string(), "S-1-5-18");
        assert_eq!(it.size_hint(), (0, Some(1)));

        let a1 = it.next().unwrap().unwrap();
        assert_eq!(a1.ace_type(), NtfsAceType::AccessDenied);
        assert_eq!(a1.ace_type_raw(), 1);
        assert_eq!(a1.flags(), NtfsAceFlags::CONTAINER_INHERIT);
        assert_eq!(usize::from(a1.size()), ace1_len);
        assert_eq!(a1.access_mask().unwrap(), 0x4455_6677);
        assert_eq!(a1.sid().unwrap().to_sid_string(), "S-1-5-32-544");

        assert!(it.next().is_none());
        assert_eq!(it.size_hint(), (0, Some(0)));
    }

    #[test]
    fn iterator_errors_when_ace_header_truncated() {
        // ace_count claims 2 ACEs, but only one fits; the second read must
        // detect the header runs past the data (anchors `+`/`>` at 104).
        let ace0 = make_basic_ace(0, 0, 0x1, &[18]);
        let acl_bytes = make_acl(2, 2, &[ace0]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        let mut it = acl.entries();
        assert!(it.next().unwrap().is_ok());
        assert!(it.next().unwrap().is_err());
        // After an error the iterator is exhausted.
        assert!(it.next().is_none());
    }

    #[test]
    fn iterator_errors_on_undersized_ace_size_field() {
        // A single ACE whose declared size (2) is below ACE_HEADER_SIZE (4)
        // anchors the `<` boundary at line 115.
        let bad_ace = vec![0x00, 0x00, 0x02, 0x00];
        let acl_bytes = make_acl(2, 1, &[bad_ace]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        assert!(acl.entries().next().unwrap().is_err());
    }

    #[test]
    fn iterator_errors_when_ace_body_exceeds_acl() {
        // Header size 4 is fine, but the declared ACE size (12) extends past
        // the ACL data, anchoring `+`/`>` at line 123.
        let mut ace = vec![0x00, 0x00, 0x0C, 0x00];
        ace.extend_from_slice(&[0x00; 4]); // only 8 bytes present
        let acl_bytes = make_acl(2, 1, &[ace]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        assert!(acl.entries().next().unwrap().is_err());
    }

    #[test]
    fn access_mask_and_sid_length_boundaries() {
        // An ACE that is exactly long enough for the access mask but one byte
        // short of an 8-byte SID: access_mask succeeds, sid fails. This pins
        // the `<` comparisons and `+` offsets at lines 182 and 202.
        let mut ace = vec![0x00, 0x00, 0x00, 0x00];
        ace.extend_from_slice(&0xAABB_CCDDu32.to_le_bytes()); // access mask
        ace.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]); // 7-byte SID stub
        let size = u16::try_from(ace.len()).expect("test value fits u16");
        ace[2..4].copy_from_slice(&size.to_le_bytes());
        let acl_bytes = make_acl(2, 1, &[ace]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        let a = acl.entries().next().unwrap().unwrap();
        assert_eq!(a.access_mask().unwrap(), 0xAABB_CCDD);
        assert!(a.sid().is_err());

        // An ACE too short even for the access mask: access_mask fails.
        let mut tiny = vec![0x00, 0x00, 0x00, 0x00];
        tiny.extend_from_slice(&[0x00, 0x00, 0x00]); // 3-byte body
        let tiny_size = u16::try_from(tiny.len()).expect("test value fits u16");
        tiny[2..4].copy_from_slice(&tiny_size.to_le_bytes());
        let tiny_acl = make_acl(2, 1, &[tiny]);
        let acl2 = NtfsAcl::from_bytes(&tiny_acl, NtfsPosition::none()).unwrap();
        let a2 = acl2.entries().next().unwrap().unwrap();
        assert!(a2.access_mask().is_err());
    }

    #[test]
    fn access_mask_succeeds_at_exact_minimum_length() {
        // An ACE of exactly ACE_HEADER_SIZE + 4 (8) bytes: header + access
        // mask, no SID. `data.len() < 8` is false, so access_mask succeeds.
        // A `<` -> `<=` flip at line 182 would wrongly reject this.
        let mut ace = vec![0x00, 0x00, 0x00, 0x00];
        ace.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        let size = u16::try_from(ace.len()).expect("test value fits u16");
        assert_eq!(size, 8);
        ace[2..4].copy_from_slice(&size.to_le_bytes());
        let acl_bytes = make_acl(2, 1, &[ace]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        let a = acl.entries().next().unwrap().unwrap();
        assert_eq!(a.access_mask().unwrap(), 0x1234_5678);
        // 8 bytes is still one short of the 16 needed for the SID guard.
        assert!(a.sid().is_err());
    }

    #[test]
    fn sid_succeeds_at_exact_minimum_length() {
        // An ACE of exactly sid_offset + 8 (16) bytes carries a minimal
        // 8-byte SID (zero sub-authorities). `data.len() < 16` is false, so
        // sid() succeeds; a `<` -> `<=` flip at line 202 would reject it.
        let mut ace = vec![0x00, 0x00, 0x00, 0x00];
        ace.extend_from_slice(&0u32.to_le_bytes()); // access mask
        // 8-byte SID: revision 1, 0 sub-authorities, authority 5.
        ace.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]);
        let size = u16::try_from(ace.len()).expect("test value fits u16");
        assert_eq!(size, 16);
        ace[2..4].copy_from_slice(&size.to_le_bytes());
        let acl_bytes = make_acl(2, 1, &[ace]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        let a = acl.entries().next().unwrap().unwrap();
        let sid = a.sid().unwrap();
        assert_eq!(sid.revision(), 1);
        assert_eq!(sid.authority(), 5);
    }

    #[test]
    fn sid_guard_reports_ace_error_not_sid_error() {
        // A 12-byte ACE: long enough for the access mask but short of the
        // 16-byte SID guard. The guard itself must fire and return an
        // InvalidAce error. With the guard's offset `+` turned into `-` (or
        // the `<` weakened) the guard is bypassed and the deeper
        // NtfsSid::from_bytes call would instead yield an InvalidSid error.
        let mut ace = vec![0x00, 0x00, 0x00, 0x00];
        ace.extend_from_slice(&0u32.to_le_bytes()); // access mask
        ace.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // 4-byte SID stub
        let size = u16::try_from(ace.len()).expect("test value fits u16");
        assert_eq!(size, 12);
        ace[2..4].copy_from_slice(&size.to_le_bytes());
        let acl_bytes = make_acl(2, 1, &[ace]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        let a = acl.entries().next().unwrap().unwrap();
        let err = a.sid().unwrap_err();
        assert!(
            matches!(err, NtfsError::InvalidAce { .. }),
            "expected the ACE-length guard to fire, got {err:?}",
        );
    }

    #[test]
    fn iterator_reads_large_ace_with_nonzero_size_high_byte() {
        // A single ACE of size 260 (0x0104): the size field's high byte is
        // nonzero, so reading `data[offset + 3]` (vs a `- 3` flip) actually
        // matters. The ACE must be sliced to its full 260 bytes for
        // access_mask to succeed.
        let mut ace = vec![0x00, 0x00, 0x00, 0x00];
        ace.extend_from_slice(&0xCAFE_F00Du32.to_le_bytes());
        ace.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]); // SID
        ace.resize(260, 0x00); // pad to declared size 260
        ace[2..4].copy_from_slice(&260u16.to_le_bytes());
        let acl_bytes = make_acl(2, 1, &[ace]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        let a = acl.entries().next().unwrap().unwrap();
        assert_eq!(a.size(), 260);
        assert_eq!(a.access_mask().unwrap(), 0xCAFE_F00D);
        assert_eq!(a.sid().unwrap().authority(), 5);
    }

    #[test]
    fn ace_type_display_each_named_arm() {
        // Each explicitly named Display arm produces a distinct string, so
        // deleting any arm changes the output.
        assert_eq!(format!("{}", NtfsAceType::AccessAllowed), "ACCESS_ALLOWED");
        assert_eq!(format!("{}", NtfsAceType::AccessDenied), "ACCESS_DENIED");
        assert_eq!(format!("{}", NtfsAceType::SystemAudit), "SYSTEM_AUDIT");
        assert_eq!(format!("{}", NtfsAceType::SystemAlarm), "SYSTEM_ALARM");
        assert_eq!(
            format!("{}", NtfsAceType::AccessAllowedObject),
            "ACCESS_ALLOWED_OBJECT"
        );
        assert_eq!(
            format!("{}", NtfsAceType::AccessDeniedObject),
            "ACCESS_DENIED_OBJECT"
        );
        assert_eq!(
            format!("{}", NtfsAceType::SystemMandatoryLabel),
            "SYSTEM_MANDATORY_LABEL"
        );
        // The catch-all arm falls back to the Debug name.
        assert_eq!(
            format!("{}", NtfsAceType::SystemAccessFilter),
            "SystemAccessFilter"
        );
    }

    #[test]
    fn iterator_accepts_header_only_ace_ending_at_boundary() {
        // A single 4-byte header-only ACE (size == ACE_HEADER_SIZE) that ends
        // exactly at the ACL data boundary. `offset + ACE_HEADER_SIZE` equals
        // `data.len()`, so a `>` -> `>=` flip at line 104 would wrongly error.
        let header_only = vec![0x02, 0x00, 0x04, 0x00];
        let acl_bytes = make_acl(2, 1, &[header_only]);
        let acl = NtfsAcl::from_bytes(&acl_bytes, NtfsPosition::none()).unwrap();
        let mut it = acl.entries();
        let ace = it.next().unwrap().unwrap();
        assert_eq!(ace.ace_type(), NtfsAceType::SystemAudit);
        assert_eq!(ace.size(), 4);
        assert!(it.next().is_none());
    }

    #[test]
    fn ace_flags_display_renders_set_flags() {
        // The flags Display delegates to the inner bitflags formatter; a
        // non-empty set must render its flag names, not the Default (empty)
        // string a `fmt -> Ok(Default::default())` replacement would produce.
        let flags = NtfsAceFlags::INHERITED | NtfsAceFlags::OBJECT_INHERIT;
        let rendered = format!("{flags}");
        assert!(rendered.contains("OBJECT_INHERIT"), "got {rendered:?}");
        assert!(rendered.contains("INHERITED"), "got {rendered:?}");
        assert_ne!(rendered, "");
    }
}
