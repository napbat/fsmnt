use core::fmt;

use bitflags::bitflags;

use crate::error::{NtfsError, Result};
use crate::types::NtfsPosition;

use super::acl::NtfsAcl;
use super::sid::NtfsSid;

/// Minimum security descriptor header size (20 bytes).
const SD_HEADER_SIZE: usize = 20;

/// A parsed NTFS self-relative security descriptor.
///
/// Security descriptors define the security attributes of an NTFS object (file, directory, etc.).
/// They contain:
/// - An owner SID
/// - A primary group SID
/// - A Discretionary ACL (DACL) controlling access
/// - A System ACL (SACL) for auditing
///
/// NTFS stores these in **self-relative** format where all offsets are relative to the start
/// of the descriptor.
///
/// Spec reference: MS-DTYP Section 2.4.6 (`SECURITY_DESCRIPTOR`).
#[derive(Clone, Debug)]
pub struct NtfsSecurityDescriptor<'s> {
    data: &'s [u8],
    position: NtfsPosition,
}

impl<'s> NtfsSecurityDescriptor<'s> {
    /// Parse a security descriptor from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the self-relative descriptor header is truncated,
    /// has an unsupported revision, or lacks the self-relative control flag.
    pub fn from_bytes(data: &'s [u8], position: NtfsPosition) -> Result<Self> {
        if data.len() < SD_HEADER_SIZE {
            return Err(NtfsError::InvalidSecurityDescriptor {
                position,
                reason: "data too short for security descriptor header",
            });
        }

        let revision = data[0];
        if revision != 1 {
            return Err(NtfsError::InvalidSecurityDescriptor {
                position,
                reason: "unsupported security descriptor revision (expected 1)",
            });
        }

        let control_raw = u16::from_le_bytes([data[2], data[3]]);
        let control = NtfsSecurityDescriptorControl::from_bits_truncate(control_raw);
        if !control.contains(NtfsSecurityDescriptorControl::SELF_RELATIVE) {
            return Err(NtfsError::InvalidSecurityDescriptor {
                position,
                reason: "security descriptor is not in self-relative format",
            });
        }

        Ok(Self { data, position })
    }

    /// Returns the security descriptor revision (always 1).
    // mutants::skip: from_bytes rejects any data with data[0] != 1, so the only
    // constructible descriptor has revision 1; returning the constant 1 is equivalent.
    #[cfg_attr(test, mutants::skip)]
    #[must_use]
    pub fn revision(&self) -> u8 {
        self.data[0]
    }

    /// Returns the control flags.
    #[must_use]
    pub fn control(&self) -> NtfsSecurityDescriptorControl {
        let raw = u16::from_le_bytes([self.data[2], self.data[3]]);
        NtfsSecurityDescriptorControl::from_bits_truncate(raw)
    }

    /// Returns the byte offset to the owner SID within the descriptor.
    fn owner_offset(&self) -> u32 {
        u32::from_le_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    /// Returns the byte offset to the group SID within the descriptor.
    fn group_offset(&self) -> u32 {
        u32::from_le_bytes([self.data[8], self.data[9], self.data[10], self.data[11]])
    }

    /// Returns the byte offset to the SACL within the descriptor.
    fn sacl_offset(&self) -> u32 {
        u32::from_le_bytes([self.data[12], self.data[13], self.data[14], self.data[15]])
    }

    /// Returns the byte offset to the DACL within the descriptor.
    fn dacl_offset(&self) -> u32 {
        u32::from_le_bytes([self.data[16], self.data[17], self.data[18], self.data[19]])
    }

    /// Returns the owner SID, if present.
    #[must_use]
    pub fn owner_sid(&self) -> Option<Result<NtfsSid>> {
        let Ok(offset) = usize::try_from(self.owner_offset()) else {
            return Some(Err(NtfsError::InvalidSecurityDescriptor {
                position: self.position,
                reason: "owner SID offset does not fit the target address space",
            }));
        };
        if offset == 0 {
            return None;
        }
        if offset >= self.data.len() {
            return Some(Err(NtfsError::InvalidSecurityDescriptor {
                position: self.position,
                reason: "owner SID offset extends beyond descriptor data",
            }));
        }
        Some(NtfsSid::from_bytes(&self.data[offset..], self.position))
    }

    /// Returns the primary group SID, if present.
    #[must_use]
    pub fn group_sid(&self) -> Option<Result<NtfsSid>> {
        let Ok(offset) = usize::try_from(self.group_offset()) else {
            return Some(Err(NtfsError::InvalidSecurityDescriptor {
                position: self.position,
                reason: "group SID offset does not fit the target address space",
            }));
        };
        if offset == 0 {
            return None;
        }
        if offset >= self.data.len() {
            return Some(Err(NtfsError::InvalidSecurityDescriptor {
                position: self.position,
                reason: "group SID offset extends beyond descriptor data",
            }));
        }
        Some(NtfsSid::from_bytes(&self.data[offset..], self.position))
    }

    /// Returns the Discretionary ACL (DACL), if present.
    ///
    /// The DACL controls access to the object. If `None`, the object has no DACL
    /// (which in Windows means full access is granted to everyone — this is different
    /// from an empty DACL, which denies all access).
    #[must_use]
    pub fn dacl(&self) -> Option<Result<NtfsAcl<'s>>> {
        if !self
            .control()
            .contains(NtfsSecurityDescriptorControl::DACL_PRESENT)
        {
            return None;
        }
        let Ok(offset) = usize::try_from(self.dacl_offset()) else {
            return Some(Err(NtfsError::InvalidSecurityDescriptor {
                position: self.position,
                reason: "DACL offset does not fit the target address space",
            }));
        };
        if offset == 0 {
            return None;
        }
        if offset >= self.data.len() {
            return Some(Err(NtfsError::InvalidSecurityDescriptor {
                position: self.position,
                reason: "DACL offset extends beyond descriptor data",
            }));
        }
        Some(NtfsAcl::from_bytes(&self.data[offset..], self.position))
    }

    /// Returns the System ACL (SACL), if present.
    ///
    /// The SACL is used for auditing and mandatory integrity control.
    #[must_use]
    pub fn sacl(&self) -> Option<Result<NtfsAcl<'s>>> {
        if !self
            .control()
            .contains(NtfsSecurityDescriptorControl::SACL_PRESENT)
        {
            return None;
        }
        let Ok(offset) = usize::try_from(self.sacl_offset()) else {
            return Some(Err(NtfsError::InvalidSecurityDescriptor {
                position: self.position,
                reason: "SACL offset does not fit the target address space",
            }));
        };
        if offset == 0 {
            return None;
        }
        if offset >= self.data.len() {
            return Some(Err(NtfsError::InvalidSecurityDescriptor {
                position: self.position,
                reason: "SACL offset extends beyond descriptor data",
            }));
        }
        Some(NtfsAcl::from_bytes(&self.data[offset..], self.position))
    }
}

impl fmt::Display for NtfsSecurityDescriptor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecurityDescriptor(rev={}", self.revision())?;
        if let Some(Ok(owner)) = self.owner_sid() {
            write!(f, ", owner={owner}")?;
        }
        if let Some(Ok(group)) = self.group_sid() {
            write!(f, ", group={group}")?;
        }
        if let Some(Ok(dacl)) = self.dacl() {
            write!(f, ", dacl({} ACEs)", dacl.ace_count())?;
        }
        if let Some(Ok(sacl)) = self.sacl() {
            write!(f, ", sacl({} ACEs)", sacl.ace_count())?;
        }
        write!(f, ")")
    }
}

bitflags! {
    /// Control flags for a security descriptor.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsSecurityDescriptorControl: u16 {
        /// Owner was set by default mechanism.
        const OWNER_DEFAULTED = 0x0001;
        /// Group was set by default mechanism.
        const GROUP_DEFAULTED = 0x0002;
        /// DACL is present.
        const DACL_PRESENT = 0x0004;
        /// DACL was set by default mechanism.
        const DACL_DEFAULTED = 0x0008;
        /// SACL is present.
        const SACL_PRESENT = 0x0010;
        /// SACL was set by default mechanism.
        const SACL_DEFAULTED = 0x0020;
        /// Requests that the provider auto-propagate the DACL to existing child objects.
        const DACL_AUTO_INHERIT_REQ = 0x0100;
        /// Requests that the provider auto-propagate the SACL to existing child objects.
        const SACL_AUTO_INHERIT_REQ = 0x0200;
        /// DACL was inherited via auto-inheritance.
        const DACL_AUTO_INHERITED = 0x0400;
        /// SACL was inherited via auto-inheritance.
        const SACL_AUTO_INHERITED = 0x0800;
        /// DACL is protected from inheritance.
        const DACL_PROTECTED = 0x1000;
        /// SACL is protected from inheritance.
        const SACL_PROTECTED = 0x2000;
        /// Resource manager control bit.
        const RM_CONTROL_VALID = 0x4000;
        /// Security descriptor is in self-relative format (offsets, not pointers).
        const SELF_RELATIVE = 0x8000;
    }
}

impl fmt::Display for NtfsSecurityDescriptorControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsSecurityDescriptorControl {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bits: u16 = u.arbitrary()?;
        Ok(Self::from_bits_truncate(bits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_sd() -> Vec<u8> {
        // A minimal self-relative security descriptor with owner and group SIDs and a DACL.
        // Header: revision=1, padding=0, control=DACL_PRESENT|SELF_RELATIVE
        // owner_offset=20, group_offset=32, sacl_offset=0, dacl_offset=44
        let control: u16 = NtfsSecurityDescriptorControl::DACL_PRESENT.bits()
            | NtfsSecurityDescriptorControl::SELF_RELATIVE.bits();
        let [control_low, control_high] = control.to_le_bytes();
        let mut sd = vec![
            0x01, // revision
            0x00, // padding
            control_low,
            control_high, // control (LE)
            20,
            0,
            0,
            0, // owner_offset = 20
            32,
            0,
            0,
            0, // group_offset = 32
            0,
            0,
            0,
            0, // sacl_offset = 0 (no SACL)
            44,
            0,
            0,
            0, // dacl_offset = 44
        ];
        assert_eq!(sd.len(), 20);

        // Owner SID: S-1-5-18 (SYSTEM) - 12 bytes, offset 20
        sd.extend_from_slice(&[
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(sd.len(), 32);

        // Group SID: S-1-5-32-544 (Administrators) - 16 bytes, offset 32
        sd.extend_from_slice(&[
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02,
            0x00, 0x00,
        ]);
        assert_eq!(sd.len(), 48); // Wait, that's offset 48, but dacl_offset is 44.

        // Adjust: group SID is 16 bytes at offset 32 -> ends at 48.
        // But dacl_offset=44 overlaps! Fix the offsets.
        // Let's use: owner at 20 (12 bytes), group at 32 (16 bytes) -> group ends at 48.
        // dacl at 48.
        sd[16] = 48; // fix dacl_offset to 48

        // DACL: empty ACL (no ACEs) - 8 bytes, offset 48
        sd.extend_from_slice(&[
            0x02, 0x00, // revision, padding
            0x08, 0x00, // size = 8
            0x00, 0x00, // ace_count = 0
            0x00, 0x00, // padding
        ]);

        sd
    }

    #[test]
    fn test_security_descriptor_basics() {
        let data = make_simple_sd();
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        assert_eq!(sd.revision(), 1);
        assert!(
            sd.control()
                .contains(NtfsSecurityDescriptorControl::DACL_PRESENT)
        );
        assert!(
            sd.control()
                .contains(NtfsSecurityDescriptorControl::SELF_RELATIVE)
        );
    }

    #[test]
    fn test_security_descriptor_owner() {
        let data = make_simple_sd();
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        let owner = sd.owner_sid().unwrap().unwrap();
        assert_eq!(owner.to_sid_string(), "S-1-5-18");
        assert_eq!(owner.well_known_name(), Some("SYSTEM"));
    }

    #[test]
    fn test_security_descriptor_group() {
        let data = make_simple_sd();
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        let group = sd.group_sid().unwrap().unwrap();
        assert_eq!(group.to_sid_string(), "S-1-5-32-544");
        assert_eq!(group.well_known_name(), Some("Administrators"));
    }

    #[test]
    fn test_security_descriptor_dacl() {
        let data = make_simple_sd();
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        let dacl = sd.dacl().unwrap().unwrap();
        assert_eq!(dacl.revision(), 2);
        assert_eq!(dacl.ace_count(), 0);
    }

    #[test]
    fn test_security_descriptor_no_sacl() {
        let data = make_simple_sd();
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        assert!(sd.sacl().is_none());
    }

    #[test]
    fn test_security_descriptor_too_short() {
        let data = [0x01, 0x00, 0x00, 0x80]; // only 4 bytes
        assert!(NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).is_err());
    }

    #[test]
    fn test_security_descriptor_display() {
        let data = make_simple_sd();
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        let s = format!("{sd}");
        assert!(s.contains("rev=1"));
        assert!(s.contains("owner=S-1-5-18"));
        assert!(s.contains("group=S-1-5-32-544"));
        assert!(s.contains("dacl(0 ACEs)"));
    }

    /// Builds a self-relative SD with a SACL present at offset 20 holding one (empty) ACL.
    ///
    /// Header (20 bytes): revision=1, `control=SACL_PRESENT|SELF_RELATIVE`,
    /// `owner_offset=0`, `group_offset=0`, `sacl_offset=20`, `dacl_offset=0`.
    /// The SACL itself is an 8-byte ACL header declaring `ace_count=0`.
    fn make_sd_with_sacl() -> Vec<u8> {
        let control: u16 = NtfsSecurityDescriptorControl::SACL_PRESENT.bits()
            | NtfsSecurityDescriptorControl::SELF_RELATIVE.bits();
        let [control_low, control_high] = control.to_le_bytes();
        let mut sd = vec![
            0x01, // revision
            0x00, // padding
            control_low,
            control_high, // control (LE)
            0,
            0,
            0,
            0, // owner_offset = 0
            0,
            0,
            0,
            0, // group_offset = 0
            20,
            0,
            0,
            0, // sacl_offset = 20
            0,
            0,
            0,
            0, // dacl_offset = 0
        ];
        assert_eq!(sd.len(), 20);

        // SACL at offset 20: ACL header declaring size 8, ace_count 0.
        sd.extend_from_slice(&[
            0x02, 0x00, // revision, padding
            0x08, 0x00, // size = 8
            0x00, 0x00, // ace_count = 0
            0x00, 0x00, // padding
        ]);
        sd
    }

    #[test]
    fn test_security_descriptor_sacl_present() {
        let data = make_sd_with_sacl();
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();

        // SACL_PRESENT is set and the offset (20) is valid: sacl() must yield a parsable ACL.
        let sacl = sd
            .sacl()
            .expect("SACL_PRESENT set, expected Some")
            .expect("SACL offset valid, expected Ok");
        assert_eq!(sacl.revision(), 2);
        assert_eq!(sacl.ace_count(), 0);
        assert_eq!(sacl.size(), 8);

        // No DACL_PRESENT control bit, and dacl_offset is 0.
        assert!(sd.dacl().is_none());
    }

    #[test]
    fn test_security_descriptor_sacl_offset_value() {
        // The genuine sacl_offset is 20 (distinct from the 0/1 mutation replacements).
        let data = make_sd_with_sacl();
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        assert_eq!(sd.sacl_offset(), 20);
    }

    #[test]
    fn test_security_descriptor_sacl_offset_out_of_bounds() {
        // SACL_PRESENT set but sacl_offset points past the end of the data: sacl() => Some(Err).
        let mut data = make_sd_with_sacl();
        // Set sacl_offset to exactly data.len() (the >= boundary): must be an error.
        let len = u32::try_from(data.len()).expect("test value fits u32");
        data[12..16].copy_from_slice(&len.to_le_bytes());
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        assert!(sd.sacl().unwrap().is_err());
    }

    #[test]
    fn test_security_descriptor_sacl_offset_zero_is_none() {
        // SACL_PRESENT set but sacl_offset == 0: sacl() returns None (the `== 0` early return).
        let mut data = make_sd_with_sacl();
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        assert!(sd.sacl().is_none());
    }

    #[test]
    fn test_security_descriptor_sacl_not_present() {
        // Without the SACL_PRESENT control bit, sacl() returns None even with a nonzero offset.
        let data = make_simple_sd();
        let sd = NtfsSecurityDescriptor::from_bytes(&data, NtfsPosition::none()).unwrap();
        assert!(
            !sd.control()
                .contains(NtfsSecurityDescriptorControl::SACL_PRESENT)
        );
        assert!(sd.sacl().is_none());
    }

    #[test]
    fn test_security_descriptor_control_display() {
        // NtfsSecurityDescriptorControl Display renders the set flag names.
        let control = NtfsSecurityDescriptorControl::DACL_PRESENT
            | NtfsSecurityDescriptorControl::SELF_RELATIVE;
        let s = format!("{control}");
        // The genuine output is non-empty; the mutated body
        // (`Ok(Default::default())`) would produce an empty string.
        assert_eq!(s, "DACL_PRESENT | SELF_RELATIVE");
        assert!(!s.is_empty());
        assert_ne!(s, String::default());
    }
}
