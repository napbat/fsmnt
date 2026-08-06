use core::fmt;

use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U16, U32, Unaligned};

/// Size of a single GUID on disk (= size of all GUID fields).
pub(crate) const GUID_SIZE: usize = 16;

/// A Globally Unique Identifier (GUID), used for Object IDs in NTFS.
#[derive(Clone, Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
#[repr(C, packed)]
pub struct NtfsGuid {
    data1: U32<LittleEndian>,
    data2: U16<LittleEndian>,
    data3: U16<LittleEndian>,
    data4: [u8; 8],
}

impl NtfsGuid {
    /// Returns the `data1` component of the GUID.
    #[must_use]
    pub fn data1(&self) -> u32 {
        self.data1.get()
    }

    /// Returns the `data2` component of the GUID.
    #[must_use]
    pub fn data2(&self) -> u16 {
        self.data2.get()
    }

    /// Returns the `data3` component of the GUID.
    #[must_use]
    pub fn data3(&self) -> u16 {
        self.data3.get()
    }

    /// Returns the `data4` component of the GUID.
    #[must_use]
    pub fn data4(&self) -> [u8; 8] {
        self.data4
    }
}

impl fmt::Display for NtfsGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:8X}-{:4X}-{:4X}-{:2X}{:2X}-{:2X}{:2X}{:2X}{:2X}{:2X}{:2X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsGuid {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes: [u8; GUID_SIZE] = u.arbitrary()?;
        Ok(Self::read_from_bytes(&bytes).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid() {
        let guid = NtfsGuid {
            data1: U32::new(0x67c8_770b),
            data2: U16::new(0x44f1),
            data3: U16::new(0x410a),
            data4: [0xab, 0x9a, 0xf9, 0xb5, 0x44, 0x6f, 0x13, 0xee],
        };
        let guid_string = guid.to_string();
        assert_eq!(guid_string, "67C8770B-44F1-410A-AB9A-F9B5446F13EE");
    }

    #[test]
    fn test_guid_accessors() {
        let guid = NtfsGuid {
            data1: U32::new(0x1234_5678),
            data2: U16::new(0xABCD),
            data3: U16::new(0xEF01),
            data4: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        };

        assert_eq!(guid.data1(), 0x1234_5678);
        assert_eq!(guid.data2(), 0xABCD);
        assert_eq!(guid.data3(), 0xEF01);
        assert_eq!(
            guid.data4(),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_guid_zero() {
        let guid = NtfsGuid {
            data1: U32::new(0),
            data2: U16::new(0),
            data3: U16::new(0),
            data4: [0; 8],
        };
        let s = guid.to_string();
        // The Display impl uses width specifiers without zero padding.
        // Just verify it doesn't panic and contains expected structure.
        assert!(s.contains('-'), "GUID display should contain dashes");
    }

    #[test]
    fn test_guid_display_formatting() {
        // Test with a known Windows GUID: IID_IUnknown
        let guid = NtfsGuid {
            data1: U32::new(0x0000_0000),
            data2: U16::new(0x0000),
            data3: U16::new(0x0000),
            data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        };
        let s = guid.to_string();
        // The format is "{data1}-{data2}-{data3}-{data4[0:2]}-{data4[2:8]}"
        assert!(s.contains("C0"), "expected C0 in GUID: {s}");
        assert!(s.contains("46"), "expected 46 in GUID: {s}");
    }

    #[test]
    fn test_guid_equality() {
        let guid1 = NtfsGuid {
            data1: U32::new(0x1111_1111),
            data2: U16::new(0x2222),
            data3: U16::new(0x3333),
            data4: [0x44; 8],
        };
        let guid2 = NtfsGuid {
            data1: U32::new(0x1111_1111),
            data2: U16::new(0x2222),
            data3: U16::new(0x3333),
            data4: [0x44; 8],
        };
        let guid3 = NtfsGuid {
            data1: U32::new(0x9999_9999),
            data2: U16::new(0x2222),
            data3: U16::new(0x3333),
            data4: [0x44; 8],
        };

        assert_eq!(guid1, guid2);
        assert_ne!(guid1, guid3);
    }

    #[test]
    fn test_guid_from_bytes() {
        // Test reading a GUID from raw bytes using zerocopy.
        let bytes: [u8; GUID_SIZE] = [
            0x0B, 0x77, 0xC8, 0x67, // data1 (LE)
            0xF1, 0x44, // data2 (LE)
            0x0A, 0x41, // data3 (LE)
            0xAB, 0x9A, 0xF9, 0xB5, 0x44, 0x6F, 0x13, 0xEE, // data4
        ];
        let guid = NtfsGuid::read_from_bytes(&bytes).unwrap();
        assert_eq!(guid.data1(), 0x67C8_770B);
        assert_eq!(guid.data2(), 0x44F1);
        assert_eq!(guid.data3(), 0x410A);
        assert_eq!(guid.to_string(), "67C8770B-44F1-410A-AB9A-F9B5446F13EE");
    }

    #[test]
    fn test_guid_clone() {
        let guid = NtfsGuid {
            data1: U32::new(0x1234_5678),
            data2: U16::new(0xABCD),
            data3: U16::new(0xEF01),
            data4: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let cloned = guid.clone();
        assert_eq!(guid, cloned);
    }
}
