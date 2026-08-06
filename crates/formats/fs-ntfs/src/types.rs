use core::fmt;
use core::num::NonZeroU64;
use core::ops::{Add, AddAssign};

use derive_more::{Binary, Display, From, LowerHex, Octal, UpperHex};
use zerocopy::byteorder::LittleEndian;
use zerocopy::{FromBytes, I64, Immutable, KnownLayout, U64, Unaligned};

use crate::error::{NtfsError, Result};
use crate::ntfs::Ntfs;

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).expect("supported Rust targets have at most 64-bit pointers")
}

/// An absolute nonzero byte position on the NTFS filesystem.
/// Can be used to seek, but even more often in [`NtfsError`] variants to assist with debugging.
///
/// Note that there may be cases when no valid position can be given for the current situation.
/// For example, this may happen when a reader is on a sparse Data Run or it has been seeked to a
/// position outside the valid range.
/// Therefore, this structure internally uses an [`Option`] of a [`NonZeroU64`] to alternatively
/// store a `None` value if no valid position can be given.
#[derive(Clone, Copy, Debug, Eq, From, Ord, PartialEq, PartialOrd)]
pub struct NtfsPosition(Option<NonZeroU64>);

impl NtfsPosition {
    const NONE_STR: &'static str = "<NONE>";

    pub(crate) const fn new(position: u64) -> Self {
        Self(NonZeroU64::new(position))
    }

    /// Returns a position with no value, indicating the byte offset is unknown.
    #[must_use]
    pub const fn none() -> Self {
        Self(None)
    }

    /// Returns the stored position, or `None` if there is no valid position.
    #[must_use]
    pub const fn value(&self) -> Option<NonZeroU64> {
        self.0
    }
}

impl Add<u16> for NtfsPosition {
    type Output = Self;

    fn add(self, other: u16) -> Self {
        self + u64::from(other)
    }
}

impl Add<u64> for NtfsPosition {
    type Output = Self;

    fn add(self, other: u64) -> Self {
        let new_value = self
            .0
            .and_then(|position| NonZeroU64::new(position.get().wrapping_add(other)));
        Self(new_value)
    }
}

impl Add<usize> for NtfsPosition {
    type Output = Self;

    fn add(self, other: usize) -> Self {
        self + usize_to_u64(other)
    }
}

impl AddAssign<u16> for NtfsPosition {
    fn add_assign(&mut self, other: u16) {
        *self = *self + other;
    }
}

impl AddAssign<u64> for NtfsPosition {
    fn add_assign(&mut self, other: u64) {
        *self = *self + other;
    }
}

impl AddAssign<usize> for NtfsPosition {
    fn add_assign(&mut self, other: usize) {
        *self = *self + other;
    }
}

impl fmt::Binary for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::Binary::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl fmt::Display for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::Display::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl fmt::LowerHex for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::LowerHex::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl fmt::Octal for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::Octal::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl fmt::UpperHex for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::UpperHex::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl From<NonZeroU64> for NtfsPosition {
    fn from(value: NonZeroU64) -> Self {
        Self(Some(value))
    }
}

/// A Logical Cluster Number (LCN).
///
/// NTFS divides a filesystem into clusters of a given size (power of two), see [`Ntfs::cluster_size`].
/// The LCN is an absolute cluster index into the filesystem.
#[derive(
    Binary,
    Clone,
    Copy,
    Debug,
    Display,
    Eq,
    FromBytes,
    Immutable,
    KnownLayout,
    LowerHex,
    Octal,
    Ord,
    PartialEq,
    PartialOrd,
    Unaligned,
    UpperHex,
)]
#[repr(transparent)]
pub struct Lcn(U64<LittleEndian>);

impl Lcn {
    /// Performs a checked addition of the given Virtual Cluster Number (VCN), returning a new LCN.
    pub fn checked_add(&self, vcn: Vcn) -> Option<Lcn> {
        let offset = vcn.0.get().unsigned_abs();
        if vcn.0 >= 0 {
            self.0.get().checked_add(offset).map(Into::into)
        } else {
            self.0.get().checked_sub(offset).map(Into::into)
        }
    }

    /// Returns the absolute byte position of this LCN within the filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error if the cluster offset cannot be represented without overflow.
    pub fn position(&self, ntfs: &Ntfs) -> Result<NtfsPosition> {
        let value = self
            .0
            .get()
            .checked_mul(u64::from(ntfs.cluster_size()))
            .ok_or(NtfsError::LcnTooBig { lcn: *self })?;
        Ok(NtfsPosition::new(value))
    }

    /// Returns the stored Logical Cluster Number.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.0.get()
    }
}

impl From<u64> for Lcn {
    fn from(value: u64) -> Self {
        Self(U64::new(value))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Lcn {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u64>()?))
    }
}

/// A Virtual Cluster Number (VCN).
///
/// NTFS divides a filesystem into clusters of a given size (power of two), see [`Ntfs::cluster_size`].
/// The VCN is a cluster index into the filesystem that is relative to a Logical Cluster Number (LCN)
/// or relative to the start of an attribute value.
#[derive(
    Binary,
    Clone,
    Copy,
    Debug,
    Display,
    Eq,
    FromBytes,
    Immutable,
    KnownLayout,
    LowerHex,
    Octal,
    Ord,
    PartialEq,
    PartialOrd,
    Unaligned,
    UpperHex,
)]
#[repr(transparent)]
pub struct Vcn(I64<LittleEndian>);

impl Vcn {
    /// Converts this VCN into a byte offset (with respect to the cluster size of the provided [`Ntfs`] filesystem).
    ///
    /// # Errors
    ///
    /// Returns an error if the cluster offset cannot be represented without overflow.
    pub fn offset(&self, ntfs: &Ntfs) -> Result<i64> {
        self.0
            .get()
            .checked_mul(i64::from(ntfs.cluster_size()))
            .ok_or(NtfsError::VcnTooBig { vcn: *self })
    }

    /// Returns the stored Virtual Cluster Number.
    #[must_use]
    pub fn value(&self) -> i64 {
        self.0.get()
    }
}

impl From<i64> for Vcn {
    fn from(value: i64) -> Self {
        Self(I64::new(value))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Vcn {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<i64>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntfs_position_new_and_value() {
        let pos = NtfsPosition::new(42);
        assert!(pos.value().is_some());
        assert_eq!(pos.value().unwrap().get(), 42);
    }

    #[test]
    fn test_ntfs_position_zero_is_none() {
        // Position 0 maps to None (NonZeroU64 can't hold 0).
        let pos = NtfsPosition::new(0);
        assert!(pos.value().is_none());
    }

    #[test]
    fn test_ntfs_position_none() {
        let pos = NtfsPosition::none();
        assert!(pos.value().is_none());
    }

    #[test]
    fn test_ntfs_position_add_u64() {
        let pos = NtfsPosition::new(100);
        let pos2 = pos + 50u64;
        assert_eq!(pos2.value().unwrap().get(), 150);
    }

    #[test]
    fn test_ntfs_position_add_u16() {
        let pos = NtfsPosition::new(100);
        let pos2 = pos + 10u16;
        assert_eq!(pos2.value().unwrap().get(), 110);
    }

    #[test]
    fn test_ntfs_position_add_usize() {
        let pos = NtfsPosition::new(100);
        let pos2 = pos + 20usize;
        assert_eq!(pos2.value().unwrap().get(), 120);
    }

    #[test]
    fn test_ntfs_position_add_assign() {
        let mut pos = NtfsPosition::new(100);
        pos += 50u64;
        assert_eq!(pos.value().unwrap().get(), 150);

        pos += 10u16;
        assert_eq!(pos.value().unwrap().get(), 160);

        pos += 5usize;
        assert_eq!(pos.value().unwrap().get(), 165);
    }

    #[test]
    fn test_ntfs_position_none_add() {
        // Adding to None should remain None.
        let pos = NtfsPosition::none();
        let pos2 = pos + 42u64;
        assert!(pos2.value().is_none());
    }

    #[test]
    fn test_ntfs_position_display() {
        let pos = NtfsPosition::new(12345);
        assert_eq!(format!("{pos}"), "12345");

        let none_pos = NtfsPosition::none();
        assert_eq!(format!("{none_pos}"), "<NONE>");
    }

    #[test]
    fn test_ntfs_position_hex_display() {
        let pos = NtfsPosition::new(255);
        assert_eq!(format!("{pos:x}"), "ff");
        assert_eq!(format!("{pos:X}"), "FF");

        let none_pos = NtfsPosition::none();
        assert_eq!(format!("{none_pos:x}"), "<NONE>");
    }

    #[test]
    fn test_ntfs_position_binary_display() {
        let pos = NtfsPosition::new(5);
        assert_eq!(format!("{pos:b}"), "101");

        let none_pos = NtfsPosition::none();
        assert_eq!(format!("{none_pos:b}"), "<NONE>");
    }

    #[test]
    fn test_ntfs_position_octal_display() {
        let pos = NtfsPosition::new(8);
        assert_eq!(format!("{pos:o}"), "10");

        let none_pos = NtfsPosition::none();
        assert_eq!(format!("{none_pos:o}"), "<NONE>");
    }

    #[test]
    fn test_ntfs_position_ordering() {
        let pos1 = NtfsPosition::new(100);
        let pos2 = NtfsPosition::new(200);
        let none = NtfsPosition::none();

        assert!(pos1 < pos2);
        assert!(none < pos1); // None sorts before Some
        assert_eq!(pos1, NtfsPosition::new(100));
    }

    #[test]
    fn test_ntfs_position_from_nonzerou64() {
        let nz = NonZeroU64::new(42).unwrap();
        let pos = NtfsPosition::from(nz);
        assert_eq!(pos.value().unwrap().get(), 42);
    }

    #[test]
    fn test_lcn_value_and_from() {
        let lcn = Lcn::from(1024);
        assert_eq!(lcn.value(), 1024);
    }

    #[test]
    fn test_lcn_position() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let lcn = Lcn::from(1);
        let pos = lcn.position(&ntfs).unwrap();
        // LCN 1 * cluster_size should give us the position.
        assert_eq!(pos.value().unwrap().get(), u64::from(ntfs.cluster_size()));
    }

    #[test]
    fn test_lcn_checked_add_positive_vcn() {
        let lcn = Lcn::from(100);
        let vcn = Vcn::from(5);
        let result = lcn.checked_add(vcn).unwrap();
        assert_eq!(result.value(), 105);
    }

    #[test]
    fn test_lcn_checked_add_negative_vcn() {
        let lcn = Lcn::from(100);
        let vcn = Vcn::from(-5);
        let result = lcn.checked_add(vcn).unwrap();
        assert_eq!(result.value(), 95);
    }

    #[test]
    fn test_lcn_display() {
        let lcn = Lcn::from(42);
        assert_eq!(format!("{lcn}"), "42");
    }

    #[test]
    fn test_vcn_value_and_from() {
        let vcn = Vcn::from(42i64);
        assert_eq!(vcn.value(), 42);

        let vcn_neg = Vcn::from(-10i64);
        assert_eq!(vcn_neg.value(), -10);
    }

    #[test]
    fn test_vcn_offset() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let vcn = Vcn::from(2i64);
        let offset = vcn.offset(&ntfs).unwrap();
        assert_eq!(offset, 2 * i64::from(ntfs.cluster_size()));
    }

    /// Build a minimal in-memory NTFS image whose boot sector yields a
    /// 4096-byte cluster size. `Ntfs::new` only reads the boot sector
    /// (MFT positioning is pure arithmetic), so this is enough to obtain
    /// a real `Ntfs` with a known cluster size.
    fn synthetic_ntfs_image() -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; 1024];
        buf[0] = 0xEB;
        buf[1] = 0x52;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector
        buf[0x0D] = 8; // sectors_per_cluster -> cluster_size = 4096
        buf[0x28..0x30].copy_from_slice(&0x1000u64.to_le_bytes()); // total_sectors
        buf[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // mft_lcn
        buf[0x38..0x40].copy_from_slice(&1u64.to_le_bytes()); // mft_mirror_lcn
        buf[0x40] = (-10i8).cast_unsigned(); // clusters_per_mft_record
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf
    }

    #[test]
    fn test_vcn_offset_synthetic_exact() {
        let image = synthetic_ntfs_image();
        let mut cursor = std::io::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        assert_eq!(ntfs.cluster_size(), 4096);

        // VCN 3 * 4096 = 12288: distinct from the -1/0/1 replacements.
        let vcn = Vcn::from(3i64);
        assert_eq!(vcn.offset(&ntfs).unwrap(), 12288);

        // Negative VCN multiplies too: -2 * 4096 = -8192.
        let vcn = Vcn::from(-2i64);
        assert_eq!(vcn.offset(&ntfs).unwrap(), -8192);
    }

    #[test]
    fn test_lcn_position_synthetic_exact() {
        let image = synthetic_ntfs_image();
        let mut cursor = std::io::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();

        // LCN 5 * 4096 = 20480.
        let lcn = Lcn::from(5);
        assert_eq!(lcn.position(&ntfs).unwrap().value().unwrap().get(), 20480);
    }

    #[test]
    fn test_vcn_display() {
        let vcn = Vcn::from(-7i64);
        assert_eq!(format!("{vcn}"), "-7");
    }
}
