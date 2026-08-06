use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::error::Result;
use crate::file::NtfsFile;
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;

/// Absolute reference to a File Record on the filesystem, composed out of a File Record Number and a Sequence Number.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/file_reference.html>
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(transparent)]
pub struct NtfsFileReference([u8; 8]);

impl NtfsFileReference {
    pub(crate) const fn new(file_reference_bytes: [u8; 8]) -> Self {
        Self(file_reference_bytes)
    }

    /// Creates an [`NtfsFileReference`] from a File Record Number and a Sequence Number.
    // mutants::skip: the 48-bit record number and the seq<<48 term occupy
    // disjoint bit ranges after masking, so `|` and `^` are identical here.
    #[cfg_attr(test, mutants::skip)]
    pub fn from_parts(file_record_number: u64, sequence_number: u16) -> Self {
        let value = (file_record_number & 0xffff_ffff_ffff) | ((sequence_number as u64) << 48);
        Self(value.to_le_bytes())
    }

    /// Returns the 48-bit File Record Number.
    ///
    /// This can be fed into [`Ntfs::file`] to create an [`NtfsFile`] object for the corresponding File Record
    /// (if you cannot use [`Self::to_file`] for some reason).
    pub fn file_record_number(&self) -> u64 {
        u64::from_le_bytes(self.0) & 0xffff_ffff_ffff
    }

    /// Returns the 16-bit sequence number of the File Record.
    ///
    /// In a consistent file system, this number matches what [`NtfsFile::sequence_number`] returns.
    pub fn sequence_number(&self) -> u16 {
        (u64::from_le_bytes(self.0) >> 48) as u16
    }

    /// Returns whether the referenced file is an NTFS system metafile
    /// (MFT records 0–23).
    ///
    /// See [`NtfsFile::is_system_metafile`] for details.
    pub fn is_system_metafile(&self) -> bool {
        self.file_record_number() < 24
    }

    /// Returns an [`NtfsFile`] for the file referenced by this object.
    pub fn to_file<'n, T>(&self, ntfs: &'n Ntfs, fs: &mut T) -> Result<NtfsFile<'n>>
    where
        T: Read + Seek,
    {
        ntfs.file(fs, self.file_record_number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_parts_roundtrip() {
        let file_ref = NtfsFileReference::from_parts(42, 7);
        assert_eq!(file_ref.file_record_number(), 42);
        assert_eq!(file_ref.sequence_number(), 7);
    }

    #[test]
    fn test_from_parts_max_values() {
        // 48-bit max record number, 16-bit max sequence number.
        let max_record = 0xffff_ffff_ffff;
        let max_seq = 0xffff;
        let file_ref = NtfsFileReference::from_parts(max_record, max_seq);
        assert_eq!(file_ref.file_record_number(), max_record);
        assert_eq!(file_ref.sequence_number(), max_seq);
    }

    #[test]
    fn test_from_parts_truncates_record_number() {
        // Record numbers above 48 bits should be masked.
        let file_ref = NtfsFileReference::from_parts(0x1_0000_0000_0005, 1);
        assert_eq!(file_ref.file_record_number(), 5);
        assert_eq!(file_ref.sequence_number(), 1);
    }

    #[test]
    fn test_is_system_metafile_below_boundary() {
        // Record number 23 is the last system metafile (< 24).
        let file_ref = NtfsFileReference::from_parts(23, 1);
        assert!(file_ref.is_system_metafile());
        // Record number 0 is also a system metafile.
        let zero_ref = NtfsFileReference::from_parts(0, 1);
        assert!(zero_ref.is_system_metafile());
    }

    #[test]
    fn test_is_system_metafile_at_and_above_boundary() {
        // Record number 24 is the first non-system file (not < 24).
        let file_ref = NtfsFileReference::from_parts(24, 1);
        assert!(!file_ref.is_system_metafile());
        // A clearly higher record number is also not a system metafile.
        let high_ref = NtfsFileReference::from_parts(100, 1);
        assert!(!high_ref.is_system_metafile());
    }
}
