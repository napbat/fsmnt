//! Readers for attribute value types.

mod attribute_list_non_resident;
#[cfg(feature = "compression")]
mod compressed;
mod non_resident;
mod resident;
#[cfg(feature = "compression")]
mod wof;

pub use attribute_list_non_resident::*;
#[cfg(feature = "compression")]
pub use compressed::*;
pub use non_resident::*;
pub use resident::*;
#[cfg(feature = "compression")]
pub use wof::*;

use fs_common::error::IoError;
use fs_common::io::FsReadSeek;

use crate::data_run_map::DataRunMap;
use crate::error::{NtfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::types::NtfsPosition;

/// Reader that abstracts over all attribute value types, returned by [`NtfsAttribute::value`].
///
/// [`NtfsAttribute::value`]: crate::NtfsAttribute::value
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum NtfsAttributeValue<'n, 'f> {
    /// A resident attribute value (which is entirely contained in the NTFS File Record).
    Resident(NtfsResidentAttributeValue<'f>),
    /// A non-resident attribute value (whose data is in a cluster range outside the File Record).
    NonResident(NtfsNonResidentAttributeValue<'n, 'f>),
    /// A non-resident attribute value that is part of an Attribute List (and may span multiple connected attributes).
    AttributeListNonResident(NtfsAttributeListNonResidentAttributeValue<'n, 'f>),
    /// A compressed non-resident attribute value (requires the `compression` feature).
    #[cfg(feature = "compression")]
    CompressedNonResident(NtfsCompressedNonResidentAttributeValue<'n, 'f>),
}

impl<'n, 'f> NtfsAttributeValue<'n, 'f> {
    /// Returns a variant of this reader that implements [`Read`] and [`Seek`]
    /// by mutably borrowing the filesystem reader.
    pub fn attach<'a, T>(self, fs: &'a mut T) -> fs_common::io::Attached<'a, Self, T>
    where
        T: Read + Seek,
    {
        fs_common::io::Attached::new(self, fs)
    }

    /// Extracts the data runs from this non-resident attribute value
    /// into an owned [`DataRunMap`].
    ///
    /// Returns an error for resident or compressed values.
    pub(crate) fn data_run_map<T: Read + Seek>(&self, fs: &mut T) -> Result<DataRunMap> {
        match self {
            Self::NonResident(v) => DataRunMap::from_data_runs(v.data_runs()),
            Self::AttributeListNonResident(v) => v.data_run_map(fs),
            Self::Resident(_) => Err(NtfsError::UnexpectedResidentAttribute {
                position: self.data_position(),
            }),
            #[cfg(feature = "compression")]
            Self::CompressedNonResident(_) => Err(NtfsError::CompressedAttributeNotSupported),
        }
    }

    /// Returns the absolute current data seek position within the filesystem, in bytes.
    /// This may be `None` if:
    ///   * The current seek position is outside the valid range, or
    ///   * The attribute does not have a Data Run, or
    ///   * The current Data Run is a "sparse" Data Run.
    pub fn data_position(&self) -> NtfsPosition {
        match self {
            Self::Resident(inner) => inner.data_position(),
            Self::NonResident(inner) => inner.data_position(),
            Self::AttributeListNonResident(inner) => inner.data_position(),
            #[cfg(feature = "compression")]
            Self::CompressedNonResident(_) => NtfsPosition::none(),
        }
    }

    /// Returns `true` if the attribute value contains no data.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total length of the attribute value data, in bytes.
    pub fn len(&self) -> u64 {
        match self {
            Self::Resident(inner) => inner.len(),
            Self::NonResident(inner) => inner.len(),
            Self::AttributeListNonResident(inner) => inner.len(),
            #[cfg(feature = "compression")]
            Self::CompressedNonResident(inner) => inner.len(),
        }
    }

    /// Returns the current stream position within this value, in bytes.
    pub fn stream_position(&self) -> u64 {
        match self {
            Self::Resident(inner) => inner.stream_position(),
            Self::NonResident(inner) => inner.stream_position(),
            Self::AttributeListNonResident(inner) => inner.stream_position(),
            #[cfg(feature = "compression")]
            Self::CompressedNonResident(inner) => inner.stream_position(),
        }
    }
}

impl<R: Read + Seek> FsReadSeek<R> for NtfsAttributeValue<'_, '_> {
    type Error = NtfsError;

    fn read(&mut self, fs: &mut R, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Resident(inner) => inner.read(fs, buf),
            Self::NonResident(inner) => inner.read(fs, buf),
            Self::AttributeListNonResident(inner) => inner.read(fs, buf),
            #[cfg(feature = "compression")]
            Self::CompressedNonResident(inner) => inner.read(fs, buf),
        }
    }

    fn seek(&mut self, fs: &mut R, pos: SeekFrom) -> Result<u64> {
        match self {
            Self::Resident(inner) => inner.seek(fs, pos),
            Self::NonResident(inner) => inner.seek(fs, pos),
            Self::AttributeListNonResident(inner) => inner.seek(fs, pos),
            #[cfg(feature = "compression")]
            Self::CompressedNonResident(inner) => inner.seek(fs, pos),
        }
    }

    fn stream_position(&self) -> u64 {
        match self {
            Self::Resident(inner) => inner.stream_position(),
            Self::NonResident(inner) => inner.stream_position(),
            Self::AttributeListNonResident(inner) => inner.stream_position(),
            #[cfg(feature = "compression")]
            Self::CompressedNonResident(inner) => inner.stream_position(),
        }
    }

    fn len(&self) -> u64 {
        match self {
            Self::Resident(inner) => inner.len(),
            Self::NonResident(inner) => inner.len(),
            Self::AttributeListNonResident(inner) => inner.len(),
            #[cfg(feature = "compression")]
            Self::CompressedNonResident(inner) => inner.len(),
        }
    }
}

pub(crate) fn seek_contiguous(
    stream_position: &mut u64,
    length: u64,
    pos: SeekFrom,
) -> Result<u64> {
    // This implementation is taken from https://github.com/rust-lang/rust/blob/18c524fbae3ab1bf6ed9196168d8c68fc6aec61a/library/std/src/io/cursor.rs
    // It handles all signed/unsigned arithmetics properly and outputs the known `io` error message.
    let (base_pos, offset) = match pos {
        SeekFrom::Start(n) => {
            *stream_position = n;
            return Ok(n);
        }
        SeekFrom::End(n) => (length, n),
        SeekFrom::Current(n) => (*stream_position, n),
    };

    let new_pos = if offset >= 0 {
        base_pos.checked_add(offset as u64)
    } else {
        base_pos.checked_sub(offset.wrapping_neg() as u64)
    };

    match new_pos {
        Some(n) => {
            *stream_position = n;
            Ok(*stream_position)
        }
        None => Err(IoError::invalid_input().into()),
    }
}

#[cfg(test)]
mod tests {
    use fs_common::io::FsReadSeek;

    use crate::attribute_value::NtfsResidentAttributeValue;
    use crate::indexes::NtfsFileNameIndex;
    use crate::io::SeekFrom;
    use crate::ntfs::Ntfs;
    use crate::types::NtfsPosition;

    use super::NtfsAttributeValue;

    /// A `Read + Seek` reader that fails on any access. The resident
    /// variant never touches the filesystem, so all delegation assertions
    /// hold without real I/O.
    struct UnusedFs;

    impl std::io::Read for UnusedFs {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            panic!("resident value must not read from the filesystem")
        }
    }

    impl std::io::Seek for UnusedFs {
        fn seek(&mut self, _pos: std::io::SeekFrom) -> std::io::Result<u64> {
            panic!("resident value must not seek the filesystem")
        }
    }

    /// Wrap a byte slice as a resident `NtfsAttributeValue`.
    fn resident(data: &[u8]) -> NtfsAttributeValue<'_, '_> {
        NtfsAttributeValue::Resident(NtfsResidentAttributeValue::new(data, NtfsPosition::none()))
    }

    #[test]
    fn resident_len_and_is_empty_delegate() {
        // A 5-byte resident value reports its true length, distinct from
        // the 0/1 return-value replacements.
        let value = resident(b"12345");
        assert_eq!(value.len(), 5);
        assert!(!value.is_empty());

        let empty = resident(&[]);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn resident_stream_position_tracks_reads() {
        let mut fs = UnusedFs;
        let mut value = resident(b"abcdef");
        // Fresh value starts at position 0.
        assert_eq!(value.stream_position(), 0);
        assert_eq!(FsReadSeek::<UnusedFs>::stream_position(&value), 0);

        let mut buf = [0u8; 3];
        let n = value.read(&mut fs, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf, b"abc");
        // After reading 3 bytes the position advanced to 3, distinct from
        // the 0/1 return-value replacements.
        assert_eq!(value.stream_position(), 3);
        assert_eq!(FsReadSeek::<UnusedFs>::stream_position(&value), 3);
    }

    #[test]
    fn resident_read_returns_actual_byte_count() {
        let mut fs = UnusedFs;
        let mut value = resident(b"wxyz");
        let mut buf = [0u8; 4];
        // Reads 4 bytes (not the 0/1 replacement) and fills the buffer.
        let n = value.read(&mut fs, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, b"wxyz");
    }

    #[test]
    fn resident_seek_returns_target_offset() {
        let mut fs = UnusedFs;
        let mut value = resident(b"0123456789");
        // Seeking to offset 4 returns 4, distinct from the 0/1 replacement.
        let pos = value.seek(&mut fs, SeekFrom::Start(4)).unwrap();
        assert_eq!(pos, 4);
        assert_eq!(value.stream_position(), 4);

        // A second distinct seek confirms the returned value is the offset.
        let pos = value.seek(&mut fs, SeekFrom::Start(7)).unwrap();
        assert_eq!(pos, 7);
    }

    #[test]
    fn resident_fsreadseek_len_delegates() {
        let value = resident(b"abcdefg");
        // The FsReadSeek::len delegation reports 7, not 0/1.
        assert_eq!(FsReadSeek::<UnusedFs>::len(&value), 7);
    }

    #[test]
    fn read_exact_full_file() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "file-with-12345")
            .unwrap()
            .unwrap();
        let file = entry.to_file(&ntfs, &mut testfs1).unwrap();
        let data_item = file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attr = data_item.to_attribute().unwrap();
        let mut value = data_attr.value(&mut testfs1).unwrap();

        let mut buf = [0u8; 5];
        value.read_exact(&mut testfs1, &mut buf).unwrap();
        assert_eq!(&buf, b"12345");
    }

    #[test]
    fn read_exact_past_end_fails() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "file-with-12345")
            .unwrap()
            .unwrap();
        let file = entry.to_file(&ntfs, &mut testfs1).unwrap();
        let data_item = file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attr = data_item.to_attribute().unwrap();
        let mut value = data_attr.value(&mut testfs1).unwrap();

        let mut buf = [0u8; 10];
        let result = value.read_exact(&mut testfs1, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn is_empty() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "file-with-12345")
            .unwrap()
            .unwrap();
        let file = entry.to_file(&ntfs, &mut testfs1).unwrap();
        let data_item = file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attr = data_item.to_attribute().unwrap();
        let value = data_attr.value(&mut testfs1).unwrap();

        assert!(!value.is_empty());
    }
}
