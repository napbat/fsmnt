//! This module implements a reader for a value that is already in memory and can therefore be accessed via a slice.
//! This is the case for all resident attribute values and Index Record values.
//! Such values are part of NTFS records. NTFS records can't be directly read from the filesystem, which is why they
//! are always read into a buffer first and then fixed up in memory.
//! Further accesses to the record data can then happen via slices.

use super::seek_contiguous;
use fs_common::error::IoError;
use fs_common::io::FsReadSeek;

use crate::error::{NtfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::types::NtfsPosition;

fn slice_len_u64(data: &[u8]) -> u64 {
    u64::try_from(data.len()).expect("supported Rust targets have at most 64-bit pointers")
}

/// Reader for a value of a resident NTFS Attribute (which is entirely contained in the NTFS File Record).
#[derive(Clone, Debug)]
pub struct NtfsResidentAttributeValue<'f> {
    data: &'f [u8],
    position: NtfsPosition,
    stream_position: u64,
}

impl<'f> NtfsResidentAttributeValue<'f> {
    pub(crate) fn new(data: &'f [u8], position: NtfsPosition) -> Self {
        Self {
            data,
            position,
            stream_position: 0,
        }
    }

    /// Returns a slice of the entire value data.
    ///
    /// Remember that a resident attribute fits entirely inside the NTFS File Record
    /// of the requested file.
    /// Hence, the fixed up File Record is entirely in memory at this stage and a slice
    /// to a resident attribute value can be obtained easily.
    #[must_use]
    pub fn data(&self) -> &'f [u8] {
        self.data
    }

    /// Returns the absolute current data seek position within the filesystem, in bytes.
    /// This may be `None` if the current seek position is outside the valid range.
    #[must_use]
    pub fn data_position(&self) -> NtfsPosition {
        if self.stream_position <= self.len() {
            self.position + self.stream_position
        } else {
            NtfsPosition::none()
        }
    }

    /// Returns `true` if the resident attribute value contains no data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total length of the resident attribute value data, in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        slice_len_u64(self.data)
    }

    /// Returns the current stream position within this value, in bytes.
    #[must_use]
    pub fn stream_position(&self) -> u64 {
        self.stream_position
    }

    fn remaining_len(&self) -> u64 {
        self.len().saturating_sub(self.stream_position)
    }
}

impl<R: Read + Seek> FsReadSeek<R> for NtfsResidentAttributeValue<'_> {
    type Error = NtfsError;

    fn read(&mut self, _fs: &mut R, buf: &mut [u8]) -> Result<usize> {
        if self.remaining_len() == 0 {
            return Ok(0);
        }

        let remaining_len =
            usize::try_from(self.remaining_len()).map_err(|_| IoError::invalid_input())?;
        let bytes_to_read = usize::min(buf.len(), remaining_len);
        let work_slice = &mut buf[..bytes_to_read];

        let start = usize::try_from(self.stream_position).map_err(|_| IoError::invalid_input())?;
        let end = start + bytes_to_read;
        work_slice.copy_from_slice(&self.data[start..end]);

        self.stream_position +=
            u64::try_from(bytes_to_read).map_err(|_| IoError::invalid_input())?;
        Ok(bytes_to_read)
    }

    fn seek(&mut self, _fs: &mut R, pos: SeekFrom) -> Result<u64> {
        let length = self.len();
        seek_contiguous(&mut self.stream_position, length, pos)
    }

    fn stream_position(&self) -> u64 {
        self.stream_position
    }

    fn len(&self) -> u64 {
        slice_len_u64(self.data)
    }
}

#[cfg(test)]
mod tests {
    use crate::io::SeekFrom;

    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;
    use crate::types::NtfsPosition;
    use fs_common::io::FsReadSeek;

    use super::NtfsResidentAttributeValue;

    /// Builds a synthetic resident value over a fixed byte slice anchored at
    /// a non-zero on-disk position. A throwaway `Cursor` stands in for the
    /// (unused) backing reader.
    const SYNTH_DATA: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const SYNTH_POSITION: u64 = 0x4000;

    fn synth_value() -> NtfsResidentAttributeValue<'static> {
        NtfsResidentAttributeValue::new(SYNTH_DATA, NtfsPosition::new(SYNTH_POSITION))
    }

    #[test]
    fn synth_data_and_len() {
        let value = synth_value();
        // data() returns the exact backing slice (not empty / not [0] / [1]).
        assert_eq!(value.data(), SYNTH_DATA);
        // len() is the slice length, distinct from 0/1.
        assert_eq!(value.len(), 5);
        assert!(!value.is_empty());
    }

    #[test]
    fn synth_is_empty_true_and_false() {
        // Non-empty data: is_empty() must be false (kills `-> true`).
        assert!(!synth_value().is_empty());
        // Empty data: is_empty() must be true (kills `-> false`, and the
        // `== with !=` swap in `len() == 0`).
        let empty = NtfsResidentAttributeValue::new(&[], NtfsPosition::new(SYNTH_POSITION));
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn synth_data_position_within_and_beyond_range() {
        let mut value = synth_value();
        let mut fs = std::io::Cursor::new(alloc::vec::Vec::new());

        // At stream position 0 the data position equals the anchor.
        assert_eq!(value.data_position().value().unwrap().get(), SYNTH_POSITION);

        // Seek exactly to len (boundary): `stream_position <= len` is true,
        // so a valid position is returned (kills `<= with >`).
        value.seek(&mut fs, SeekFrom::Start(5)).unwrap();
        assert_eq!(
            value.data_position().value().unwrap().get(),
            SYNTH_POSITION + 5
        );

        // One past len: out of range, so no valid position.
        value.seek(&mut fs, SeekFrom::Start(6)).unwrap();
        assert_eq!(value.data_position().value(), None);
    }

    #[test]
    fn synth_stream_position_tracks_reads() {
        let mut value = synth_value();
        let mut fs = std::io::Cursor::new(alloc::vec::Vec::new());

        // Initially zero.
        assert_eq!(value.stream_position(), 0);
        assert_eq!(
            FsReadSeek::<std::io::Cursor<alloc::vec::Vec<u8>>>::stream_position(&value),
            0
        );

        // Read 3 bytes; the inherent and trait stream positions advance by
        // exactly 3 (kills `-> 0`, `-> 1`, and `+= with *=`).
        let mut buf = [0u8; 3];
        let n = value.read(&mut fs, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(value.stream_position(), 3);
        assert_eq!(
            FsReadSeek::<std::io::Cursor<alloc::vec::Vec<u8>>>::stream_position(&value),
            3
        );
    }

    #[test]
    fn synth_read_consumes_then_returns_zero_at_end() {
        let mut value = synth_value();
        let mut fs = std::io::Cursor::new(alloc::vec::Vec::new());

        // First read returns the genuine byte count (kills `-> Ok(0)`/`Ok(1)`
        // and the `remaining_len() == 0` -> `!=` swap, which would early-exit
        // here with Ok(0)).
        let mut buf = [0u8; 8];
        let n = value.read(&mut fs, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], SYNTH_DATA);

        // At end, a further read returns exactly 0.
        let mut buf2 = [0xFFu8; 4];
        let n2 = value.read(&mut fs, &mut buf2).unwrap();
        assert_eq!(n2, 0);
        assert_eq!(buf2, [0xFF; 4]);
    }

    #[test]
    fn synth_seek_returns_new_position_and_trait_len() {
        let mut value = synth_value();
        let mut fs = std::io::Cursor::new(alloc::vec::Vec::new());

        // seek returns the resulting stream position (kills `-> Ok(0)`/`Ok(1)`).
        let pos = value.seek(&mut fs, SeekFrom::Start(4)).unwrap();
        assert_eq!(pos, 4);
        assert_eq!(value.stream_position(), 4);

        // trait len() reports the data length (kills `-> 0`/`-> 1`).
        assert_eq!(
            FsReadSeek::<std::io::Cursor<alloc::vec::Vec<u8>>>::len(&value),
            5
        );
    }

    #[test]
    fn test_read_and_seek() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "file-with-12345".
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "file-with-12345")
                .unwrap()
                .unwrap();
        let file = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Get its data attribute.
        let data_attribute_item = file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attribute = data_attribute_item.to_attribute().unwrap();
        assert!(data_attribute.is_resident());
        assert_eq!(data_attribute.value_length(), 5);

        let mut data_attribute_value = data_attribute.value(&mut testfs1).unwrap();
        assert_eq!(data_attribute_value.stream_position(), 0);
        assert_eq!(data_attribute_value.len(), 5);

        // TEST READING
        let data_position_before = data_attribute_value.data_position().value().unwrap();

        // We have a 6 bytes buffer, but the file is only 5 bytes long.
        // The last byte should be untouched.
        let mut buf = [0xCCu8; 6];
        let bytes_read = data_attribute_value.read(&mut testfs1, &mut buf).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(buf, [b'1', b'2', b'3', b'4', b'5', 0xCC]);

        // The internal position should have stopped directly after the last byte of the file,
        // and must also yield a valid data position.
        assert_eq!(data_attribute_value.stream_position(), 5);

        let data_position_after = data_attribute_value.data_position().value().unwrap();
        assert_eq!(
            data_position_after,
            data_position_before.checked_add(5).unwrap()
        );

        // TEST SEEKING
        // A seek to the beginning should yield the data position before the read.
        data_attribute_value
            .seek(&mut testfs1, SeekFrom::Start(0))
            .unwrap();
        assert_eq!(data_attribute_value.stream_position(), 0);
        assert_eq!(
            data_attribute_value.data_position().value().unwrap(),
            data_position_before
        );

        // A seek to one byte after the last read byte should yield the data position
        // after the read.
        data_attribute_value
            .seek(&mut testfs1, SeekFrom::Start(5))
            .unwrap();
        assert_eq!(data_attribute_value.stream_position(), 5);
        assert_eq!(
            data_attribute_value.data_position().value().unwrap(),
            data_position_after
        );

        // A seek beyond the size of the data must yield no valid data position.
        data_attribute_value
            .seek(&mut testfs1, SeekFrom::Start(6))
            .unwrap();
        assert_eq!(data_attribute_value.stream_position(), 6);
        assert_eq!(data_attribute_value.data_position().value(), None);
    }

    #[test]
    fn test_resident_seek_from_end() {
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

        // Seek to 2 bytes before the end.
        value.seek(&mut testfs1, SeekFrom::End(-2)).unwrap();
        assert_eq!(value.stream_position(), 3);

        let mut buf = [0u8; 2];
        let bytes_read = value.read(&mut testfs1, &mut buf).unwrap();
        assert_eq!(bytes_read, 2);
        assert_eq!(&buf, b"45");
    }

    #[test]
    fn test_resident_seek_current() {
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

        // Read 2 bytes, then seek forward by 1.
        let mut buf = [0u8; 2];
        value.read_exact(&mut testfs1, &mut buf).unwrap();
        assert_eq!(&buf, b"12");
        assert_eq!(value.stream_position(), 2);

        value.seek(&mut testfs1, SeekFrom::Current(1)).unwrap();
        assert_eq!(value.stream_position(), 3);

        value.read_exact(&mut testfs1, &mut buf).unwrap();
        assert_eq!(&buf, b"45");
    }

    #[test]
    fn test_resident_data_slice() {
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

        // Resident attributes expose a data() slice.
        let resident_value = data_attr.resident_value().unwrap();
        assert_eq!(resident_value.data(), b"12345");
        assert!(!resident_value.is_empty());
        assert_eq!(resident_value.len(), 5);
    }

    #[test]
    fn test_resident_read_past_end() {
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

        // Seek to end.
        value.seek(&mut testfs1, SeekFrom::Start(5)).unwrap();

        // Reading at the end should return 0 bytes.
        let mut buf = [0xCCu8; 4];
        let bytes_read = value.read(&mut testfs1, &mut buf).unwrap();
        assert_eq!(bytes_read, 0);
        assert_eq!(buf, [0xCC; 4]); // buffer untouched
    }
}
