use core::ops::Range;

use memoffset::offset_of;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::index_entry::{IndexNodeEntryRanges, NtfsIndexNodeEntries};
use crate::index_record::{INDEX_NODE_HEADER_SIZE, IndexNodeHeader};
use crate::indexes::NtfsIndexEntryType;
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Size of all [`IndexRootHeader`] fields plus some reserved bytes.
const INDEX_ROOT_HEADER_SIZE: usize = 16;

#[repr(C, packed)]
struct IndexRootHeader {
    ty: u32,
    collation_rule: u32,
    index_record_size: u32,
    clusters_per_index_record: i8,
}

/// Structure of an $`INDEX_ROOT` attribute.
///
/// This attribute describes the top-level nodes of a B-tree.
/// The sub-nodes are managed via [`NtfsIndexAllocation`].
///
/// NTFS uses B-trees for describing directories (as indexes of [`NtfsFileName`]s), looking up Object IDs,
/// Reparse Points, and Security Descriptors, to just name a few.
///
/// An $`INDEX_ROOT` attribute is always resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/index_root.html>
///
/// NTFS on-disk structure; no direct MS-FSCC equivalent.
///
/// [`NtfsFileName`]: crate::structured_values::NtfsFileName
/// [`NtfsIndexAllocation`]: crate::structured_values::NtfsIndexAllocation
#[derive(Clone, Debug)]
pub struct NtfsIndexRoot<'f> {
    slice: &'f [u8],
    position: NtfsPosition,
}

const LARGE_INDEX_FLAG: u8 = 0x01;

impl<'f> NtfsIndexRoot<'f> {
    fn new(slice: &'f [u8], position: NtfsPosition) -> Result<Self> {
        if slice.len() < INDEX_ROOT_HEADER_SIZE + INDEX_NODE_HEADER_SIZE {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::IndexRoot,
                expected: u64::try_from(INDEX_ROOT_HEADER_SIZE)
                    .expect("the fixed index-root header size fits in u64"),
                actual: u64::try_from(slice.len()).unwrap_or(u64::MAX),
            });
        }

        let index_root = Self { slice, position };
        index_root.validate_sizes()?;

        Ok(index_root)
    }

    /// Returns an iterator over all top-level nodes of the B-tree.
    ///
    /// # Errors
    ///
    /// Returns an error if the on-disk index entry offsets or sizes do not
    /// describe a valid range within the index root.
    pub fn entries<E>(&self) -> Result<NtfsIndexNodeEntries<'f, E>>
    where
        E: NtfsIndexEntryType,
    {
        let (entries_range, position) = self.entries_range_and_position();
        let slice = &self.slice[entries_range];

        Ok(NtfsIndexNodeEntries::new(slice, position))
    }

    fn entries_range_and_position(&self) -> (Range<usize>, NtfsPosition) {
        let start = INDEX_ROOT_HEADER_SIZE
            .saturating_add(usize::try_from(self.index_entries_offset()).unwrap_or(usize::MAX));
        let end = INDEX_ROOT_HEADER_SIZE
            .saturating_add(usize::try_from(self.index_data_size()).unwrap_or(usize::MAX));
        let position = self.position + start;

        (start..end, position)
    }

    pub(crate) fn entry_ranges<E>(&self) -> IndexNodeEntryRanges<E>
    where
        E: NtfsIndexEntryType,
    {
        let (entries_range, position) = self.entries_range_and_position();
        let entries_data = self.slice[entries_range].to_vec();
        let range = 0..entries_data.len();

        IndexNodeEntryRanges::new(entries_data, range, position)
    }

    /// Raw bytes of the slack space region (between used entries and allocated space).
    ///
    /// When files are deleted from a directory, their index entries are removed from the B-tree
    /// but the data is **not zeroed**. This slack space may contain recoverable file names,
    /// timestamps, and MFT references.
    #[must_use]
    pub fn slack_data(&self) -> &[u8] {
        let start = INDEX_ROOT_HEADER_SIZE
            .saturating_add(usize::try_from(self.index_data_size()).unwrap_or(usize::MAX));
        let end = INDEX_ROOT_HEADER_SIZE
            .saturating_add(usize::try_from(self.index_allocated_size()).unwrap_or(usize::MAX));
        let start = start.min(self.slice.len());
        let end = end.min(self.slice.len());
        if start >= end {
            return &[];
        }
        &self.slice[start..end]
    }

    /// Byte position on disk where slack space starts.
    #[must_use]
    pub fn slack_position(&self) -> NtfsPosition {
        let start = INDEX_ROOT_HEADER_SIZE
            .saturating_add(usize::try_from(self.index_data_size()).unwrap_or(usize::MAX));
        self.position + start
    }

    /// Returns the allocated size of this NTFS Index Root, in bytes.
    #[must_use]
    pub fn index_allocated_size(&self) -> u32 {
        let start = INDEX_ROOT_HEADER_SIZE + offset_of!(IndexNodeHeader, allocated_size);
        self.read_u32(start)
    }

    /// Returns the size actually used by index data within this NTFS Index Root, in bytes.
    #[must_use]
    pub fn index_data_size(&self) -> u32 {
        let start = INDEX_ROOT_HEADER_SIZE + offset_of!(IndexNodeHeader, index_size);
        self.read_u32(start)
    }

    // mutants::skip: `entries_offset` is the first field of IndexNodeHeader,
    // so offset_of!(..) is 0; `16 + 0` and `16 - 0` are provably equal,
    // making the `+` -> `-` mutant equivalent (untestable).
    #[cfg_attr(test, mutants::skip)]
    fn index_entries_offset(&self) -> u32 {
        let start = INDEX_ROOT_HEADER_SIZE + offset_of!(IndexNodeHeader, entries_offset);
        self.read_u32(start)
    }

    /// Returns the size of a single Index Record, in bytes.
    #[must_use]
    pub fn index_record_size(&self) -> u32 {
        let start = offset_of!(IndexRootHeader, index_record_size);
        self.read_u32(start)
    }

    /// Returns whether the index belonging to this Index Root is large enough
    /// to need an extra Index Allocation attribute.
    /// Otherwise, the entire index information is stored in this Index Root.
    #[must_use]
    pub fn is_large_index(&self) -> bool {
        let start = INDEX_ROOT_HEADER_SIZE + offset_of!(IndexNodeHeader, flags);
        (self.slice[start] & LARGE_INDEX_FLAG) != 0
    }

    /// Returns the absolute position of this Index Root within the filesystem, in bytes.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position
    }

    fn read_u32(&self, start: usize) -> u32 {
        let bytes = self.slice[start..]
            .first_chunk()
            .expect("validated index-root headers contain every fixed-width field");
        u32::from_le_bytes(*bytes)
    }

    fn validate_sizes(&self) -> Result<()> {
        let (entries_range, _position) = self.entries_range_and_position();

        if entries_range.start > entries_range.end {
            return Err(NtfsError::InvalidIndexRootEntriesRange {
                position: self.position,
                start: entries_range.start,
                end: entries_range.end,
            });
        }

        if entries_range.start >= self.slice.len() {
            return Err(NtfsError::InvalidIndexRootEntriesOffset {
                position: self.position,
                expected: entries_range.start,
                actual: self.slice.len(),
            });
        }

        if entries_range.end > self.slice.len() {
            return Err(NtfsError::InvalidIndexRootUsedSize {
                position: self.position,
                expected: entries_range.end,
                actual: self.slice.len(),
            });
        }

        Ok(())
    }
}

impl<'n, 'f> NtfsStructuredValue<'n, 'f> for NtfsIndexRoot<'f> {
    const TY: NtfsAttributeType = NtfsAttributeType::IndexRoot;

    fn from_attribute_value<T>(_fs: &mut T, value: NtfsAttributeValue<'n, 'f>) -> Result<Self>
    where
        T: Read + Seek,
    {
        let position = value.data_position();

        let NtfsAttributeValue::Resident(resident_value) = value else {
            return Err(NtfsError::UnexpectedNonResidentAttribute { position });
        };

        Self::new(resident_value.data(), position)
    }
}

impl<'f> NtfsStructuredValueFromResidentAttributeValue<'_, 'f> for NtfsIndexRoot<'f> {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        Self::new(value.data(), value.data_position())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::NtfsAttributeType;
    use crate::ntfs::Ntfs;
    use crate::structured_values::NtfsIndexRoot;
    use fsmnt_parser_core::iter::FsTryIterator;

    /// Build a synthetic `$INDEX_ROOT` attribute slice.
    ///
    /// Layout (little-endian):
    /// `IndexRootHeader` (16 bytes incl. reserved): `ty`@0, `collation_rule`@4,
    /// `index_record_size`@8, `clusters_per_index_record`@12.
    /// `IndexNodeHeader` @16: `entries_offset`@16, `index_size`@20,
    /// `allocated_size`@24, `flags`@28.
    /// The buffer is `INDEX_ROOT_HEADER_SIZE + allocated_size` bytes long.
    fn build_index_root(
        index_record_size: u32,
        entries_offset: u32,
        index_data_size: u32,
        allocated_size: u32,
        flags: u8,
    ) -> alloc::vec::Vec<u8> {
        let total = INDEX_ROOT_HEADER_SIZE
            + usize::try_from(allocated_size).expect("test allocated size fits usize");
        let mut buf = alloc::vec![0u8; total.max(INDEX_ROOT_HEADER_SIZE + INDEX_NODE_HEADER_SIZE)];
        // IndexRootHeader
        buf[0..4].copy_from_slice(&0x30u32.to_le_bytes()); // ty (FileName)
        buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // collation_rule
        buf[8..12].copy_from_slice(&index_record_size.to_le_bytes());
        buf[12] = (-12i8).cast_unsigned(); // clusters_per_index_record
        // IndexNodeHeader at offset 16.
        buf[16..20].copy_from_slice(&entries_offset.to_le_bytes());
        buf[20..24].copy_from_slice(&index_data_size.to_le_bytes());
        buf[24..28].copy_from_slice(&allocated_size.to_le_bytes());
        buf[28] = flags;
        buf
    }

    #[test]
    fn test_index_root_accessors_exact() {
        // entries_offset=16, data_size=48, allocated=80, record_size=4096.
        let buf = build_index_root(4096, 16, 48, 80, 0x00);
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x1000)).expect("valid index root");

        assert_eq!(root.index_record_size(), 4096);
        assert_eq!(root.index_data_size(), 48);
        assert_eq!(root.index_allocated_size(), 80);
        assert!(!root.is_large_index());
        assert_eq!(root.position().value().unwrap().get(), 0x1000);
    }

    #[test]
    fn test_index_root_is_large_index_flag() {
        // LARGE_INDEX_FLAG (0x01) set.
        let buf = build_index_root(4096, 16, 48, 80, 0x01);
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x1000)).unwrap();
        assert!(root.is_large_index());

        // A different bit set (0x02) must NOT be reported as large index;
        // distinguishes `& 0x01` from `| 0x01` / `^ 0x01`.
        let buf = build_index_root(4096, 16, 48, 80, 0x02);
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x1000)).unwrap();
        assert!(!root.is_large_index());

        // Both bits set: 0x03 & 0x01 = 1 -> large.
        let buf = build_index_root(4096, 16, 48, 80, 0x03);
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x1000)).unwrap();
        assert!(root.is_large_index());
    }

    #[test]
    fn test_index_root_slack_data_and_position_exact() {
        // entries_offset=16, data_size=32, allocated=64.
        // slack = bytes [16+32 .. 16+64] = [48 .. 80], length 32.
        let buf = build_index_root(4096, 16, 32, 64, 0x00);
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x2000)).unwrap();

        let slack = root.slack_data();
        assert_eq!(slack.len(), 32);
        // Pointer identity: slack begins at offset 48 in the slice.
        assert_eq!(slack.as_ptr(), buf[48..].as_ptr());

        // slack_position = position + (INDEX_ROOT_HEADER_SIZE + data_size)
        //                = 0x2000 + 48.
        assert_eq!(root.slack_position().value().unwrap().get(), 0x2000 + 48);
    }

    #[test]
    fn test_index_root_slack_data_end_uses_addition() {
        // Build a slice LARGER than INDEX_ROOT_HEADER_SIZE + allocated_size so
        // the `.min(slice.len())` clamp does not mask the `+` -> `*` mutant.
        // data_size=0 (start=16), allocated_size=4 (end=16+4=20).
        // Original slack = [16..20] (len 4). The `*` mutant computes
        // 16*4=64, giving a much longer slack region.
        let mut buf = build_index_root(4096, 0, 0, 4, 0x00);
        buf.resize(100, 0); // trailing padding beyond allocated_size
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x100)).unwrap();
        assert_eq!(root.slack_data().len(), 4);
    }

    #[test]
    fn test_index_root_slack_data_marks_recoverable_bytes() {
        // Place distinctive bytes in the slack region [48..80] and ensure
        // slack_data returns exactly those.
        let mut buf = build_index_root(4096, 16, 32, 64, 0x00);
        for (i, b) in buf[48..80].iter_mut().enumerate() {
            *b = u8::try_from(i).expect("test value fits u8").wrapping_add(1);
        }
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x2000)).unwrap();
        let slack = root.slack_data();
        assert_eq!(slack[0], 1);
        assert_eq!(slack[31], 32);
    }

    #[test]
    fn test_index_root_entries_range_and_position() {
        // entries_offset=16, data_size=40.
        // start = 16 + 16 = 32, end = 16 + 40 = 56.
        let buf = build_index_root(4096, 16, 40, 80, 0x00);
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x4000)).unwrap();

        let (range, position) = root.entries_range_and_position();
        assert_eq!(range.start, 32);
        assert_eq!(range.end, 56);
        // position = base 0x4000 + start(32).
        assert_eq!(position.value().unwrap().get(), 0x4000 + 32);
    }

    #[test]
    fn test_index_root_validate_sizes_rejects_offset_beyond_slice() {
        // start == end (passes the start>end check) but start lands exactly
        // at slice.len(): entries_offset == data_size == allocated_size == 80,
        // so start = end = slice.len() = 96. The `>=` boundary fires here;
        // a `<` mutant would let it through.
        let buf = build_index_root(4096, 80, 80, 80, 0x00);
        let err = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x10)).unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidIndexRootEntriesOffset { .. }
        ));
    }

    #[test]
    fn test_index_root_validate_sizes_rejects_used_beyond_slice() {
        // data_size larger than the allocated slice -> end > slice.len().
        // entries_offset valid (0), data_size=200, allocated=16 (slice=32).
        let buf = build_index_root(4096, 0, 200, 16, 0x00);
        let err = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x10)).unwrap_err();
        assert!(matches!(err, NtfsError::InvalidIndexRootUsedSize { .. }));
    }

    #[test]
    fn test_index_root_slack_data_empty_when_no_slack() {
        // data_size == allocated_size -> no slack (start >= end).
        let buf = build_index_root(4096, 16, 48, 48, 0x00);
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x100)).unwrap();
        assert!(root.slack_data().is_empty());
    }

    #[test]
    fn test_index_root_validate_accepts_empty_entries_range() {
        // entries_offset == data_size -> range.start == range.end, an empty
        // but VALID entries range. `start > end` is false; the `>=` mutant
        // would wrongly reject this.
        let buf = build_index_root(4096, 16, 16, 80, 0x00);
        let root = NtfsIndexRoot::new(&buf, NtfsPosition::new(0x100)).unwrap();
        let (range, _) = root.entries_range_and_position();
        assert_eq!(range.start, range.end);
        assert_eq!(range.start, 32);
    }

    #[test]
    fn test_index_root_slack_data() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Get the INDEX_ROOT attribute
        let mut attrs = root_dir.attributes();
        let mut index_root_item = None;
        while let Some(item) = attrs.try_next(&mut testfs1).unwrap() {
            let attr = item.to_attribute().unwrap();
            if attr.ty().unwrap() == NtfsAttributeType::IndexRoot {
                index_root_item = Some(item);
                break;
            }
        }

        let index_root_item = index_root_item.expect("root dir should have INDEX_ROOT");
        let index_root_attr = index_root_item.to_attribute().unwrap();
        let index_root = index_root_attr
            .resident_structured_value::<NtfsIndexRoot>()
            .unwrap();

        let slack = index_root.slack_data();
        let slack_pos = index_root.slack_position();

        // Slack size should be allocated - used
        let expected_len =
            usize::try_from(index_root.index_allocated_size() - index_root.index_data_size())
                .expect("test slack length fits usize");
        assert_eq!(slack.len(), expected_len);

        // Position should be valid
        assert!(slack_pos.value().is_some());
    }
}
