use core::ops::Range;

use alloc::vec;
use alloc::vec::Vec;
use memoffset::offset_of;

use crate::attribute_value::NtfsAttributeValue;
use crate::error::{NtfsError, Result};
use crate::index_entry::{IndexNodeEntryRanges, NtfsIndexNodeEntries};
use crate::indexes::NtfsIndexEntryType;
use crate::io::{Read, Seek};
use crate::record::Record;
use crate::record::RecordHeader;
use crate::types::{NtfsPosition, Vcn};
use fs_common::io::FsReadSeek;

/// Size of all [`IndexRecordHeader`] fields.
const INDEX_RECORD_HEADER_SIZE: u32 = 24;

/// Maximum allowed index record size (256 KB).
///
/// Real NTFS volumes use 4096 bytes. This generous cap prevents unbounded
/// allocations from crafted `$INDEX_ROOT` attributes while still accepting any
/// legitimate filesystem.
const MAX_INDEX_RECORD_SIZE: u32 = 256 * 1024;

#[repr(C, packed)]
struct IndexRecordHeader {
    record_header: RecordHeader,
    vcn: i64,
}

/// Size of all [`IndexNodeHeader`] fields plus some reserved bytes.
pub(crate) const INDEX_NODE_HEADER_SIZE: usize = 16;

#[repr(C, packed)]
pub(crate) struct IndexNodeHeader {
    pub(crate) entries_offset: u32,
    pub(crate) index_size: u32,
    pub(crate) allocated_size: u32,
    pub(crate) flags: u8,
}

/// A single NTFS Index Record.
///
/// These records are denoted via an `INDX` signature on the filesystem.
///
/// NTFS uses B-tree indexes to quickly look up files, Object IDs, Reparse Points, Security Descriptors, etc.
/// An Index Record is further comprised of Index Entries, which contain the actual key/data (see [`NtfsIndexEntry`],
/// iterated via [`NtfsIndexNodeEntries`]).
///
/// [`NtfsIndexEntry`]: crate::NtfsIndexEntry
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/index_record.html>
#[derive(Debug)]
pub struct NtfsIndexRecord {
    record: Record,
}

const HAS_SUBNODES_FLAG: u8 = 0x01;

impl NtfsIndexRecord {
    pub(crate) fn new<T>(
        fs: &mut T,
        mut value: NtfsAttributeValue,
        index_record_size: u32,
    ) -> Result<Self>
    where
        T: Read + Seek,
    {
        let data_position = value.data_position();

        if index_record_size > MAX_INDEX_RECORD_SIZE {
            return Err(NtfsError::InvalidIndexAllocatedSize {
                position: data_position,
                expected: MAX_INDEX_RECORD_SIZE,
                actual: index_record_size,
            });
        }

        let mut data = vec![0; index_record_size as usize];
        value.read_exact(fs, &mut data)?;

        Self::from_raw_data(data, data_position)
    }

    /// Creates an [`NtfsIndexRecord`] from pre-read raw data.
    ///
    /// Performs the same signature and fixup validation as [`Self::new`]
    /// but skips the I/O step, which is handled by the caller.
    pub(crate) fn from_raw_data(data: Vec<u8>, position: NtfsPosition) -> Result<Self> {
        let mut record = Record::new(data, position);
        Self::validate_signature(&record)?;
        record.fixup()?;

        let index_record = Self { record };
        index_record.validate_sizes()?;

        Ok(index_record)
    }

    /// Returns an iterator over all entries of this Index Record (cf. [`NtfsIndexEntry`]).
    ///
    /// [`NtfsIndexEntry`]: crate::NtfsIndexEntry
    pub fn entries<'s, E>(&'s self) -> Result<NtfsIndexNodeEntries<'s, E>>
    where
        E: NtfsIndexEntryType,
    {
        let (entries_range, position) = self.entries_range_and_position();
        let data = &self.record.data()[entries_range];

        Ok(NtfsIndexNodeEntries::new(data, position))
    }

    fn entries_range_and_position(&self) -> (Range<usize>, NtfsPosition) {
        let start = INDEX_RECORD_HEADER_SIZE as usize + self.index_entries_offset() as usize;
        let end = INDEX_RECORD_HEADER_SIZE as usize + self.index_data_size() as usize;
        let position = self.record.position() + start;

        (start..end, position)
    }

    /// Returns whether this index node has sub-nodes.
    /// Otherwise, this index node is a leaf node.
    pub fn has_subnodes(&self) -> bool {
        let start = INDEX_RECORD_HEADER_SIZE as usize + offset_of!(IndexNodeHeader, flags);
        let flags = self.record.data()[start];
        (flags & HAS_SUBNODES_FLAG) != 0
    }

    /// Returns the allocated size of this NTFS Index Record, in bytes.
    pub fn index_allocated_size(&self) -> u32 {
        let start = INDEX_RECORD_HEADER_SIZE as usize + offset_of!(IndexNodeHeader, allocated_size);
        u32::from_le_bytes(*self.record.data()[start..].first_chunk().unwrap())
    }

    /// Returns the size actually used by index data within this NTFS Index Record, in bytes.
    pub fn index_data_size(&self) -> u32 {
        let start = INDEX_RECORD_HEADER_SIZE as usize + offset_of!(IndexNodeHeader, index_size);
        u32::from_le_bytes(*self.record.data()[start..].first_chunk().unwrap())
    }

    pub(crate) fn index_entries_offset(&self) -> u32 {
        let start = INDEX_RECORD_HEADER_SIZE as usize + offset_of!(IndexNodeHeader, entries_offset);
        u32::from_le_bytes(*self.record.data()[start..].first_chunk().unwrap())
    }

    pub(crate) fn into_entry_ranges<E>(self) -> IndexNodeEntryRanges<E>
    where
        E: NtfsIndexEntryType,
    {
        let (entries_range, position) = self.entries_range_and_position();
        IndexNodeEntryRanges::new(self.record.into_data(), entries_range, position)
    }

    fn validate_signature(record: &Record) -> Result<()> {
        let signature = record.signature()?;
        let expected = b"INDX";

        if &signature == expected {
            Ok(())
        } else {
            Err(NtfsError::InvalidIndexSignature {
                position: record.position(),
                expected,
                actual: signature,
            })
        }
    }

    fn validate_sizes(&self) -> Result<()> {
        let index_record_size = self.record.len() as u64;

        // The total size allocated for this Index Record must not be larger than
        // the size defined for all index records of this index. Perform the
        // arithmetic in u64 to avoid overflow on malformed on-disk values.
        let total_allocated_size =
            INDEX_RECORD_HEADER_SIZE as u64 + self.index_allocated_size() as u64;
        if total_allocated_size > index_record_size {
            return Err(NtfsError::InvalidIndexAllocatedSize {
                position: self.record.position(),
                expected: index_record_size.min(u32::MAX as u64) as u32,
                actual: total_allocated_size.min(u32::MAX as u64) as u32,
            });
        }

        // Furthermore, the total used size for this Index Record must not be
        // larger than the total allocated size.
        let total_data_size = INDEX_RECORD_HEADER_SIZE as u64 + self.index_data_size() as u64;
        if total_data_size > total_allocated_size {
            return Err(NtfsError::InvalidIndexUsedSize {
                position: self.record.position(),
                expected: total_allocated_size.min(u32::MAX as u64) as u32,
                actual: total_data_size.min(u32::MAX as u64) as u32,
            });
        }

        Ok(())
    }

    /// Raw bytes of the slack space region (between used entries and allocated space).
    ///
    /// When files are deleted from a directory, their index entries are removed from the B-tree
    /// but the data is **not zeroed**. This slack space may contain recoverable file names,
    /// timestamps, and MFT references.
    pub fn slack_data(&self) -> &[u8] {
        let data = self.record.data();
        let start = INDEX_RECORD_HEADER_SIZE as usize + self.index_data_size() as usize;
        let end = INDEX_RECORD_HEADER_SIZE as usize + self.index_allocated_size() as usize;
        let start = start.min(data.len());
        let end = end.min(data.len());
        if start >= end {
            return &[];
        }
        &data[start..end]
    }

    /// Byte position on disk where slack space starts.
    pub fn slack_position(&self) -> NtfsPosition {
        let start = INDEX_RECORD_HEADER_SIZE as usize + self.index_data_size() as usize;
        self.record.position() + start
    }

    /// Returns the Virtual Cluster Number (VCN) of this Index Record, as reported by the header of this Index Record.
    ///
    /// This can be used to double-check that an Index Record is the actually requested one.
    /// [`NtfsIndexAllocation::record_from_vcn`] uses it for that purpose.
    ///
    /// [`NtfsIndexAllocation::record_from_vcn`]: crate::structured_values::NtfsIndexAllocation::record_from_vcn
    pub fn vcn(&self) -> Vcn {
        let start = offset_of!(IndexRecordHeader, vcn);
        Vcn::from(i64::from_le_bytes(
            *self.record.data()[start..].first_chunk().unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::NtfsAttributeType;
    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;
    use crate::structured_values::{NtfsIndexAllocation, NtfsIndexRoot};
    use fs_common::iter::FsTryIterator;

    /// Builds a synthetic single-sector (512-byte) `INDX` record with the
    /// given node-header fields, ready for [`NtfsIndexRecord::from_raw_data`].
    ///
    /// Field layout (little-endian) mirrors the on-disk structure:
    /// - 0..4   "INDX" signature
    /// - 4..6   update_sequence_offset (= 40)
    /// - 6..8   update_sequence_count  (= 2: one USN + one fixup entry)
    /// - 8..16  logfile_sequence_number
    /// - 16..24 VCN (`IndexRecordHeader::vcn`)
    /// - 24..28 IndexNodeHeader::entries_offset
    /// - 28..32 IndexNodeHeader::index_size (used data size)
    /// - 32..36 IndexNodeHeader::allocated_size
    /// - 36     IndexNodeHeader::flags
    /// - 40..42 Update Sequence Number (USN)
    /// - 42..44 fixup array entry 0 (replaces bytes at 510..512)
    /// - 510..512 the USN (pre-fixup), overwritten with the array entry
    fn build_indx(
        vcn: i64,
        entries_offset: u32,
        index_data_size: u32,
        allocated_size: u32,
        flags: u8,
    ) -> Vec<u8> {
        build_indx_sectors(
            vcn,
            entries_offset,
            index_data_size,
            allocated_size,
            flags,
            1,
        )
    }

    /// Builds a synthetic `INDX` record spanning `sectors` 512-byte sectors.
    /// The Update Sequence Array carries one fixup entry per sector.
    fn build_indx_sectors(
        vcn: i64,
        entries_offset: u32,
        index_data_size: u32,
        allocated_size: u32,
        flags: u8,
        sectors: usize,
    ) -> Vec<u8> {
        const USN: u16 = 0x0001;
        const FIXUP_ENTRY: u16 = 0xCAFE;

        let mut data = vec![0u8; sectors * 512];
        data[0..4].copy_from_slice(b"INDX");
        data[4..6].copy_from_slice(&40u16.to_le_bytes()); // update_sequence_offset
        // update_sequence_count = sectors + 1 (one USN + one entry per sector).
        data[6..8].copy_from_slice(&((sectors as u16) + 1).to_le_bytes());
        data[16..24].copy_from_slice(&vcn.to_le_bytes());
        data[24..28].copy_from_slice(&entries_offset.to_le_bytes());
        data[28..32].copy_from_slice(&index_data_size.to_le_bytes());
        data[32..36].copy_from_slice(&allocated_size.to_le_bytes());
        data[36] = flags;
        // Update Sequence Array at offset 40: USN then one entry per sector.
        data[40..42].copy_from_slice(&USN.to_le_bytes());
        for s in 0..sectors {
            let entry_off = 42 + s * 2;
            data[entry_off..entry_off + 2].copy_from_slice(&FIXUP_ENTRY.to_le_bytes());
            // The last 2 bytes of each sector must equal the USN before fixup.
            let sector_tail = (s + 1) * 512 - 2;
            data[sector_tail..sector_tail + 2].copy_from_slice(&USN.to_le_bytes());
        }
        data
    }

    /// A well-formed synthetic record with distinct, non-default fields.
    fn synth_record() -> NtfsIndexRecord {
        // entries_offset=16, index_data_size=100, allocated_size=400, flags=1.
        let data = build_indx(0x55, 16, 100, 400, HAS_SUBNODES_FLAG);
        NtfsIndexRecord::from_raw_data(data, NtfsPosition::new(0x10000)).unwrap()
    }

    #[test]
    fn synth_record_parses_and_applies_fixup() {
        let record = synth_record();
        // Fixup replaced the last two bytes of the sector with the array
        // entry 0xCAFE (kills signature/fixup regressions).
        assert_eq!(&record.record.data()[510..512], &0xCAFEu16.to_le_bytes());
        assert_eq!(record.vcn().value(), 0x55);
    }

    #[test]
    fn synth_header_field_accessors() {
        let record = synth_record();
        // Each accessor reads its own little-endian field, distinct from
        // 0/1 and from the other fields.
        assert_eq!(record.index_entries_offset(), 16);
        assert_eq!(record.index_data_size(), 100);
        assert_eq!(record.index_allocated_size(), 400);
    }

    #[test]
    fn synth_has_subnodes_flag() {
        // flags bit 0 set -> has subnodes.
        let with = synth_record();
        assert!(with.has_subnodes());

        // flags bit 0 clear -> leaf node (kills `-> true`, `& with |/^`,
        // `!= with ==`).
        let data = build_indx(0x55, 16, 100, 400, 0x00);
        let leaf = NtfsIndexRecord::from_raw_data(data, NtfsPosition::new(0x10000)).unwrap();
        assert!(!leaf.has_subnodes());

        // A non-subnode bit set must NOT register as subnodes (kills
        // `& with |` which would treat 0x02 as set).
        let data = build_indx(0x55, 16, 100, 400, 0x02);
        let other = NtfsIndexRecord::from_raw_data(data, NtfsPosition::new(0x10000)).unwrap();
        assert!(!other.has_subnodes());
    }

    #[test]
    fn synth_entries_range_and_position() {
        let record = synth_record();
        let (range, position) = record.entries_range_and_position();
        // start = 24 + entries_offset(16) = 40; end = 24 + data_size(100) = 124.
        assert_eq!(range, 40..124);
        // position = record position (0x10000) + start (40).
        assert_eq!(position.value().unwrap().get(), 0x10000 + 40);
    }

    #[test]
    fn synth_slack_data_and_position() {
        let record = synth_record();
        // slack runs from 24+data_size(100)=124 to 24+allocated_size(400)=424.
        let slack = record.slack_data();
        assert_eq!(slack.len(), 424 - 124);
        assert_eq!(slack.as_ptr(), record.record.data()[124..].as_ptr());

        // slack_position = record position + 124.
        assert_eq!(
            record.slack_position().value().unwrap().get(),
            0x10000 + 124
        );
    }

    #[test]
    fn synth_slack_data_empty_when_no_slack() {
        // data_size == allocated_size: start >= end, so slack is empty.
        let data = build_indx(0x55, 16, 200, 200, HAS_SUBNODES_FLAG);
        let record = NtfsIndexRecord::from_raw_data(data, NtfsPosition::new(0x10000)).unwrap();
        assert!(record.slack_data().is_empty());
    }

    #[test]
    fn validate_rejects_bad_signature() {
        let mut data = build_indx(0, 16, 100, 400, 0);
        data[0..4].copy_from_slice(b"BADX");
        let err = NtfsIndexRecord::from_raw_data(data, NtfsPosition::new(0x10000)).unwrap_err();
        match err {
            NtfsError::InvalidIndexSignature { actual, .. } => assert_eq!(&actual, b"BADX"),
            other => panic!("expected InvalidIndexSignature, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_allocated_size_exceeding_record() {
        // allocated_size so large that 24 + allocated_size > 512.
        let data = build_indx(0, 16, 100, 600, 0);
        let err = NtfsIndexRecord::from_raw_data(data, NtfsPosition::new(0x10000)).unwrap_err();
        match err {
            NtfsError::InvalidIndexAllocatedSize { .. } => {}
            other => panic!("expected InvalidIndexAllocatedSize, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_allocated_size_at_record_boundary() {
        // 24 + allocated_size == 512 exactly: must NOT error (kills the
        // `> with >=` swap in validate_sizes). data_size <= allocated_size.
        let record_ok = NtfsIndexRecord::from_raw_data(
            build_indx(0, 16, 100, 512 - 24, HAS_SUBNODES_FLAG),
            NtfsPosition::new(0x10000),
        );
        assert!(record_ok.is_ok());
    }

    #[test]
    fn validate_rejects_data_size_exceeding_allocated() {
        // data_size > allocated_size triggers InvalidIndexUsedSize.
        let data = build_indx(0, 16, 300, 200, 0);
        let err = NtfsIndexRecord::from_raw_data(data, NtfsPosition::new(0x10000)).unwrap_err();
        match err {
            NtfsError::InvalidIndexUsedSize { .. } => {}
            other => panic!("expected InvalidIndexUsedSize, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_data_size_equal_to_allocated() {
        // data_size == allocated_size: total_data_size == total_allocated_size,
        // not greater, so must succeed (kills `> with >=` at line 190).
        let record_ok = NtfsIndexRecord::from_raw_data(
            build_indx(0, 16, 300, 300, HAS_SUBNODES_FLAG),
            NtfsPosition::new(0x10000),
        );
        assert!(record_ok.is_ok());
    }

    #[test]
    fn new_accepts_size_within_max_and_rejects_above_max() {
        use crate::attribute_value::NtfsAttributeValue;
        use crate::attribute_value::NtfsResidentAttributeValue;

        // A valid 2048-byte (4-sector) record. 2048 is well under the real
        // MAX_INDEX_RECORD_SIZE (262144) but above the `*`->`+` mutant value
        // (256+1024 = 1280) and the `*`->`/` mutant value (256/1024 = 0), so
        // those mutants would wrongly reject this record.
        let data = build_indx_sectors(0x7, 16, 100, 1024, HAS_SUBNODES_FLAG, 4);
        let value = NtfsAttributeValue::Resident(NtfsResidentAttributeValue::new(
            &data,
            NtfsPosition::new(0x20000),
        ));
        let mut fs = std::io::Cursor::new(Vec::<u8>::new());
        let record = NtfsIndexRecord::new(&mut fs, value, 2048).unwrap();
        assert_eq!(record.index_allocated_size(), 1024);

        // A size above the real maximum must be rejected.
        let value = NtfsAttributeValue::Resident(NtfsResidentAttributeValue::new(
            &data,
            NtfsPosition::new(0x20000),
        ));
        let err = NtfsIndexRecord::new(&mut fs, value, MAX_INDEX_RECORD_SIZE + 1).unwrap_err();
        match err {
            NtfsError::InvalidIndexAllocatedSize { expected, .. } => {
                assert_eq!(expected, MAX_INDEX_RECORD_SIZE);
            }
            other => panic!("expected InvalidIndexAllocatedSize, got {other:?}"),
        }
    }

    #[test]
    fn test_index_record_slack_data() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // Navigate to "many_subdirs" which has a large B-tree with INDX records.
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "many_subdirs")
            .unwrap()
            .unwrap();
        let many_subdirs = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Get INDEX_ROOT and INDEX_ALLOCATION attributes
        let mut attrs = many_subdirs.attributes();
        let mut index_root_item = None;
        let mut index_alloc_item = None;
        while let Some(item) = attrs.try_next(&mut testfs1).unwrap() {
            let attr = item.to_attribute().unwrap();
            let ty = attr.ty().unwrap();
            if ty == NtfsAttributeType::IndexRoot {
                index_root_item = Some(item);
            } else if ty == NtfsAttributeType::IndexAllocation {
                index_alloc_item = Some(item);
            }
        }

        let index_root_item = index_root_item.unwrap();
        let index_root_attr = index_root_item.to_attribute().unwrap();
        let index_root = index_root_attr
            .resident_structured_value::<NtfsIndexRoot>()
            .unwrap();
        let index_record_size = index_root.index_record_size();

        let index_alloc_item = index_alloc_item.unwrap();
        let alloc_attr = index_alloc_item.to_attribute().unwrap();
        let index_alloc = alloc_attr
            .structured_value::<_, NtfsIndexAllocation>(&mut testfs1)
            .unwrap();

        let mut record_iter = index_alloc.records(index_record_size);
        let mut checked_records = 0;
        while let Some(record) = record_iter.try_next(&mut testfs1).unwrap() {
            let slack = record.slack_data();
            let slack_pos = record.slack_position();

            // Slack data size should be allocated - used
            let expected_len = (record.index_allocated_size() - record.index_data_size()) as usize;
            assert_eq!(slack.len(), expected_len);

            // slack_position should be valid (non-None) for on-disk records
            assert!(slack_pos.value().is_some());

            checked_records += 1;
        }
        assert!(checked_records > 0, "should have at least one INDX record");
    }
}
