use alloc::boxed::Box;

use crate::attribute::NtfsAttributeType;
use crate::data_run_map::DataRunMap;
use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;

/// Sequential iterator over all MFT file records.
///
/// Created via [`Ntfs::mft_entries`]. Opens the MFT `$DATA` attribute once
/// during construction, extracts the data run layout, then iterates records
/// by computing physical disk positions from the cached layout.
///
/// Records with invalid FILE signatures or USA fixup failures are yielded
/// as `Err` — the caller decides whether to skip or report them.
#[derive(Clone, Debug)]
pub struct NtfsMftEntries {
    /// Physical layout of the MFT on disk (from data runs).
    map: DataRunMap,
    /// Index into segments for the current record.
    segment_index: usize,
    /// Byte offset consumed within the current segment.
    offset_in_segment: u64,
    /// Current MFT record number (0-based).
    current_record: u64,
    /// Total number of MFT records.
    total_records: u64,
    /// File record size in bytes (from Ntfs).
    file_record_size: u32,
}

impl NtfsMftEntries {
    /// Creates a new MFT iterator. Opens MFT record #0, extracts data run
    /// layout, then releases all borrows.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn new<T: Read + Seek>(ntfs: &Ntfs, fs: &mut T) -> Result<Self> {
        // Open MFT file record #0.
        let mft_position = ntfs
            .mft_position()
            .value()
            .ok_or(NtfsError::InvalidMftLcn)?;
        let mft = NtfsFile::new(ntfs, fs, mft_position, 0)?;

        // Find the MFT's $DATA attribute (always present in the base record #0).
        let mft_data_attribute =
            mft.find_resident_attribute(NtfsAttributeType::Data, None, None)?;

        // Get the non-resident value to access data runs.
        let non_resident_value = mft_data_attribute.non_resident_value()?;
        let mft_data_size = non_resident_value.len();

        let map = DataRunMap::from_data_runs(non_resident_value.data_runs())?;

        let file_record_size = ntfs.file_record_size();
        let total_records = mft_data_size / u64::from(file_record_size);

        Ok(Self {
            map,
            segment_index: 0,
            offset_in_segment: 0,
            current_record: 0,
            total_records,
            file_record_size,
        })
    }

    /// Builds an iterator directly from its component parts for unit
    /// tests, bypassing the filesystem read in [`NtfsMftEntries::new`].
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        map: DataRunMap,
        total_records: u64,
        file_record_size: u32,
    ) -> Self {
        Self {
            map,
            segment_index: 0,
            offset_in_segment: 0,
            current_record: 0,
            total_records,
            file_record_size,
        }
    }

    /// Total number of MFT records.
    #[must_use]
    pub fn total_records(&self) -> u64 {
        self.total_records
    }

    /// Current record number (the one that will be returned by the next `next()` call).
    #[must_use]
    pub fn current_record(&self) -> u64 {
        self.current_record
    }

    /// Returns the next MFT file record, or `None` when exhausted.
    ///
    /// Records with invalid FILE signatures or USA fixup failures are
    /// yielded as `Err` — the caller decides whether to skip or report them.
    pub fn next<'n, T: Read + Seek>(
        &mut self,
        ntfs: &'n Ntfs,
        fs: &mut T,
    ) -> Option<Result<NtfsFile<'n>>> {
        if self.current_record >= self.total_records {
            return None;
        }

        // Get the current segment (should always be valid if total_records is correct).
        let Some((seg_position, seg_size)) = self.map.segment(self.segment_index) else {
            // We've run off the end of segments before exhausting records.
            // This shouldn't happen with a well-formed MFT, but handle gracefully.
            self.current_record = self.total_records;
            return None;
        };

        // Compute the physical position for this record.
        let position = seg_position + self.offset_in_segment;
        let record_number = self.current_record;

        // Advance state before the read so we make progress even on error.
        self.offset_in_segment += u64::from(self.file_record_size);
        if self.offset_in_segment >= seg_size {
            self.segment_index += 1;
            self.offset_in_segment = 0;
        }
        self.current_record += 1;

        // Check for sparse segment (MFT shouldn't be sparse, but be safe).
        let Some(disk_position) = position.value() else {
            return Some(Err(NtfsError::InvalidFileRecordNumber {
                file_record_number: record_number,
            }));
        };

        Some(
            NtfsFile::new(ntfs, fs, disk_position, record_number).map_err(|e| {
                NtfsError::MftRecordParseFailed {
                    record_number,
                    source: Box::new(e),
                }
            }),
        )
    }

    /// Resets the iterator to a specific record number.
    ///
    /// The next `next()` call will return that record. If `record_number`
    /// is past the end, subsequent `next()` calls will return `None`.
    pub fn seek_to_record(&mut self, record_number: u64) {
        if record_number >= self.total_records {
            // Set to end state.
            self.current_record = self.total_records;
            self.segment_index = self.map.segment_count();
            self.offset_in_segment = 0;
            return;
        }

        let byte_offset = record_number * u64::from(self.file_record_size);
        if let Some((idx, offset)) = self.map.resolve_index(byte_offset) {
            self.segment_index = idx;
            self.offset_in_segment = offset;
            self.current_record = record_number;
        } else {
            // Shouldn't reach here if total_records is consistent with segments,
            // but handle gracefully.
            self.current_record = self.total_records;
            self.segment_index = self.map.segment_count();
            self.offset_in_segment = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsmnt_testkit::Cursor;

    const FRS: u32 = 1024; // file record size
    const FRS_USIZE: usize = 1024;
    const REGION_START: u64 = 4096; // physical byte offset of record 0

    /// Builds a minimal valid 512-byte NTFS boot sector for `Ntfs::new`.
    fn make_boot_sector() -> [u8; 512] {
        let mut bs = [0u8; 512];
        bs[3..11].copy_from_slice(b"NTFS    ");
        bs[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector
        bs[0x0D] = 1; // sectors_per_cluster
        bs[0x28..0x30].copy_from_slice(&65536u64.to_le_bytes()); // total_sectors
        bs[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // mft_lcn
        bs[0x38..0x40].copy_from_slice(&2u64.to_le_bytes()); // mft_mirror_lcn
        bs[0x40] = 0xF6; // clusters_per_mft_record = -10 => 1024-byte records
        bs[510] = 0x55;
        bs[511] = 0xAA;
        bs
    }

    /// Builds a valid 1 KiB FILE record (signature + USA fixup) with the
    /// given `flags` and on-disk `sequence_number` (used to tell records at
    /// different physical positions apart). No attributes are required for
    /// the iterator tests.
    fn make_file_record(flags: u16, seq: u16) -> Vec<u8> {
        let mut rec = vec![0u8; FRS_USIZE];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes()); // update_sequence_offset
        rec[6..8].copy_from_slice(&3u16.to_le_bytes()); // update_sequence_count
        let usn = 0x0001u16;
        rec[0x30..0x32].copy_from_slice(&usn.to_le_bytes()); // USN
        rec[0x32..0x34].copy_from_slice(&0xAAAAu16.to_le_bytes());
        rec[0x34..0x36].copy_from_slice(&0xBBBBu16.to_le_bytes());
        rec[510..512].copy_from_slice(&usn.to_le_bytes());
        rec[1022..1024].copy_from_slice(&usn.to_le_bytes());
        rec[16..18].copy_from_slice(&seq.to_le_bytes()); // sequence_number
        rec[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard_link_count
        rec[20..22].copy_from_slice(&56u16.to_le_bytes()); // first_attribute_offset
        rec[22..24].copy_from_slice(&flags.to_le_bytes()); // flags
        rec[24..28].copy_from_slice(&FRS.to_le_bytes()); // data_size
        rec[28..32].copy_from_slice(&FRS.to_le_bytes()); // allocated_size
        // An immediate End marker for the (unused) attribute list.
        rec[56..60].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        rec
    }

    /// Builds an image with `count` consecutive valid FILE records starting
    /// at `REGION_START`, plus the boot sector. Each record N carries
    /// `sequence_number` `N + 10`, so reads from the wrong physical position
    /// are observable. Returns the cursor and a single-segment `DataRunMap`.
    fn make_image(count: u64) -> (Cursor<Vec<u8>>, DataRunMap) {
        let region_len = count * u64::from(FRS);
        let mut data =
            vec![0u8; usize::try_from(REGION_START + region_len).expect("test value fits usize")];
        data[0..512].copy_from_slice(&make_boot_sector());
        for i in 0..count {
            let off =
                usize::try_from(REGION_START + i * u64::from(FRS)).expect("test value fits usize");
            data[off..off + FRS_USIZE].copy_from_slice(&make_file_record(
                1,
                u16::try_from(i + 10).expect("test value fits u16"),
            ));
        }
        let map = DataRunMap::from_segments_for_test(&[(Some(REGION_START), region_len)]);
        (Cursor::new(data), map)
    }

    fn make_ntfs(fs: &mut Cursor<Vec<u8>>) -> Ntfs {
        Ntfs::new(fs).unwrap()
    }

    #[test]
    fn synthetic_total_and_current_record() {
        let (mut fs, map) = make_image(3);
        // `Ntfs::new` validates the synthetic boot sector before the test
        // builds the iterator from explicit parts.
        let _ = make_ntfs(&mut fs);
        let iter = NtfsMftEntries::from_parts_for_test(map, 3, FRS);
        // Genuine values, distinct from the 0/1 return replacements.
        assert_eq!(iter.total_records(), 3);
        assert_eq!(iter.current_record(), 0);
    }

    #[test]
    fn synthetic_next_iterates_all_records_in_order() {
        let (mut fs, map) = make_image(3);
        let ntfs = make_ntfs(&mut fs);
        let mut iter = NtfsMftEntries::from_parts_for_test(map, 3, FRS);

        // Each record parses (line 83 `>=` keeps iterating below total) and
        // the record numbers advance 0,1,2 (lines 100/108). The on-disk
        // sequence_number (N+10) confirms each read came from the correct
        // physical position, so the offset math `offset_in_segment += FRS`
        // (line 103) is exercised: a `*=` mutation would keep reading
        // record 0's bytes and observe the wrong sequence number.
        for expected in 0..3u64 {
            assert_eq!(iter.current_record(), expected);
            let file = iter.next(&ntfs, &mut fs).unwrap().unwrap();
            assert_eq!(file.file_record_number(), expected);
            assert_eq!(
                file.sequence_number(),
                u16::try_from(expected + 10).expect("test value fits u16")
            );
        }
        // After three records the iterator is exhausted (line 83 boundary).
        assert!(iter.next(&ntfs, &mut fs).is_none());
        assert_eq!(iter.current_record(), 3);
    }

    #[test]
    fn synthetic_next_advances_segment_at_boundary() {
        // Two segments of one record each. After the first record the
        // offset reaches the segment size, so segment_index advances and
        // offset resets (lines 103/104/105). The second record lives in the
        // second segment at a different physical position.
        let region_len = u64::from(FRS);
        let mut data = vec![
            0u8;
            usize::try_from(REGION_START + 4 * u64::from(FRS))
                .expect("test value fits usize")
        ];
        data[0..512].copy_from_slice(&make_boot_sector());
        // Record 0 (seq 10) at REGION_START, record 1 (seq 20) at
        // REGION_START + 2*FRS — a different physical position.
        let pos0 = REGION_START;
        let pos1 = REGION_START + 2 * u64::from(FRS);
        data[usize::try_from(pos0).expect("test value fits usize")
            ..usize::try_from(pos0).expect("test value fits usize") + FRS_USIZE]
            .copy_from_slice(&make_file_record(1, 10));
        data[usize::try_from(pos1).expect("test value fits usize")
            ..usize::try_from(pos1).expect("test value fits usize") + FRS_USIZE]
            .copy_from_slice(&make_file_record(1, 20));
        let mut fs = Cursor::new(data);
        let ntfs = make_ntfs(&mut fs);

        let map = DataRunMap::from_segments_for_test(&[
            (Some(pos0), region_len),
            (Some(pos1), region_len),
        ]);
        let mut iter = NtfsMftEntries::from_parts_for_test(map, 2, FRS);

        let f0 = iter.next(&ntfs, &mut fs).unwrap().unwrap();
        assert_eq!(f0.file_record_number(), 0);
        assert_eq!(f0.sequence_number(), 10);
        // The second record must come from the second segment at pos1
        // (seq 20). A broken segment advance (line 105 `*=`) or a failure to
        // advance the offset (line 103 `*=`) would re-read pos0 (seq 10) and
        // observe the wrong sequence number.
        let f1 = iter.next(&ntfs, &mut fs).unwrap().unwrap();
        assert_eq!(f1.file_record_number(), 1);
        assert_eq!(f1.sequence_number(), 20);
        assert!(iter.next(&ntfs, &mut fs).is_none());
    }

    #[test]
    fn synthetic_next_sparse_position_yields_error() {
        // A sparse segment makes the physical position unknown, so `next`
        // returns InvalidFileRecordNumber with the captured record number
        // (lines 100/108) without touching the filesystem.
        let mut fs = Cursor::new({
            let mut d = vec![0u8; 512];
            d[0..512].copy_from_slice(&make_boot_sector());
            d
        });
        let ntfs = make_ntfs(&mut fs);
        let map = DataRunMap::from_segments_for_test(&[(None, 2 * u64::from(FRS))]);
        let mut iter = NtfsMftEntries::from_parts_for_test(map, 2, FRS);

        match iter.next(&ntfs, &mut fs) {
            Some(Err(NtfsError::InvalidFileRecordNumber { file_record_number })) => {
                assert_eq!(file_record_number, 0);
            }
            other => panic!("expected record 0 error, got {other:?}"),
        }
        match iter.next(&ntfs, &mut fs) {
            Some(Err(NtfsError::InvalidFileRecordNumber { file_record_number })) => {
                assert_eq!(file_record_number, 1);
            }
            other => panic!("expected record 1 error, got {other:?}"),
        }
        assert!(iter.next(&ntfs, &mut fs).is_none());
    }

    #[test]
    fn synthetic_seek_to_record_positions_iterator() {
        let (mut fs, map) = make_image(4);
        let ntfs = make_ntfs(&mut fs);
        let mut iter = NtfsMftEntries::from_parts_for_test(map, 4, FRS);

        // seek_to_record(2) computes byte_offset = 2 * FRS (line 143) and
        // resolves to record 2 (line 135 keeps in-range records). The
        // sequence_number (12) proves the read landed on record 2's bytes;
        // a `*`->`/` mutation of the offset math would compute byte_offset
        // 2/FRS = 0 and re-read record 0 (seq 10).
        iter.seek_to_record(2);
        assert_eq!(iter.current_record(), 2);
        let file = iter.next(&ntfs, &mut fs).unwrap().unwrap();
        assert_eq!(file.file_record_number(), 2);
        assert_eq!(file.sequence_number(), 12);

        // seek back to 0.
        iter.seek_to_record(0);
        assert_eq!(iter.current_record(), 0);
        let file = iter.next(&ntfs, &mut fs).unwrap().unwrap();
        assert_eq!(file.file_record_number(), 0);
        assert_eq!(file.sequence_number(), 10);
    }

    #[test]
    fn synthetic_seek_past_end_sets_end_state() {
        let (mut fs, map) = make_image(3);
        let ntfs = make_ntfs(&mut fs);
        let mut iter = NtfsMftEntries::from_parts_for_test(map, 3, FRS);

        // record_number >= total_records (line 135 boundary) => end state.
        iter.seek_to_record(3);
        assert_eq!(iter.current_record(), 3);
        assert!(iter.next(&ntfs, &mut fs).is_none());

        iter.seek_to_record(100);
        assert!(iter.next(&ntfs, &mut fs).is_none());
    }

    #[test]
    fn synthetic_seek_to_last_in_range_record() {
        // record_number == total_records - 1 is in range (line 135 `>=`
        // boundary): it must position at that record, not the end state.
        let (mut fs, map) = make_image(3);
        let ntfs = make_ntfs(&mut fs);
        let mut iter = NtfsMftEntries::from_parts_for_test(map, 3, FRS);

        iter.seek_to_record(2);
        assert_eq!(iter.current_record(), 2);
        let file = iter.next(&ntfs, &mut fs).unwrap().unwrap();
        assert_eq!(file.file_record_number(), 2);
    }

    #[test]
    fn test_mft_entries_iterate_all() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut iter = NtfsMftEntries::new(&ntfs, &mut testfs1).unwrap();
        let total = iter.total_records();
        assert!(total > 0);

        let mut count = 0u64;
        while let Some(result) = iter.next(&ntfs, &mut testfs1) {
            // We don't care about errors here, just count.
            let _ = result;
            count += 1;
        }
        assert_eq!(count, total);

        // Verify record 0 is the MFT itself (has $DATA attribute).
        let mut iter2 = NtfsMftEntries::new(&ntfs, &mut testfs1).unwrap();
        let mft_file = iter2.next(&ntfs, &mut testfs1).unwrap().unwrap();
        assert_eq!(mft_file.file_record_number(), 0);
        // MFT should have a $DATA attribute.
        let data_item = mft_file.data(&mut testfs1, "");
        assert!(data_item.is_some());
    }

    #[test]
    fn test_mft_entries_known_files() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut iter = NtfsMftEntries::new(&ntfs, &mut testfs1).unwrap();

        // Collect first 12 records (system files 0-11).
        let mut files = Vec::new();
        for _ in 0..12 {
            match iter.next(&ntfs, &mut testfs1) {
                Some(Ok(file)) => files.push(file),
                Some(Err(_)) => panic!("unexpected error reading system file"),
                None => panic!("MFT has fewer than 12 records"),
            }
        }

        // Record 5 is the root directory.
        assert_eq!(files[5].file_record_number(), 5);
        assert!(files[5].is_directory());
    }

    #[test]
    fn test_mft_entries_seek_to_record() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut iter = NtfsMftEntries::new(&ntfs, &mut testfs1).unwrap();

        // Seek to record 5 (root directory).
        iter.seek_to_record(5);
        let file = iter.next(&ntfs, &mut testfs1).unwrap().unwrap();
        assert_eq!(file.file_record_number(), 5);
        assert!(file.is_directory());

        // Seek back to record 0 (MFT).
        iter.seek_to_record(0);
        let file = iter.next(&ntfs, &mut testfs1).unwrap().unwrap();
        assert_eq!(file.file_record_number(), 0);
    }

    #[test]
    fn test_mft_entries_seek_past_end() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut iter = NtfsMftEntries::new(&ntfs, &mut testfs1).unwrap();
        let total = iter.total_records();

        iter.seek_to_record(total + 100);
        assert!(iter.next(&ntfs, &mut testfs1).is_none());
    }

    #[test]
    fn test_mft_entries_current_record() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut iter = NtfsMftEntries::new(&ntfs, &mut testfs1).unwrap();
        assert_eq!(iter.current_record(), 0);

        // Advance a few records.
        iter.next(&ntfs, &mut testfs1);
        assert_eq!(iter.current_record(), 1);

        iter.next(&ntfs, &mut testfs1);
        assert_eq!(iter.current_record(), 2);

        // Seek and verify.
        iter.seek_to_record(10);
        assert_eq!(iter.current_record(), 10);

        iter.next(&ntfs, &mut testfs1);
        assert_eq!(iter.current_record(), 11);
    }

    #[test]
    fn test_mft_entries_via_ntfs_convenience() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut iter = ntfs.mft_entries(&mut testfs1).unwrap();
        let total = iter.total_records();
        assert!(total > 0);

        // Verify first record is the MFT.
        let file = iter.next(&ntfs, &mut testfs1).unwrap().unwrap();
        assert_eq!(file.file_record_number(), 0);
    }

    #[test]
    fn test_mft_entries_wraps_parse_errors_with_record_number() {
        // Load the test filesystem into a mutable buffer.
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        // Read the MFT position and record size so we can corrupt a record.
        let file_record_size =
            usize::try_from(ntfs.file_record_size()).expect("test record size fits in usize");

        // Corrupt record #2's FILE signature (overwrite first 4 bytes with zeros).
        // Record #2 starts at the MFT data position + 2 * record_size.
        // We need the physical position from the MFT's data runs.
        let mut iter = NtfsMftEntries::new(&ntfs, &mut testfs1).unwrap();

        // Skip to record 0, read its position by advancing once.
        let mft_file = iter.next(&ntfs, &mut testfs1).unwrap().unwrap();
        let mft_data_item = mft_file.data(&mut testfs1, "").unwrap().unwrap();
        let mft_attr = mft_data_item.to_attribute().unwrap();
        let nrv = mft_attr.non_resident_value().unwrap();

        // Resolve physical offset via DataRunMap (handles fragmented MFTs).
        let map = DataRunMap::from_data_runs(nrv.data_runs()).unwrap();
        let logical_offset =
            2 * u64::try_from(file_record_size).expect("test record size fits in u64");
        let (pos, _) = map.resolve_position(logical_offset).unwrap();
        let record2_offset = pos.value().unwrap().get();
        let buf = testfs1.get_mut();
        buf[usize::try_from(record2_offset).expect("test value fits usize")
            ..usize::try_from(record2_offset).expect("test value fits usize") + 4]
            .copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Re-parse and iterate — record #2 should yield MftRecordParseFailed.
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mut iter = NtfsMftEntries::new(&ntfs, &mut testfs1).unwrap();

        // Record 0 and 1 should still parse fine.
        assert!(iter.next(&ntfs, &mut testfs1).unwrap().is_ok());
        assert!(iter.next(&ntfs, &mut testfs1).unwrap().is_ok());

        // Record 2 should be MftRecordParseFailed with record_number = 2.
        let err = iter.next(&ntfs, &mut testfs1).unwrap().unwrap_err();
        match err {
            NtfsError::MftRecordParseFailed {
                record_number,
                source,
            } => {
                assert_eq!(record_number, 2);
                assert!(
                    matches!(*source, NtfsError::InvalidFileSignature { .. }),
                    "inner error should be InvalidFileSignature, got: {source}",
                );
            }
            other => panic!("expected MftRecordParseFailed, got: {other}"),
        }

        // Remaining records should continue to iterate.
        assert!(iter.next(&ntfs, &mut testfs1).unwrap().is_ok());
    }

    #[test]
    fn test_mft_entries_skip_errors() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut iter = NtfsMftEntries::new(&ntfs, &mut testfs1).unwrap();
        let total = iter.total_records();

        let mut ok_count = 0u64;
        let mut err_count = 0u64;

        while let Some(result) = iter.next(&ntfs, &mut testfs1) {
            match result {
                Ok(_) => ok_count += 1,
                Err(_) => err_count += 1,
            }
        }

        assert_eq!(ok_count + err_count, total);
        // Most records should parse OK on a well-formed test filesystem.
        assert!(
            ok_count > err_count,
            "expected mostly Ok, got {ok_count} Ok vs {err_count} Err"
        );
    }
}
