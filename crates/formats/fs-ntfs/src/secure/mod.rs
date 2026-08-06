//! $Secure system file parsing for NTFS security descriptors.
//!
//! The `$Secure` file (MFT entry 9) stores all security descriptors
//! on an NTFS 3.x+ volume. This module provides:
//!
//! - **Entry iteration** ([`NtfsSdsEntries`]) — walk all `$SDS`
//!   entries with mirror comparison.
//! - **Index lookup** ([`ntfs_secure_lookup`],
//!   [`ntfs_secure_lookup_by_hash`]) — find descriptors by security
//!   ID or hash via the `$SII`/`$SDH` indexes.
//! - **Stream statistics** ([`ntfs_secure_sds_info`]) — summary
//!   of the `$SDS` stream.

mod entry;
mod lookup;

pub use entry::{NtfsSdsEntries, NtfsSdsEntry, NtfsSdsMirrorStatus, NtfsSdsStreamInfo};
pub use lookup::{ntfs_secure_lookup, ntfs_secure_lookup_by_hash, ntfs_secure_sdh_entries};

use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::io::{Read, Seek};

/// Create an iterator over all `$SDS` entries in the `$Secure`
/// system file.
///
/// The `$SDS` stream stores every security descriptor ever assigned
/// on the volume. Entries are never deleted, making this a
/// forensically valuable source of historical ACL and ownership
/// data.
///
/// The `secure_file` parameter should be the `$Secure` file
/// (MFT entry 9), obtained via `ntfs.file(&mut fs, 9)`.
pub fn ntfs_secure_sds_entries<'n, 'f, T>(
    secure_file: &'f NtfsFile<'n>,
    fs: &mut T,
) -> Result<NtfsSdsEntries<'n, 'f>>
where
    T: Read + Seek,
{
    let sds_item = lookup::find_named_data_attribute(secure_file, fs, "$SDS")?;
    let sds_attribute = sds_item.to_attribute()?;
    let stream_len = sds_attribute.value(fs)?.len();

    Ok(NtfsSdsEntries::new(sds_item, stream_len))
}

/// Walk the entire `$SDS` stream and return summary statistics.
///
/// This is a convenience wrapper around
/// [`ntfs_secure_sds_entries`] that iterates every entry and
/// accumulates counts.
pub fn ntfs_secure_sds_info<T>(secure_file: &NtfsFile<'_>, fs: &mut T) -> Result<NtfsSdsStreamInfo>
where
    T: Read + Seek,
{
    let mut entries = ntfs_secure_sds_entries(secure_file, fs)?;
    let mut buf = alloc::vec::Vec::new();

    let mut info = NtfsSdsStreamInfo {
        total_entries: 0,
        total_slack_bytes: 0,
        stream_tail_bytes: 0,
        mirror_checked: 0,
        mirror_mismatches: 0,
        mirror_unavailable: 0,
    };

    while let Some(result) = entries.next(fs, &mut buf) {
        // Skip structural corruption; propagate transport errors.
        let entry = match result {
            Ok(e) => e,
            Err(NtfsError::InvalidSdsEntry { .. }) => continue,
            Err(e) => return Err(e),
        };

        info.total_entries += 1;
        info.total_slack_bytes += entry.slack_before();

        match entry.mirror_status() {
            NtfsSdsMirrorStatus::Match => {
                info.mirror_checked += 1;
            }
            NtfsSdsMirrorStatus::Mismatch => {
                info.mirror_checked += 1;
                info.mirror_mismatches += 1;
            }
            NtfsSdsMirrorStatus::Unavailable => {
                info.mirror_unavailable += 1;
            }
        }
    }

    info.stream_tail_bytes = entries.stream_len().saturating_sub(entries.position());

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::KnownNtfsFileRecordNumber;
    use crate::ntfs::Ntfs;

    use crate::types::NtfsPosition;
    use entry::{
        SDS_BLOCK_PAIR_SIZE, SDS_BLOCK_SIZE, SDS_ENTRY_ALIGNMENT, SDS_HEADER_SIZE, SDS_MAX_SIZE,
        align_up,
    };
    use lookup::{open_sdh_index, open_sii_index};

    /// Helper: find any MFT entry with a nonzero security_id.
    fn find_nonzero_security_id(ntfs: &Ntfs, fs: &mut std::io::Cursor<Vec<u8>>) -> Option<u32> {
        for record in 0..12u64 {
            if let Ok(file) = ntfs.file(fs, record)
                && let Ok(info) = file.info()
                && let Some(sid) = info.security_id()
                && sid > 0
            {
                return Some(sid);
            }
        }
        None
    }

    #[test]
    fn test_secure_lookup_happy_path() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let security_id = match find_nonzero_security_id(&ntfs, &mut testfs1) {
            Some(sid) => sid,
            None => return,
        };

        let mut buf = Vec::new();
        let desc = ntfs_secure_lookup(&secure_file, &mut testfs1, security_id, &mut buf).unwrap();
        assert_eq!(desc.revision(), 1);
        assert!(desc.owner_sid().is_some());

        let owner = desc.owner_sid().unwrap().unwrap();
        let sid_str = owner.to_sid_string();
        assert!(sid_str.starts_with("S-1-"), "unexpected SID: {sid_str}");
    }

    #[test]
    fn test_secure_lookup_not_found() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut buf = Vec::new();
        let result = ntfs_secure_lookup(&secure_file, &mut testfs1, 0xDEAD_BEEF, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_sii_index_opens() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut buf = Vec::new();
        let result = ntfs_secure_lookup(&secure_file, &mut testfs1, 0, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_file_attributes() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();
        assert!(!secure_file.is_directory());
        assert!(secure_file.hard_link_count() > 0);
    }

    #[test]
    fn test_sdh_index_opens() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let result = open_sdh_index(&secure_file, &mut testfs1);
        assert!(result.is_ok(), "failed to open $SDH index: {result:?}");
    }

    #[test]
    fn test_sdh_sii_cross_check() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let security_id = match find_nonzero_security_id(&ntfs, &mut testfs1) {
            Some(sid) => sid,
            None => return,
        };

        let sii_index = open_sii_index(&secure_file, &mut testfs1).unwrap();
        let mut finder = sii_index.finder();
        let entry = finder
            .find(&mut testfs1, |key| security_id.cmp(&key.security_id()))
            .unwrap()
            .unwrap();
        let sii_data = entry.data().unwrap().unwrap();
        let hash = sii_data.hash();
        let sii_offset = sii_data.sds_offset();

        let sdh_entries = ntfs_secure_sdh_entries(&secure_file, &mut testfs1, hash).unwrap();
        assert!(
            !sdh_entries.is_empty(),
            "$SDH should have entries for hash {hash:#x}"
        );

        let matching = sdh_entries.iter().any(|e| e.sds_offset() == sii_offset);
        assert!(
            matching,
            "no $SDH entry matches $SII offset {sii_offset} \
             for hash {hash:#x}"
        );
    }

    #[test]
    fn test_sdh_entries_for_known_hash() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let security_id = match find_nonzero_security_id(&ntfs, &mut testfs1) {
            Some(sid) => sid,
            None => return,
        };

        let sii_index = open_sii_index(&secure_file, &mut testfs1).unwrap();
        let mut finder = sii_index.finder();
        let entry = finder
            .find(&mut testfs1, |key| security_id.cmp(&key.security_id()))
            .unwrap()
            .unwrap();
        let hash = entry.data().unwrap().unwrap().hash();

        let entries = ntfs_secure_sdh_entries(&secure_file, &mut testfs1, hash).unwrap();
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_sdh_lookup_by_hash_happy_path() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let security_id = match find_nonzero_security_id(&ntfs, &mut testfs1) {
            Some(sid) => sid,
            None => return,
        };

        let sii_index = open_sii_index(&secure_file, &mut testfs1).unwrap();
        let mut finder = sii_index.finder();
        let entry = finder
            .find(&mut testfs1, |key| security_id.cmp(&key.security_id()))
            .unwrap()
            .unwrap();
        let hash = entry.data().unwrap().unwrap().hash();

        let mut buf = Vec::new();
        let desc = ntfs_secure_lookup_by_hash(&secure_file, &mut testfs1, hash, &mut buf).unwrap();
        assert_eq!(desc.revision(), 1);
        assert!(desc.owner_sid().is_some());

        let owner = desc.owner_sid().unwrap().unwrap();
        let sid_str = owner.to_sid_string();
        assert!(sid_str.starts_with("S-1-"), "unexpected SID: {sid_str}");
    }

    #[test]
    fn test_sdh_lookup_not_found() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut buf = Vec::new();
        let result = ntfs_secure_lookup_by_hash(&secure_file, &mut testfs1, 0xDEAD_BEEF, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_sds_entry_accessors() {
        let mut entry_data = vec![0u8; 40];
        entry_data[0..4].copy_from_slice(&0x0000_1234u32.to_le_bytes());
        entry_data[4..8].copy_from_slice(&42u32.to_le_bytes());
        entry_data[8..16].copy_from_slice(&0u64.to_le_bytes());
        entry_data[16..20].copy_from_slice(&40u32.to_le_bytes());
        entry_data[20] = 1;
        entry_data[22..24].copy_from_slice(&0x8004u16.to_le_bytes());

        let entry = NtfsSdsEntry {
            data: &entry_data,
            stream_offset: 0x100,
            mirror_status: NtfsSdsMirrorStatus::Match,
            slack_before: 4,
        };

        assert_eq!(entry.hash(), 0x1234);
        assert_eq!(entry.security_id(), 42);
        assert_eq!(entry.sds_offset(), 0);
        assert_eq!(entry.entry_size(), 40);
        assert_eq!(entry.stream_offset(), 0x100);
        assert_eq!(entry.mirror_status(), NtfsSdsMirrorStatus::Match);
        assert_eq!(entry.slack_before(), 4);
        assert_eq!(entry.entry_payload().len(), 20);
        assert!(entry.descriptor().is_ok());
        assert_eq!(entry.descriptor().unwrap().revision(), 1);
    }

    #[test]
    fn test_sds_entries_happy_path() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut entries_iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let mut buf = Vec::new();
        let mut count = 0u64;

        while let Some(result) = entries_iter.next(&mut testfs1, &mut buf) {
            let entry = result.unwrap();
            assert!(
                entry.entry_size() as usize >= SDS_HEADER_SIZE,
                "entry_size {} too small at offset {:#x}",
                entry.entry_size(),
                entry.stream_offset(),
            );
            let desc = entry.descriptor().unwrap();
            assert_eq!(desc.revision(), 1);
            count += 1;
        }

        if find_nonzero_security_id(&ntfs, &mut testfs1).is_some() {
            assert!(count > 0, "expected at least one $SDS entry");
        }
    }

    #[test]
    fn test_sdh_entries_not_found() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let entries = ntfs_secure_sdh_entries(&secure_file, &mut testfs1, 0xDEAD_BEEF).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_sds_entries_cross_check_sii() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut entries_iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let mut sds_buf = Vec::new();
        let mut sii_buf = Vec::new();
        let mut checked = 0u64;

        while let Some(result) = entries_iter.next(&mut testfs1, &mut sds_buf) {
            let entry = result.unwrap();
            let sid = entry.security_id();

            let sii_desc = match ntfs_secure_lookup(&secure_file, &mut testfs1, sid, &mut sii_buf) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let sds_desc = entry.descriptor().unwrap();
            assert_eq!(
                sds_desc.revision(),
                sii_desc.revision(),
                "revision mismatch for security_id {sid}"
            );
            checked += 1;
        }

        if find_nonzero_security_id(&ntfs, &mut testfs1).is_some() {
            assert!(checked > 0, "expected at least one cross-checked entry");
        }
    }

    #[test]
    fn test_sds_entries_mirror_accounting() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut entries_iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let stream_len = entries_iter.stream_len();
        let mut buf = Vec::new();

        let mut total_entries = 0u64;
        let mut mirror_checked = 0u64;
        let mut mirror_unavailable = 0u64;

        while let Some(result) = entries_iter.next(&mut testfs1, &mut buf) {
            let entry = result.unwrap();
            total_entries += 1;

            match entry.mirror_status() {
                NtfsSdsMirrorStatus::Match | NtfsSdsMirrorStatus::Mismatch => {
                    mirror_checked += 1;
                }
                NtfsSdsMirrorStatus::Unavailable => {
                    mirror_unavailable += 1;
                }
            }

            assert!(
                entry.slack_before() < SDS_BLOCK_SIZE,
                "slack_before {} exceeds block size at \
                 offset {:#x}",
                entry.slack_before(),
                entry.stream_offset(),
            );
        }

        if stream_len >= SDS_BLOCK_PAIR_SIZE && total_entries > 0 {
            assert!(
                mirror_checked > 0 || mirror_unavailable == total_entries,
                "expected some mirror checks for \
                 stream_len={stream_len:#x}"
            );
        }
    }

    #[test]
    fn test_sds_entries_slack_accounting() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut entries_iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let mut buf = Vec::new();

        let mut total_slack = 0u64;
        let mut total_covered = 0u64;

        while let Some(result) = entries_iter.next(&mut testfs1, &mut buf) {
            let entry = result.unwrap();
            total_slack += entry.slack_before();
            total_covered += align_up(u64::from(entry.entry_size()), SDS_ENTRY_ALIGNMENT);
        }

        let stream_tail = entries_iter
            .stream_len()
            .saturating_sub(entries_iter.position());

        assert!(
            total_slack + total_covered + stream_tail <= entries_iter.stream_len(),
            "slack accounting overflow: slack={total_slack} \
             covered={total_covered} tail={stream_tail} \
             stream_len={}",
            entries_iter.stream_len(),
        );
    }

    #[test]
    fn test_invalid_sds_entry_error_format() {
        let err = NtfsError::InvalidSdsEntry {
            position: NtfsPosition::new(0x1234),
            reason: "$SDS entry has zero size but \
                     non-zero header",
        };
        let msg = err.to_string();
        assert!(msg.contains("0x1234"), "missing position: {msg}");
        assert!(msg.contains("zero size"), "missing reason: {msg}");
    }

    #[test]
    fn test_sds_entry_all_accessors_on_testfs() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut entries_iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let mut buf = Vec::new();

        if let Some(Ok(entry)) = entries_iter.next(&mut testfs1, &mut buf) {
            let _hash = entry.hash();
            let _sid = entry.security_id();
            let _sds_off = entry.sds_offset();
            let _size = entry.entry_size();
            let _stream_off = entry.stream_offset();
            let _mirror = entry.mirror_status();
            let _slack = entry.slack_before();
            let _payload = entry.entry_payload();

            let desc = entry.descriptor().unwrap();
            assert_eq!(desc.revision(), 1);
            assert!(desc.owner_sid().is_some());
        }
    }

    #[test]
    fn test_sds_stream_info() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let info = ntfs_secure_sds_info(&secure_file, &mut testfs1).unwrap();

        let mut entries_iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let mut buf = Vec::new();
        let mut manual_count = 0u64;
        while let Some(Ok(_)) = entries_iter.next(&mut testfs1, &mut buf) {
            manual_count += 1;
        }

        assert_eq!(info.total_entries, manual_count);
        assert_eq!(
            info.mirror_checked,
            info.total_entries - info.mirror_unavailable
        );
    }

    #[test]
    fn test_sds_mirror_status_variants() {
        let m = NtfsSdsMirrorStatus::Match;
        let mm = NtfsSdsMirrorStatus::Mismatch;
        let u = NtfsSdsMirrorStatus::Unavailable;
        assert_ne!(m, mm);
        assert_ne!(m, u);
        assert_ne!(mm, u);
        assert_eq!(m, NtfsSdsMirrorStatus::Match);
    }

    /// Map $SDS stream offsets to physical disk offsets.
    fn sds_physical_offsets(
        testfs: &mut std::io::Cursor<Vec<u8>>,
        secure_file: &NtfsFile<'_>,
        stream_offset: u64,
    ) -> Vec<usize> {
        use crate::attribute_value::NtfsAttributeValue;
        use crate::data_run_map::DataRunMap;

        let sds_item =
            lookup::find_named_data_attribute(secure_file, testfs, "$SDS").expect("$SDS attribute");
        let sds_attr = sds_item.to_attribute().expect("attribute");
        let sds_value = sds_attr.value(testfs).expect("value");
        let non_resident = match sds_value {
            NtfsAttributeValue::NonResident(nr) => nr,
            _ => panic!("$SDS should be non-resident"),
        };
        let map = DataRunMap::from_data_runs(non_resident.data_runs()).expect("data run map");

        let mut offsets = Vec::new();
        for &virtual_offset in &[stream_offset, stream_offset + SDS_BLOCK_SIZE] {
            if let Some((pos, _remaining)) = map.resolve_position(virtual_offset)
                && let Some(nz) = pos.value()
            {
                offsets.push(nz.get() as usize);
            }
        }
        assert!(
            !offsets.is_empty(),
            "$SDS stream offset {stream_offset:#x} could not \
             be resolved to a physical position"
        );
        offsets
    }

    /// Corrupt the entry_size field at physical locations.
    fn corrupt_sds_entry_size(
        testfs: &mut std::io::Cursor<Vec<u8>>,
        secure_file: &NtfsFile<'_>,
        stream_offset: u64,
        new_entry_size: u32,
    ) -> Vec<u8> {
        let offsets = sds_physical_offsets(testfs, secure_file, stream_offset);
        let mut raw = testfs.get_ref().clone();
        for phys in offsets {
            raw[phys + 16..phys + 20].copy_from_slice(&new_entry_size.to_le_bytes());
        }
        raw
    }

    fn ntfs_from_raw_bytes(raw: Vec<u8>) -> (std::io::Cursor<Vec<u8>>, Ntfs) {
        let mut cursor = std::io::Cursor::new(raw);
        let ntfs = Ntfs::new(&mut cursor).expect("Ntfs::new on modified image");
        (cursor, ntfs)
    }

    #[test]
    fn test_sds_truncated_header_at_eof() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let mut buf = Vec::new();
        let first = iter.next(&mut testfs1, &mut buf);
        if first.is_none() {
            return;
        }
        let entry = first.unwrap().unwrap();
        let entry_end = entry.stream_offset() + u64::from(entry.entry_size());
        let aligned_end = align_up(entry_end, SDS_ENTRY_ALIGNMENT);

        let mut iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        iter.stream_len = aligned_end + 10;

        let mut buf = Vec::new();
        let first = iter.next(&mut testfs1, &mut buf);
        assert!(first.is_some(), "first entry should be readable");
        first.unwrap().unwrap();

        let result = iter.next(&mut testfs1, &mut buf);
        match result {
            Some(Err(e)) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("truncated"),
                    "expected truncated header error: {msg}"
                );
            }
            Some(Ok(_)) => {
                panic!("expected error, got Ok entry");
            }
            None => {
                panic!("expected error, got None");
            }
        }

        assert!(iter.next(&mut testfs1, &mut buf).is_none());
    }

    #[test]
    fn test_sds_entry_extends_beyond_stream() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let mut buf = Vec::new();
        let first = iter.next(&mut testfs1, &mut buf);
        if first.is_none() {
            return;
        }
        let entry = first.unwrap().unwrap();
        let entry_size = u64::from(entry.entry_size());

        let mut iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        iter.stream_len = SDS_HEADER_SIZE as u64 + entry_size / 2;

        let mut buf = Vec::new();
        let result = iter.next(&mut testfs1, &mut buf);
        match result {
            Some(Err(e)) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("beyond") || msg.contains("extends"),
                    "expected stream-end error: {msg}"
                );
            }
            Some(Ok(_)) => {
                panic!("expected error, got Ok entry");
            }
            None => {
                panic!("expected error, got None");
            }
        }

        assert!(iter.next(&mut testfs1, &mut buf).is_none());
    }

    /// Corrupts the first SDS entry's size and asserts the
    /// iterator returns an error containing `expected_msg`.
    fn assert_corrupt_first_entry_size_error(corrupt_size: u32, expected_msg: &str) {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let mut buf = Vec::new();
        let first = iter.next(&mut testfs1, &mut buf);
        if first.is_none() {
            return;
        }
        let stream_offset = first.unwrap().unwrap().stream_offset();

        let raw = corrupt_sds_entry_size(&mut testfs1, &secure_file, stream_offset, corrupt_size);

        let (mut cursor, ntfs2) = ntfs_from_raw_bytes(raw);
        let secure2 = ntfs2
            .file(&mut cursor, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();
        let mut iter = ntfs_secure_sds_entries(&secure2, &mut cursor).unwrap();
        let mut buf = Vec::new();

        let result = iter.next(&mut cursor, &mut buf);
        match result {
            Some(Err(e)) => {
                let msg = e.to_string();
                assert!(
                    msg.contains(expected_msg),
                    "expected '{expected_msg}' error: {msg}"
                );
            }
            Some(Ok(_)) => {
                panic!("expected error, got Ok entry");
            }
            None => {
                panic!("expected error, got None");
            }
        }
    }

    #[test]
    fn test_sds_zero_size_entry() {
        assert_corrupt_first_entry_size_error(0, "zero size");
    }

    #[test]
    fn test_sds_entry_too_small_for_header() {
        assert_corrupt_first_entry_size_error(15, "too small");
    }

    #[test]
    fn test_sds_entry_exceeds_maximum_size() {
        assert_corrupt_first_entry_size_error((SDS_MAX_SIZE + 1) as u32, "exceeds maximum");
    }

    #[test]
    fn test_sds_entry_crosses_block_boundary() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let secure_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();

        let mut iter = ntfs_secure_sds_entries(&secure_file, &mut testfs1).unwrap();
        let mut buf = Vec::new();
        let first = iter.next(&mut testfs1, &mut buf);
        if first.is_none() {
            return;
        }
        let entry = first.unwrap().unwrap();
        let entry_end = entry.stream_offset() + u64::from(entry.entry_size());
        let second_offset = align_up(entry_end, SDS_ENTRY_ALIGNMENT);

        let second = iter.next(&mut testfs1, &mut buf);
        if second.is_none() {
            return;
        }
        second.unwrap().unwrap();

        let rel = second_offset % SDS_BLOCK_PAIR_SIZE;
        if rel == 0 || rel >= SDS_BLOCK_SIZE {
            return;
        }

        let cross_size = (SDS_BLOCK_SIZE - rel + 1) as u32;
        if cross_size as usize > SDS_MAX_SIZE {
            return;
        }

        let raw = corrupt_sds_entry_size(&mut testfs1, &secure_file, second_offset, cross_size);

        let (mut cursor, ntfs2) = ntfs_from_raw_bytes(raw);
        let secure2 = ntfs2
            .file(&mut cursor, KnownNtfsFileRecordNumber::Secure as u64)
            .unwrap();
        let mut iter = ntfs_secure_sds_entries(&secure2, &mut cursor).unwrap();
        let mut buf = Vec::new();

        let first_result = iter.next(&mut cursor, &mut buf);
        assert!(first_result.is_some());
        first_result.unwrap().unwrap();

        let result = iter.next(&mut cursor, &mut buf);
        match result {
            Some(Err(e)) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("block boundary"),
                    "expected block-boundary error: {msg}"
                );
            }
            Some(Ok(_)) => {
                panic!("expected error, got Ok entry");
            }
            None => {
                panic!("expected error, got None");
            }
        }
    }
}
