use super::*;
use crate::attribute::NtfsAttributeType;
use crate::indexes::NtfsFileNameIndex;
use crate::indexes::NtfsReparsePointIndex;
use crate::indexes::NtfsSecurityIdIndex;
use crate::ntfs::Ntfs;
use crate::structured_values::NtfsIndexRoot;
use fs_common::iter::FsTryIterator;

#[test]
fn test_index_node_entry_flags() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    // Access the root directory's $INDEX_ROOT directly to see raw index entries
    // including the LAST_ENTRY sentinel.
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let mut attrs = root_dir.attributes_raw();

    // Find $INDEX_ROOT attribute.
    let index_root_attr = loop {
        let attr = attrs.next().unwrap().unwrap();
        if attr.ty().unwrap() == NtfsAttributeType::IndexRoot {
            break attr;
        }
    };

    let index_root = index_root_attr
        .resident_structured_value::<NtfsIndexRoot>()
        .unwrap();

    let entries = index_root.entries::<NtfsFileNameIndex>().unwrap();
    let mut found_last = false;
    let mut entry_count = 0;

    for entry in entries {
        let entry = entry.unwrap();
        let flags = entry.flags();
        entry_count += 1;

        if flags.contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            found_last = true;
            // Last entry should not have a key.
            assert!(entry.key().is_none());
        } else {
            // Non-last entries should have a key.
            assert!(entry.key().is_some());
            // key_length should be nonzero.
            assert!(entry.key_length() > 0);
        }

        // Every entry should have a valid length.
        assert!(entry.index_entry_length() >= 16);
    }

    assert!(found_last, "should have encountered the LAST_ENTRY flag");
    assert!(
        entry_count >= 1,
        "index root should have at least one entry"
    );
}

#[test]
fn test_index_entry_file_reference() {
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

    // The file reference should resolve to a valid file.
    let file_ref = entry.file_reference();
    let file = file_ref.to_file(&ntfs, &mut testfs1).unwrap();
    assert!(!file.is_directory());
}

#[test]
fn test_index_entry_position_is_nonzero() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut entries = root_dir_index.entries();

    // Check that entries have nonzero positions.
    if let Some(entry) = entries.try_next(&mut testfs1).unwrap() {
        // The position should point somewhere in the filesystem.
        assert!(entry.position().value().is_some());
    }
}

#[test]
fn test_index_entry_subnode_vcn_in_large_dir() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    // Navigate to "many_subdirs" which has a large B-tree index.
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "many_subdirs")
        .unwrap()
        .unwrap();
    let many_subdirs = entry.to_file(&ntfs, &mut testfs1).unwrap();
    assert!(many_subdirs.is_directory());

    // Access index root directly to see HAS_SUBNODE entries.
    let mut attrs = many_subdirs.attributes_raw();
    let index_root_attr = loop {
        let attr = attrs.next().unwrap().unwrap();
        if attr.ty().unwrap() == NtfsAttributeType::IndexRoot {
            break attr;
        }
    };
    let index_root = index_root_attr
        .resident_structured_value::<NtfsIndexRoot>()
        .unwrap();

    // A large index should have entries with HAS_SUBNODE.
    assert!(index_root.is_large_index());

    let entries = index_root.entries::<NtfsFileNameIndex>().unwrap();
    let mut found_subnode = false;

    for entry in entries {
        let entry = entry.unwrap();
        if entry.flags().contains(NtfsIndexEntryFlags::HAS_SUBNODE) {
            let vcn = entry.subnode_vcn().unwrap().unwrap();
            assert!(vcn.value() >= 0);
            found_subnode = true;
        }
    }

    assert!(
        found_subnode,
        "expected HAS_SUBNODE entries in many_subdirs"
    );
}

/// Builds a synthetic 28-byte `$R` index entry buffer with hardcoded
/// little-endian bytes, suitable for `NtfsIndexEntry::new()`.
///
/// Layout (`INDEX_ENTRY_HEADER_SIZE` = 16, key = 12):
///   [0..8]   header file reference (for `HasFileReference`)
///   [8..10]  `index_entry_length` (u16 LE)
///   [10..12] `key_length` (u16 LE)
///   [12]     flags (u8)
///   [13..16] reserved
///   [16..20] `reparse_tag` (u32 LE)
///   [20..28] key `file_reference` (u64 LE packed)
fn build_synthetic_r_entry(
    header_file_ref: [u8; 8],
    reparse_tag: [u8; 4],
    key_file_ref: [u8; 8],
    flags: u8,
) -> [u8; 28] {
    let mut buf = [0u8; 28];
    buf[0..8].copy_from_slice(&header_file_ref);
    buf[8..10].copy_from_slice(&28u16.to_le_bytes());
    buf[10..12].copy_from_slice(&12u16.to_le_bytes());
    buf[12] = flags;
    buf[16..20].copy_from_slice(&reparse_tag);
    buf[20..28].copy_from_slice(&key_file_ref);
    buf
}

#[test]
fn synthetic_r_entry_key_round_trip() {
    // header file ref: record=100, seq=7
    // tag = 0xA000_001D (IO_REPARSE_TAG_LX_SYMLINK)
    // key file ref: record=5678, seq=2
    let header_ref: [u8; 8] = [0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00];
    let tag: [u8; 4] = [0x1D, 0x00, 0x00, 0xA0];
    let key_ref: [u8; 8] = [0x2E, 0x16, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00];
    let buf = build_synthetic_r_entry(header_ref, tag, key_ref, 0);

    let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x1000))
        .expect("should parse synthetic $R entry");

    // Header file reference (from HasFileReference trait)
    let hdr_ref = entry.file_reference();
    assert_eq!(hdr_ref.file_record_number(), 100);
    assert_eq!(hdr_ref.sequence_number(), 7);

    // Key
    let key = entry
        .key()
        .expect("non-last entry should have a key")
        .expect("key parsing should succeed");
    assert_eq!(key.reparse_tag(), 0xA000_001D);
    assert_eq!(key.file_reference().file_record_number(), 5678);
    assert_eq!(key.file_reference().sequence_number(), 2);

    // Structural fields
    assert_eq!(entry.index_entry_length(), 28);
    assert_eq!(entry.key_length(), 12);
    assert!(!entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY));
    assert!(!entry.flags().contains(NtfsIndexEntryFlags::HAS_SUBNODE));
}

#[test]
fn synthetic_r_entry_last_entry_has_no_key() {
    let buf = build_synthetic_r_entry(
        [0; 8],
        [0x0C, 0x00, 0x00, 0xA0],
        [0; 8],
        NtfsIndexEntryFlags::LAST_ENTRY.bits(),
    );

    let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::none())
        .expect("should parse last-entry sentinel");

    assert!(entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY));
    assert!(entry.key().is_none(), "last entry should not return a key");
}

#[test]
fn synthetic_r_entry_header_and_key_refs_differ() {
    // Verify that the header file reference and key file reference
    // are parsed from independent byte ranges.
    let header_ref: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00];
    let key_ref: [u8; 8] = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00];
    let buf = build_synthetic_r_entry(header_ref, [0x12, 0x00, 0x00, 0x80], key_ref, 0);

    let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x2000))
        .expect("should parse entry with differing refs");

    // Header ref: record=1, seq=10
    assert_eq!(entry.file_reference().file_record_number(), 1);
    assert_eq!(entry.file_reference().sequence_number(), 10);

    // Key ref: record=255, seq=20
    let key = entry.key().unwrap().unwrap();
    assert_eq!(key.reparse_tag(), 0x8000_0012);
    assert_eq!(key.file_reference().file_record_number(), 255);
    assert_eq!(key.file_reference().sequence_number(), 20);
}

#[test]
fn synthetic_r_entry_rejects_truncated_buffer() {
    let buf = [0u8; 15]; // Less than INDEX_ENTRY_HEADER_SIZE (16)
    let result = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x500));
    assert!(
        result.is_err(),
        "buffer shorter than header should be rejected"
    );
}

/// Builds a synthetic `$SII` index entry (an entry type that *has data*).
///
/// Layout (header 16 + key 4 + data 20 = 40 bytes):
///   [0..2]   `data_offset`  (u16 LE) = 20
///   [2..4]   `data_length`  (u16 LE) = 20
///   [4..8]   padding
///   [8..10]  `index_entry_length` (u16 LE) = 40
///   [10..12] `key_length` (u16 LE) = 4
///   [12]     flags
///   [13..16] reserved
///   [16..20] $SII key: `security_id` (u32 LE)
///   [20..40] $SII data: hash, `security_id`, `sds_offset`, `sds_size`
fn build_sii_entry(security_id: u32, flags: u8) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[0..2].copy_from_slice(&20u16.to_le_bytes()); // data_offset
    buf[2..4].copy_from_slice(&20u16.to_le_bytes()); // data_length
    buf[8..10].copy_from_slice(&40u16.to_le_bytes()); // index_entry_length
    buf[10..12].copy_from_slice(&4u16.to_le_bytes()); // key_length
    buf[12] = flags;
    buf[16..20].copy_from_slice(&security_id.to_le_bytes()); // key
    // $SII data body (20 bytes): hash, security_id, sds_offset, sds_size.
    buf[20..24].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // hash
    buf[24..28].copy_from_slice(&security_id.to_le_bytes()); // security_id
    buf[28..36].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes()); // sds_offset
    buf[36..40].copy_from_slice(&0x4444u32.to_le_bytes()); // sds_size
    buf
}

#[test]
fn sii_entry_data_offset_and_length() {
    let buf = build_sii_entry(0x1234_5678, 0);
    let entry = NtfsIndexEntry::<NtfsSecurityIdIndex>::new(&buf, NtfsPosition::new(0x800))
        .expect("should parse synthetic $SII entry");

    // data_offset and data_length return the genuine header values
    // (distinct from the 0/1 replacements).
    assert_eq!(entry.data_offset(), 20);
    assert_eq!(entry.data_length(), 20);
    assert_eq!(entry.key_length(), 4);
    assert_eq!(entry.index_entry_length(), 40);

    // The key parses to the expected security ID.
    let key = entry.key().unwrap().unwrap();
    assert_eq!(key.security_id(), 0x1234_5678);
}

#[test]
fn sii_entry_data_round_trip() {
    let buf = build_sii_entry(0x00AB_CDEF, 0);
    let entry = NtfsIndexEntry::<NtfsSecurityIdIndex>::new(&buf, NtfsPosition::new(0x800))
        .expect("should parse synthetic $SII entry");

    // data() slices [data_offset .. data_offset + data_length] and parses
    // the $SII data body. A wrong offset/length or a None replacement
    // changes the parsed fields.
    let data = entry.data().expect("entry has data").expect("data parses");
    assert_eq!(data.hash(), 0xDEAD_BEEF);
    assert_eq!(data.security_id(), 0x00AB_CDEF);
    assert_eq!(data.sds_offset(), 0x0102_0304_0506_0708);
    assert_eq!(data.sds_size(), 0x4444);
}

#[test]
fn sii_entry_data_none_when_offset_or_length_zero() {
    // data_offset == 0 -> None (anchors the `== 0` / `||` checks at 146).
    let mut zero_offset = build_sii_entry(1, 0);
    zero_offset[0..2].copy_from_slice(&0u16.to_le_bytes());
    let entry = NtfsIndexEntry::<NtfsSecurityIdIndex>::new(&zero_offset, NtfsPosition::none())
        .expect("parses with zero data_offset");
    assert!(entry.data().is_none());

    // data_length == 0 -> None.
    let mut zero_length = build_sii_entry(1, 0);
    zero_length[2..4].copy_from_slice(&0u16.to_le_bytes());
    let entry2 = NtfsIndexEntry::<NtfsSecurityIdIndex>::new(&zero_length, NtfsPosition::none())
        .expect("parses with zero data_length");
    assert!(entry2.data().is_none());
}

#[test]
fn r_entry_key_data_round_trip() {
    // key_data() returns the raw key slice [16 .. 16 + key_length].
    let header_ref: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
    let tag: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
    let key_ref: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let buf = build_synthetic_r_entry(header_ref, tag, key_ref, 0);

    let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x1000))
        .expect("should parse synthetic $R entry");

    let key_data = entry
        .key_data()
        .expect("non-last entry has key data")
        .expect("key data slice is in range");
    // 12-byte key: the reparse tag bytes followed by the key file ref.
    assert_eq!(key_data.len(), 12);
    assert_eq!(&key_data[0..4], &tag);
    assert_eq!(&key_data[4..12], &key_ref);

    // key_ref() builds the borrowed key view from the same bytes.
    let kref = entry.key_ref().unwrap().unwrap();
    assert_eq!(kref.reparse_tag(), 0xDDCC_BBAA);
}

#[test]
fn r_entry_key_data_none_for_last_entry() {
    // The LAST_ENTRY flag means no key, so key_data and key_ref are None.
    let buf = build_synthetic_r_entry(
        [0; 8],
        [0x0C, 0x00, 0x00, 0xA0],
        [0; 8],
        NtfsIndexEntryFlags::LAST_ENTRY.bits(),
    );
    let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::none())
        .expect("parses last-entry sentinel");
    assert!(entry.key_data().is_none());
    assert!(entry.key_ref().is_none());
}

/// Builds an `$R` entry carrying a subnode VCN at its very end.
///
/// `HAS_SUBNODE` is set and the 8-byte VCN occupies the last 8 bytes of the
/// entry, i.e. [`index_entry_length` - 8 .. `index_entry_length`].
fn build_r_entry_with_subnode(vcn: i64) -> [u8; 36] {
    let mut buf = [0u8; 36];
    buf[8..10].copy_from_slice(&36u16.to_le_bytes()); // index_entry_length
    buf[10..12].copy_from_slice(&12u16.to_le_bytes()); // key_length
    buf[12] = NtfsIndexEntryFlags::HAS_SUBNODE.bits();
    // key occupies [16..28]; the subnode VCN sits in the final 8 bytes.
    buf[28..36].copy_from_slice(&vcn.to_le_bytes());
    buf
}

#[test]
fn r_entry_subnode_vcn_round_trip() {
    let buf = build_r_entry_with_subnode(0x0011_2233_4455_6677);
    let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x2000))
        .expect("parses entry with subnode");
    assert!(entry.flags().contains(NtfsIndexEntryFlags::HAS_SUBNODE));
    let vcn = entry.subnode_vcn().expect("has subnode").expect("vcn ok");
    assert_eq!(vcn.value(), 0x0011_2233_4455_6677);
}

#[test]
fn r_entry_subnode_vcn_none_without_flag() {
    // Without HAS_SUBNODE, subnode_vcn returns None (anchors `!` at 306).
    let buf = build_synthetic_r_entry([0; 8], [0; 4], [0; 8], 0);
    let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::none())
        .expect("parses entry without subnode");
    assert!(entry.subnode_vcn().is_none());
}

#[test]
fn validate_size_rejects_tiny_and_oversize() {
    // index_entry_length smaller than the header (anchors `<` at 352).
    let mut too_small = build_synthetic_r_entry([0; 8], [0; 4], [0; 8], 0);
    too_small[8..10].copy_from_slice(&8u16.to_le_bytes());
    assert!(
        NtfsIndexEntry::<NtfsReparsePointIndex>::new(&too_small, NtfsPosition::none()).is_err()
    );

    // index_entry_length larger than the slice (anchors `>` at 360).
    let mut too_big = build_synthetic_r_entry([0; 8], [0; 4], [0; 8], 0);
    too_big[8..10].copy_from_slice(&64u16.to_le_bytes());
    assert!(
        NtfsIndexEntry::<NtfsReparsePointIndex>::new(&too_big, NtfsPosition::none()).is_err()
    );

    // Exactly INDEX_ENTRY_HEADER_SIZE (16) for both lengths is valid.
    let mut exact = [0u8; 16];
    exact[8..10].copy_from_slice(&16u16.to_le_bytes());
    assert!(NtfsIndexEntry::<NtfsReparsePointIndex>::new(&exact, NtfsPosition::none()).is_ok());
}

#[test]
fn dir_entry_real_index_delegates_key() {
    // An IndexEntry dir entry delegates key/key_ref and reports
    // is_index_entry; the dot variants report their own predicates.
    let header_ref: [u8; 8] = [0x05, 0, 0, 0, 0, 0, 0, 0];
    let buf = build_synthetic_r_entry(
        header_ref,
        [0x12, 0, 0, 0x80],
        [0x07, 0, 0, 0, 0, 0, 0, 0],
        0,
    );
    let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::none())
        .expect("parses entry");

    let dir_entry = NtfsDirEntry::IndexEntry(entry);
    assert!(dir_entry.is_index_entry());
    assert!(!dir_entry.is_current_directory());
    assert!(!dir_entry.is_parent_directory());
    let key = dir_entry.key().expect("real entry has a key").unwrap();
    assert_eq!(key.reparse_tag(), 0x8000_0012);
    assert!(dir_entry.key_ref().is_some());

    let cur: NtfsDirEntry<NtfsReparsePointIndex> =
        NtfsDirEntry::CurrentDirectory(NtfsFileReference::new([0; 8]));
    assert!(cur.is_current_directory());
    assert!(!cur.is_parent_directory());
    assert!(!cur.is_index_entry());
    assert!(cur.key().is_none());
    assert!(cur.key_ref().is_none());

    let parent: NtfsDirEntry<NtfsReparsePointIndex> =
        NtfsDirEntry::ParentDirectory(NtfsFileReference::new([0; 8]));
    assert!(parent.is_parent_directory());
    assert!(!parent.is_current_directory());
}

#[test]
fn index_node_entry_ranges_iterates_two_entries() {
    // Two non-last $R entries followed by a LAST_ENTRY sentinel. The
    // ranges iterator must advance by index_entry_length each time
    // (anchors `+` at 492) and stop at the sentinel.
    let e0 =
        build_synthetic_r_entry([0x01, 0, 0, 0, 0, 0, 0, 0], [0x10, 0, 0, 0xA0], [0; 8], 0);
    let e1 =
        build_synthetic_r_entry([0x02, 0, 0, 0, 0, 0, 0, 0], [0x20, 0, 0, 0xA0], [0; 8], 0);
    let last = build_synthetic_r_entry(
        [0; 8],
        [0; 4],
        [0; 8],
        NtfsIndexEntryFlags::LAST_ENTRY.bits(),
    );
    let mut data = Vec::new();
    data.extend_from_slice(&e0);
    data.extend_from_slice(&e1);
    data.extend_from_slice(&last);
    let total = data.len();

    let ranges = IndexNodeEntryRanges::<NtfsReparsePointIndex>::new(
        data.clone(),
        0..total,
        NtfsPosition::new(0x4000),
    );
    let collected: Vec<_> = ranges.collect::<Result<_>>().unwrap();
    // e0, e1, and the sentinel are all yielded (3 ranges).
    assert_eq!(collected.len(), 3);
    assert_eq!(
        collected[0]
            .clone()
            .to_entry(&data)
            .unwrap()
            .index_entry_length(),
        28
    );
    // The second range starts exactly one entry length in.
    let second = collected[1].clone().to_entry(&data).unwrap();
    assert_eq!(second.file_reference().file_record_number(), 2);
}

#[test]
fn index_node_entries_iterates_until_last() {
    // The slice-based iterator yields each entry and stops at LAST_ENTRY.
    let e0 =
        build_synthetic_r_entry([0x09, 0, 0, 0, 0, 0, 0, 0], [0x10, 0, 0, 0xA0], [0; 8], 0);
    let last = build_synthetic_r_entry(
        [0; 8],
        [0; 4],
        [0; 8],
        NtfsIndexEntryFlags::LAST_ENTRY.bits(),
    );
    let mut data = Vec::new();
    data.extend_from_slice(&e0);
    data.extend_from_slice(&last);

    let entries =
        NtfsIndexNodeEntries::<NtfsReparsePointIndex>::new(&data, NtfsPosition::new(0x6000));
    let collected: Vec<_> = entries.collect::<Result<_>>().unwrap();
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].file_reference().file_record_number(), 9);
    assert!(
        collected[1]
            .flags()
            .contains(NtfsIndexEntryFlags::LAST_ENTRY)
    );
}

#[test]
fn index_entry_flags_display_renders_bits() {
    // The flags Display delegates to the bitflags formatter; a non-empty
    // set must not render as the Default (empty) string.
    let flags = NtfsIndexEntryFlags::HAS_SUBNODE | NtfsIndexEntryFlags::LAST_ENTRY;
    let rendered = format!("{flags}");
    assert_ne!(rendered, "");
    assert!(rendered.contains("HAS_SUBNODE"), "got {rendered:?}");
    assert!(rendered.contains("LAST_ENTRY"), "got {rendered:?}");
}
