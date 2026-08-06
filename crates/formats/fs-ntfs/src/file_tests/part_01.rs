use super::*;
use crate::indexes::NtfsFileNameIndex;
use crate::ntfs::Ntfs;
use crate::slack_recovery::SlackRecoveryConfig;
use crate::structured_values::NtfsFileNamespace;
use fs_common::iter::FsTryIterator;

use super::synthetic;

#[test]
fn test_synthetic_header_accessors() {
    // A directory record (IN_USE | IS_DIRECTORY), seq 7, 3 hard links,
    // with one FILE_NAME attribute so attribute iteration is valid.
    let fname = synthetic::file_name_value(5, 1, 3, true, "dir");
    let attrs = [synthetic::ResidentAttr {
        ty: NtfsAttributeType::FileName,
        instance: 0,
        name: "",
        value: fname,
    }];
    let record = synthetic::file_record(0x0003, 7, 3, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 42);
    let file = synthetic::open_file(&ntfs, &mut cursor, 42);

    assert_eq!(file.allocated_size(), u32::try_from(synthetic::RECORD_SIZE).expect("test value fits u32"));
    assert_eq!(file.first_attribute_offset(), 0x38);
    assert_eq!(file.sequence_number(), 7);
    assert_eq!(file.hard_link_count(), 3);
    assert_eq!(file.file_record_number(), 42);
    assert!(file.is_directory());
    assert!(file.flags().contains(NtfsFileFlags::IN_USE));
    assert!(file.flags().contains(NtfsFileFlags::IS_DIRECTORY));
    // data_size is the used span; must be > 0 and <= allocated.
    assert!(file.data_size() > 0);
    assert!(file.data_size() <= file.allocated_size());
}

#[test]
fn test_synthetic_non_directory_flags() {
    // IN_USE but not a directory.
    let fname = synthetic::file_name_value(5, 1, 1, false, "file.txt");
    let attrs = [synthetic::ResidentAttr {
        ty: NtfsAttributeType::FileName,
        instance: 0,
        name: "",
        value: fname,
    }];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    assert!(!file.is_directory());
    assert!(file.flags().contains(NtfsFileFlags::IN_USE));
}

#[test]
fn test_synthetic_is_system_metafile() {
    let record = synthetic::file_record(0x0001, 1, 1, &[]);

    // Record 23 is the last system metafile (< 24).
    let (ntfs, mut cursor) = synthetic::load(&record, 23);
    let file = synthetic::open_file(&ntfs, &mut cursor, 23);
    assert!(file.is_system_metafile());

    // Record 24 is the first non-system file.
    let (ntfs, mut cursor) = synthetic::load(&record, 24);
    let file = synthetic::open_file(&ntfs, &mut cursor, 24);
    assert!(!file.is_system_metafile());

    // Record 0 ($MFT) is a system metafile.
    let (ntfs, mut cursor) = synthetic::load(&record, 0);
    let file = synthetic::open_file(&ntfs, &mut cursor, 0);
    assert!(file.is_system_metafile());
}

#[test]
fn test_synthetic_validate_signature_rejects_bad() {
    use core::num::NonZeroU64;
    // Corrupt the FILE signature; NtfsFile::new must reject it.
    let mut record = synthetic::file_record(0x0001, 1, 1, &[]);
    record[0..4].copy_from_slice(b"BAAD");
    let mut image = vec![0u8; usize::try_from(synthetic::RECORD_POSITION).expect("test value fits usize") + synthetic::RECORD_SIZE];
    image[..synthetic::SECTOR_SIZE].copy_from_slice(&synthetic::boot_sector());
    image[usize::try_from(synthetic::RECORD_POSITION).expect("test value fits usize")..].copy_from_slice(&record);
    let mut cursor = fsmnt_testkit::Cursor::new(image);
    let ntfs = Ntfs::new(&mut cursor).unwrap();
    let result = NtfsFile::new(
        &ntfs,
        &mut cursor,
        NonZeroU64::new(synthetic::RECORD_POSITION).unwrap(),
        1,
    );
    assert!(matches!(
        result.unwrap_err(),
        NtfsError::InvalidFileSignature { .. }
    ));
}

#[test]
fn test_synthetic_validate_sizes_rejects_oversized_allocated() {
    use core::num::NonZeroU64;
    // allocated_size larger than the record must be rejected.
    let mut record = synthetic::file_record(0x0001, 1, 1, &[]);
    // allocated_size at offset 28: set to record_size + 512 (too big).
    record[28..32].copy_from_slice(&(u32::try_from(synthetic::RECORD_SIZE).expect("test value fits u32") + 512).to_le_bytes());
    // Repair fixup: the byte at 510 / 1022 may have changed; rebuild USA.
    // Offset 28 is in sector 0, not at a sector end, so USA stays valid.
    let mut image = vec![0u8; usize::try_from(synthetic::RECORD_POSITION).expect("test value fits usize") + synthetic::RECORD_SIZE];
    image[..synthetic::SECTOR_SIZE].copy_from_slice(&synthetic::boot_sector());
    image[usize::try_from(synthetic::RECORD_POSITION).expect("test value fits usize")..].copy_from_slice(&record);
    let mut cursor = fsmnt_testkit::Cursor::new(image);
    let ntfs = Ntfs::new(&mut cursor).unwrap();
    let result = NtfsFile::new(
        &ntfs,
        &mut cursor,
        NonZeroU64::new(synthetic::RECORD_POSITION).unwrap(),
        1,
    );
    assert!(matches!(
        result.unwrap_err(),
        NtfsError::InvalidFileAllocatedSize { .. }
    ));
}

#[test]
fn test_synthetic_validate_sizes_rejects_data_gt_allocated() {
    use core::num::NonZeroU64;
    // data_size > allocated_size must be rejected (second check in validate_sizes).
    let mut record = synthetic::file_record(0x0001, 1, 1, &[]);
    // allocated_size = 512 (fits the record), data_size = 600 (> allocated).
    record[28..32].copy_from_slice(&512u32.to_le_bytes());
    record[24..28].copy_from_slice(&600u32.to_le_bytes());
    let mut image = vec![0u8; usize::try_from(synthetic::RECORD_POSITION).expect("test value fits usize") + synthetic::RECORD_SIZE];
    image[..synthetic::SECTOR_SIZE].copy_from_slice(&synthetic::boot_sector());
    image[usize::try_from(synthetic::RECORD_POSITION).expect("test value fits usize")..].copy_from_slice(&record);
    let mut cursor = fsmnt_testkit::Cursor::new(image);
    let ntfs = Ntfs::new(&mut cursor).unwrap();
    let result = NtfsFile::new(
        &ntfs,
        &mut cursor,
        NonZeroU64::new(synthetic::RECORD_POSITION).unwrap(),
        1,
    );
    assert!(matches!(
        result.unwrap_err(),
        NtfsError::InvalidFileUsedSize { .. }
    ));
}

#[test]
fn test_synthetic_validate_sizes_accepts_equal_boundaries() {
    use core::num::NonZeroU64;
    // allocated_size == record len and data_size == allocated_size are
    // both accepted (boundary `>` not `>=`).
    let mut record = synthetic::file_record(0x0001, 1, 1, &[]);
    record[28..32].copy_from_slice(&u32::try_from(synthetic::RECORD_SIZE).expect("test value fits u32").to_le_bytes());
    record[24..28].copy_from_slice(&u32::try_from(synthetic::RECORD_SIZE).expect("test value fits u32").to_le_bytes());
    let mut image = vec![0u8; usize::try_from(synthetic::RECORD_POSITION).expect("test value fits usize") + synthetic::RECORD_SIZE];
    image[..synthetic::SECTOR_SIZE].copy_from_slice(&synthetic::boot_sector());
    image[usize::try_from(synthetic::RECORD_POSITION).expect("test value fits usize")..].copy_from_slice(&record);
    let mut cursor = fsmnt_testkit::Cursor::new(image);
    let ntfs = Ntfs::new(&mut cursor).unwrap();
    let file = NtfsFile::new(
        &ntfs,
        &mut cursor,
        NonZeroU64::new(synthetic::RECORD_POSITION).unwrap(),
        1,
    )
    .unwrap();
    assert_eq!(file.allocated_size(), u32::try_from(synthetic::RECORD_SIZE).expect("test value fits u32"));
    assert_eq!(file.data_size(), u32::try_from(synthetic::RECORD_SIZE).expect("test value fits u32"));
}

#[test]
fn test_synthetic_data_attribute_lookup() {
    // Two $DATA attributes: unnamed (empty name) and "stream2".
    let attrs = [
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 0,
            name: "",
            value: vec![0xAA; 8],
        },
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 1,
            name: "stream2",
            value: vec![0xBB; 4],
        },
    ];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (mut ntfs, mut cursor) = synthetic::load(&record, 30);
    ntfs.read_upcase_table(&mut cursor).ok(); // best-effort; not present, falls back

    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    // Unnamed $DATA exists and is found (no upcase needed).
    let unnamed = file.data(&mut cursor, "").unwrap().unwrap();
    let attr = unnamed.to_attribute().unwrap();
    assert_eq!(attr.ty().unwrap(), NtfsAttributeType::Data);
    assert!(attr.name().unwrap().is_empty());
}

#[test]
fn test_synthetic_data_named_stream_lookup() {
    // A file (record 1) with two $DATA streams: unnamed and "stream2".
    // Looking up by a non-empty name exercises the case-insensitive
    // `upcase_cmp(...) == Ordering::Equal` path (line 247), which needs
    // the $UpCase table loaded.
    let attrs = [
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 0,
            name: "",
            value: vec![0xAA; 8],
        },
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 1,
            name: "stream2",
            value: vec![0xBB; 4],
        },
    ];
    let file_record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let image = synthetic::mft_image_with_upcase(&[file_record]);
    let mut cursor = fsmnt_testkit::Cursor::new(image);
    let mut ntfs = Ntfs::new(&mut cursor).unwrap();
    ntfs.read_upcase_table(&mut cursor)
        .expect("synthetic $UpCase must load");

    let file = ntfs.file(&mut cursor, 1).unwrap();

    // The named stream is found via case-insensitive comparison
    // (lowercase query matches the stored lowercase name with an identity
    // upcase table).
    let named = file.data(&mut cursor, "stream2").unwrap().unwrap();
    let attr = named.to_attribute().unwrap();
    assert_eq!(attr.name().unwrap(), "stream2");

    // A non-matching name returns None (the `== Equal` comparison fails).
    assert!(file.data(&mut cursor, "no_such_stream").is_none());
}

#[test]
fn test_synthetic_data_attribute_absent_returns_none() {
    // A record with only a FILE_NAME attribute has no $DATA.
    let fname = synthetic::file_name_value(5, 1, 1, false, "x");
    let attrs = [synthetic::ResidentAttr {
        ty: NtfsAttributeType::FileName,
        instance: 0,
        name: "",
        value: fname,
    }];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    assert!(file.data(&mut cursor, "").is_none());
}

#[test]
fn test_synthetic_name_lookup() {
    // FILE_NAME with Win32 namespace, parent record 5.
    let fname = synthetic::file_name_value(5, 1, 1, false, "hello.txt");
    let attrs = [synthetic::ResidentAttr {
        ty: NtfsAttributeType::FileName,
        instance: 0,
        name: "",
        value: fname,
    }];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    let name = file.name(&mut cursor, None, None).unwrap().unwrap();
    assert_eq!(name.name().to_string().unwrap(), "hello.txt");
    assert_eq!(name.namespace(), NtfsFileNamespace::Win32);
    assert_eq!(name.parent_directory_reference().file_record_number(), 5);

    // Filtering by the matching namespace finds it.
    assert!(
        file.name(&mut cursor, Some(NtfsFileNamespace::Win32), None)
            .is_some()
    );
    // Filtering by a non-matching namespace finds nothing.
    assert!(
        file.name(&mut cursor, Some(NtfsFileNamespace::Dos), None)
            .is_none()
    );
    // Filtering by the matching parent record finds it.
    assert!(file.name(&mut cursor, None, Some(5)).is_some());
    // Filtering by a non-matching parent record finds nothing.
    assert!(file.name(&mut cursor, None, Some(99)).is_none());
}

#[test]
fn test_synthetic_name_absent_returns_none() {
    // A record with only a $DATA attribute has no FILE_NAME.
    let attrs = [synthetic::ResidentAttr {
        ty: NtfsAttributeType::Data,
        instance: 0,
        name: "",
        value: vec![0u8; 4],
    }];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);
    assert!(file.name(&mut cursor, None, None).is_none());
}

#[test]
fn test_synthetic_name_pair_separate_win32_and_dos() {
    // Win32 long name + DOS short name with the same parent => paired.
    let win32 = synthetic::file_name_value(5, 1, 1, false, "longname.txt");
    let dos = synthetic::file_name_value(5, 1, 2, false, "LONGNA~1.TXT");
    let attrs = [
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 0,
            name: "",
            value: win32,
        },
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 1,
            name: "",
            value: dos,
        },
    ];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    let pair = file.name_pair(&mut cursor, None).unwrap().unwrap();
    assert_eq!(pair.primary.name().to_string().unwrap(), "longname.txt");
    let short = pair.short_name.expect("expected a DOS short name");
    assert_eq!(short.name().to_string().unwrap(), "LONGNA~1.TXT");
}

#[test]
fn test_synthetic_name_pair_dos_belongs_to_other_parent() {
    // Win32 (parent 5) + DOS (parent 9) => DOS must NOT be paired
    // (different parent directory). Exercises the `==` filter at line 730.
    let win32 = synthetic::file_name_value(5, 1, 1, false, "longname.txt");
    let dos = synthetic::file_name_value(9, 1, 2, false, "LONGNA~1.TXT");
    let attrs = [
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 0,
            name: "",
            value: win32,
        },
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 1,
            name: "",
            value: dos,
        },
    ];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    let pair = file.name_pair(&mut cursor, None).unwrap().unwrap();
    assert_eq!(pair.primary.name().to_string().unwrap(), "longname.txt");
    assert!(
        pair.short_name.is_none(),
        "DOS name for a different parent must not be paired"
    );
}

#[test]
fn test_synthetic_name_pair_combined_win32anddos() {
    // A single Win32AndDos entry => primary set, no separate short name.
    let combined = synthetic::file_name_value(5, 1, 3, false, "FILE.TXT");
    let attrs = [synthetic::ResidentAttr {
        ty: NtfsAttributeType::FileName,
        instance: 0,
        name: "",
        value: combined,
    }];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    let pair = file.name_pair(&mut cursor, None).unwrap().unwrap();
    assert_eq!(pair.primary.name().to_string().unwrap(), "FILE.TXT");
    assert!(pair.primary.namespace().is_combined());
    assert!(pair.short_name.is_none());
}

#[test]
fn test_synthetic_name_pair_parent_filter() {
    // A Win32 name with parent record 5. Filtering name_pair by the
    // matching parent (5) returns the pair; filtering by a different
    // parent (99) returns None. Guards the `!= parent_record_number`
    // filter at line 702.
    let win32 = synthetic::file_name_value(5, 1, 1, false, "longname.txt");
    let attrs = [synthetic::ResidentAttr {
        ty: NtfsAttributeType::FileName,
        instance: 0,
        name: "",
        value: win32,
    }];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    // Matching parent => Some.
    let pair = file.name_pair(&mut cursor, Some(5)).unwrap().unwrap();
    assert_eq!(pair.primary.name().to_string().unwrap(), "longname.txt");

    // Non-matching parent => None (the only FILE_NAME is skipped).
    assert!(file.name_pair(&mut cursor, Some(99)).is_none());
}

#[test]
fn test_synthetic_reparse_point_found_and_absent() {
    // Microsoft mount-point tag (0xA0000003), 0 data bytes => parses.
    let mut reparse = vec![0u8; 8];
    reparse[0..4].copy_from_slice(&0xA000_0003u32.to_le_bytes()); // reparse_tag
    reparse[4..6].copy_from_slice(&0u16.to_le_bytes()); // reparse_data_length
    let attrs = [
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 0,
            name: "",
            value: vec![0u8; 4],
        },
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::ReparsePoint,
            instance: 1,
            name: "",
            value: reparse,
        },
    ];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    let rp = file.reparse_point(&mut cursor).unwrap().unwrap();
    assert_eq!(rp.tag(), 0xA000_0003);

    // A record without a reparse point returns None.
    let record2 = synthetic::file_record(
        0x0001,
        1,
        1,
        &[synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 0,
            name: "",
            value: vec![0u8; 4],
        }],
    );
    let (ntfs2, mut cursor2) = synthetic::load(&record2, 31);
    let file2 = synthetic::open_file(&ntfs2, &mut cursor2, 31);
    assert!(file2.reparse_point(&mut cursor2).is_none());
}

#[test]
fn test_synthetic_find_resident_attribute_filters() {
    // Two $DATA attributes; find by name and by instance.
    let attrs = [
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 0,
            name: "",
            value: vec![0xAA; 4],
        },
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 5,
            name: "named",
            value: vec![0xBB; 4],
        },
    ];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let _ = &mut cursor;
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    // Find unnamed $DATA (name "" matches the first).
    let unnamed = file
        .find_resident_attribute(NtfsAttributeType::Data, Some(""), None)
        .unwrap();
    assert_eq!(unnamed.instance(), 0);

    // Find named $DATA "named".
    let named = file
        .find_resident_attribute(NtfsAttributeType::Data, Some("named"), None)
        .unwrap();
    assert_eq!(named.instance(), 5);

    // Find by instance only.
    let by_instance = file
        .find_resident_attribute(NtfsAttributeType::Data, None, Some(5))
        .unwrap();
    assert_eq!(by_instance.instance(), 5);

    // A type that is not present returns AttributeNotFound.
    assert!(matches!(
        file.find_resident_attribute(NtfsAttributeType::StandardInformation, None, None)
            .unwrap_err(),
        NtfsError::InvalidStructuredValueSize { .. } | NtfsError::AttributeNotFound { .. }
    ));
}

#[test]
fn test_synthetic_flags_display() {
    let flags = NtfsFileFlags::IN_USE | NtfsFileFlags::IS_DIRECTORY;
    let rendered = format!("{flags}");
    // The Display impl renders the active flag names; the
    // Ok(Default::default()) mutant would render an empty string.
    assert_eq!(rendered, "IN_USE | IS_DIRECTORY");
    assert!(!rendered.is_empty());
}

#[test]
fn test_synthetic_directory_index_non_directory_errors() {
    // A non-directory record must return NotADirectory from
    // directory_index (guards the `!self.is_directory()` check).
    let attrs = [synthetic::ResidentAttr {
        ty: NtfsAttributeType::Data,
        instance: 0,
        name: "",
        value: vec![0u8; 4],
    }];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);
    assert!(matches!(
        file.directory_index(&mut cursor).unwrap_err(),
        NtfsError::NotADirectory { .. }
    ));
}

#[test]
fn test_synthetic_directory_index_succeeds_for_directory() {
    // A well-formed directory's directory_index must succeed and its
    // index must enumerate the one child entry. Guards the
    // `!self.is_directory()` check (deleting `!` would error here).
    let dir = synthetic::directory_record(7, false, "child.txt");
    let image = synthetic::mft_image(&[dir]);
    let mut cursor = fsmnt_testkit::Cursor::new(image);
    let ntfs = Ntfs::new(&mut cursor).unwrap();

    let dir_file = ntfs.file(&mut cursor, 1).unwrap();
    let index = dir_file
        .directory_index(&mut cursor)
        .expect("directory_index must succeed for a directory");

    let mut iter = index.entries();
    let entry = iter
        .try_next(&mut cursor)
        .unwrap()
        .expect("expected one index entry");
    assert_eq!(entry.file_reference().file_record_number(), 7);
}

#[test]
fn test_synthetic_recover_slack_non_directory_errors() {
    // recover_directory_slack must reject non-directories before any
    // index work (guards the `!self.is_directory()` check at line 403).
    let attrs = [synthetic::ResidentAttr {
        ty: NtfsAttributeType::Data,
        instance: 0,
        name: "",
        value: vec![0u8; 4],
    }];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);
    let result = file.recover_directory_slack(&mut cursor, SlackRecoveryConfig::default());
    assert!(matches!(
        result.unwrap_err(),
        NtfsError::NotADirectory { .. }
    ));
}

#[test]
fn test_synthetic_find_attribute_filters_type_and_name() {
    // StandardInformation is absent; FILE_NAME and two $DATA present.
    let fname = synthetic::file_name_value(5, 1, 1, false, "x");
    let attrs = [
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 0,
            name: "",
            value: fname,
        },
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 1,
            name: "",
            value: vec![0xAA; 4],
        },
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 2,
            name: "alt",
            value: vec![0xBB; 4],
        },
    ];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    // find_attribute by type (no name) returns the first $DATA.
    let any_data = file
        .find_attribute(&mut cursor, NtfsAttributeType::Data, None)
        .unwrap();
    assert_eq!(any_data.to_attribute().unwrap().instance(), 1);

    // find_attribute by type AND name returns the named one.
    let named = file
        .find_attribute(&mut cursor, NtfsAttributeType::Data, Some("alt"))
        .unwrap();
    assert_eq!(named.to_attribute().unwrap().instance(), 2);

    // A type not present errors.
    assert!(matches!(
        file.find_attribute(&mut cursor, NtfsAttributeType::IndexRoot, None)
            .unwrap_err(),
        NtfsError::AttributeNotFound { .. }
    ));
    // A present type with a non-matching name errors.
    assert!(matches!(
        file.find_attribute(&mut cursor, NtfsAttributeType::Data, Some("nope"))
            .unwrap_err(),
        NtfsError::AttributeNotFound { .. }
    ));
}

#[test]
fn test_synthetic_record_data_matches_fixed_up_bytes() {
    // record_data() must return the post-fixup record bytes, which
    // begin with the FILE signature and reflect our header fields.
    let record = synthetic::file_record(0x0001, 9, 2, &[]);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    let data = file.record_data();
    assert_eq!(data.len(), synthetic::RECORD_SIZE);
    assert_eq!(&data[0..4], b"FILE");
    // sequence_number (offset 16) and hard_link_count (offset 18).
    assert_eq!(u16::from_le_bytes([data[16], data[17]]), 9);
    assert_eq!(u16::from_le_bytes([data[18], data[19]]), 2);
    // record_data is not an empty/single-byte leaked vec.
    assert!(data.len() > 1);
}

#[test]
fn test_recover_directory_slack() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let config = SlackRecoveryConfig {
        require_parent_match: false,
        ..SlackRecoveryConfig::default()
    };

    let recovered = root_dir
        .recover_directory_slack(&mut testfs1, config)
        .unwrap();

    // All recovered entries should have nonzero name_length and valid score.
    for entry in &recovered {
        assert!(entry.file_name().name_length() > 0);
        assert!(entry.validation().score() <= 6);
    }
}

#[test]
fn test_recover_directory_slack_large_index() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    // Navigate to "many_subdirs" which has INDEX_ALLOCATION with many INDX records.
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "many_subdirs")
        .unwrap()
        .unwrap();
    let many_subdirs = entry.to_file(&ntfs, &mut testfs1).unwrap();

    let config = SlackRecoveryConfig {
        require_parent_match: false,
        ..SlackRecoveryConfig::default()
    };

    let recovered = many_subdirs
        .recover_directory_slack(&mut testfs1, config)
        .unwrap();

    for entry in &recovered {
        assert!(entry.file_name().name_length() > 0);
        assert!(entry.validation().score() <= 6);
    }
}

#[test]
fn test_recover_directory_slack_not_a_directory() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();

    // $MFT (record 0) is a file, not a directory.
    let mft = ntfs
        .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT.as_u64())
        .unwrap();

    let config = SlackRecoveryConfig::default();
    let result = mft.recover_directory_slack(&mut testfs1, config);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        NtfsError::NotADirectory { .. }
    ));
}

#[test]
fn test_recover_directory_slack_empty_dir() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    // Navigate to edge-cases/empty-directory.
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "edge-cases")
        .unwrap()
        .unwrap();
    let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = edge_cases_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "empty-directory")
        .unwrap()
        .unwrap();
    let empty_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();
    assert!(empty_dir.is_directory());

    let config = SlackRecoveryConfig::default();
    let recovered = empty_dir
        .recover_directory_slack(&mut testfs1, config)
        .unwrap();

    // Empty directory should have no slack entries (or very few if any).
    // The key thing is it completes without error.
    for entry in &recovered {
        assert!(entry.file_name().name_length() > 0);
    }
}

#[test]
fn test_parent_reference_root_directory() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Root directory's parent is itself.
    let parent_ref = root_dir.parent_reference(&mut testfs1).unwrap();
    assert_eq!(
        parent_ref.file_record_number(),
        KnownNtfsFileRecordNumber::RootDirectory.as_u64()
    );
}

#[test]
fn test_parent_reference_system_file() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();

    // $MFT's parent should be the root directory (MFT 5).
    let mft = ntfs
        .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT.as_u64())
        .unwrap();
    let parent_ref = mft.parent_reference(&mut testfs1).unwrap();
    assert_eq!(
        parent_ref.file_record_number(),
        KnownNtfsFileRecordNumber::RootDirectory.as_u64()
    );
}

#[test]
fn test_name_pair_system_file() {
    // $MFT is a system file whose name conforms to 8.3 — it should be Win32AndDos.
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    let mft = ntfs
        .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT.as_u64())
        .unwrap();

    let pair = mft.name_pair(&mut testfs1, None).unwrap().unwrap();
    assert_eq!(pair.primary.name(), "$MFT");
    assert!(pair.primary.namespace().is_combined());
    assert!(pair.short_name.is_none());
}

#[test]
fn test_name_pair_root_directory() {
    // The root directory (.) should also have a Win32AndDos name.
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    let root = ntfs
        .file(
            &mut testfs1,
            KnownNtfsFileRecordNumber::RootDirectory.as_u64(),
        )
        .unwrap();

    let pair = root.name_pair(&mut testfs1, None).unwrap().unwrap();
    assert_eq!(pair.primary.name(), ".");
    assert!(pair.primary.namespace().is_combined());
    assert!(pair.short_name.is_none());
}
