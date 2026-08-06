use super::*;
use crate::test_helpers::*;
use alloc::vec;
use std::io::Cursor;

#[test]
fn drive_select_accessor() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();
    assert_eq!(exfat.drive_select(), 0x80);
}

#[test]
fn new_succeeds_on_valid_image() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();
    assert_eq!(exfat.bytes_per_sector(), 512);
    assert_eq!(exfat.cluster_size(), 512);
    assert_eq!(exfat.cluster_count(), 100);
    assert_eq!(exfat.number_of_fats(), 1);
}

#[test]
fn accessors_return_expected_values() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();

    assert_eq!(exfat.bytes_per_sector(), 512);
    assert_eq!(exfat.cluster_size(), 512);
    assert_eq!(exfat.cluster_count(), 100);
    assert_eq!(exfat.fat_offset(), 512); // sector 1 * 512
    assert_eq!(exfat.fat_length_bytes(), 512); // 1 sector * 512
    assert_eq!(exfat.cluster_heap_offset(), 3 * 512);
    assert_eq!(exfat.root_directory_cluster(), 2);
    assert_eq!(exfat.volume_serial_number(), 0xDEAD_BEEF);
    assert_eq!(exfat.filesystem_revision(), 0x0100);
    assert_eq!(exfat.filesystem_revision_major(), 1);
    assert_eq!(exfat.filesystem_revision_minor(), 0);
    assert_eq!(exfat.volume_flags(), VolumeFlags::empty());
    assert_eq!(exfat.percent_in_use(), 50);
    assert_eq!(exfat.number_of_fats(), 1);
}

#[test]
fn boot_checksum_valid_on_correct_image() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();
    assert!(exfat.boot_checksum_valid());
}

#[test]
fn boot_checksum_invalid_on_corrupted_image() {
    let mut image = make_image();
    // Corrupt sector 5 data (well within sectors 0-10)
    image[5 * 512] = 0xFF;
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();
    assert!(!exfat.boot_checksum_valid());
}

#[test]
fn new_rejects_all_zeros() {
    let image = vec![0u8; 512 * 20];
    let mut cursor = Cursor::new(image);
    assert!(ExFat::new(&mut cursor).is_err());
}

#[test]
fn backup_boot_sector_fallback() {
    let mut image = make_image();

    // Corrupt primary boot sector filesystem name.
    image[3] = b'X';

    // Write a valid boot sector at backup offset (sector 12).
    let backup_offset = 12 * 512;
    // Ensure the image is large enough.
    if image.len() < backup_offset + 512 {
        image.resize(backup_offset + 512 + 512 * 100, 0);
    }
    let valid_image = make_image();
    image[backup_offset..backup_offset + 512].copy_from_slice(&valid_image[..512]);

    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();
    assert_eq!(exfat.cluster_count(), 100);
}

#[test]
fn primary_error_returned_when_both_fail() {
    let mut image = vec![0u8; 512 * 20];
    // Give it a valid-ish filesystem name but bad signature.
    image[3..11].copy_from_slice(b"EXFAT   ");
    // boot_signature at 0x1FE is 0 -> invalid

    let mut cursor = Cursor::new(image);
    let err = ExFat::new(&mut cursor).unwrap_err();
    // Should be the primary error (InvalidBootSignature).
    assert!(
        matches!(err, ExFatError::InvalidBootSignature { .. }),
        "Expected InvalidBootSignature, got: {err:?}"
    );
}

#[test]
fn cluster_offset_first_cluster() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();

    // cluster 2 should be at cluster_heap_byte_offset
    let offset = exfat.cluster_offset(2).unwrap();
    assert_eq!(offset, exfat.cluster_heap_offset());
}

#[test]
fn cluster_offset_last_valid() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();

    // Last valid cluster = cluster_count + 1 = 101
    let offset = exfat.cluster_offset(101).unwrap();
    let expected = exfat.cluster_heap_offset() + (101u64 - 2) * u64::from(exfat.cluster_size());
    assert_eq!(offset, expected);
}

#[test]
fn cluster_offset_rejects_zero() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();

    let err = exfat.cluster_offset(0).unwrap_err();
    assert!(matches!(err, ExFatError::InvalidCluster { cluster: 0 }));
}

#[test]
fn cluster_offset_rejects_one() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();

    let err = exfat.cluster_offset(1).unwrap_err();
    assert!(matches!(err, ExFatError::InvalidCluster { cluster: 1 }));
}

#[test]
fn cluster_offset_rejects_out_of_range() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();

    // cluster_count + 2 = 102 is invalid
    let err = exfat.cluster_offset(102).unwrap_err();
    assert!(matches!(err, ExFatError::InvalidCluster { cluster: 102 }));
}

#[test]
fn volume_flags_dirty() {
    let mut image = make_image();
    // Set VolumeDirty flag (bit 1) at offset 0x6A
    image[0x6A] = 0x02;

    // Recompute checksum since we changed the image.
    // Note: bytes 106 (0x6A) and 107 (0x6B) are skipped in the
    // checksum, so the old checksum in sector 11 is still valid.
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();
    assert!(exfat.volume_flags().contains(VolumeFlags::VOLUME_DIRTY));
}

#[test]
fn load_metadata_bitmap_and_upcase() {
    let mut image = make_image();

    // Set up FAT: cluster 2 (root dir) -> EOC,
    // cluster 3 (bitmap data) -> EOC,
    // cluster 4 (upcase data) -> EOC
    let fat_base = 512; // sector 1
    // Cluster 2 = EOC
    image[fat_base + 2 * 4..fat_base + 2 * 4 + 4]
        .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // Cluster 3 = EOC
    image[fat_base + 3 * 4..fat_base + 3 * 4 + 4]
        .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // Cluster 4 = EOC
    image[fat_base + 4 * 4..fat_base + 4 * 4 + 4]
        .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    let cluster_heap = 3 * 512; // sector 3
    let root_dir_off = cluster_heap; // cluster 2

    // Write bitmap entry (0x81) at slot 0 of root dir
    image[root_dir_off] = 0x81;
    image[root_dir_off + 1] = 0x00; // first bitmap
    // first_cluster = 3 at offset 20
    image[root_dir_off + 20..root_dir_off + 24].copy_from_slice(&3u32.to_le_bytes());
    // data_length = 13 bytes
    image[root_dir_off + 24..root_dir_off + 32].copy_from_slice(&13u64.to_le_bytes());

    // Write bitmap data in cluster 3
    let bitmap_cluster_off = cluster_heap + 512; // cluster 3
    image[bitmap_cluster_off] = 0xFF;
    image[bitmap_cluster_off + 1] = 0x03;

    // Build compressed identity upcase table
    let mut upcase_compressed: Vec<u8> = Vec::new();
    // Skip 0x8000 entries, then skip 0x8000 more (total 65536)
    upcase_compressed.extend_from_slice(&0xFFFFu16.to_le_bytes());
    upcase_compressed.extend_from_slice(&0x8000u16.to_le_bytes());
    upcase_compressed.extend_from_slice(&0xFFFFu16.to_le_bytes());
    upcase_compressed.extend_from_slice(&0x8000u16.to_le_bytes());

    let upcase_checksum = {
        let mut cs: u32 = 0;
        for &byte in &upcase_compressed {
            let bit0 = if cs & 1 != 0 { 0x8000_0000u32 } else { 0 };
            cs = bit0.wrapping_add(cs >> 1).wrapping_add(u32::from(byte));
        }
        cs
    };

    // Write upcase entry (0x82) at slot 1 of root dir
    let upcase_entry_off = root_dir_off + 32;
    image[upcase_entry_off] = 0x82;
    // table_checksum at offset 4
    image[upcase_entry_off + 4..upcase_entry_off + 8]
        .copy_from_slice(&upcase_checksum.to_le_bytes());
    // first_cluster = 4 at offset 20
    image[upcase_entry_off + 20..upcase_entry_off + 24].copy_from_slice(&4u32.to_le_bytes());
    // data_length
    image[upcase_entry_off + 24..upcase_entry_off + 32]
        .copy_from_slice(
            &u64::try_from(upcase_compressed.len())
                .expect("test table length fits u64")
                .to_le_bytes(),
        );

    // Write upcase data in cluster 4
    let upcase_cluster_off = cluster_heap + 2 * 512;
    image[upcase_cluster_off..upcase_cluster_off + upcase_compressed.len()]
        .copy_from_slice(&upcase_compressed);

    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();

    // Before load_metadata, bitmap and upcase should be None
    assert!(exfat.bitmap().is_none());
    assert!(exfat.upcase_table().is_none());

    exfat.load_metadata(&mut cursor).unwrap();

    // Bitmap should be loaded
    let bitmap = exfat.bitmap().unwrap();
    assert!(bitmap.is_allocated(2).unwrap()); // byte 0 bit 0
    assert!(!bitmap.is_allocated(12).unwrap()); // byte 1 bit 2

    // Upcase table should be loaded (all identity)
    let upcase = exfat.upcase_table().unwrap();
    assert_eq!(upcase.upcase(0x0041), 0x0041); // 'A' -> 'A'
    assert_eq!(upcase.upcase(0x0061), 0x0061); // identity table
}

#[test]
fn load_metadata_missing_bitmap_returns_error() {
    let mut image = make_image();
    let fat_base = 512;
    image[fat_base + 2 * 4..fat_base + 2 * 4 + 4]
        .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // Root dir is empty (all zeros = end-of-directory)
    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();

    let err = exfat.load_metadata(&mut cursor).unwrap_err();
    assert!(matches!(err, ExFatError::BitmapNotFound));
}

/// Sets up FAT entries, bitmap entry+data, and upcase entry+data
/// in an image. Returns the next free root dir slot offset.
fn setup_metadata(image: &mut [u8]) -> usize {
    use crate::dir_entry::*;

    let fat_base = 512;
    let cluster_heap = 3 * 512;
    let root_off = cluster_heap;

    // FAT: cluster 2-4 -> EOC
    for c in 2..=4u32 {
        let off = fat_base + usize::try_from(c).expect("test cluster fits usize") * 4;
        image[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }

    // Bitmap entry (0x81) at slot 0
    image[root_off] = ENTRY_TYPE_BITMAP;
    image[root_off + 20..root_off + 24].copy_from_slice(&3u32.to_le_bytes());
    image[root_off + 24..root_off + 32].copy_from_slice(&13u64.to_le_bytes());

    // Bitmap data in cluster 3
    image[cluster_heap + 512] = 0xFF;

    // Compressed identity upcase table (two 0x8000 skips = 65536 total)
    let mut upcase_data = Vec::new();
    upcase_data.extend_from_slice(&0xFFFFu16.to_le_bytes());
    upcase_data.extend_from_slice(&0x8000u16.to_le_bytes());
    upcase_data.extend_from_slice(&0xFFFFu16.to_le_bytes());
    upcase_data.extend_from_slice(&0x8000u16.to_le_bytes());
    let upcase_cs = {
        let mut cs: u32 = 0;
        for &b in &upcase_data {
            let bit0 = if cs & 1 != 0 { 0x8000_0000u32 } else { 0 };
            cs = bit0.wrapping_add(cs >> 1).wrapping_add(u32::from(b));
        }
        cs
    };

    // Upcase entry (0x82) at slot 1
    let slot1 = root_off + DIR_ENTRY_SIZE;
    image[slot1] = ENTRY_TYPE_UPCASE;
    image[slot1 + 4..slot1 + 8].copy_from_slice(&upcase_cs.to_le_bytes());
    image[slot1 + 20..slot1 + 24].copy_from_slice(&4u32.to_le_bytes());
    image[slot1 + 24..slot1 + 32].copy_from_slice(
        &u64::try_from(upcase_data.len())
            .expect("test table length fits u64")
            .to_le_bytes(),
    );

    // Upcase data in cluster 4
    let uc_off = cluster_heap + 2 * 512;
    image[uc_off..uc_off + upcase_data.len()].copy_from_slice(&upcase_data);

    // Return offset of slot 2 (first free root dir entry)
    root_off + 2 * DIR_ENTRY_SIZE
}

/// Writes a file entry set (0x85 + 0xC0 + 0xC1) at the given
/// offset in the image. Uses the identity upcase table for
/// `NameHash` (name must already be uppercase or not use a-z).
fn write_file_entry(
    image: &mut [u8],
    offset: usize,
    name: &str,
    first_cluster: u32,
    data_length: u64,
    is_directory: bool,
) {
    use crate::dir_entry::*;
    use crate::entry_set::compute_set_checksum;
    use crate::upcase::compute_name_hash;

    let utf16: Vec<u16> = name.encode_utf16().collect();
    // Identity upcase table => name_hash of already-uppercase name
    let name_hash = compute_name_hash(&utf16);

    let mut entry_bytes = vec![0u8; 3 * DIR_ENTRY_SIZE];
    // Primary (0x85)
    entry_bytes[0] = ENTRY_TYPE_FILE;
    entry_bytes[1] = 2; // secondary_count
    if is_directory {
        entry_bytes[4] = 0x10; // DIRECTORY attribute
    } else {
        entry_bytes[4] = 0x20; // ARCHIVE attribute
    }
    // Stream (0xC0)
    entry_bytes[32] = ENTRY_TYPE_STREAM;
    entry_bytes[33] = 0x01;
    entry_bytes[35] =
        u8::try_from(utf16.len()).expect("test name fits the exFAT length field");
    entry_bytes[36..38].copy_from_slice(&name_hash.to_le_bytes());
    entry_bytes[52..56].copy_from_slice(&first_cluster.to_le_bytes());
    entry_bytes[56..64].copy_from_slice(&data_length.to_le_bytes());
    entry_bytes[40..48].copy_from_slice(&data_length.to_le_bytes());
    // Name (0xC1)
    entry_bytes[64] = ENTRY_TYPE_NAME;
    for (i, &ch) in utf16.iter().enumerate() {
        let [lo, hi] = ch.to_le_bytes();
        entry_bytes[66 + i * 2] = lo;
        entry_bytes[66 + i * 2 + 1] = hi;
    }
    // Checksum
    let cs = compute_set_checksum(&entry_bytes);
    entry_bytes[2..4].copy_from_slice(&cs.to_le_bytes());

    image[offset..offset + entry_bytes.len()].copy_from_slice(&entry_bytes);
}

#[test]
fn open_file_in_root_directory() {
    let mut image = make_image();
    let slot2 = setup_metadata(&mut image);

    write_file_entry(&mut image, slot2, "README.TXT", 10, 100, false);

    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let es = exfat.open(&mut cursor, "README.TXT").unwrap();
    assert_eq!(es.name_string(), "README.TXT");
    assert_eq!(es.first_cluster(), 10);
}

#[test]
fn open_not_found() {
    let mut image = make_image();
    setup_metadata(&mut image);

    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    assert!(matches!(
        exfat.open(&mut cursor, "nonexistent.txt"),
        Err(ExFatError::NotFound)
    ));
}

#[test]
fn open_empty_path_not_found() {
    let mut image = make_image();
    setup_metadata(&mut image);

    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    assert!(matches!(
        exfat.open(&mut cursor, ""),
        Err(ExFatError::NotFound)
    ));
}

#[test]
fn open_without_metadata_returns_error() {
    let image = make_image();
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();

    assert!(matches!(
        exfat.open(&mut cursor, "anything"),
        Err(ExFatError::MetadataNotLoaded)
    ));
}

#[test]
fn open_multi_component_path() {
    let mut image = make_image();
    let slot2 = setup_metadata(&mut image);

    // Add DOCS/ directory pointing to cluster 5
    write_file_entry(&mut image, slot2, "DOCS", 5, 0, true);

    // FAT: cluster 5 -> EOC
    let fat_base = 512;
    let off = fat_base + 5 * 4;
    image[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // Write README.TXT in cluster 5 (DOCS directory)
    let cluster5_off = 3 * 512 + (5 - 2) * 512;
    write_file_entry(&mut image, cluster5_off, "README.TXT", 10, 100, false);

    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let es = exfat.open(&mut cursor, "DOCS/README.TXT").unwrap();
    assert_eq!(es.name_string(), "README.TXT");
    assert_eq!(es.first_cluster(), 10);
}

/// Pins `filesystem_revision_major` and `filesystem_revision_minor`
/// to actual u16 byte extraction. Default `make_image()` produces
/// revision 0x0100 (major=1, minor=0) which collides with the
/// `→ 1` and `→ 0` accessor-constant mutations. Using revision
/// 0x0001 (major=0, minor=1) makes both mutations observably
/// wrong.
#[test]
fn filesystem_revision_accessors_extract_high_and_low_bytes() {
    let mut image = make_image();
    // Revision 0x0001 (major=0, minor=1). Major must be 0 or 1
    // for validate_boot_sector to accept it.
    image[0x68..0x6A].copy_from_slice(&0x0001u16.to_le_bytes());
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();
    assert_eq!(exfat.filesystem_revision_major(), 0);
    assert_eq!(exfat.filesystem_revision_minor(), 1);
}

/// `number_of_fats` accessor must return the stored value
/// (1 or 2 per spec). Default image has 1 FAT; this test pins
/// the 2-FAT case and kills `→ 1` accessor-constant mutation.
#[test]
fn number_of_fats_returns_two_for_two_fat_image() {
    let mut image = make_image();
    image[0x6E] = 2; // NumberOfFats byte
    let mut cursor = Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();
    assert_eq!(exfat.number_of_fats(), 2);
}

/// `load_metadata` computes `entries_per_cluster = cluster_size /
/// DIR_ENTRY_SIZE` to bound the per-cluster slot scan. Mutating
/// `/` to `*` blows the bound to `cluster_size * DIR_ENTRY_SIZE`
/// (16384 here), so the inner loop keeps reading 32-byte slots
/// far past the cluster boundary and into uninitialised image
/// regions until it hits EOF and errors. By stamping a non-END
/// entry-type byte (0xAB) at every slot byte-0 position past
/// the bitmap+upcase entries, no `ENTRY_TYPE_END` short-circuit
/// fires before EOF.
#[test]
fn load_metadata_uses_cluster_size_divided_by_entry_size() {
    let mut image = make_image();
    let _ = setup_metadata(&mut image);

    let cluster_heap = 3 * 512;
    // Slot byte-0 positions are at cluster_heap + slot_idx * 32.
    // Preserve byte-0 of cluster 3 (bitmap data, set to 0xFF by
    // setup_metadata) and cluster 4 (upcase data, starts with
    // 0xFF marker). All other byte-0 positions in 2..1600 must
    // be non-zero so the mutated loop never finds ENTRY_TYPE_END.
    let bitmap_data_off = cluster_heap + 512;
    let upcase_data_off = cluster_heap + 2 * 512;
    for slot_idx in 2..1600usize {
        let off = cluster_heap + slot_idx * 32;
        if off >= image.len() {
            break;
        }
        if off == bitmap_data_off || off == upcase_data_off {
            continue;
        }
        image[off] = 0xAB;
    }

    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    // Original `/`: scans 16 slots in cluster 2 (bitmap@0,
    // upcase@1, slots 2..15 are 0xAB → skip), exits loop, no
    // more clusters, returns Ok.
    // Mutated `*`: scans 16384 slots, eventually reads past EOF
    // (image is only 52736 bytes) → returns Err.
    exfat
        .load_metadata(&mut cursor)
        .expect("original entries_per_cluster bound stops at slot 16");
}

/// `read_data_from_cluster`'s `while bytes_read < len` loop must
/// stop the moment the declared data length is satisfied — any
/// extra iteration may step the cluster iterator onto invalid
/// FAT entries that follow the data. Setting up FAT[3]→5 and
/// FAT[5]=`cluster_count+99` (out of range) means an unwanted
/// extra step yields `InvalidCluster`, which the mutation
/// `< → <=` surfaces but the correct `<` avoids.
#[test]
fn read_data_from_cluster_does_not_advance_past_completed_data() {
    let mut image = make_image();
    let _ = setup_metadata(&mut image);
    // FAT[3] -> 5 (extra cluster); FAT[5] = 200 (well beyond
    // cluster_count = 100, so InvalidCluster).
    let fat_base = 512;
    image[fat_base + 3 * 4..fat_base + 3 * 4 + 4].copy_from_slice(&5u32.to_le_bytes());
    image[fat_base + 5 * 4..fat_base + 5 * 4 + 4].copy_from_slice(&200u32.to_le_bytes());

    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat
        .load_metadata(&mut cursor)
        .expect("bitmap data is 13 bytes — fits in one cluster, no extra step needed");
}

/// The `open` path splitter filters out empty components and
/// `"."` via `!s.is_empty() && *s != "."`. Mutating `&&` to
/// `||` keeps both empty strings and `"."` as path components.
/// Even with a file literally named `"."` in the root, the
/// original implementation returns `NotFound` for path `"."`
/// because no real component remains after filtering. The
/// mutation would instead resolve the dot entry and return it.
#[test]
fn open_dot_path_returns_not_found_even_when_dot_file_exists() {
    let mut image = make_image();
    let slot2 = setup_metadata(&mut image);
    write_file_entry(&mut image, slot2, ".", 10, 100, false);

    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    assert!(matches!(
        exfat.open(&mut cursor, "."),
        Err(ExFatError::NotFound)
    ));
}

#[test]
fn open_not_a_directory_error() {
    let mut image = make_image();
    let slot2 = setup_metadata(&mut image);

    // Add a regular file (not a directory)
    write_file_entry(&mut image, slot2, "FILE.TXT", 10, 100, false);

    let mut cursor = Cursor::new(image);
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    // Try to traverse through a file as if it were a directory
    assert!(matches!(
        exfat.open(&mut cursor, "FILE.TXT/sub.txt"),
        Err(ExFatError::NotADirectory)
    ));
}
