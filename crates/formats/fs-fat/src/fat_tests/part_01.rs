use super::*;
use alloc::string::ToString;

// Tests for FatType::from_clusters with boundary values
// FAT12: < 4085 clusters (0x0FF5)
// FAT16: >= 4085 and < 65525 clusters (0xFFF5)
// FAT32: >= 65525 clusters

#[test]
fn test_fat_type_from_clusters_fat12() {
    // FAT12 for cluster counts below FAT16_MIN_CLUSTERS (4085)
    assert_eq!(FatType::from_clusters(0), FatType::Fat12);
    assert_eq!(FatType::from_clusters(1), FatType::Fat12);
    assert_eq!(FatType::from_clusters(100), FatType::Fat12);
    assert_eq!(FatType::from_clusters(4084), FatType::Fat12);
}

#[test]
fn test_fat_type_from_clusters_fat12_fat16_boundary() {
    // Boundary: 4084 -> FAT12, 4085 -> FAT16
    assert_eq!(FatType::from_clusters(4084), FatType::Fat12);
    assert_eq!(FatType::from_clusters(4085), FatType::Fat16);
}

#[test]
fn test_fat_type_from_clusters_fat16() {
    // FAT16 for cluster counts >= 4085 and < 65525
    assert_eq!(FatType::from_clusters(4085), FatType::Fat16);
    assert_eq!(FatType::from_clusters(10000), FatType::Fat16);
    assert_eq!(FatType::from_clusters(65524), FatType::Fat16);
}

#[test]
fn test_fat_type_from_clusters_fat16_fat32_boundary() {
    // Boundary: 65524 -> FAT16, 65525 -> FAT32
    assert_eq!(FatType::from_clusters(65524), FatType::Fat16);
    assert_eq!(FatType::from_clusters(65525), FatType::Fat32);
}

#[test]
fn test_fat_type_from_clusters_fat32() {
    // FAT32 for cluster counts >= 65525
    assert_eq!(FatType::from_clusters(65525), FatType::Fat32);
    assert_eq!(FatType::from_clusters(100_000), FatType::Fat32);
    assert_eq!(FatType::from_clusters(1_000_000), FatType::Fat32);
    assert_eq!(FatType::from_clusters(u32::MAX), FatType::Fat32);
}

// Tests for FatType Display trait
#[test]
fn test_fat_type_display_fat12() {
    assert_eq!(FatType::Fat12.to_string(), "FAT12");
}

#[test]
fn test_fat_type_display_fat16() {
    assert_eq!(FatType::Fat16.to_string(), "FAT16");
}

#[test]
fn test_fat_type_display_fat32() {
    assert_eq!(FatType::Fat32.to_string(), "FAT32");
}

// Test FatType equality and copy traits
#[test]
fn test_fat_type_equality() {
    assert_eq!(FatType::Fat12, FatType::Fat12);
    assert_eq!(FatType::Fat16, FatType::Fat16);
    assert_eq!(FatType::Fat32, FatType::Fat32);

    assert_ne!(FatType::Fat12, FatType::Fat16);
    assert_ne!(FatType::Fat16, FatType::Fat32);
    assert_ne!(FatType::Fat12, FatType::Fat32);
}

#[test]
fn test_fat_type_copy() {
    let original = FatType::Fat16;
    let copy = original;
    assert_eq!(original, copy);
}

#[test]
fn test_fat_type_debug() {
    // Debug representation
    assert_eq!(format!("{:?}", FatType::Fat12), "Fat12");
    assert_eq!(format!("{:?}", FatType::Fat16), "Fat16");
    assert_eq!(format!("{:?}", FatType::Fat32), "Fat32");
}

// Test the constants
#[test]
fn test_fat_type_constants() {
    // Verify the constant values match expected FAT specification
    assert_eq!(FatType::FAT16_MIN_CLUSTERS, 0x0FF5); // 4085
    assert_eq!(FatType::FAT32_MIN_CLUSTERS, 0xFFF5); // 65525
}

#[test]
fn test_fat_new_bitlocker_encrypted() {
    let mut buf = [0u8; BOOT_SECTOR_SIZE];
    buf[510] = 0x55;
    buf[511] = 0xAA;
    buf[3..11].copy_from_slice(b"-FVE-FS-");
    buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    buf[0x0D] = 8;

    let mut cursor = fsmnt_testkit::Cursor::new(&buf[..]);
    let err = Fat::new(&mut cursor).unwrap_err();
    let FatError::BitLockerEncrypted { oem_id } = err else {
        panic!("Expected BitLockerEncrypted, got {err}");
    };
    assert_eq!(&oem_id, b"-FVE-FS-");
}

#[test]
fn test_fat_new_bitlocker_display() {
    let err = FatError::BitLockerEncrypted {
        oem_id: *b"-FVE-FS-",
    };
    let msg = err.to_string();
    assert!(msg.contains("BitLocker"), "should mention BitLocker: {msg}");
    assert!(msg.contains("Decrypt"), "should suggest decryption: {msg}");
}

// ----------------------------------------------------------------------
// Image builders for end-to-end FAT tests (FAT12, FAT16, FAT32).
// Each fixture uses concrete, distinct values for every BPB field so
// getter mutants (`-> u32 with 0/1`, etc.) become observable.
// ----------------------------------------------------------------------

use alloc::vec;
use alloc::vec::Vec;
use fsmnt_testkit::Cursor;

/// 1.44 MB floppy-style FAT12: 2880 sectors × 512 B, spc=1, 1 reserved
/// sector, 2 FATs × 9 sectors, 224 root entries = 14 root sectors.
/// First data sector = 1 + 2*9 + 14 = 33. Data sectors = 2880-33 = 2847.
/// Clusters = 2847 → FAT12.
fn build_fat12_image() -> Vec<u8> {
    // Image needs to cover up to cluster 5 (data starts at sector 33;
    // we use 40 sectors to be safe).
    let mut img = vec![0u8; 40 * 512];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSDOS5.0");
    img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    img[0x0D] = 1; // spc
    img[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes()); // reserved
    img[0x10] = 2; // num_fats
    img[0x11..0x13].copy_from_slice(&224u16.to_le_bytes());
    img[0x13..0x15].copy_from_slice(&2880u16.to_le_bytes());
    img[0x15] = 0xF0; // 1.44 MB floppy
    img[0x16..0x18].copy_from_slice(&9u16.to_le_bytes()); // spf16
    img[0x18..0x1A].copy_from_slice(&18u16.to_le_bytes());
    img[0x1A..0x1C].copy_from_slice(&2u16.to_le_bytes());
    img[0x24] = 0x00;
    img[0x26] = 0x29;
    img[0x27..0x2B].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    img[0x2B..0x36].copy_from_slice(b"VOLUME12   ");
    img[0x36..0x3E].copy_from_slice(b"FAT12   ");
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    // FAT[0..1] reserved (12-bit packed across 3 bytes per entry pair):
    //   FAT[0] = 0xFF0 (media descriptor 0xF0 + 0xFFFs)
    //   FAT[1] = 0xFFF (EOC marker)
    // Bytes 0..3 of FAT region encode (FAT[0], FAT[1]) = packed.
    // Use a simple chain: FAT[2] = 3 (cluster 2 → cluster 3),
    // FAT[3] = EOC (0xFFF).
    let f = 0x200;
    // 12-bit entries: bytes [F0 FF FF | 03 F0 FF | ...]
    // FAT[0] low 8 = 0xF0, FAT[0] high 4 + FAT[1] low 4 = 0xF, FAT[1] high 8 = 0xFF
    img[f] = 0xF0;
    img[f + 1] = 0xFF;
    img[f + 2] = 0xFF;
    // FAT[2] = 0x003 (next = cluster 3): byte[3] = 0x03,
    // byte[4] low 4 = 0; FAT[3] = 0xFFF: byte[4] high 4 = 0xF, byte[5] = 0xFF
    img[f + 3] = 0x03;
    img[f + 4] = 0xF0;
    img[f + 5] = 0xFF;
    img
}

/// FAT16 image with 4084 → 4085+ clusters (depending on caller).
/// `total_sectors=4104`, spc=1, reserved=1, 1 FAT × 17 sectors,
/// 16 root entries = 1 sector. `first_data=1+17+1=19`. Data=4085.
fn build_fat16_image() -> Vec<u8> {
    let mut img = vec![0u8; 4104 * 512];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSDOS5.0");
    img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    img[0x0D] = 1;
    img[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes());
    img[0x10] = 1;
    img[0x11..0x13].copy_from_slice(&16u16.to_le_bytes());
    img[0x13..0x15].copy_from_slice(&4104u16.to_le_bytes());
    img[0x15] = 0xF8;
    img[0x16..0x18].copy_from_slice(&17u16.to_le_bytes());
    img[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
    img[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
    img[0x24] = 0x80;
    img[0x26] = 0x29;
    img[0x27..0x2B].copy_from_slice(&0xCAFE_F00Du32.to_le_bytes());
    img[0x2B..0x36].copy_from_slice(b"VOLUME16   ");
    img[0x36..0x3E].copy_from_slice(b"FAT16   ");
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    // FAT[0..1] reserved, FAT[2] = 3, FAT[3] = 0xFFFF (EOC).
    let f = 0x200;
    img[f..f + 2].copy_from_slice(&0xFFF8u16.to_le_bytes());
    img[f + 2..f + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
    img[f + 4..f + 6].copy_from_slice(&3u16.to_le_bytes()); // FAT[2] -> 3
    img[f + 6..f + 8].copy_from_slice(&0xFFFFu16.to_le_bytes()); // FAT[3] EOC
    img
}

/// FAT32 image: spc=1, 32 reserved, 1 FAT × 512 sectors, no root entries,
/// `total_sectors_32=66069` → data sectors=65525 → exactly FAT32 threshold.
fn build_fat32_image() -> Vec<u8> {
    let mut img = vec![0u8; 66069 * 512];
    img[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    img[3..11].copy_from_slice(b"MSDOS5.0");
    img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    img[0x0D] = 1;
    img[0x0E..0x10].copy_from_slice(&32u16.to_le_bytes());
    img[0x10] = 1;
    img[0x15] = 0xF8;
    img[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
    img[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
    img[0x20..0x24].copy_from_slice(&66069u32.to_le_bytes());
    img[0x24..0x28].copy_from_slice(&512u32.to_le_bytes()); // sectors_per_fat_32
    img[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes()); // root_cluster=2
    img[0x30..0x32].copy_from_slice(&0xFFFFu16.to_le_bytes()); // no FSInfo
    img[0x40] = 0x80;
    img[0x42] = 0x29;
    img[0x43..0x47].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    img[0x47..0x52].copy_from_slice(b"VOLUME32   ");
    img[0x52..0x5A].copy_from_slice(b"FAT32   ");
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    // FAT[0..2] reserved, FAT[2] = 3, FAT[3] = EOC.
    let f = 32 * 512;
    img[f..f + 4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes()); // FAT[0]
    img[f + 4..f + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[1]
    img[f + 8..f + 12].copy_from_slice(&3u32.to_le_bytes()); // FAT[2] -> 3
    img[f + 12..f + 16].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[3] EOC
    img
}

// ----------------------------------------------------------------------
// Getter tests: assert each value at the exact level returned by the
// crate API. Catches `-> uN with 0/1` mutants for sector_size, size,
// sectors_per_fat, fat_start_sector, root_dir_sectors,
// first_data_sector, total_clusters, serial_number, etc.
// ----------------------------------------------------------------------

#[test]
fn fat16_getters_expose_bpb_derived_values() {
    let img = build_fat16_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("fat16 image parses");

    assert_eq!(fat.fat_type(), FatType::Fat16);
    assert_eq!(fat.cluster_size(), 512);
    assert_eq!(fat.sector_size(), 512);
    assert_eq!(fat.size(), 4104 * 512);
    assert_eq!(fat.sectors_per_fat(), 17);
    assert_eq!(fat.fat_start_sector(), 1);
    assert_eq!(fat.root_dir_sectors(), 1); // (16*32 + 511)/512 = 1
    assert_eq!(fat.first_data_sector(), 19);
    assert_eq!(fat.total_clusters(), 4085);
    assert_eq!(fat.root_cluster(), 0); // FAT16 has no root cluster
    assert_eq!(fat.serial_number(), 0xCAFE_F00D);

    // FAT12 boundary: 4085 → FAT16 (just into FAT16 territory).
    let img12 = build_fat12_image();
    let mut cur12 = Cursor::new(img12);
    let fat12 = Fat::new(&mut cur12).expect("fat12 image parses");
    assert_eq!(fat12.fat_type(), FatType::Fat12);
    assert_eq!(fat12.serial_number(), 0xDEAD_BEEF);
    // 2880-33 = 2847 clusters → FAT12.
    assert_eq!(fat12.total_clusters(), 2847);

    let img32 = build_fat32_image();
    let mut cur32 = Cursor::new(img32);
    let fat32 = Fat::new(&mut cur32).expect("fat32 image parses");
    assert_eq!(fat32.fat_type(), FatType::Fat32);
    assert_eq!(fat32.root_cluster(), 2);
    assert_eq!(fat32.sectors_per_fat(), 512);
    assert_eq!(fat32.fat_start_sector(), 32);
    assert_eq!(fat32.root_dir_sectors(), 0);
    assert_eq!(fat32.first_data_sector(), 32 + 512);
    assert_eq!(fat32.serial_number(), 0x1234_5678);
}

#[test]
fn cluster_offset_rejects_reserved_and_oob_clusters() {
    // Catches `> with >=/==` at line 388 and `>= with <` etc. on the
    // upper bound: cluster 0, 1 are reserved (always invalid);
    // total_clusters + 1 is the highest valid index;
    // total_clusters + 2 must reject.
    let img = build_fat16_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");

    assert!(matches!(
        fat.cluster_offset(0),
        Err(FatError::InvalidCluster { cluster: 0 })
    ));
    assert!(matches!(
        fat.cluster_offset(1),
        Err(FatError::InvalidCluster { cluster: 1 })
    ));
    // Cluster 2 = first data sector.
    let offset_2 = fat.cluster_offset(2).expect("cluster 2 valid");
    assert_eq!(offset_2, 19 * 512);
    // Cluster 3 = sector 20.
    let offset_3 = fat.cluster_offset(3).expect("cluster 3 valid");
    assert_eq!(offset_3, 20 * 512);
    // Highest valid cluster: total_clusters + 1 = 4086.
    assert!(fat.cluster_offset(4086).is_ok());
    // One past = invalid.
    assert!(matches!(
        fat.cluster_offset(4087),
        Err(FatError::InvalidCluster { cluster: 4087 })
    ));
}

#[test]
fn root_dir_offset_and_size_for_fat16() {
    // Pins `* with +` on root_dir_size and the FAT16 root location.
    let img = build_fat16_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");

    // FAT16 root sits at (first_data_sector - root_dir_sectors) =
    // 19 - 1 = 18, in byte terms 18 * 512 = 9216.
    assert_eq!(fat.root_dir_offset(), 18 * 512);
    // root_dir_size = root_dir_sectors * sector_size = 1 * 512 = 512.
    assert_eq!(fat.root_dir_size(), 512);
}

// ----------------------------------------------------------------------
// next_cluster_fat12 / 16 / 32 — anchor the FAT table indexing math
// and the end-of-chain / bad-cluster markers.
// ----------------------------------------------------------------------

#[test]
fn next_cluster_fat16_follows_chain_and_returns_none_at_eoc() {
    let img = build_fat16_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");

    // FAT[2] → 3, FAT[3] → EOC (0xFFFF).
    let next2 = fat.next_cluster(&mut cur, 2).expect("read FAT[2]");
    assert_eq!(next2, Some(3));
    let next3 = fat.next_cluster(&mut cur, 3).expect("read FAT[3]");
    assert_eq!(next3, None);
}

#[test]
fn next_cluster_fat16_reports_bad_cluster_marker() {
    // FAT[2] = 0xFFF7 means cluster 2 is BAD.
    let mut img = build_fat16_image();
    let f = 0x200;
    img[f + 4..f + 6].copy_from_slice(&0xFFF7u16.to_le_bytes());

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let err = fat.next_cluster(&mut cur, 2).unwrap_err();
    assert!(matches!(err, FatError::BadCluster { cluster: 2 }));
}

#[test]
fn next_cluster_fat12_follows_chain_and_returns_none_at_eoc() {
    let img = build_fat12_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");

    // FAT12 stores entries packed 1.5 bytes each:
    //   even cluster N: low 12 bits of u16 at offset N*1.5
    //   odd cluster N:  high 12 bits of u16 at offset N*1.5
    // FAT[2] (even) = 0x003 (next = 3); FAT[3] (odd) = 0xFFF (EOC).
    let next2 = fat.next_cluster(&mut cur, 2).expect("read FAT[2]");
    assert_eq!(next2, Some(3));
    let next3 = fat.next_cluster(&mut cur, 3).expect("read FAT[3]");
    assert_eq!(next3, None);
}

#[test]
fn next_cluster_fat32_masks_high_4_bits_and_follows_chain() {
    let mut img = build_fat32_image();
    // Set FAT[2] = 0xF000_0003 — the high 4 bits should be masked off
    // so the next cluster is 3, not 0xF000_0003.
    let f = 32 * 512;
    img[f + 8..f + 12].copy_from_slice(&0xF000_0003u32.to_le_bytes());

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let next2 = fat.next_cluster(&mut cur, 2).expect("read FAT[2]");
    assert_eq!(next2, Some(3));
    let next3 = fat.next_cluster(&mut cur, 3).expect("read FAT[3]");
    assert_eq!(next3, None);
}

#[test]
fn next_cluster_fat32_reports_bad_cluster_marker() {
    let mut img = build_fat32_image();
    let f = 32 * 512;
    img[f + 8..f + 12].copy_from_slice(&0x0FFF_FFF7u32.to_le_bytes());

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let err = fat.next_cluster(&mut cur, 2).unwrap_err();
    assert!(matches!(err, FatError::BadCluster { cluster: 2 }));
}

#[test]
fn next_cluster_rejects_reserved_and_out_of_range_clusters() {
    // Catches `|| -> &&` and `> with ==/>=` at line 424 plus the
    // wholesale `Ok(None)/Some(0)/Some(1)` return mutants on the
    // generic `next_cluster` dispatcher.
    let img = build_fat16_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");

    assert!(matches!(
        fat.next_cluster(&mut cur, 0),
        Err(FatError::InvalidCluster { cluster: 0 })
    ));
    assert!(matches!(
        fat.next_cluster(&mut cur, 1),
        Err(FatError::InvalidCluster { cluster: 1 })
    ));
    // total_clusters + 1 = 4086 is valid (highest data cluster).
    // total_clusters + 2 = 4087 is out of range.
    assert!(matches!(
        fat.next_cluster(&mut cur, 4087),
        Err(FatError::InvalidCluster { cluster: 4087 })
    ));
}

// ----------------------------------------------------------------------
// volume_name — locate the VOLUME_ID entry in the root directory.
// ----------------------------------------------------------------------

#[test]
fn volume_name_returns_trimmed_label_from_root() {
    // Build an image with a VOLUME_ID entry whose label has trailing
    // spaces. The returned String must strip the trailing spaces
    // (anchors `+ with -/*` arithmetic on the trim-end position).
    let mut img = build_fat16_image();
    // FAT16: first_data_sector = 19, root_dir_sectors = 1, so
    // root_dir_offset = (19 - 1) * 512 = 9216 (sector 18).
    let r = 18 * 512;
    let mut name = *b"MYDISK     ";
    // Pad: MYDISK followed by spaces.
    img[r..r + 11].copy_from_slice(&name);
    // Attributes = VOLUME_ID (0x08).
    img[r + 0x0B] = 0x08;
    // Slot 1: end marker (already zero).

    // Silence the unused-var warning.
    let _ = &mut name;

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let label = fat.volume_name(&mut cur).expect("read");
    assert_eq!(label.as_deref(), Some("MYDISK"));
}

#[test]
fn volume_name_returns_none_when_no_volume_id_entry() {
    // Catches `-> Ok(Some(...))` mutants on the volume_name return
    // path: with no VOLUME_ID entry in the root, the function must
    // return Ok(None).
    let mut img = build_fat16_image();
    let r = 18 * 512;
    // Slot 0: regular file (no VOLUME_ID).
    img[r..r + 11].copy_from_slice(b"DATA    TXT");
    img[r + 0x0B] = 0x20; // ARCHIVE
    // Slot 1: end marker.

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let label = fat.volume_name(&mut cur).expect("read");
    assert_eq!(label, None);
}

// ----------------------------------------------------------------------
// Fat::open — path traversal with `..`, files, missing entries.
// ----------------------------------------------------------------------

#[test]
fn open_returns_root_for_empty_or_slash_path() {
    // Catches the wholesale `Ok(...)` return mutants and the early
    // `components.peek().is_none()` branch.
    let img = build_fat16_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");

    let root = fat.open(&mut cur, "").expect("empty path opens root");
    assert!(root.is_directory());
    assert_eq!(root.first_cluster(), None);

    let slash = fat.open(&mut cur, "/").expect("slash opens root");
    assert!(slash.is_directory());

    // Backslash also normalizes.
    let bslash = fat.open(&mut cur, "\\").expect("backslash opens root");
    assert!(bslash.is_directory());
}

#[test]
fn open_not_found_returns_error() {
    // Catches `== with !=` boundary mutations in the open loop's
    // entry-lookup path.
    let img = build_fat16_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");

    let err = fat.open(&mut cur, "/MISSING.TXT").unwrap_err();
    assert!(matches!(err, FatError::NotFound));
}

#[test]
fn open_intermediate_non_directory_returns_not_a_directory() {
    // Place a regular file FILE.TXT at the root, then try to open
    // /FILE.TXT/INNER. The intermediate FILE.TXT is not a directory
    // → must return NotADirectory.
    let mut img = build_fat16_image();
    let r = 18 * 512;
    img[r..r + 11].copy_from_slice(b"FILE    TXT");
    img[r + 0x0B] = 0x20; // ARCHIVE
    // first_cluster_low = 0 (no real data needed for this test).

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let err = fat.open(&mut cur, "/FILE.TXT/INNER.TXT").unwrap_err();
    assert!(matches!(err, FatError::NotADirectory));
}

#[test]
fn validate_sectors_per_cluster_rejects_zero_and_non_power_of_two() {
    // Pins both arms of the `|| ` chain: spc=0 trips the first
    // arm, spc=3 trips the second. spc=2 must succeed.
    assert!(matches!(
        Fat::validate_sectors_per_cluster(0),
        Err(FatError::InvalidSectorsPerCluster { actual: 0 })
    ));
    assert!(matches!(
        Fat::validate_sectors_per_cluster(3),
        Err(FatError::InvalidSectorsPerCluster { actual: 3 })
    ));
    assert!(matches!(
        Fat::validate_sectors_per_cluster(5),
        Err(FatError::InvalidSectorsPerCluster { actual: 5 })
    ));
    assert!(Fat::validate_sectors_per_cluster(1).is_ok());
    assert!(Fat::validate_sectors_per_cluster(2).is_ok());
    assert!(Fat::validate_sectors_per_cluster(8).is_ok());
    assert!(Fat::validate_sectors_per_cluster(128).is_ok());
}

#[test]
fn cluster_size_and_total_sectors_for_fat32_use_bpb_arithmetic() {
    // Catches `* with +/-/` mutations on `size = total_sectors * sector_size`
    // (line 231) and `/ with *` on `data_sectors / sectors_per_cluster`
    // (line 226 in new_fat32). The expected size = 66069 * 512 =
    // 33_827_328; mutated `total_sectors + sector_size` = 66069+512 =
    // 66_581, far smaller.
    let img = build_fat32_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    assert_eq!(fat.size(), 66069u64 * 512);

    // FAT32 total_clusters = data_sectors / spc = 65525 / 1 = 65525.
    // Mutated `/ with *`: 65525 * 1 = 65525 (same — equivalent for spc=1).
    // To distinguish, we'd need spc > 1. The fat12 image has spc=1
    // (also indistinguishable). Build an explicit spc=2 image:
    // - bps=512, spc=2 → cluster_size=1024
    // - reserved=2, fats=1, spf16=4, root=16 (=1 sector), total=4112
    // - first_data = 2+4+1 = 7, data = 4105, total_clusters = 4105/2 = 2052 → FAT12
    let mut img = vec![0u8; 4112 * 512];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"MSDOS5.0");
    img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    img[0x0D] = 2; // spc=2
    img[0x0E..0x10].copy_from_slice(&2u16.to_le_bytes());
    img[0x10] = 1;
    img[0x11..0x13].copy_from_slice(&16u16.to_le_bytes());
    img[0x13..0x15].copy_from_slice(&4112u16.to_le_bytes());
    img[0x15] = 0xF8;
    img[0x16..0x18].copy_from_slice(&4u16.to_le_bytes());
    img[0x26] = 0x29;
    img[0x36..0x3E].copy_from_slice(b"FAT12   ");
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("spc=2 image parses");
    // total_clusters = (4112 - 7) / 2 = 4105 / 2 = 2052.
    assert_eq!(fat.cluster_size(), 1024);
    assert_eq!(fat.total_clusters(), 2052);
}

#[test]
fn next_cluster_rejects_top_of_range_boundary() {
    // Catches `> with >=` at line 424 by feeding total_clusters + 1
    // (highest valid) and total_clusters + 2 (just past). Original
    // accepts the highest valid; mutated `>=` rejects it.
    let img = build_fat16_image();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");

    // Highest valid: total_clusters + 1 = 4086. Without writing FAT
    // table entries that far, reading FAT[4086] will return 0 (free)
    // and the function returns Some(0). The important thing is that
    // it does NOT return Err(InvalidCluster).
    let result = fat.next_cluster(&mut cur, 4086);
    assert!(
        !matches!(result, Err(FatError::InvalidCluster { cluster: 4086 })),
        "cluster 4086 must be accepted as in-range: got {result:?}",
    );
}

#[cfg(feature = "arbitrary")]
#[test]
fn arbitrary_fat_type_maps_each_in_range_value_to_a_distinct_variant() {
    // Catches `delete match arm 0` and `delete match arm 1` in the
    // arbitrary impl. Use a buffer with varied bytes so that
    // `int_in_range(0..=2)` cycles through all three possible
    // inputs (0, 1, 2). If a match arm is deleted, the deleted
    // input value collapses into the `_ => Fat32` fall-through,
    // shrinking the set of observed variants from 3 to 2.
    use arbitrary::{Arbitrary, Unstructured};

    let seed: Vec<u8> = (0u8..=255).collect();
    let mut u = Unstructured::new(&seed);
    let mut seen_fat12 = false;
    let mut seen_fat16 = false;
    let mut seen_fat32 = false;
    for _ in 0..255 {
        match FatType::arbitrary(&mut u) {
            Ok(FatType::Fat12) => seen_fat12 = true,
            Ok(FatType::Fat16) => seen_fat16 = true,
            Ok(FatType::Fat32) => seen_fat32 = true,
            Err(_) => break,
        }
    }
    assert!(
        seen_fat12 && seen_fat16 && seen_fat32,
        "arbitrary must yield every FatType variant (got 12={seen_fat12}, 16={seen_fat16}, 32={seen_fat32})",
    );
}

#[test]
fn new_fat32_divides_data_sectors_by_sectors_per_cluster() {
    // Catches `/ with *` at line 245 (`total_clusters = data_sectors /
    // spc`). Build a minimal image syntactically classified as FAT32
    // (sectors_per_fat_16 = 0 and root_entry_count = 0) with spc=2
    // so the divisor differs from 1 and `*` becomes observable.
    // FAT32 routine fires regardless of actual cluster count.
    let mut img = vec![0u8; 50 * 512];
    img[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    img[3..11].copy_from_slice(b"MSDOS5.0");
    img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    img[0x0D] = 2; // spc=2
    img[0x0E..0x10].copy_from_slice(&32u16.to_le_bytes());
    img[0x10] = 1;
    img[0x15] = 0xF8;
    img[0x20..0x24].copy_from_slice(&50u32.to_le_bytes());
    img[0x24..0x28].copy_from_slice(&4u32.to_le_bytes()); // sectors_per_fat_32
    img[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes()); // root_cluster
    img[0x30..0x32].copy_from_slice(&0xFFFFu16.to_le_bytes());
    img[0x40] = 0x80;
    img[0x42] = 0x29;
    img[0x52..0x5A].copy_from_slice(b"FAT32   ");
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("parses as FAT32 layout");
    // total_clusters = (50 - 32 - 4) / 2 = 14 / 2 = 7.
    // Mutated `*`: 14 * 2 = 28.
    assert_eq!(fat.total_clusters(), 7);
    assert_eq!(fat.cluster_size(), 1024); // 512 * spc=2
}

#[test]
fn next_cluster_fat12_shifts_odd_entry_right_to_recover_value() {
    // Build a FAT12 image where FAT[3] (odd cluster) points to a
    // specific data cluster. Anchors line 451's `>> 4` against `<< 4`:
    //   - Original `entry >> 4`: extracts the high 12 bits.
    //   - Mutated `entry << 4`: shifts the byte pattern left, often
    //     wrapping into the >=0x0FF8 EOC range and returning None.
    //
    // Layout: FAT[2] = 3, FAT[3] = 0x0A0 (data cluster 160), FAT[160] = EOC.
    // Bytes in the FAT table:
    //   FAT[2..3] occupy bytes 3..6:
    //     byte[3] = 0x03 (low 8 of FAT[2])
    //     byte[4] = (high 4 of FAT[2]) | (low 4 of FAT[3] << 4) = 0x00 | 0x00 = 0x00
    //               Wait — odd-cluster math: FAT[3] low 4 are stored in
    //               byte[4] high 4, FAT[3] high 8 are in byte[5].
    //               For FAT[3] = 0x0A0: low 4 = 0x0, high 8 = 0x0A.
    //               byte[4] = (high 4 of FAT[2]=0) | (low 4 of FAT[3]=0 << 4) = 0
    //               byte[5] = high 8 of FAT[3] = 0x0A
    let mut img = build_fat12_image();
    let f = 0x200;
    // Overwrite FAT[2..3]: FAT[2]=3, FAT[3]=0x0A0.
    img[f + 3] = 0x03; // low 8 of FAT[2]
    img[f + 4] = 0x00; // high 4 of FAT[2] (0) | low 4 of FAT[3] (0) << 4
    img[f + 5] = 0x0A; // high 8 of FAT[3]

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let next3 = fat.next_cluster(&mut cur, 3).expect("read FAT[3]");
    assert_eq!(
        next3,
        Some(0x0A0),
        "FAT[3] must decode to 0x0A0 via `entry >> 4`; mutated `<< 4` would produce 0x0A00 (>=0x0FF8, EOC)",
    );
}
