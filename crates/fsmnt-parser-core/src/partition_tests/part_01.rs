use super::*;
use core::mem::size_of;

// ------------------------------------------------------------------
// Builders
// ------------------------------------------------------------------

fn mbr_entry_bytes(
    boot: u8,
    partition_type: u8,
    start_lba: u32,
    sector_count: u32,
) -> [u8; MBR_ENTRY_SIZE] {
    let mut bytes = [0u8; MBR_ENTRY_SIZE];
    bytes[0] = boot;
    bytes[4] = partition_type;
    bytes[8..12].copy_from_slice(&start_lba.to_le_bytes());
    bytes[12..16].copy_from_slice(&sector_count.to_le_bytes());
    bytes
}

fn build_mbr(entries: [[u8; MBR_ENTRY_SIZE]; 4], signature: u16) -> [u8; 512] {
    let mut buf = [0u8; 512];
    for (i, entry) in entries.iter().enumerate() {
        let offset = 446 + i * MBR_ENTRY_SIZE;
        buf[offset..offset + MBR_ENTRY_SIZE].copy_from_slice(entry);
    }
    buf[510..512].copy_from_slice(&signature.to_le_bytes());
    buf
}

fn build_gpt_header_bytes() -> [u8; 92] {
    let mut buf = [0u8; 92];
    buf[0..8].copy_from_slice(&GPT_SIGNATURE.to_le_bytes()); // signature
    buf[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision
    buf[12..16].copy_from_slice(&92u32.to_le_bytes()); // header_size
    buf[16..20].copy_from_slice(&0u32.to_le_bytes()); // header_crc32
    buf[24..32].copy_from_slice(&1u64.to_le_bytes()); // current_lba
    buf[32..40].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes()); // backup_lba
    buf[40..48].copy_from_slice(&34u64.to_le_bytes()); // first_usable_lba
    buf[48..56].copy_from_slice(&0xFFFF_F000u64.to_le_bytes()); // last_usable_lba
    // disk_guid (offset 56-71, 16 bytes) left zero
    buf[72..80].copy_from_slice(&2u64.to_le_bytes()); // partition_entry_lba
    buf[80..84].copy_from_slice(&128u32.to_le_bytes()); // num_partition_entries
    let entry_size = u32::try_from(GPT_ENTRY_SIZE).expect("GPT entry size fits u32");
    buf[84..88].copy_from_slice(&entry_size.to_le_bytes()); // partition_entry_size
    // partition_entries_crc32 (offset 88-91) left zero
    buf
}

fn build_gpt_partition_entry(
    type_guid: [u8; 16],
    start_lba: u64,
    end_lba: u64,
    name_utf16: &[u16],
) -> [u8; GPT_ENTRY_SIZE] {
    let mut buf = [0u8; GPT_ENTRY_SIZE];
    buf[0..16].copy_from_slice(&type_guid);
    // partition_guid (16..32) left zero
    buf[32..40].copy_from_slice(&start_lba.to_le_bytes());
    buf[40..48].copy_from_slice(&end_lba.to_le_bytes());
    // attributes (56..64) left zero
    for (i, &c) in name_utf16.iter().enumerate().take(36) {
        let off = 56 + i * 2;
        buf[off..off + 2].copy_from_slice(&c.to_le_bytes());
    }
    buf
}

// ------------------------------------------------------------------
// Structure sizes (catches accidental layout changes)
// ------------------------------------------------------------------

#[test]
fn structure_sizes() {
    assert_eq!(size_of::<MbrPartitionEntry>(), MBR_ENTRY_SIZE);
    assert_eq!(size_of::<Mbr>(), 512);
    assert_eq!(size_of::<GptHeader>(), 92);
    assert_eq!(size_of::<GptPartitionEntry>(), GPT_ENTRY_SIZE);
}

// ------------------------------------------------------------------
// MbrPartitionEntry
// ------------------------------------------------------------------

#[test]
fn mbr_entry_is_empty_only_when_type_is_zero() {
    let empty_bytes = mbr_entry_bytes(0, 0, 0, 0);
    let empty = MbrPartitionEntry::ref_from_bytes(&empty_bytes).unwrap();
    assert!(empty.is_empty());

    let ntfs_bytes = mbr_entry_bytes(0, 0x07, 0, 0);
    let ntfs = MbrPartitionEntry::ref_from_bytes(&ntfs_bytes).unwrap();
    assert!(!ntfs.is_empty());

    // Type byte alone (without LBA/size) is enough to be "non-empty".
    let unknown_bytes = mbr_entry_bytes(0, 0xAB, 100, 200);
    let unknown = MbrPartitionEntry::ref_from_bytes(&unknown_bytes).unwrap();
    assert!(!unknown.is_empty());
}

#[test]
fn mbr_entry_is_gpt_protective_matches_0xee_only() {
    let protective_bytes = mbr_entry_bytes(0, MBR_TYPE_GPT_PROTECTIVE, 1, 100);
    let protective = MbrPartitionEntry::ref_from_bytes(&protective_bytes).unwrap();
    assert!(protective.is_gpt_protective());

    let ntfs_bytes = mbr_entry_bytes(0, 0x07, 0, 0);
    let ntfs = MbrPartitionEntry::ref_from_bytes(&ntfs_bytes).unwrap();
    assert!(!ntfs.is_gpt_protective());
}

#[test]
fn mbr_entry_start_offset_multiplies_lba_by_sector_size() {
    let bytes = mbr_entry_bytes(0, 0x07, 2048, 1024);
    let entry = MbrPartitionEntry::ref_from_bytes(&bytes).unwrap();
    // Distinct sector sizes so + / / cannot accidentally match *.
    assert_eq!(entry.start_offset(512), 2048 * 512);
    assert_eq!(entry.start_offset(4096), 2048 * 4096);
    // Distinguishes from `0` and `1` constant-replacement mutants.
    assert!(entry.start_offset(512) > 1);
}

#[test]
fn mbr_entry_size_bytes_multiplies_sector_count_by_sector_size() {
    let bytes = mbr_entry_bytes(0, 0x07, 0, 1024);
    let entry = MbrPartitionEntry::ref_from_bytes(&bytes).unwrap();
    assert_eq!(entry.size_bytes(512), 1024 * 512);
    assert_eq!(entry.size_bytes(4096), 1024 * 4096);
    assert!(entry.size_bytes(512) > 1);
}

#[test]
fn mbr_entry_type_name_distinct_for_each_known_type() {
    // Each known type returns its own distinct label — catches both
    // wholesale-replacement mutants (-> None / Some("xyzzy")) and
    // per-arm `delete match arm 0xXX` deletions, which would fall
    // through to None.
    let pairs: &[(u8, &str)] = &[
        (0x07, "NTFS/HPFS/exFAT"),
        (0x0B, "FAT32 (CHS)"),
        (0x0C, "FAT32 (LBA)"),
        (0x0E, "FAT16 (LBA)"),
        (0x0F, "Extended (LBA)"),
        (0x82, "Linux Swap"),
        (0x83, "Linux"),
        (0xEE, "GPT Protective"),
        (0xEF, "EFI System"),
    ];
    for &(byte, label) in pairs {
        let bytes = mbr_entry_bytes(0, byte, 0, 0);
        let entry = MbrPartitionEntry::ref_from_bytes(&bytes).unwrap();
        assert_eq!(entry.type_name(), Some(label), "type 0x{byte:02X}");
    }

    // Unknown type — must return None (rules out `Some("")` / `Some("xyzzy")` mutants).
    let unknown_bytes = mbr_entry_bytes(0, 0xAB, 0, 0);
    let unknown = MbrPartitionEntry::ref_from_bytes(&unknown_bytes).unwrap();
    assert_eq!(unknown.type_name(), None);
}

// ------------------------------------------------------------------
// Mbr
// ------------------------------------------------------------------

#[test]
fn mbr_from_bytes_requires_full_sector() {
    // 511 bytes is one short of a full MBR.
    let short = [0u8; 511];
    assert!(Mbr::from_bytes(&short).is_none());

    // 512+ succeeds; only the first 512 bytes are consumed.
    let full = [0u8; 512];
    assert!(Mbr::from_bytes(&full).is_some());

    let oversize = [0u8; 1024];
    assert!(Mbr::from_bytes(&oversize).is_some());
}

#[test]
fn mbr_is_valid_only_when_signature_matches() {
    let entries = [mbr_entry_bytes(0, 0, 0, 0); 4];

    let buf = build_mbr(entries, MBR_SIGNATURE);
    assert!(Mbr::from_bytes(&buf).unwrap().is_valid());

    let bad = build_mbr(entries, 0x1234);
    assert!(!Mbr::from_bytes(&bad).unwrap().is_valid());

    // The 0xAA55 signature is little-endian; the wrong byte order is invalid.
    let swapped = build_mbr(entries, 0x55AA);
    assert!(!Mbr::from_bytes(&swapped).unwrap().is_valid());
}

#[test]
fn mbr_is_gpt_protective_requires_valid_signature_and_protective_first_entry() {
    // Valid signature + first entry is GPT protective: yes.
    let mut entries = [mbr_entry_bytes(0, 0, 0, 0); 4];
    entries[0] = mbr_entry_bytes(0, MBR_TYPE_GPT_PROTECTIVE, 1, 0xFFFF_FFFF);
    let buf = build_mbr(entries, MBR_SIGNATURE);
    assert!(Mbr::from_bytes(&buf).unwrap().is_gpt_protective());

    // Valid signature but first entry NTFS — not GPT.
    let mut entries = [mbr_entry_bytes(0, 0, 0, 0); 4];
    entries[0] = mbr_entry_bytes(0, 0x07, 2048, 1000);
    let buf = build_mbr(entries, MBR_SIGNATURE);
    assert!(!Mbr::from_bytes(&buf).unwrap().is_gpt_protective());

    // Wrong signature, even with protective first entry — not GPT.
    let mut entries = [mbr_entry_bytes(0, 0, 0, 0); 4];
    entries[0] = mbr_entry_bytes(0, MBR_TYPE_GPT_PROTECTIVE, 1, 0xFFFF_FFFF);
    let buf = build_mbr(entries, 0xBEEF);
    assert!(!Mbr::from_bytes(&buf).unwrap().is_gpt_protective());
}

#[test]
fn mbr_valid_partitions_filters_empty_entries() {
    let entries = [
        mbr_entry_bytes(0x80, 0x07, 2048, 1000),
        mbr_entry_bytes(0, 0, 0, 0),
        mbr_entry_bytes(0, 0x83, 3048, 2000),
        mbr_entry_bytes(0, 0, 0, 0),
    ];
    let buf = build_mbr(entries, MBR_SIGNATURE);
    let mbr = Mbr::from_bytes(&buf).unwrap();
    let valid: Vec<u8> = mbr.valid_partitions().map(|p| p.partition_type).collect();
    assert_eq!(valid, vec![0x07, 0x83]);

    // All-empty MBR yields an empty iterator.
    let empty_entries = [mbr_entry_bytes(0, 0, 0, 0); 4];
    let buf = build_mbr(empty_entries, MBR_SIGNATURE);
    let mbr = Mbr::from_bytes(&buf).unwrap();
    assert_eq!(mbr.valid_partitions().count(), 0);
}

#[test]
fn mbr_is_plausible_table_accepts_tables_a_partitioner_could_have_written() {
    let entries = [
        mbr_entry_bytes(0x80, 0x07, 2048, 1000),
        mbr_entry_bytes(0x00, 0x83, 3048, 2000),
        mbr_entry_bytes(0, 0, 0, 0),
        mbr_entry_bytes(0, 0, 0, 0),
    ];
    let buf = build_mbr(entries, MBR_SIGNATURE);
    assert!(Mbr::from_bytes(&buf).unwrap().is_plausible_table());

    // Empty entries carry no claims to contradict, so a table of
    // nothing but empties is vacuously plausible.
    let buf = build_mbr([mbr_entry_bytes(0, 0, 0, 0); 4], MBR_SIGNATURE);
    assert!(Mbr::from_bytes(&buf).unwrap().is_plausible_table());
}

#[test]
fn mbr_is_plausible_table_rejects_random_data_that_ends_in_the_signature() {
    // A boot indicator no partitioner writes.
    let entries = [
        mbr_entry_bytes(0x27, 0x07, 2048, 1000),
        mbr_entry_bytes(0, 0, 0, 0),
        mbr_entry_bytes(0, 0, 0, 0),
        mbr_entry_bytes(0, 0, 0, 0),
    ];
    let buf = build_mbr(entries, MBR_SIGNATURE);
    assert!(!Mbr::from_bytes(&buf).unwrap().is_plausible_table());

    // A partition of no sectors, and one starting on the table's own
    // sector.
    for entry in [
        mbr_entry_bytes(0x00, 0x07, 2048, 0),
        mbr_entry_bytes(0x00, 0x07, 0, 1000),
    ] {
        let entries = [
            entry,
            mbr_entry_bytes(0, 0, 0, 0),
            mbr_entry_bytes(0, 0, 0, 0),
            mbr_entry_bytes(0, 0, 0, 0),
        ];
        let buf = build_mbr(entries, MBR_SIGNATURE);
        assert!(!Mbr::from_bytes(&buf).unwrap().is_plausible_table());
    }

    // Two entries claiming the same sectors.
    let entries = [
        mbr_entry_bytes(0x00, 0x07, 2048, 4096),
        mbr_entry_bytes(0x00, 0x83, 4096, 4096),
        mbr_entry_bytes(0, 0, 0, 0),
        mbr_entry_bytes(0, 0, 0, 0),
    ];
    let buf = build_mbr(entries, MBR_SIGNATURE);
    assert!(!Mbr::from_bytes(&buf).unwrap().is_plausible_table());
}

// ------------------------------------------------------------------
// GptHeader
// ------------------------------------------------------------------

#[test]
fn gpt_header_from_bytes_requires_at_least_92_bytes() {
    let short = [0u8; 91];
    assert!(GptHeader::from_bytes(&short).is_none());

    let exact = [0u8; 92];
    assert!(GptHeader::from_bytes(&exact).is_some());

    let oversize = [0u8; 512];
    assert!(GptHeader::from_bytes(&oversize).is_some());
}

#[test]
fn gpt_header_is_valid_only_for_efi_part_signature() {
    let buf = build_gpt_header_bytes();
    assert!(GptHeader::from_bytes(&buf).unwrap().is_valid());

    // Flip a byte in the signature → invalid.
    let mut bad = buf;
    bad[0] ^= 0xFF;
    assert!(!GptHeader::from_bytes(&bad).unwrap().is_valid());

    // Zero header (no signature) is not valid.
    let zeros = [0u8; 92];
    assert!(!GptHeader::from_bytes(&zeros).unwrap().is_valid());
}

// ------------------------------------------------------------------
// GptPartitionEntry
// ------------------------------------------------------------------

#[test]
fn gpt_entry_from_bytes_requires_128_bytes() {
    let short = [0u8; 127];
    assert!(GptPartitionEntry::from_bytes(&short).is_none());

    let exact = [0u8; GPT_ENTRY_SIZE];
    assert!(GptPartitionEntry::from_bytes(&exact).is_some());
}

#[test]
fn gpt_entry_is_empty_only_for_null_type_guid() {
    let empty = build_gpt_partition_entry(NULL_GUID, 0, 0, &[]);
    assert!(GptPartitionEntry::from_bytes(&empty).unwrap().is_empty());

    let occupied = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 1, 100, &[]);
    assert!(!GptPartitionEntry::from_bytes(&occupied).unwrap().is_empty());

    // Any non-zero type GUID counts as occupied — flip a single bit.
    let mut almost = NULL_GUID;
    almost[7] = 0x01;
    let entry = build_gpt_partition_entry(almost, 0, 0, &[]);
    assert!(!GptPartitionEntry::from_bytes(&entry).unwrap().is_empty());
}

#[test]
fn gpt_entry_start_offset_multiplies_lba_by_sector_size() {
    let entry = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 34, 2047, &[]);
    let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
    assert_eq!(parsed.start_offset(512), 34 * 512);
    assert_eq!(parsed.start_offset(4096), 34 * 4096);
}

#[test]
fn gpt_entry_size_bytes_uses_inclusive_end_lba() {
    // sectors [start..=end] inclusive → (end - start + 1) sectors.
    let entry = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 100, 199, &[]);
    let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
    // 100 sectors of 512 = 51_200.
    assert_eq!(parsed.size_bytes(512), 100 * 512);

    // Single-sector partition: start == end → 1 sector.
    let single = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 50, 50, &[]);
    let single = GptPartitionEntry::from_bytes(&single).unwrap();
    assert_eq!(single.size_bytes(512), 512);
}

#[test]
fn gpt_entry_name_string_decodes_utf16_until_null() {
    // "EFI" followed by 0 terminator.
    let name = [0x0045u16, 0x0046, 0x0049, 0x0000, 0x0058];
    let entry = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 0, 0, &name);
    let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
    // take_while stops at the first NUL — trailing 0x58 ('X') is excluded.
    assert_eq!(parsed.name_string(), "EFI");

    // Empty name (all zeros) decodes to empty string.
    let empty_name = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 0, 0, &[]);
    assert_eq!(
        GptPartitionEntry::from_bytes(&empty_name)
            .unwrap()
            .name_string(),
        ""
    );
}

#[test]
fn gpt_entry_type_guid_string_formats_mixed_endian_uuid() {
    // EFI System Partition GUID is the canonical mixed-endian test case:
    // bytes 0..4 little-endian, 4..6 LE, 6..8 LE, 8..16 big-endian (raw).
    let entry = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 0, 0, &[]);
    let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
    assert_eq!(
        parsed.type_guid_string(),
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
    );
}

#[test]
fn gpt_entry_partition_guid_string_formats_mixed_endian_uuid() {
    let mut guid = [0u8; 16];
    // First 4 bytes are emitted reversed: stored 0x01,0x02,0x03,0x04 → "04030201"
    guid[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    guid[4..6].copy_from_slice(&[0x05, 0x06]);
    guid[6..8].copy_from_slice(&[0x07, 0x08]);
    guid[8..16].copy_from_slice(&[0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);

    let mut entry = [0u8; GPT_ENTRY_SIZE];
    entry[0..16].copy_from_slice(&GptPartitionEntry::EFI_SYSTEM_GUID);
    entry[16..32].copy_from_slice(&guid);
    let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
    assert_eq!(
        parsed.partition_guid_string(),
        "04030201-0605-0807-090A-0B0C0D0E0F10"
    );
}

#[test]
fn gpt_entry_type_name_distinct_for_each_known_guid() {
    let pairs: &[([u8; 16], &str)] = &[
        (GptPartitionEntry::EFI_SYSTEM_GUID, "EFI System"),
        (
            GptPartitionEntry::MICROSOFT_BASIC_DATA_GUID,
            "Basic Data (NTFS/FAT)",
        ),
        (
            GptPartitionEntry::MICROSOFT_RESERVED_GUID,
            "Microsoft Reserved",
        ),
        (GptPartitionEntry::WINDOWS_RECOVERY_GUID, "Windows Recovery"),
        (GptPartitionEntry::LINUX_FILESYSTEM_GUID, "Linux filesystem"),
    ];
    for &(guid, label) in pairs {
        let entry = build_gpt_partition_entry(guid, 0, 0, &[]);
        let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
        assert_eq!(parsed.type_name(), Some(label));
    }

    // Unknown GUID — type_name must return None (rules out wholesale
    // -> Some(...) / -> None mutants).
    let mut unknown = [0u8; 16];
    unknown[0] = 0xDE;
    unknown[1] = 0xAD;
    let entry = build_gpt_partition_entry(unknown, 0, 0, &[]);
    let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
    assert_eq!(parsed.type_name(), None);
}

#[test]
fn linux_filesystem_guid_uses_gpt_mixed_endian_storage() {
    let entry = build_gpt_partition_entry(GptPartitionEntry::LINUX_FILESYSTEM_GUID, 0, 0, &[]);
    let parsed = GptPartitionEntry::from_bytes(&entry).unwrap();
    assert_eq!(
        parsed.type_guid_string(),
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
    );
}

// ------------------------------------------------------------------
// read_gpt_header / read_gpt_partitions (std-only)
// ------------------------------------------------------------------

#[cfg(feature = "std")]
fn build_gpt_disk_image(partition_entries: &[[u8; GPT_ENTRY_SIZE]]) -> Vec<u8> {
    // 4 sectors of 512 bytes is enough for a protective MBR + GPT header +
    // 128 GPT partition entries (128 entries * 128 bytes = 16384 bytes = 32 sectors).
    // We use 36 sectors total to leave room for the entry array.
    let sector_size = 512usize;
    let mut buf = vec![0u8; sector_size * 36];

    // LBA 0: protective MBR (left mostly zero, no signature needed for these tests).
    // LBA 1: GPT header.
    let header = build_gpt_header_bytes();
    buf[sector_size..sector_size + 92].copy_from_slice(&header);

    // LBA 2..: partition entries.
    let entry_offset = sector_size * 2;
    for (i, entry) in partition_entries.iter().enumerate() {
        let off = entry_offset + i * GPT_ENTRY_SIZE;
        buf[off..off + GPT_ENTRY_SIZE].copy_from_slice(entry);
    }
    buf
}

#[cfg(feature = "std")]
#[test]
fn read_gpt_header_seeks_to_lba_1_and_returns_parsed_header() {
    use std::io::Cursor;
    let disk = build_gpt_disk_image(&[]);
    let mut cursor = Cursor::new(disk);
    let header = read_gpt_header(&mut cursor, 512).unwrap();
    assert!(header.is_valid());
    assert_eq!(header.partition_entry_lba.get(), 2);
    assert_eq!(header.num_partition_entries.get(), 128);
    assert_eq!(header.partition_entry_size.get(), 128);
}

#[cfg(feature = "std")]
#[test]
fn read_gpt_header_rejects_signature_mismatch() {
    use std::io::Cursor;
    let mut disk = build_gpt_disk_image(&[]);
    // Corrupt the GPT signature at LBA 1.
    disk[512] ^= 0xFF;
    let mut cursor = Cursor::new(disk);
    let err = read_gpt_header(&mut cursor, 512).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[cfg(feature = "std")]
#[test]
fn read_gpt_partitions_returns_only_non_empty_entries() {
    use std::io::Cursor;
    let efi = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 34, 2047, &[]);
    let basic_data = build_gpt_partition_entry(
        GptPartitionEntry::MICROSOFT_BASIC_DATA_GUID,
        2048,
        4095,
        &[],
    );
    let empty = [0u8; GPT_ENTRY_SIZE];

    // Layout: [efi, empty, basic_data, empty, empty, ...]
    let mut all = vec![empty; 128];
    all[0] = efi;
    all[2] = basic_data;

    let disk = build_gpt_disk_image(&all);
    let mut cursor = Cursor::new(disk);
    let header = read_gpt_header(&mut cursor, 512).unwrap();
    let parts = read_gpt_partitions(&mut cursor, &header, 512).unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].type_guid, GptPartitionEntry::EFI_SYSTEM_GUID);
    assert_eq!(
        parts[1].type_guid,
        GptPartitionEntry::MICROSOFT_BASIC_DATA_GUID
    );
    assert_eq!(parts[0].start_lba.get(), 34);
    assert_eq!(parts[1].start_lba.get(), 2048);
}

#[cfg(feature = "std")]
#[test]
fn read_gpt_partitions_uses_entry_size_for_seek_arithmetic() {
    // Build a disk where every entry slot is populated so that the
    // entry-LBA * sector-size offset must be correct or we'd read
    // garbage and see fewer parsed entries.
    use std::io::Cursor;
    let efi = build_gpt_partition_entry(GptPartitionEntry::EFI_SYSTEM_GUID, 34, 2047, &[]);
    let all = vec![efi; 128];

    let disk = build_gpt_disk_image(&all);
    let mut cursor = Cursor::new(disk);
    let header = read_gpt_header(&mut cursor, 512).unwrap();
    let parts = read_gpt_partitions(&mut cursor, &header, 512).unwrap();
    assert_eq!(parts.len(), 128);
    for part in &parts {
        assert_eq!(part.type_guid, GptPartitionEntry::EFI_SYSTEM_GUID);
    }
}
