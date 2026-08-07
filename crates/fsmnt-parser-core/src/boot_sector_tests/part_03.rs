#[test]
fn determine_fat_type_rejects_when_total_sectors_at_or_below_first_data() {
    // Anchors line 1225 `<= with >` — when total_sectors equals the
    // first_data_sector, there are zero data sectors, which is
    // pathological. The function returns Unknown rather than 0
    // clusters → FAT12. Mutated `>` would only reject when
    // total_sectors is strictly less than first_data_sector, letting
    // the boundary value through to determine_fat_type returning
    // FAT12 for `0 < 4085`.
    //
    // Layout: 1 spc, 1 reserved, 2 FATs, root=16 (1 sector), spf16=1
    // → first_data_sector = 1 + 2*1 + 1 = 4.
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 2, 16, 4, 1, 0);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
    let err = parse_boot_sector(&buf).unwrap_err();
    assert_eq!(err, ParseError::UnknownFilesystem);
}

#[test]
fn determine_fat_type_multiplies_num_fats_by_fat_size() {
    // first_data_sector = reserved + (num_fats * fat_size) + root_dir_sectors.
    // Mutating `num_fats * fat_size` → `num_fats / fat_size` collapses
    // 2 / 128 to 0, dropping 256 sectors from first_data_sector and
    // shifting cluster_count above the FAT12 threshold. Pick total=4200
    // so the original lands at 3911 clusters (FAT12) and the mutated
    // calculation lands at 4167 (FAT16).
    //
    // Layout: bps=512, spc=1, reserved=1, num_fats=2, root=512 entries
    // (32 root-dir sectors), spf16=128. first_data_orig = 1 + 256 + 32
    // = 289; first_data_mut = 1 + 0 + 32 = 33.
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 2, 512, 4200, 128, 0);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
    assert!(matches!(
        parse_boot_sector(&buf).unwrap(),
        ParsedBootSector::Fat12 { .. }
    ));
}

#[test]
fn determine_fat_type_uses_sectors_per_cluster_to_divide_data_sectors() {
    // Catches `/ with %` and `/ with *` at line 1230 (data_sectors /
    // sectors_per_cluster). With sectors_per_cluster = 8 the original
    // computes cluster_count = data_sectors / 8; `%` would compute
    // data_sectors mod 8 (tiny number, FAT12); `*` would compute
    // data_sectors * 8 (huge, FAT32 territory and the outer match
    // rejects via UnknownFilesystem).
    //
    // Aim for FAT16 territory: spc=8, spf16=64, total=2_000_000.
    // first_data_sector = 1 + 2*64 + 32 = 161. data_sectors = 1_999_839.
    // cluster_count = 1_999_839 / 8 = 249_979 → FAT32 territory →
    // outer FAT16 match rejects → UnknownFilesystem.
    //
    // Mutated `/` → `%`: cluster_count = 1_999_839 % 8 = 7 → FAT12.
    // The fixture asserts the result is NOT FAT12.
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 8, 1, 2, 512, 0, 64, 2_000_000);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT16   ");
    let parsed = parse_boot_sector(&buf);
    assert!(
        !matches!(parsed, Ok(ParsedBootSector::Fat12 { .. })),
        "data_sectors / sectors_per_cluster must produce FAT32-sized cluster_count (not FAT12); got {parsed:?}",
    );
}

#[test]
fn from_bytes_rejects_crafted_gpt_with_valid_ext_sanity_fields() {
    // A maliciously-crafted GPT partition-entry area where bytes at
    // 0x438 pass ALL four probe_ext sanity checks (magic + log_block_size
    // + non-zero blocks_per_group + non-zero inodes_per_group). With the
    // old detection order (probe_ext first) this would misclassify the
    // disk as Ext and cause detect_layout to skip partition enumeration.
    let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];

    // Valid protective MBR:
    buf[0x1C2] = 0xEE; // Partition entry 1 type = GPT protective
    buf[0x1FE] = 0x55; // MBR boot signature
    buf[0x1FF] = 0xAA;

    // Full ext-sanity region:
    synthesize_ext_superblock(&mut buf);

    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::GptPartitioned,
        "GPT must win over a probe_ext-passing sanity region",
    );
}
