#[test]
fn test_diagnose_boot_sector_buffer_too_small() {
    let diagnosis = diagnose_boot_sector(&[0u8; 128]);
    assert_eq!(
        diagnosis,
        BootSectorDiagnosis::Unknown(BootSectorUnknownReason::BufferTooSmall)
    );
}

#[test]
fn test_diagnose_boot_sector_all_zeroes() {
    let diagnosis = diagnose_boot_sector(&[0u8; 512]);
    assert_eq!(
        diagnosis,
        BootSectorDiagnosis::Unknown(BootSectorUnknownReason::AllZeroes)
    );
}

#[test]
fn test_diagnose_boot_sector_invalid_signature() {
    let mut buffer = [0u8; 512];
    buffer[3..11].copy_from_slice(b"NTFS    ");
    let diagnosis = diagnose_boot_sector(&buffer);
    assert_eq!(
        diagnosis,
        BootSectorDiagnosis::Unknown(BootSectorUnknownReason::InvalidBootSignature)
    );
}

#[test]
fn test_diagnose_boot_sector_unknown_with_hints() {
    let mut buffer = [0u8; 512];
    buffer[510] = 0x55;
    buffer[511] = 0xAA;
    buffer[3..11].copy_from_slice(b"NTFS    ");
    // invalid bytes per sector keeps this from parsing as NTFS
    buffer[0x0B..0x0D].copy_from_slice(&123u16.to_le_bytes());

    let diagnosis = diagnose_boot_sector(&buffer);
    assert_eq!(
        diagnosis,
        BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnknownFilesystem {
            ntfs_oem_hint: true,
            exfat_hint: false,
            bitlocker_hint: false,
            mbr_layout_hint: true,
        })
    );
}

#[test]
fn test_diagnose_boot_sector_unsupported_hpfs() {
    let mut buffer = [0u8; 512];
    buffer[510] = 0x55;
    buffer[511] = 0xAA;
    buffer[3..11].copy_from_slice(b"HPFS    ");
    buffer[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    buffer[0x0D] = 1;
    buffer[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes());
    buffer[0x10] = 2;
    buffer[0x11..0x13].copy_from_slice(&512u16.to_le_bytes());
    buffer[0x13..0x15].copy_from_slice(&0u16.to_le_bytes());
    buffer[0x15] = 0xF8;
    buffer[0x16..0x18].copy_from_slice(&9u16.to_le_bytes());
    buffer[0x20..0x24].copy_from_slice(&32768u32.to_le_bytes());

    let diagnosis = diagnose_boot_sector(&buffer);
    assert_eq!(
        diagnosis,
        BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnsupportedFilesystem(
            FilesystemType::Hpfs
        ))
    );
}

// ========================================================================
// DetectedBootSector non-BPB filesystem detection tests
// ========================================================================

fn synthesize_ext_superblock(buf: &mut [u8]) {
    // s_magic at offset 1024 + 0x38 = 0x438 (little-endian 0xEF53)
    buf[0x438] = 0x53;
    buf[0x439] = 0xEF;
    // s_log_block_size at offset 1024 + 0x18: set to 2 (4 KiB blocks)
    buf[1024 + 0x18..1024 + 0x18 + 4].copy_from_slice(&2u32.to_le_bytes());
    // s_blocks_per_group at offset 1024 + 0x20: non-zero
    buf[1024 + 0x20..1024 + 0x20 + 4].copy_from_slice(&32_768u32.to_le_bytes());
    // s_inodes_per_group at offset 1024 + 0x28: non-zero
    buf[1024 + 0x28..1024 + 0x28 + 4].copy_from_slice(&8_192u32.to_le_bytes());
}

#[test]
fn from_bytes_detects_ext_with_valid_sanity_fields() {
    let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
    synthesize_ext_superblock(&mut buf);
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Ext
    );
}

fn synthesize_apfs_superblock(buf: &mut [u8]) {
    // obj_phys_t object type at 0x18: OBJECT_TYPE_NX_SUPERBLOCK (0x01).
    buf[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
    // nx_magic at 0x20: "NXSB".
    buf[0x20..0x24].copy_from_slice(b"NXSB");
    // nx_block_size at 0x24: 4 KiB.
    buf[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
}

fn synthesize_btrfs_superblock(buf: &mut [u8]) {
    let base = 0x1_0000;
    buf[base + 0x30..base + 0x38].copy_from_slice(&0x1_0000u64.to_le_bytes());
    buf[base + 0x40..base + 0x48].copy_from_slice(b"_BHRfS_M");
    buf[base + 0x48..base + 0x50].copy_from_slice(&42u64.to_le_bytes());
    buf[base + 0x70..base + 0x78].copy_from_slice(&1_073_741_824u64.to_le_bytes());
    buf[base + 0x78..base + 0x80].copy_from_slice(&16_777_216u64.to_le_bytes());
    buf[base + 0x88..base + 0x90].copy_from_slice(&1u64.to_le_bytes());
    buf[base + 0x90..base + 0x94].copy_from_slice(&4096u32.to_le_bytes());
    buf[base + 0x94..base + 0x98].copy_from_slice(&16_384u32.to_le_bytes());
}

fn btrfs_volume_probe() -> Vec<u8> {
    let offset = usize::try_from(BTRFS_PRIMARY_SUPERBLOCK_OFFSET).expect("offset fits usize");
    vec![0_u8; offset + BTRFS_SUPERBLOCK_PROBE_SIZE]
}

#[test]
fn from_bytes_detects_apfs_container() {
    let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
    synthesize_apfs_superblock(&mut buf);
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Apfs
    );
    assert!(DetectedBootSector::Apfs.is_filesystem());
}

#[test]
fn from_bytes_rejects_apfs_with_bad_block_size() {
    // A non-power-of-two nx_block_size must not be classified as APFS.
    let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
    synthesize_apfs_superblock(&mut buf);
    buf[0x24..0x28].copy_from_slice(&5000u32.to_le_bytes());
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

#[test]
fn from_bytes_detects_btrfs_primary_superblock() {
    let mut buf = btrfs_volume_probe();
    synthesize_btrfs_superblock(&mut buf);

    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Btrfs
    );
    assert!(DetectedBootSector::Btrfs.is_filesystem());
}

#[test]
fn from_bytes_rejects_btrfs_magic_without_primary_address() {
    let mut buf = btrfs_volume_probe();
    synthesize_btrfs_superblock(&mut buf);
    buf[0x1_0030..0x1_0038].fill(0);

    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

#[test]
fn from_bytes_rejects_btrfs_with_invalid_node_geometry() {
    let mut buf = btrfs_volume_probe();
    synthesize_btrfs_superblock(&mut buf);
    buf[0x1_0094..0x1_0098].copy_from_slice(&8192u32.to_le_bytes());
    buf[0x1_0090..0x1_0094].copy_from_slice(&16_384u32.to_le_bytes());

    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

#[test]
fn from_bytes_requires_btrfs_geometry_region() {
    let mut buf = vec![0u8; 0x1_0097];
    let base = 0x1_0000;
    buf[base + 0x40..base + 0x48].copy_from_slice(b"_BHRfS_M");

    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

#[test]
fn from_bytes_short_buffer_does_not_detect_ext() {
    // Buffer below EXT_PROBE_MIN_LEN must fall through to the existing
    // 512-byte signature checks and return Unknown for unrecognized
    // bytes. A real ext image's first 512 bytes don't carry the ext
    // magic.
    let buf = vec![0u8; 512];
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

#[test]
fn from_bytes_ext_detection_requires_full_magic_region() {
    // Buffer one byte short of 0x43A must not claim Ext.
    let buf = vec![0u8; EXT_PROBE_MIN_LEN - 1];
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

#[test]
fn from_bytes_prefers_gpt_over_coincidental_ext_magic_in_partition_array() {
    // Construct 2048 bytes of "GPT disk with stray 0xEF53 at 0x438":
    //   bytes 0..512:   protective MBR with type 0xEE + 0xAA55 signature
    //   bytes 512..:    ignored GPT-header region
    //   bytes 1024..:   plant 0xEF53 at 0x438 WITHOUT supporting sanity
    //                   fields, so probe_ext must reject.
    let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
    // MBR partition entry 1 type = 0xEE (protective GPT marker)
    buf[0x1C2] = 0xEE;
    // MBR boot signature
    buf[0x1FE] = 0x55;
    buf[0x1FF] = 0xAA;
    // Bare ext magic — sanity fields remain zero.
    buf[0x438] = 0x53;
    buf[0x439] = 0xEF;

    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::GptPartitioned,
        "probe_ext must reject magic-only; GPT classification must win",
    );
}

#[test]
fn from_bytes_rejects_ext_when_sanity_fields_are_bogus() {
    let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
    // Plant magic and non-zero blocks/inodes per group, but set
    // log_block_size to an out-of-range value.
    buf[0x438] = 0x53;
    buf[0x439] = 0xEF;
    buf[EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE] = 99; // out of 0..=6
    buf[EXT_SUPERBLOCK_OFFSET + SB_S_BLOCKS_PER_GROUP] = 1;
    buf[EXT_SUPERBLOCK_OFFSET + SB_S_INODES_PER_GROUP] = 1;
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

// ========================================================================
// probe_ext / probe_apfs constant and boundary tests
// ========================================================================

#[test]
fn ext_probe_min_len_matches_block_group_nr_field_end() {
    // The constant must equal the offset of the last byte of
    // s_block_group_nr + 1 — the furthest field the probe reads. Catches
    // arithmetic-operator mutations on the constant expression
    // (e.g. `+` → `-` or `*`).
    assert_eq!(EXT_PROBE_MIN_LEN, 0x45C);
}

#[test]
fn ext_probe_short_buffer_at_minimum_minus_one_returns_unknown() {
    // A buffer one byte short of EXT_PROBE_MIN_LEN lacks the last byte of
    // s_block_group_nr, so the u16 read at 0x45A would index out of
    // bounds. The size check in probe_ext must reject this buffer; any
    // mutation that shrinks EXT_PROBE_MIN_LEN makes the check pass and
    // the read then panics.
    let buf = vec![0u8; EXT_PROBE_MIN_LEN - 1];
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

#[test]
fn ext_probe_succeeds_at_exact_minimum_buffer_size() {
    // Buffer of exactly EXT_PROBE_MIN_LEN bytes — the smallest size that
    // fits every probed field, s_block_group_nr included. Catches
    // mutations that grow EXT_PROBE_MIN_LEN (e.g. `+ 2` → `* 2`) which
    // would push the size threshold above the buffer length.
    let mut buf = vec![0u8; EXT_PROBE_MIN_LEN];
    synthesize_ext_superblock(&mut buf);
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Ext
    );
}

#[test]
fn ext_probe_rejects_backup_superblock() {
    // A backup superblock is byte-for-byte a plausible superblock except
    // that s_block_group_nr names the group it lives in. Landing on one
    // partway into a filesystem must not read as a filesystem start.
    let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
    synthesize_ext_superblock(&mut buf);
    buf[EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR..EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR + 2]
        .copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
    assert_eq!(ext_backup_superblock_group(&buf), Some(3));
}

#[test]
fn ext_backup_superblock_group_is_none_for_primary_and_non_ext() {
    let mut primary = vec![0u8; FS_DETECT_PROBE_SIZE];
    synthesize_ext_superblock(&mut primary);
    assert_eq!(ext_backup_superblock_group(&primary), None);

    // Same non-zero group number, but no ext magic: not a superblock at
    // all, so no backup diagnosis either.
    let mut not_ext = vec![0u8; FS_DETECT_PROBE_SIZE];
    not_ext[EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR..EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR + 2]
        .copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(ext_backup_superblock_group(&not_ext), None);

    // Too short to hold s_block_group_nr.
    assert_eq!(ext_backup_superblock_group(&primary[..EXT_PROBE_MIN_LEN - 1]), None);
}

#[test]
fn ext_probe_rejects_log_block_size_above_six() {
    // s_log_block_size of 7 must reject — anchors the `> 6` boundary
    // against `>= 6` (which would reject the valid 6).
    let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
    synthesize_ext_superblock(&mut buf);
    buf[EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE
        ..EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE + 4]
        .copy_from_slice(&7u32.to_le_bytes());
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

#[test]
fn ext_probe_accepts_log_block_size_exactly_six() {
    // s_log_block_size of 6 must pass — anchors `> 6` against `>= 6`.
    let mut buf = vec![0u8; FS_DETECT_PROBE_SIZE];
    synthesize_ext_superblock(&mut buf);
    buf[EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE
        ..EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE + 4]
        .copy_from_slice(&6u32.to_le_bytes());
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Ext
    );
}

#[test]
fn apfs_probe_min_len_matches_block_size_field_end() {
    // Catches arithmetic-operator mutations on the constant expression
    // at line 85 (e.g. `+ 4` → `- 4` or `* 4`).
    assert_eq!(APFS_PROBE_MIN_LEN, 0x28);
}

#[test]
fn apfs_probe_succeeds_at_minimum_buffer_size() {
    // 0x28 bytes is the smallest buffer that fits nx_block_size at
    // offset 0x24..0x28. Buffer < 512 short-circuits standard detection
    // to BufferTooSmall, but probe_apfs still runs from the diagnose
    // fall-through, so APFS classification can succeed.
    let mut buf = vec![0u8; 0x28];
    buf[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
    buf[0x20..0x24].copy_from_slice(b"NXSB");
    buf[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Apfs
    );
}

#[test]
fn apfs_probe_below_minimum_buffer_size_returns_unknown() {
    // A buffer of 0x27 bytes is one short of fitting nx_block_size.
    // Catches `< with <=` (would reject 0x28, the valid minimum) and
    // any mutation that lets a too-short buffer through (which would
    // then panic reading at 0x24..0x28).
    let mut buf = vec![0u8; 0x27];
    buf[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
    buf[0x20..0x24].copy_from_slice(b"NXSB");
    assert_eq!(
        DetectedBootSector::from_bytes(&buf),
        DetectedBootSector::Unknown
    );
}

// ========================================================================
// DosBpb::looks_like_ntfs — each of the four AND-chain branches must
// independently veto an NTFS classification.
// ========================================================================

#[test]
fn looks_like_ntfs_requires_every_field_zero() {
    // Each row keeps three of the four fields zero and makes the fourth
    // non-zero. The `&&` chain must reject every row; mutating any
    // `&&` to `||` would let three of the four cases through.
    let cases: &[(u16, u8, u16, u16)] =
        &[(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)];
    for &(reserved, num_fats, root_entry, spf16) in cases {
        let bpb = create_dos_bpb(512, 8, reserved, num_fats, root_entry, 0, spf16, 0);
        assert!(
            !bpb.looks_like_ntfs(),
            "fields (reserved={reserved}, num_fats={num_fats}, root_entry={root_entry}, spf16={spf16}) must not classify as NTFS",
        );
    }

    // Sanity baseline: all-zero still classifies as NTFS-like.
    let ntfs = create_dos_bpb(512, 8, 0, 0, 0, 0, 0, 0);
    assert!(ntfs.looks_like_ntfs());
}

// ========================================================================
// DetectedBootSector::is_partition_table — anchor MBR/GPT as true.
// ========================================================================

#[test]
fn is_partition_table_true_for_mbr_and_gpt_only() {
    assert!(DetectedBootSector::MbrPartitioned.is_partition_table());
    assert!(DetectedBootSector::GptPartitioned.is_partition_table());
    // Non-partition-table variants must remain false.
    assert!(!DetectedBootSector::Ntfs.is_partition_table());
    assert!(!DetectedBootSector::Fat32.is_partition_table());
    assert!(!DetectedBootSector::ExFat.is_partition_table());
    assert!(!DetectedBootSector::Ext.is_partition_table());
    assert!(!DetectedBootSector::Apfs.is_partition_table());
    assert!(!DetectedBootSector::Btrfs.is_partition_table());
    assert!(!DetectedBootSector::BitLocker.is_partition_table());
    assert!(!DetectedBootSector::Unknown.is_partition_table());
}

// ========================================================================
// diagnose_boot_sector_standard hints — exfat_zeroed_bpb / OR logic.
// ========================================================================

#[test]
fn unknown_diagnosis_reports_exfat_zeroed_bpb_hint_when_bpb_is_all_zero() {
    // OEM "NTFS    " (so ntfs_oem_hint=true, exfat_oem_hint=false) plus
    // an all-zero BPB region. Parse fails at bytes_per_sector=0 and
    // falls through to partition-table parsing, which (no valid entries)
    // returns UnknownFilesystem — exposing the hint flags. This catches
    // both `b == 0 → b != 0` (would flip the zeroed-region check) and
    // `|| → &&` in the exfat_hint combination (would AND the two
    // exfat sub-hints, losing the zeroed-region signal).
    let mut buffer = [0u8; 512];
    buffer[510] = 0x55;
    buffer[511] = 0xAA;
    buffer[3..11].copy_from_slice(b"NTFS    ");
    // BPB region [0x0B..0x40] left all-zero on purpose.

    let diagnosis = diagnose_boot_sector(&buffer);
    assert_eq!(
        diagnosis,
        BootSectorDiagnosis::Unknown(BootSectorUnknownReason::UnknownFilesystem {
            ntfs_oem_hint: true,
            exfat_hint: true,
            bitlocker_hint: false,
            mbr_layout_hint: true,
        })
    );
}

// ========================================================================
// ExFatBootSector::is_valid — each guard rejects the corresponding
// malformation; the well-formed sector must classify as valid.
// ========================================================================

#[test]
fn exfat_is_valid_well_formed_sector() {
    // Pins `-> bool with false` on the function and the boundary shifts
    // 9 and 12 against `!(9..=12).contains(...)`.
    let bs9 = create_exfat_boot_sector(9, 3, 0);
    assert!(bs9.is_valid());
    let bs12 = create_exfat_boot_sector(12, 0, 0);
    assert!(bs12.is_valid());
}

#[test]
fn exfat_is_valid_rejects_each_invariant_violation() {
    // Bad filesystem_name — pins `!= with ==` at line 692:34.
    let mut bs = create_exfat_boot_sector(9, 3, 0);
    bs.filesystem_name = *b"EXFATXY!";
    assert!(!bs.is_valid());

    // Non-zero byte in must_be_zero — pins `delete !` at line 697:12
    // and `== with !=` at line 697:49.
    let mut bs = create_exfat_boot_sector(9, 3, 0);
    bs.must_be_zero[27] = 0xAB;
    assert!(!bs.is_valid());

    // Bad boot_signature — pins `!= with ==` at line 702:38.
    let mut bs = create_exfat_boot_sector(9, 3, 0);
    bs.boot_signature = U16::new(0x1234);
    assert!(!bs.is_valid());

    // bytes_per_sector_shift out of range below — pins `delete !` at
    // line 707:12 (would accept invalid shifts).
    let bs = create_exfat_boot_sector(8, 3, 0);
    assert!(!bs.is_valid());

    // bytes_per_sector_shift out of range above.
    let bs = create_exfat_boot_sector(13, 3, 0);
    assert!(!bs.is_valid());
}

// ========================================================================
// Full-sector parsing for each filesystem type and the partition table
// fallback. These exercise try_parse_filesystem and determine_fat_type.
// ========================================================================

/// Stamp the boot signature into bytes 0x1FE..0x200.
fn stamp_boot_signature(buf: &mut [u8; 512]) {
    buf[510] = 0x55;
    buf[511] = 0xAA;
}

/// Build a DOS BPB-bearing boot sector with the given parameters and OEM.
/// `total_16` is encoded in the 16-bit `total_sectors_16` slot; if zero,
/// `total_32` carries the 32-bit slot.
#[expect(clippy::too_many_arguments, reason = "mirrors the BPB layout")]
fn build_dos_boot_sector(
    oem: [u8; 8],
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    root_entry_count: u16,
    total_16: u16,
    spf16: u16,
    total_32: u32,
) -> [u8; 512] {
    let mut buf = [0u8; 512];
    buf[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    buf[3..11].copy_from_slice(&oem);
    buf[0x0B..0x0D].copy_from_slice(&bytes_per_sector.to_le_bytes());
    buf[0x0D] = sectors_per_cluster;
    buf[0x0E..0x10].copy_from_slice(&reserved_sectors.to_le_bytes());
    buf[0x10] = num_fats;
    buf[0x11..0x13].copy_from_slice(&root_entry_count.to_le_bytes());
    buf[0x13..0x15].copy_from_slice(&total_16.to_le_bytes());
    buf[0x15] = 0xF8;
    buf[0x16..0x18].copy_from_slice(&spf16.to_le_bytes());
    buf[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
    buf[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
    buf[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
    buf[0x20..0x24].copy_from_slice(&total_32.to_le_bytes());
    stamp_boot_signature(&mut buf);
    buf
}

fn build_fat16_sector(total_sectors_16: u16, sectors_per_fat_16: u16) -> [u8; 512] {
    // FAT16: 4085 ≤ cluster_count < 65525.
    // With 32000 sectors / 4 spc and 128 spf, cluster_count ≈ 7927.
    let mut buf = build_dos_boot_sector(
        *b"MSDOS5.0",
        512,
        4,
        1,
        2,
        512,
        total_sectors_16,
        sectors_per_fat_16,
        0,
    );
    // Fat16Ebpb: boot signature at 0x26, fs type label at 0x36.
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT16   ");
    buf
}

fn build_fat12_sector() -> [u8; 512] {
    // FAT12: cluster_count < 4085. With 2880 sectors / 1 spc and 9 spf,
    // cluster_count is well below 4085 (matches a 1.44 MB floppy).
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 2, 224, 2880, 9, 0);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
    buf
}

fn build_fat32_sector() -> [u8; 512] {
    // FAT32: sectors_per_fat_16 == 0 AND root_entry_count == 0.
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 8, 32, 2, 0, 0, 0, 4_194_304);
    // Fat32Ebpb: sectors_per_fat_32 at 0x24, boot_signature at 0x42,
    // filesystem_type at 0x52.
    buf[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
    buf[0x42] = 0x29;
    buf[0x52..0x5A].copy_from_slice(b"FAT32   ");
    buf
}

fn build_ntfs_sector() -> [u8; 512] {
    // NTFS via OEM "NTFS    " (looks_like_ntfs() is true for these fields).
    let mut buf = build_dos_boot_sector(*b"NTFS    ", 512, 8, 0, 0, 0, 0, 0, 0);
    buf[0x28..0x30].copy_from_slice(&1_048_576u64.to_le_bytes());
    buf
}

fn build_hpfs_sector() -> [u8; 512] {
    // HPFS via OEM "HPFS    " — uses Fat16Ebpb layout but a different OEM.
    let mut buf = build_dos_boot_sector(*b"HPFS    ", 512, 1, 1, 2, 512, 2880, 9, 0);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
    buf
}

fn build_exfat_sector() -> [u8; 512] {
    // exFAT: OEM "EXFAT   " plus the dedicated exFAT layout in bytes
    // 0..512. The BPB region 0x0B..0x40 must be all zero.
    let mut buf = [0u8; 512];
    buf[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    buf[3..11].copy_from_slice(b"EXFAT   ");
    // 0x0B..0x40 stays all-zero (must_be_zero).
    // Partition offset / volume length at 0x40..0x50.
    buf[0x48..0x50].copy_from_slice(&1_048_576u64.to_le_bytes()); // volume_length
    // bytes_per_sector_shift = 9 → 512.
    buf[0x6C] = 9;
    // sectors_per_cluster_shift = 3 → 8.
    buf[0x6D] = 3;
    buf[0x6E] = 1; // number_of_fats
    buf[0x6F] = 0x80; // drive_select
    stamp_boot_signature(&mut buf);
    buf
}

fn build_mbr_sector_with_partition() -> [u8; 512] {
    let mut buf = [0u8; 512];
    // Partition entry 1 (offset 446): NTFS partition.
    buf[446] = 0x80; // bootable
    buf[446 + 4] = 0x07; // partition_type NTFS/HPFS/exFAT
    buf[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes()); // start_lba
    buf[446 + 12..446 + 16].copy_from_slice(&1_000_000u32.to_le_bytes()); // sector_count
    stamp_boot_signature(&mut buf);
    buf
}

fn build_gpt_protective_sector() -> [u8; 512] {
    let mut buf = [0u8; 512];
    // Partition entry 1: GPT protective marker.
    buf[446 + 4] = crate::partition::MBR_TYPE_GPT_PROTECTIVE;
    buf[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    buf[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    stamp_boot_signature(&mut buf);
    buf
}

#[test]
fn parse_boot_sector_classifies_each_supported_filesystem() {
    // Each variant gets one canonical fixture; we check both the
    // ParsedBootSector variant and DetectedBootSector::from_bytes
    // classification. Together these anchor:
    //  - line 1109 `||` (NTFS detection via OEM ID OR looks_like_ntfs)
    //  - line 1121 `==` & `&&` (FAT32 detection via two zero-field check)
    //  - line 1136 `==` (HPFS detection via OEM prefix)
    //  - line 1150/1156 match arms FAT12/FAT16
    //  - line 1074 `||` & `==` (exFAT detection via OEM OR zeroed BPB)
    //  - line 1076 `==` (exFAT BPB-zeroed all-bytes check)
    //  - the FilesystemType::Fat12 / Fat16 match arms in
    //    try_parse_filesystem.

    let fat12 = build_fat12_sector();
    assert!(matches!(
        parse_boot_sector(&fat12).unwrap(),
        ParsedBootSector::Fat12 { .. }
    ));
    assert_eq!(
        DetectedBootSector::from_bytes(&fat12),
        DetectedBootSector::Fat12
    );

    let fat16 = build_fat16_sector(32000, 128);
    assert!(matches!(
        parse_boot_sector(&fat16).unwrap(),
        ParsedBootSector::Fat16 { .. }
    ));
    assert_eq!(
        DetectedBootSector::from_bytes(&fat16),
        DetectedBootSector::Fat16
    );

    let fat32 = build_fat32_sector();
    assert!(matches!(
        parse_boot_sector(&fat32).unwrap(),
        ParsedBootSector::Fat32 { .. }
    ));
    assert_eq!(
        DetectedBootSector::from_bytes(&fat32),
        DetectedBootSector::Fat32
    );

    let ntfs = build_ntfs_sector();
    assert!(matches!(
        parse_boot_sector(&ntfs).unwrap(),
        ParsedBootSector::Ntfs { .. }
    ));
    assert_eq!(
        DetectedBootSector::from_bytes(&ntfs),
        DetectedBootSector::Ntfs
    );

    let hpfs = build_hpfs_sector();
    assert!(matches!(
        parse_boot_sector(&hpfs).unwrap(),
        ParsedBootSector::Hpfs { .. }
    ));
    // HPFS is unsupported by DetectedBootSector → maps to Unknown.
    assert_eq!(
        DetectedBootSector::from_bytes(&hpfs),
        DetectedBootSector::Unknown
    );

    let exfat = build_exfat_sector();
    assert!(matches!(
        parse_boot_sector(&exfat).unwrap(),
        ParsedBootSector::ExFat { .. }
    ));
    assert_eq!(
        DetectedBootSector::from_bytes(&exfat),
        DetectedBootSector::ExFat
    );

    let mbr = build_mbr_sector_with_partition();
    assert!(matches!(
        parse_boot_sector(&mbr).unwrap(),
        ParsedBootSector::Mbr { .. }
    ));
    assert_eq!(
        DetectedBootSector::from_bytes(&mbr),
        DetectedBootSector::MbrPartitioned
    );

    let gpt = build_gpt_protective_sector();
    assert!(matches!(
        parse_boot_sector(&gpt).unwrap(),
        ParsedBootSector::Gpt { .. }
    ));
    assert_eq!(
        DetectedBootSector::from_bytes(&gpt),
        DetectedBootSector::GptPartitioned
    );
}

#[test]
fn ntfs_detection_via_looks_like_ntfs_when_oem_is_not_ntfs() {
    // Mutating line 1109 `||` → `&&` would break detection of NTFS
    // volumes whose OEM ID was overwritten (still valid on-disk: the
    // spec allows arbitrary OEMs and Microsoft formerly warned against
    // OEM-based detection). This anchors the looks_like_ntfs() branch.
    let mut buf = build_ntfs_sector();
    buf[3..11].copy_from_slice(b"GENERIC ");
    assert!(matches!(
        parse_boot_sector(&buf).unwrap(),
        ParsedBootSector::Ntfs { .. }
    ));
}

#[test]
fn fat32_detection_requires_zero_root_entry_and_zero_sectors_per_fat_16() {
    // Both `sectors_per_fat_16 == 0` AND `root_entry_count == 0` must
    // hold for FAT32; mutating either `==` to `!=`, or the inner `&&`
    // to `||`, would misclassify these adjacent edges.
    let buf = build_fat32_sector();
    assert!(matches!(
        parse_boot_sector(&buf).unwrap(),
        ParsedBootSector::Fat32 { .. }
    ));

    // Non-zero root_entry_count → not FAT32 (lands as FAT16/12).
    let mut buf = build_fat32_sector();
    buf[0x11..0x13].copy_from_slice(&512u16.to_le_bytes());
    // The cluster-count calculation now needs a non-zero spf16 to
    // avoid the "FAT32 here" early-return inside determine_fat_type,
    // so set sectors_per_fat_16 too.
    buf[0x16..0x18].copy_from_slice(&128u16.to_le_bytes());
    buf[0x13..0x15].copy_from_slice(&32000u16.to_le_bytes());
    assert!(!matches!(
        parse_boot_sector(&buf).unwrap(),
        ParsedBootSector::Fat32 { .. }
    ));

    // Non-zero sectors_per_fat_16 → not FAT32.
    let mut buf = build_fat32_sector();
    buf[0x16..0x18].copy_from_slice(&128u16.to_le_bytes());
    buf[0x13..0x15].copy_from_slice(&32000u16.to_le_bytes());
    buf[0x11..0x13].copy_from_slice(&512u16.to_le_bytes());
    assert!(!matches!(
        parse_boot_sector(&buf).unwrap(),
        ParsedBootSector::Fat32 { .. }
    ));
}

#[test]
fn hpfs_detection_via_oem_prefix() {
    // Mutates line 1136 `==` → `!=` would swap HPFS detection. The
    // build_hpfs_sector covers the HPFS arm; an "OS2 " prefix is also
    // valid per the implementation and exercises the second `==`.
    let hpfs = build_hpfs_sector();
    assert!(matches!(
        parse_boot_sector(&hpfs).unwrap(),
        ParsedBootSector::Hpfs { .. }
    ));

    let mut os2 = hpfs;
    os2[3..7].copy_from_slice(b"OS2 ");
    assert!(matches!(
        parse_boot_sector(&os2).unwrap(),
        ParsedBootSector::Hpfs { .. }
    ));

    // Non-HPFS OEM with otherwise-identical layout lands as FAT.
    let mut fat = hpfs;
    fat[3..11].copy_from_slice(b"MSDOS5.0");
    let parsed = parse_boot_sector(&fat).unwrap();
    assert!(
        matches!(
            parsed,
            ParsedBootSector::Fat12 { .. } | ParsedBootSector::Fat16 { .. }
        ),
        "non-HPFS OEM should fall through to FAT12/16, got {parsed:?}",
    );
}

// ========================================================================
// determine_fat_type cluster-count boundaries
// ========================================================================

#[test]
fn fat12_to_fat16_boundary_at_4085_clusters() {
    // FAT16 begins at 4085 clusters. Anchors line 1232 `<` against
    // `<=`, `==`, `>`.  We choose total_sectors_16 to land just above
    // and just below the boundary.

    // 1 spc, 1 reserved sector, 2 FATs, root_entry_count=16 → 1 root-dir
    // sector (16*32=512). spf16 = 1 → fat_size = 1 sector each. So
    // first_data_sector = 1 + 2*1 + 1 = 4. cluster_count = total - 4.
    // To get 4084 (FAT12) clusters: total = 4088.
    let buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 2, 16, 4088, 1, 0);
    let mut buf = buf;
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
    assert!(matches!(
        parse_boot_sector(&buf).unwrap(),
        ParsedBootSector::Fat12 { .. }
    ));

    // 4085 clusters → FAT16. total = 4089.
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 2, 16, 4089, 1, 0);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT16   ");
    assert!(matches!(
        parse_boot_sector(&buf).unwrap(),
        ParsedBootSector::Fat16 { .. }
    ));
}

#[test]
fn fat16_to_fat32_boundary_uses_cluster_count_threshold() {
    // The FAT16/FAT32 boundary is at 65525 clusters in determine_fat_type.
    // determine_fat_type only runs when sectors_per_fat_16 != 0, so
    // both fixtures here carry a non-zero spf16. Just under the
    // boundary → FAT16; ≥ 65525 → returned as FAT32 from
    // determine_fat_type, but try_parse_filesystem's outer match would
    // then return UnknownFilesystem (FAT32 path requires spf16 == 0).
    // Anchors line 1234 `<` against `<=`, `==`, `>`.

    // 65524 clusters → FAT16. With 1 spc, 0 root entries, 1 reserved, 1
    // FAT, fat_size=1 → first_data_sector = 1+1+0 = 2. total = 65526.
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 1, 0, 0, 1, 65526);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT16   ");
    assert!(matches!(
        parse_boot_sector(&buf).unwrap(),
        ParsedBootSector::Fat16 { .. }
    ));

    // 65525 clusters → determine_fat_type returns Fat32; the outer
    // match doesn't have a FAT32 arm for FAT16-style layouts, so
    // try_parse_filesystem returns Err(UnknownFilesystem). Falls
    // through to the partition-table path, which also fails (no
    // partition entries), yielding Err(UnknownFilesystem).
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 1, 0, 0, 1, 65527);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
    let err = parse_boot_sector(&buf).unwrap_err();
    assert_eq!(err, ParseError::UnknownFilesystem);
}

#[test]
fn determine_fat_type_rejects_zero_bytes_per_sector_branch() {
    // bytes_per_sector or sectors_per_cluster of 0 makes the FAT12/16
    // path return UnknownFilesystem at the front of determine_fat_type.
    // try_parse_filesystem's early bytes_per_sector validation catches
    // bps=0 first (InvalidBytesPerSector) — so to actually exercise
    // determine_fat_type's `== 0 || == 0` guard we need a path that
    // bypasses that. Setting spc=0 with a valid bps does the job:
    // bps=512 passes the matches!() guard, then determine_fat_type
    // hits its zero-spc check.
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 0, 1, 2, 16, 4096, 1, 0);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
    // determine_fat_type → Unknown → outer match returns UnknownFilesystem.
    // Then partition-table fallback runs; no valid partitions → still
    // Err(UnknownFilesystem).
    let err = parse_boot_sector(&buf).unwrap_err();
    assert_eq!(err, ParseError::UnknownFilesystem);
}

#[test]
fn determine_fat_type_requires_non_zero_sectors_per_fat_16() {
    // sectors_per_fat_16 == 0 makes determine_fat_type return Unknown
    // because the FAT32-style EBPB doesn't carry the value here.
    // Anchors line 1210 `!= with ==` — flipping the inequality would
    // claim the value `0` is valid and proceed to a divide-by-zero
    // shaped calculation.
    //
    // Build a layout that isn't FAT32 (non-zero root_entry_count) but
    // has spf16 == 0 — the outer FAT32 branch is gated by
    // root_entry_count == 0, so we go through the FAT12/16 path,
    // which lands in determine_fat_type with spf16 == 0 and returns
    // Unknown.
    let mut buf = build_dos_boot_sector(*b"MSDOS5.0", 512, 1, 1, 2, 16, 4096, 0, 0);
    buf[0x26] = 0x29;
    buf[0x36..0x3E].copy_from_slice(b"FAT12   ");
    let err = parse_boot_sector(&buf).unwrap_err();
    assert_eq!(err, ParseError::UnknownFilesystem);
}
