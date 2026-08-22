use super::ext::*;
use super::*;
use core::mem::size_of;

#[test]
fn test_structure_sizes() {
    assert_eq!(size_of::<BootSectorHeader>(), 11);
    assert_eq!(size_of::<DosBpb>(), 25);
    assert_eq!(size_of::<Fat16Ebpb>(), 26);
    assert_eq!(size_of::<Fat32Ebpb>(), 54);
    assert_eq!(size_of::<NtfsEbpb>(), 48);
    assert_eq!(size_of::<ExFatBootSector>(), 512);
    assert_eq!(size_of::<Fat32FsInfo>(), 512);

    // Verify complete boot sector layouts
    assert_eq!(size_of::<Fat16BootSector>(), 512);
    assert_eq!(size_of::<Fat32BootSector>(), 512);
    assert_eq!(size_of::<NtfsBootSector>(), 512);
}

#[test]
fn test_ntfs_cluster_size_decode() {
    let cluster_size = 4096u32;

    // Positive value: multiply by cluster size
    assert_eq!(NtfsEbpb::decode_cluster_size_field(1, cluster_size), 4096);
    assert_eq!(NtfsEbpb::decode_cluster_size_field(2, cluster_size), 8192);

    // Negative value: 2^(-value) bytes
    // -10 (0xF6 as i8) = 2^10 = 1024
    assert_eq!(NtfsEbpb::decode_cluster_size_field(-10, cluster_size), 1024);
    // -12 (0xF4 as i8) = 2^12 = 4096
    assert_eq!(NtfsEbpb::decode_cluster_size_field(-12, cluster_size), 4096);
}

#[test]
fn test_exfat_calculations() {
    // Test shift calculations
    assert_eq!(1u32 << 9, 512); // bytes_per_sector_shift = 9
    assert_eq!(1u32 << 12, 4096); // bytes_per_sector_shift = 12
    assert_eq!(1u32 << (9 + 3), 4096); // 512 byte sectors, 8 sectors per cluster
}

fn create_header(oem_id: [u8; 8]) -> BootSectorHeader {
    BootSectorHeader {
        jump_instruction: [0xEB, 0x76, 0x90],
        oem_id,
    }
}

#[test]
fn test_boot_sector_header_is_ntfs() {
    let ntfs_header = create_header(*b"NTFS    ");
    assert!(ntfs_header.is_ntfs());
    assert!(!ntfs_header.is_exfat());

    let fat_header = create_header(*b"MSDOS5.0");
    assert!(!fat_header.is_ntfs());

    let other_header = create_header(*b"NTFS    "); // trailing different (for completeness)
    assert!(other_header.is_ntfs());

    let almost_ntfs = create_header(*b"NTFS   \0");
    assert!(!almost_ntfs.is_ntfs()); // must be exactly "NTFS    "
}

#[test]
fn test_boot_sector_header_is_exfat() {
    let exfat_header = create_header(*b"EXFAT   ");
    assert!(exfat_header.is_exfat());
    assert!(!exfat_header.is_ntfs());

    let fat_header = create_header(*b"MSDOS5.0");
    assert!(!fat_header.is_exfat());

    let almost_exfat = create_header(*b"EXFAT  \0");
    assert!(!almost_exfat.is_exfat()); // must be exactly "EXFAT   "
}

#[test]
fn test_boot_sector_header_oem_id_str() {
    let ntfs_header = create_header(*b"NTFS    ");
    assert_eq!(ntfs_header.oem_id_str(), "NTFS");

    let fat_header = create_header(*b"MSDOS5.0");
    assert_eq!(fat_header.oem_id_str(), "MSDOS5.0");

    let mkdosfs_header = create_header(*b"mkdosfs ");
    assert_eq!(mkdosfs_header.oem_id_str(), "mkdosfs");

    // Test with null bytes
    let null_header = create_header(*b"TEST\0\0\0\0");
    assert_eq!(null_header.oem_id_str(), "TEST");

    // Test with mixed spaces and nulls - trim_end removes consecutive trailing space/null
    let mixed_header = create_header(*b"ABC \0 \0\0");
    assert_eq!(mixed_header.oem_id_str(), "ABC"); // all trailing space/null trimmed
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper mirrors DosBpb fields"
)]
fn create_dos_bpb(
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    root_entry_count: u16,
    total_sectors_16: u16,
    sectors_per_fat_16: u16,
    total_sectors_32: u32,
) -> DosBpb {
    DosBpb {
        bytes_per_sector: U16::new(bytes_per_sector),
        sectors_per_cluster,
        reserved_sectors: U16::new(reserved_sectors),
        num_fats,
        root_entry_count: U16::new(root_entry_count),
        total_sectors_16: U16::new(total_sectors_16),
        media_descriptor: 0xF8,
        sectors_per_fat_16: U16::new(sectors_per_fat_16),
        sectors_per_track: U16::new(63),
        num_heads: U16::new(255),
        hidden_sectors: U32::new(0),
        total_sectors_32: U32::new(total_sectors_32),
    }
}

#[test]
fn test_dos_bpb_total_sectors_16bit() {
    // When total_sectors_16 is non-zero, use it
    let bpb = create_dos_bpb(512, 1, 1, 2, 512, 2880, 9, 0);
    assert_eq!(bpb.total_sectors(), 2880);
}

#[test]
fn ext_variant_exists_and_is_a_filesystem() {
    let variant = DetectedBootSector::Ext;
    assert!(variant.is_filesystem(), "Ext must classify as a filesystem");
    assert!(!variant.is_partition_table());
}

#[test]
fn test_dos_bpb_total_sectors_32bit() {
    // When total_sectors_16 is 0, use total_sectors_32
    let bpb = create_dos_bpb(512, 8, 32, 2, 0, 0, 0, 4_194_304);
    assert_eq!(bpb.total_sectors(), 4_194_304);
}

#[test]
fn test_dos_bpb_cluster_size() {
    // 512 bytes/sector * 1 sector/cluster = 512 bytes/cluster
    let bpb1 = create_dos_bpb(512, 1, 1, 2, 512, 2880, 9, 0);
    assert_eq!(bpb1.cluster_size(), 512);

    // 512 bytes/sector * 8 sectors/cluster = 4096 bytes/cluster
    let bpb2 = create_dos_bpb(512, 8, 32, 2, 0, 0, 0, 4_194_304);
    assert_eq!(bpb2.cluster_size(), 4096);

    // 4096 bytes/sector * 1 sector/cluster = 4096 bytes/cluster
    let bpb3 = create_dos_bpb(4096, 1, 1, 2, 0, 0, 0, 1_000_000);
    assert_eq!(bpb3.cluster_size(), 4096);

    // 4096 bytes/sector * 128 sectors/cluster = 524_288 bytes/cluster
    let bpb4 = create_dos_bpb(4096, 128, 32, 2, 0, 0, 0, 10_000_000);
    assert_eq!(bpb4.cluster_size(), 524_288);
}

#[test]
fn test_dos_bpb_looks_like_ntfs() {
    // NTFS: reserved_sectors=0, num_fats=0, root_entry_count=0, sectors_per_fat_16=0
    let ntfs_bpb = create_dos_bpb(512, 8, 0, 0, 0, 0, 0, 0);
    assert!(ntfs_bpb.looks_like_ntfs());

    // FAT16: has reserved sectors and FATs
    let fat16_bpb = create_dos_bpb(512, 4, 1, 2, 512, 32000, 128, 0);
    assert!(!fat16_bpb.looks_like_ntfs());

    // FAT32: has reserved sectors and FATs (even though sectors_per_fat_16=0)
    let fat32_bpb = create_dos_bpb(512, 8, 32, 2, 0, 0, 0, 4_194_304);
    assert!(!fat32_bpb.looks_like_ntfs()); // has reserved_sectors and num_fats
}

#[test]
fn test_dos_bpb_looks_like_exfat() {
    // exFAT: bytes_per_sector=0 (uses shift instead)
    let exfat_bpb = create_dos_bpb(0, 0, 0, 0, 0, 0, 0, 0);
    assert!(exfat_bpb.looks_like_exfat());

    // FAT: has bytes_per_sector
    let fat_bpb = create_dos_bpb(512, 4, 1, 2, 512, 32000, 128, 0);
    assert!(!fat_bpb.looks_like_exfat());
}

fn create_fat16_ebpb(boot_sig: u8, volume_label: &[u8; 11], fs_type: [u8; 8]) -> Fat16Ebpb {
    Fat16Ebpb {
        drive_number: 0x80,
        reserved1: 0,
        boot_signature: boot_sig,
        volume_serial_number: U32::new(0x1234_5678),
        volume_label: *volume_label,
        filesystem_type: fs_type,
    }
}

#[test]
fn test_fat16_ebpb_has_extended_fields() {
    // 0x29 means all extended fields are valid
    let ebpb_29 = create_fat16_ebpb(0x29, b"NO NAME    ", *b"FAT16   ");
    assert!(ebpb_29.has_extended_fields());

    // 0x28 means only serial number is valid
    let ebpb_28 = create_fat16_ebpb(0x28, b"NO NAME    ", *b"FAT16   ");
    assert!(ebpb_28.has_extended_fields());

    // Other values mean no extended fields
    let ebpb_other = create_fat16_ebpb(0x00, b"NO NAME    ", *b"FAT16   ");
    assert!(!ebpb_other.has_extended_fields());

    let ebpb_27 = create_fat16_ebpb(0x27, b"NO NAME    ", *b"FAT16   ");
    assert!(!ebpb_27.has_extended_fields());
}

#[test]
fn test_fat16_ebpb_volume_label_str() {
    let ebpb = create_fat16_ebpb(0x29, b"MY VOLUME  ", *b"FAT16   ");
    assert_eq!(ebpb.volume_label_str(), "MY VOLUME");

    let ebpb_no_label = create_fat16_ebpb(0x29, b"NO NAME    ", *b"FAT16   ");
    assert_eq!(ebpb_no_label.volume_label_str(), "NO NAME");

    // Test with null bytes
    let ebpb_null = create_fat16_ebpb(0x29, b"LABEL\0\0\0\0\0\0", *b"FAT16   ");
    assert_eq!(ebpb_null.volume_label_str(), "LABEL");
}

#[test]
fn test_fat16_ebpb_filesystem_type_str() {
    let ebpb_fat12 = create_fat16_ebpb(0x29, b"NO NAME    ", *b"FAT12   ");
    assert_eq!(ebpb_fat12.filesystem_type_str(), "FAT12");

    let ebpb_fat16 = create_fat16_ebpb(0x29, b"NO NAME    ", *b"FAT16   ");
    assert_eq!(ebpb_fat16.filesystem_type_str(), "FAT16");

    let ebpb_fat = create_fat16_ebpb(0x29, b"NO NAME    ", *b"FAT     ");
    assert_eq!(ebpb_fat.filesystem_type_str(), "FAT");
}

fn create_fat32_ebpb(ext_flags: u16, volume_label: &[u8; 11]) -> Fat32Ebpb {
    Fat32Ebpb {
        sectors_per_fat_32: U32::new(4096),
        ext_flags: U16::new(ext_flags),
        fs_version: U16::new(0),
        root_cluster: U32::new(2),
        fs_info_sector: U16::new(1),
        backup_boot_sector: U16::new(6),
        reserved: [0; 12],
        drive_number: 0x80,
        reserved1: 0,
        boot_signature: 0x29,
        volume_serial_number: U32::new(0x1234_5678),
        volume_label: *volume_label,
        filesystem_type: *b"FAT32   ",
    }
}

#[test]
fn test_fat32_ebpb_fat_mirroring_enabled() {
    // Bit 7 clear = mirroring enabled
    let ebpb_mirrored = create_fat32_ebpb(0x0000, b"NO NAME    ");
    assert!(ebpb_mirrored.fat_mirroring_enabled());

    // Bit 7 set = mirroring disabled
    let ebpb_not_mirrored = create_fat32_ebpb(0x0080, b"NO NAME    ");
    assert!(!ebpb_not_mirrored.fat_mirroring_enabled());

    // Other bits shouldn't affect this
    let ebpb_other_bits = create_fat32_ebpb(0x000F, b"NO NAME    ");
    assert!(ebpb_other_bits.fat_mirroring_enabled());
}

#[test]
fn test_fat32_ebpb_active_fat() {
    // Active FAT is in bits 0-3
    let ebpb_fat0 = create_fat32_ebpb(0x0080, b"NO NAME    ");
    assert_eq!(ebpb_fat0.active_fat(), 0);

    let ebpb_fat1 = create_fat32_ebpb(0x0081, b"NO NAME    ");
    assert_eq!(ebpb_fat1.active_fat(), 1);

    let ebpb_fat15 = create_fat32_ebpb(0x008F, b"NO NAME    ");
    assert_eq!(ebpb_fat15.active_fat(), 15);

    // Upper bits shouldn't affect result
    let ebpb_upper_bits = create_fat32_ebpb(0xFF03, b"NO NAME    ");
    assert_eq!(ebpb_upper_bits.active_fat(), 3);
}

#[test]
fn test_fat32_ebpb_volume_label_str() {
    let ebpb = create_fat32_ebpb(0x0000, b"MY DRIVE   ");
    assert_eq!(ebpb.volume_label_str(), "MY DRIVE");

    let ebpb_null = create_fat32_ebpb(0x0000, b"TEST\0\0\0\0\0\0\0");
    assert_eq!(ebpb_null.volume_label_str(), "TEST");
}

fn create_fat32_fsinfo(
    lead_sig: u32,
    struct_sig: u32,
    trail_sig: u32,
    free_count: u32,
    next_free: u32,
) -> Fat32FsInfo {
    Fat32FsInfo {
        lead_signature: U32::new(lead_sig),
        reserved1: [0; 480],
        struct_signature: U32::new(struct_sig),
        free_cluster_count: U32::new(free_count),
        next_free_cluster: U32::new(next_free),
        reserved2: [0; 12],
        trail_signature: U32::new(trail_sig),
    }
}

#[test]
fn test_fat32_fsinfo_is_valid() {
    // All signatures correct
    let valid = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        1000,
        100,
    );
    assert!(valid.is_valid());

    // Invalid lead signature
    let invalid_lead = create_fat32_fsinfo(
        0x0000_0000,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        1000,
        100,
    );
    assert!(!invalid_lead.is_valid());

    // Invalid struct signature
    let invalid_struct = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        0x0000_0000,
        Fat32FsInfo::TRAIL_SIGNATURE,
        1000,
        100,
    );
    assert!(!invalid_struct.is_valid());

    // Invalid trail signature
    let invalid_trail = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        0x0000_0000,
        1000,
        100,
    );
    assert!(!invalid_trail.is_valid());
}

#[test]
fn test_fat32_fsinfo_free_clusters() {
    // Known value
    let fsinfo_known = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        50000,
        100,
    );
    assert_eq!(fsinfo_known.free_clusters(), Some(50000));

    // Unknown (0xFFFF_FFFF)
    let fsinfo_unknown = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        0xFFFF_FFFF,
        100,
    );
    assert_eq!(fsinfo_unknown.free_clusters(), None);

    // Zero is valid
    let fsinfo_zero = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        0,
        100,
    );
    assert_eq!(fsinfo_zero.free_clusters(), Some(0));
}

#[test]
fn test_fat32_fsinfo_next_free() {
    // Valid hint (>= 2)
    let fsinfo_valid = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        1000,
        100,
    );
    assert_eq!(fsinfo_valid.next_free(), Some(100));

    // Cluster 2 is valid (first data cluster)
    let fsinfo_cluster2 = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        1000,
        2,
    );
    assert_eq!(fsinfo_cluster2.next_free(), Some(2));

    // Unknown (0xFFFF_FFFF)
    let fsinfo_unknown = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        1000,
        0xFFFF_FFFF,
    );
    assert_eq!(fsinfo_unknown.next_free(), None);

    // Invalid (< 2)
    let fsinfo_zero = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        1000,
        0,
    );
    assert_eq!(fsinfo_zero.next_free(), None);

    let fsinfo_one = create_fat32_fsinfo(
        Fat32FsInfo::LEAD_SIGNATURE,
        Fat32FsInfo::STRUCT_SIGNATURE,
        Fat32FsInfo::TRAIL_SIGNATURE,
        1000,
        1,
    );
    assert_eq!(fsinfo_one.next_free(), None);
}

fn create_exfat_boot_sector(
    bytes_per_sector_shift: u8,
    sectors_per_cluster_shift: u8,
    volume_flags: u16,
) -> ExFatBootSector {
    ExFatBootSector {
        jump_instruction: [0xEB, 0x76, 0x90],
        filesystem_name: *b"EXFAT   ",
        must_be_zero: [0; 53],
        partition_offset: U64::new(0),
        volume_length: U64::new(1_000_000),
        fat_offset: U32::new(24),
        fat_length: U32::new(1024),
        cluster_heap_offset: U32::new(1048),
        cluster_count: U32::new(100_000),
        root_directory_cluster: U32::new(4),
        volume_serial_number: U32::new(0x1234_5678),
        filesystem_revision: U16::new(0x0100),
        volume_flags: U16::new(volume_flags),
        bytes_per_sector_shift,
        sectors_per_cluster_shift,
        number_of_fats: 1,
        drive_select: 0x80,
        percent_in_use: 50,
        reserved: [0; 7],
        boot_code: [0; 390],
        boot_signature: U16::new(BOOT_SIGNATURE),
    }
}

#[test]
fn test_exfat_bytes_per_sector() {
    // Shift 9 = 512 bytes
    let exfat_512 = create_exfat_boot_sector(9, 0, 0);
    assert_eq!(exfat_512.bytes_per_sector(), 512);

    // Shift 10 = 1024 bytes
    let exfat_1024 = create_exfat_boot_sector(10, 0, 0);
    assert_eq!(exfat_1024.bytes_per_sector(), 1024);

    // Shift 11 = 2048 bytes
    let exfat_2048 = create_exfat_boot_sector(11, 0, 0);
    assert_eq!(exfat_2048.bytes_per_sector(), 2048);

    // Shift 12 = 4096 bytes
    let exfat_4096 = create_exfat_boot_sector(12, 0, 0);
    assert_eq!(exfat_4096.bytes_per_sector(), 4096);
}

#[test]
fn test_exfat_sectors_per_cluster() {
    // Shift 0 = 1 sector per cluster
    let exfat_1 = create_exfat_boot_sector(9, 0, 0);
    assert_eq!(exfat_1.sectors_per_cluster(), 1);

    // Shift 3 = 8 sectors per cluster
    let exfat_8 = create_exfat_boot_sector(9, 3, 0);
    assert_eq!(exfat_8.sectors_per_cluster(), 8);

    // Shift 7 = 128 sectors per cluster
    let exfat_128 = create_exfat_boot_sector(9, 7, 0);
    assert_eq!(exfat_128.sectors_per_cluster(), 128);
}

#[test]
fn test_exfat_cluster_size() {
    // 512 bytes/sector * 1 sector/cluster = 512 bytes
    let exfat_512 = create_exfat_boot_sector(9, 0, 0);
    assert_eq!(exfat_512.cluster_size(), 512);

    // 512 bytes/sector * 8 sectors/cluster = 4096 bytes
    let exfat_4k = create_exfat_boot_sector(9, 3, 0);
    assert_eq!(exfat_4k.cluster_size(), 4096);

    // 4096 bytes/sector * 8 sectors/cluster = 32768 bytes
    let large_sector_exfat = create_exfat_boot_sector(12, 3, 0);
    assert_eq!(large_sector_exfat.cluster_size(), 32768);

    // 4096 bytes/sector * 128 sectors/cluster = 524_288 bytes (max recommended)
    let exfat_max = create_exfat_boot_sector(12, 7, 0);
    assert_eq!(exfat_max.cluster_size(), 524_288);
}

#[test]
fn test_exfat_is_dirty() {
    // Bit 1 clear = not dirty
    let exfat_clean = create_exfat_boot_sector(9, 3, 0x0000);
    assert!(!exfat_clean.is_dirty());

    // Bit 1 set = dirty
    let exfat_dirty = create_exfat_boot_sector(9, 3, 0x0002);
    assert!(exfat_dirty.is_dirty());

    // Other bits shouldn't affect dirty flag
    let exfat_other = create_exfat_boot_sector(9, 3, 0xFFFD);
    assert!(!exfat_other.is_dirty());
}

#[test]
fn test_exfat_has_media_failure() {
    // Bit 2 clear = no media failure
    let exfat_ok = create_exfat_boot_sector(9, 3, 0x0000);
    assert!(!exfat_ok.has_media_failure());

    // Bit 2 set = media failure
    let exfat_failure = create_exfat_boot_sector(9, 3, 0x0004);
    assert!(exfat_failure.has_media_failure());

    // Other bits shouldn't affect media failure flag
    let exfat_other = create_exfat_boot_sector(9, 3, 0xFFFB);
    assert!(!exfat_other.has_media_failure());
}

#[test]
fn test_exfat_active_fat() {
    // Bit 0 clear = first FAT (0)
    let exfat_fat0 = create_exfat_boot_sector(9, 3, 0x0000);
    assert_eq!(exfat_fat0.active_fat(), 0);

    // Bit 0 set = second FAT (1)
    let exfat_fat1 = create_exfat_boot_sector(9, 3, 0x0001);
    assert_eq!(exfat_fat1.active_fat(), 1);

    // Other bits shouldn't affect active FAT
    let exfat_other = create_exfat_boot_sector(9, 3, 0xFFFE);
    assert_eq!(exfat_other.active_fat(), 0);
}

#[test]
fn test_filesystem_type_debug() {
    // Test Debug derivation
    let fat12 = FilesystemType::Fat12;
    let debug_str = format!("{fat12:?}");
    assert_eq!(debug_str, "Fat12");

    let ntfs = FilesystemType::Ntfs;
    let debug_str = format!("{ntfs:?}");
    assert_eq!(debug_str, "Ntfs");
}

#[test]
fn test_filesystem_type_clone() {
    let fat16 = FilesystemType::Fat16;
    let cloned = fat16;
    assert_eq!(fat16, cloned);
}

#[test]
fn test_filesystem_type_partial_eq() {
    assert_eq!(FilesystemType::Fat12, FilesystemType::Fat12);
    assert_ne!(FilesystemType::Fat12, FilesystemType::Fat16);
    assert_ne!(FilesystemType::Ntfs, FilesystemType::ExFat);
    assert_eq!(FilesystemType::Unknown, FilesystemType::Unknown);
}

#[test]
fn test_filesystem_type_copy() {
    let fat32 = FilesystemType::Fat32;
    let copied = fat32; // Copy, not move
    assert_eq!(fat32, copied); // Can still use original
}

#[test]
fn test_parse_error_debug() {
    let err = ParseError::BufferTooSmall;
    let debug_str = format!("{err:?}");
    assert_eq!(debug_str, "BufferTooSmall");

    let err2 = ParseError::InvalidBootSignature;
    let debug_str2 = format!("{err2:?}");
    assert_eq!(debug_str2, "InvalidBootSignature");
}

#[test]
fn test_parse_error_clone() {
    let err = ParseError::InvalidBytesPerSector;
    let cloned = err;
    assert_eq!(err, cloned);
}

#[test]
fn test_parse_error_partial_eq() {
    assert_eq!(ParseError::BufferTooSmall, ParseError::BufferTooSmall);
    assert_ne!(ParseError::BufferTooSmall, ParseError::ParseFailed);
    assert_eq!(ParseError::UnknownFilesystem, ParseError::UnknownFilesystem);
}

#[test]
fn test_parse_error_copy() {
    let err = ParseError::ParseFailed;
    let copied = err; // Copy, not move
    assert_eq!(err, copied); // Can still use original
}

#[test]
fn test_ntfs_ebpb_mft_record_size() {
    let mut ebpb_data = [0u8; 48];
    // clusters_per_mft_record at offset 0x40 - 0x24 = 0x1C (28)
    ebpb_data[28] = 0xF6u8; // -10 as i8 = 1024 bytes

    let ebpb = NtfsEbpb::ref_from_bytes(&ebpb_data).unwrap();
    assert_eq!(ebpb.mft_record_size(4096), 1024);
}

#[test]
fn test_ntfs_ebpb_index_buffer_size() {
    let mut ebpb_data = [0u8; 48];
    // clusters_per_index_buffer at offset 0x44 - 0x24 = 0x20 (32)
    ebpb_data[32] = 0xF4u8; // -12 as i8 = 4096 bytes

    let ebpb = NtfsEbpb::ref_from_bytes(&ebpb_data).unwrap();
    assert_eq!(ebpb.index_buffer_size(4096), 4096);
}

#[test]
fn test_ntfs_ebpb_positive_cluster_values() {
    let mut ebpb_data = [0u8; 48];
    // Test with positive cluster counts
    ebpb_data[28] = 2; // 2 clusters per MFT record
    ebpb_data[32] = 4; // 4 clusters per index buffer

    let ebpb = NtfsEbpb::ref_from_bytes(&ebpb_data).unwrap();
    assert_eq!(ebpb.mft_record_size(4096), 8192); // 2 * 4096
    assert_eq!(ebpb.index_buffer_size(4096), 16384); // 4 * 4096
}

#[test]
fn test_parse_boot_sector_buffer_too_small() {
    let small_buffer = [0u8; 100];
    let result = parse_boot_sector(&small_buffer);
    assert_eq!(result.unwrap_err(), ParseError::BufferTooSmall);
}

#[test]
fn test_parse_boot_sector_invalid_signature() {
    let mut buffer = [0u8; 512];
    // No boot signature (0xAA55)
    let result = parse_boot_sector(&buffer);
    assert_eq!(result.unwrap_err(), ParseError::InvalidBootSignature);

    // Wrong signature
    buffer[510] = 0x00;
    buffer[511] = 0x00;
    let result2 = parse_boot_sector(&buffer);
    assert_eq!(result2.unwrap_err(), ParseError::InvalidBootSignature);
}

#[test]
fn test_boot_sector_header_is_bitlocker() {
    let bl_header = create_header(*b"-FVE-FS-");
    assert!(bl_header.is_bitlocker());
    assert!(!bl_header.is_ntfs());
    assert!(!bl_header.is_exfat());

    let ntfs_header = create_header(*b"NTFS    ");
    assert!(!ntfs_header.is_bitlocker());

    let fat_header = create_header(*b"MSDOS5.0");
    assert!(!fat_header.is_bitlocker());

    let almost_bl = create_header(*b"-FVE-FS\0");
    assert!(!almost_bl.is_bitlocker());
}

#[test]
fn test_parse_boot_sector_bitlocker() {
    let mut buffer = [0u8; 512];

    // Boot signature
    buffer[510] = 0x55;
    buffer[511] = 0xAA;

    // OEM ID: "-FVE-FS-"
    buffer[3..11].copy_from_slice(b"-FVE-FS-");

    // BPB: valid NTFS-like layout (512 bytes/sector, 8 sectors/cluster)
    buffer[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    buffer[0x0D] = 8;

    // NTFS-style EBPB fields reused by BitLocker:
    // total_sectors at offset 0x28
    buffer[0x28..0x30].copy_from_slice(&1_048_576_u64.to_le_bytes());
    // volume_serial_number at offset 0x48
    buffer[0x48..0x50].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());

    let parsed = parse_boot_sector(&buffer).expect("should parse as BitLocker");
    match parsed {
        ParsedBootSector::BitLocker {
            header,
            bpb,
            total_sectors,
            volume_serial_number,
            boot_code,
        } => {
            assert!(header.is_bitlocker());
            assert_eq!(bpb.bytes_per_sector.get(), 512);
            assert_eq!(bpb.sectors_per_cluster, 8);
            assert_eq!(total_sectors, 1_048_576);
            assert_eq!(volume_serial_number, 0xDEAD_BEEF_CAFE_BABE);
            assert_eq!(boot_code.len(), 510 - 0x54);
        }
        other => panic!("Expected BitLocker, got {other:?}"),
    }
}

#[test]
fn test_detected_boot_sector_bitlocker() {
    let mut buffer = [0u8; 512];
    buffer[510] = 0x55;
    buffer[511] = 0xAA;
    buffer[3..11].copy_from_slice(b"-FVE-FS-");
    buffer[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    buffer[0x0D] = 8;
    buffer[0x28..0x30].copy_from_slice(&1_048_576_u64.to_le_bytes());

    let detected = DetectedBootSector::from_bytes(&buffer);
    assert_eq!(detected, DetectedBootSector::BitLocker);
    assert!(!detected.is_filesystem());
    assert!(!detected.is_partition_table());
}

#[test]
fn test_bitlocker_wins_over_ntfs_like_bpb() {
    let mut buffer = [0u8; 512];
    buffer[510] = 0x55;
    buffer[511] = 0xAA;
    buffer[3..11].copy_from_slice(b"-FVE-FS-");
    buffer[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    buffer[0x0D] = 8;
    buffer[0x28..0x30].copy_from_slice(&2_097_152_u64.to_le_bytes());

    let parsed = parse_boot_sector(&buffer).expect("should parse");
    let ParsedBootSector::BitLocker { .. } = parsed else {
        panic!("Expected BitLocker, got {parsed:?}");
    };
}

#[test]
fn test_malformed_bitlocker_falls_through_to_partition_table() {
    let mut buffer = [0u8; 512];
    buffer[510] = 0x55;
    buffer[511] = 0xAA;
    buffer[3..11].copy_from_slice(b"-FVE-FS-");
    // bytes_per_sector left at 0 — invalid BPB, so filesystem parse fails
    // and falls through to partition table detection

    let result = parse_boot_sector(&buffer);
    assert_eq!(result.unwrap_err(), ParseError::UnknownFilesystem);
}
