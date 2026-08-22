use super::*;

#[test]
fn test_as_u32_known_tags() {
    assert_eq!(NtfsReparseTag::MountPoint.as_u32(), 0xA000_0003);
    assert_eq!(NtfsReparseTag::SymbolicLink.as_u32(), 0xA000_000C);
    assert_eq!(NtfsReparseTag::LxSymlink.as_u32(), 0xA000_001D);
    assert_eq!(NtfsReparseTag::GlobalReparse.as_u32(), 0xA000_0019);
    assert_eq!(NtfsReparseTag::Wof.as_u32(), 0x8000_0017);
    assert_eq!(NtfsReparseTag::Dedup.as_u32(), 0x8000_0013);
    assert_eq!(NtfsReparseTag::Nfs.as_u32(), 0x8000_0014);
    assert_eq!(NtfsReparseTag::AppExecLink.as_u32(), 0x8000_001B);
    assert_eq!(NtfsReparseTag::StorageSync.as_u32(), 0x8000_001E);
    assert_eq!(NtfsReparseTag::Dfs.as_u32(), 0x8000_000A);
    assert_eq!(NtfsReparseTag::Dfsr.as_u32(), 0x8000_0012);
    assert_eq!(NtfsReparseTag::Wim.as_u32(), 0x8000_0008);
    assert_eq!(NtfsReparseTag::Sis.as_u32(), 0x8000_0007);
    assert_eq!(NtfsReparseTag::Cloud.as_u32(), 0x9000_001A);
    assert_eq!(NtfsReparseTag::ProjFs.as_u32(), 0x9000_001C);
    assert_eq!(NtfsReparseTag::AfUnix.as_u32(), 0x8000_0023);
    assert_eq!(NtfsReparseTag::LxFifo.as_u32(), 0x8000_0024);
    assert_eq!(NtfsReparseTag::LxChr.as_u32(), 0x8000_0025);
    assert_eq!(NtfsReparseTag::LxBlk.as_u32(), 0x8000_0026);
    assert_eq!(NtfsReparseTag::Wci.as_u32(), 0x8000_0018);
    assert_eq!(NtfsReparseTag::Wci1.as_u32(), 0x9000_1018);
    assert_eq!(NtfsReparseTag::WciTombstone.as_u32(), 0xA000_001F);
    assert_eq!(NtfsReparseTag::WciLink.as_u32(), 0xA000_0027);
    assert_eq!(NtfsReparseTag::WciLink1.as_u32(), 0xA000_1027);
    assert_eq!(NtfsReparseTag::Hsm.as_u32(), 0xC000_0004);
    assert_eq!(NtfsReparseTag::DriveExtender.as_u32(), 0x8000_0005);
    assert_eq!(NtfsReparseTag::Hsm2.as_u32(), 0x8000_0006);
    assert_eq!(NtfsReparseTag::Csv.as_u32(), 0x8000_0009);
    assert_eq!(NtfsReparseTag::FilterManager.as_u32(), 0x8000_000B);
    assert_eq!(NtfsReparseTag::IisCache.as_u32(), 0xA000_0010);
    assert_eq!(NtfsReparseTag::Appxstrm.as_u32(), 0xC000_0014);
    assert_eq!(NtfsReparseTag::FilePlaceholder.as_u32(), 0x8000_0015);
    assert_eq!(NtfsReparseTag::Dfm.as_u32(), 0x8000_0016);
    assert_eq!(NtfsReparseTag::Unhandled.as_u32(), 0x8000_0020);
    assert_eq!(NtfsReparseTag::OneDrive.as_u32(), 0x8000_0021);
    assert_eq!(NtfsReparseTag::ProjFsTombstone.as_u32(), 0xA000_0022);
    assert_eq!(NtfsReparseTag::StorageSyncFolder.as_u32(), 0x9000_0027);
}

#[test]
fn test_as_u32_unknown_tag() {
    assert_eq!(NtfsReparseTag::Unknown(0x1234_5678).as_u32(), 0x1234_5678);
    assert_eq!(NtfsReparseTag::Unknown(0).as_u32(), 0);
    assert_eq!(NtfsReparseTag::Unknown(u32::MAX).as_u32(), u32::MAX);
}

#[test]
fn test_is_microsoft_with_m_bit_set() {
    // M bit is 0x8000_0000 - all known Microsoft tags have this bit set
    assert!(NtfsReparseTag::MountPoint.is_microsoft()); // 0xA0000003
    assert!(NtfsReparseTag::SymbolicLink.is_microsoft()); // 0xA000000C
    assert!(NtfsReparseTag::Wof.is_microsoft()); // 0x80000017
    assert!(NtfsReparseTag::Cloud.is_microsoft()); // 0x9000001A
    assert!(NtfsReparseTag::ProjFs.is_microsoft()); // 0x9000001C
}

#[test]
fn test_is_microsoft_without_m_bit() {
    // Tags without M bit (third-party)
    assert!(!NtfsReparseTag::Unknown(0x0000_0000).is_microsoft());
    assert!(!NtfsReparseTag::Unknown(0x7FFF_FFFF).is_microsoft());
    assert!(!NtfsReparseTag::Unknown(0x0000_0001).is_microsoft());
}

#[test]
fn test_is_name_surrogate_with_n_bit_set() {
    // N bit is 0x2000_0000 - name surrogates represent another named entity
    assert!(NtfsReparseTag::MountPoint.is_name_surrogate()); // 0xA0000003
    assert!(NtfsReparseTag::SymbolicLink.is_name_surrogate()); // 0xA000000C
    assert!(NtfsReparseTag::LxSymlink.is_name_surrogate()); // 0xA000001D
    assert!(NtfsReparseTag::GlobalReparse.is_name_surrogate()); // 0xA0000019
}

#[test]
fn test_is_name_surrogate_without_n_bit() {
    // These tags are NOT name surrogates (no N bit)
    assert!(!NtfsReparseTag::Wof.is_name_surrogate()); // 0x80000017
    assert!(!NtfsReparseTag::Dedup.is_name_surrogate()); // 0x80000013
    assert!(!NtfsReparseTag::Cloud.is_name_surrogate()); // 0x9000001A
    assert!(!NtfsReparseTag::ProjFs.is_name_surrogate()); // 0x9000001C
    assert!(!NtfsReparseTag::Unknown(0x0000_0000).is_name_surrogate());
}

#[test]
fn test_is_directory_with_d_bit_set() {
    // D bit is 0x1000_0000 - indicates directory with tag can have children
    assert!(NtfsReparseTag::Cloud.is_directory()); // 0x9000001A
    assert!(NtfsReparseTag::ProjFs.is_directory()); // 0x9000001C
}

#[test]
fn test_is_directory_without_d_bit() {
    // These tags do NOT have D bit set
    assert!(!NtfsReparseTag::MountPoint.is_directory()); // 0xA0000003
    assert!(!NtfsReparseTag::SymbolicLink.is_directory()); // 0xA000000C
    assert!(!NtfsReparseTag::Wof.is_directory()); // 0x80000017
    assert!(!NtfsReparseTag::Unknown(0x0000_0000).is_directory());
}

#[test]
fn test_is_reserved_values() {
    assert!(NtfsReparseTag::Unknown(0).is_reserved());
    assert!(NtfsReparseTag::Unknown(1).is_reserved());
    assert!(NtfsReparseTag::Unknown(2).is_reserved());
}

#[test]
fn test_is_reserved_non_reserved_values() {
    assert!(!NtfsReparseTag::Unknown(3).is_reserved());
    assert!(!NtfsReparseTag::MountPoint.is_reserved());
    assert!(!NtfsReparseTag::SymbolicLink.is_reserved());
    assert!(!NtfsReparseTag::Unknown(0x8000_0000).is_reserved());
}

#[test]
fn test_from_u32_known_tags() {
    assert_eq!(
        NtfsReparseTag::from_u32(0xA000_0003),
        NtfsReparseTag::MountPoint
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0xA000_000C),
        NtfsReparseTag::SymbolicLink
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0xA000_001D),
        NtfsReparseTag::LxSymlink
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0xA000_0019),
        NtfsReparseTag::GlobalReparse
    );
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0017), NtfsReparseTag::Wof);
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0013), NtfsReparseTag::Dedup);
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0014), NtfsReparseTag::Nfs);
    assert_eq!(
        NtfsReparseTag::from_u32(0x8000_001B),
        NtfsReparseTag::AppExecLink
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0x8000_001E),
        NtfsReparseTag::StorageSync
    );
    assert_eq!(NtfsReparseTag::from_u32(0x8000_000A), NtfsReparseTag::Dfs);
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0012), NtfsReparseTag::Dfsr);
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0008), NtfsReparseTag::Wim);
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0007), NtfsReparseTag::Sis);
    assert_eq!(
        NtfsReparseTag::from_u32(0x9000_001C),
        NtfsReparseTag::ProjFs
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0x8000_0023),
        NtfsReparseTag::AfUnix
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0x8000_0024),
        NtfsReparseTag::LxFifo
    );
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0025), NtfsReparseTag::LxChr);
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0026), NtfsReparseTag::LxBlk);
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0018), NtfsReparseTag::Wci);
    assert_eq!(NtfsReparseTag::from_u32(0x9000_1018), NtfsReparseTag::Wci1);
    assert_eq!(
        NtfsReparseTag::from_u32(0xA000_001F),
        NtfsReparseTag::WciTombstone
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0xA000_0027),
        NtfsReparseTag::WciLink
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0xA000_1027),
        NtfsReparseTag::WciLink1
    );
    assert_eq!(NtfsReparseTag::from_u32(0xC000_0004), NtfsReparseTag::Hsm);
    assert_eq!(
        NtfsReparseTag::from_u32(0x8000_0005),
        NtfsReparseTag::DriveExtender
    );
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0006), NtfsReparseTag::Hsm2);
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0009), NtfsReparseTag::Csv);
    assert_eq!(
        NtfsReparseTag::from_u32(0x8000_000B),
        NtfsReparseTag::FilterManager
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0xA000_0010),
        NtfsReparseTag::IisCache
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0xC000_0014),
        NtfsReparseTag::Appxstrm
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0x8000_0015),
        NtfsReparseTag::FilePlaceholder
    );
    assert_eq!(NtfsReparseTag::from_u32(0x8000_0016), NtfsReparseTag::Dfm);
    assert_eq!(
        NtfsReparseTag::from_u32(0x8000_0020),
        NtfsReparseTag::Unhandled
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0x8000_0021),
        NtfsReparseTag::OneDrive
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0xA000_0022),
        NtfsReparseTag::ProjFsTombstone
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0x9000_0027),
        NtfsReparseTag::StorageSyncFolder
    );
}

#[test]
fn test_from_u32_cloud_variants() {
    // Cloud Files uses 0x9000X01A pattern where X is 0-F
    assert_eq!(NtfsReparseTag::from_u32(0x9000_001A), NtfsReparseTag::Cloud);
    assert_eq!(NtfsReparseTag::from_u32(0x9000_101A), NtfsReparseTag::Cloud);
    assert_eq!(NtfsReparseTag::from_u32(0x9000_201A), NtfsReparseTag::Cloud);
    assert_eq!(NtfsReparseTag::from_u32(0x9000_F01A), NtfsReparseTag::Cloud);
}

#[test]
fn test_from_u32_cloud_rejects_near_misses() {
    // Bits 16-27 must be zero for Cloud family
    assert_ne!(NtfsReparseTag::from_u32(0x9ABC_F01A), NtfsReparseTag::Cloud,);
    // Wrong low 12 bits
    assert_ne!(NtfsReparseTag::from_u32(0x9000_001B), NtfsReparseTag::Cloud,);
    // Wrong high nibble
    assert_ne!(NtfsReparseTag::from_u32(0x8000_001A), NtfsReparseTag::Cloud,);
}

#[test]
fn test_from_u32_unknown_tags() {
    assert_eq!(
        NtfsReparseTag::from_u32(0x1234_5678),
        NtfsReparseTag::Unknown(0x1234_5678)
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0x0000_0000),
        NtfsReparseTag::Unknown(0x0000_0000)
    );
    assert_eq!(
        NtfsReparseTag::from_u32(0xFFFF_FFFF),
        NtfsReparseTag::Unknown(0xFFFF_FFFF)
    );
}

#[test]
fn test_reparse_tags_constants() {
    assert_eq!(reparse_tags::RESERVED_ZERO, 0x0000_0000);
    assert_eq!(reparse_tags::RESERVED_ONE, 0x0000_0001);
    assert_eq!(reparse_tags::RESERVED_TWO, 0x0000_0002);
    assert_eq!(reparse_tags::MOUNT_POINT, 0xA000_0003);
    assert_eq!(reparse_tags::SYMLINK, 0xA000_000C);
    assert_eq!(reparse_tags::WOF, 0x8000_0017);
    assert_eq!(reparse_tags::DEDUP, 0x8000_0013);
    assert_eq!(reparse_tags::NFS, 0x8000_0014);
    assert_eq!(reparse_tags::APPEXECLINK, 0x8000_001B);
    assert_eq!(reparse_tags::CLOUD, 0x9000_001A);
    assert_eq!(reparse_tags::PROJFS, 0x9000_001C);
    assert_eq!(reparse_tags::LX_SYMLINK, 0xA000_001D);
    assert_eq!(reparse_tags::STORAGE_SYNC, 0x8000_001E);
    assert_eq!(reparse_tags::AF_UNIX, 0x8000_0023);
    assert_eq!(reparse_tags::LX_FIFO, 0x8000_0024);
    assert_eq!(reparse_tags::LX_CHR, 0x8000_0025);
    assert_eq!(reparse_tags::LX_BLK, 0x8000_0026);
    assert_eq!(reparse_tags::DFS, 0x8000_000A);
    assert_eq!(reparse_tags::DFSR, 0x8000_0012);
    assert_eq!(reparse_tags::WIM, 0x8000_0008);
    assert_eq!(reparse_tags::SIS, 0x8000_0007);
    assert_eq!(reparse_tags::GLOBAL_REPARSE, 0xA000_0019);
    assert_eq!(reparse_tags::WCI, 0x8000_0018);
    assert_eq!(reparse_tags::HSM, 0xC000_0004);
    assert_eq!(reparse_tags::DRIVE_EXTENDER, 0x8000_0005);
    assert_eq!(reparse_tags::HSM2, 0x8000_0006);
    assert_eq!(reparse_tags::CSV, 0x8000_0009);
    assert_eq!(reparse_tags::FILTER_MANAGER, 0x8000_000B);
    assert_eq!(reparse_tags::IIS_CACHE, 0xA000_0010);
    assert_eq!(reparse_tags::APPXSTRM, 0xC000_0014);
    assert_eq!(reparse_tags::FILE_PLACEHOLDER, 0x8000_0015);
    assert_eq!(reparse_tags::DFM, 0x8000_0016);
    assert_eq!(reparse_tags::WCI_1, 0x9000_1018);
    assert_eq!(reparse_tags::WCI_TOMBSTONE, 0xA000_001F);
    assert_eq!(reparse_tags::UNHANDLED, 0x8000_0020);
    assert_eq!(reparse_tags::ONEDRIVE, 0x8000_0021);
    assert_eq!(reparse_tags::PROJFS_TOMBSTONE, 0xA000_0022);
    assert_eq!(reparse_tags::STORAGE_SYNC_FOLDER, 0x9000_0027);
    assert_eq!(reparse_tags::WCI_LINK, 0xA000_0027);
    assert_eq!(reparse_tags::WCI_LINK_1, 0xA000_1027);
}

#[test]
fn test_symlink_flags_constants() {
    assert_eq!(symlink_flags::ABSOLUTE, 0x0000_0000);
    assert_eq!(symlink_flags::SYMLINK_FLAG_RELATIVE, 0x0000_0001);
}

#[test]
fn test_decode_utf16le_valid_ascii() {
    // "test" in UTF-16LE: t=0x74, e=0x65, s=0x73, t=0x74
    let bytes = [0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
    let result = decode_utf16le(&bytes).unwrap();
    assert_eq!(result, "test");
}

#[test]
fn test_decode_utf16le_empty() {
    let bytes: [u8; 0] = [];
    let result = decode_utf16le(&bytes).unwrap();
    assert_eq!(result, "");
}

#[test]
fn test_decode_utf16le_unicode() {
    // "日本" (Japan) in UTF-16LE: 日=0x65E5, 本=0x672C
    let bytes = [0xE5, 0x65, 0x2C, 0x67];
    let result = decode_utf16le(&bytes).unwrap();
    assert_eq!(result, "日本");
}

#[test]
fn test_decode_utf16le_odd_bytes_error() {
    // Odd number of bytes should fail
    let bytes = [0x74, 0x00, 0x65];
    let result = decode_utf16le(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_decode_utf16le_path_like() {
    // "C:\test" in UTF-16LE
    let bytes = [
        0x43, 0x00, // C
        0x3A, 0x00, // :
        0x5C, 0x00, // \
        0x74, 0x00, // t
        0x65, 0x00, // e
        0x73, 0x00, // s
        0x74, 0x00, // t
    ];
    let result = decode_utf16le(&bytes).unwrap();
    assert_eq!(result, "C:\\test");
}

/// Helper: build an `NtfsReparsePoint` with the given tag and data.
fn make_reparse_point(tag: u32, data: &[u8]) -> NtfsReparsePoint {
    NtfsReparsePoint {
        tag,
        guid: None,
        data: {
            let mut av = ArrayVec::new();
            av.try_extend_from_slice(data).expect("test data too large");
            av
        },
    }
}

#[test]
fn test_lx_symlink_simple_path() {
    // Version 2, target = "/usr/bin/test"
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes()); // version
    data.extend_from_slice(b"/usr/bin/test");
    let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
    let lx = rp.as_lx_symlink().unwrap();
    assert_eq!(lx.target_path().unwrap(), "/usr/bin/test");
    assert_eq!(lx.target_path_bytes(), b"/usr/bin/test");
}

#[test]
fn test_lx_symlink_relative_path() {
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(b"../lib/libfoo.so");
    let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
    let lx = rp.as_lx_symlink().unwrap();
    assert_eq!(lx.target_path().unwrap(), "../lib/libfoo.so");
}

#[test]
fn test_lx_symlink_empty_path() {
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes());
    // No path bytes after header
    let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
    let lx = rp.as_lx_symlink().unwrap();
    assert_eq!(lx.target_path().unwrap(), "");
    assert!(lx.target_path_bytes().is_empty());
}

#[test]
fn test_lx_symlink_wrong_tag() {
    let data = 2u32.to_le_bytes();
    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let err = rp.as_lx_symlink().unwrap_err();
    assert!(
        matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
            if expected == reparse_tags::LX_SYMLINK && actual == reparse_tags::SYMLINK)
    );
}

#[test]
fn test_lx_symlink_truncated_header() {
    // Only 3 bytes — not enough for a 4-byte version field
    let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &[0x02, 0x00, 0x00]);
    let err = rp.as_lx_symlink().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("too small")
    ));
}

#[test]
fn test_lx_symlink_wrong_version() {
    let data = 1u32.to_le_bytes(); // version 1, not 2
    let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
    let err = rp.as_lx_symlink().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("version")
    ));
}

#[test]
fn test_lx_symlink_invalid_utf8() {
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&[0xFF, 0xFE, 0x80]); // invalid UTF-8
    let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
    let lx = rp.as_lx_symlink().unwrap();
    // Raw bytes are accessible
    assert_eq!(lx.target_path_bytes(), &[0xFF, 0xFE, 0x80]);
    // But decoding to str fails
    assert!(lx.target_path().is_err());
}

#[test]
fn test_lx_symlink_unicode_path() {
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice("/home/用户/文件".as_bytes());
    let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
    let lx = rp.as_lx_symlink().unwrap();
    assert_eq!(lx.target_path().unwrap(), "/home/用户/文件");
}

/// Helper: encode a UTF-16LE null-terminated string.
fn utf16le_null(s: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes.extend_from_slice(&[0x00, 0x00]); // null terminator
    bytes
}

#[test]
fn test_app_exec_link_full() {
    let mut data = Vec::new();
    data.extend_from_slice(&3u32.to_le_bytes()); // version
    data.extend_from_slice(&utf16le_null("Microsoft.WindowsTerminal_8wekyb3d8bbwe"));
    data.extend_from_slice(&utf16le_null("Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"));
    data.extend_from_slice(&utf16le_null(r"C:\Program Files\WindowsApps\wt.exe"));
    data.extend_from_slice(&utf16le_null("0"));

    let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
    let ael = rp.as_app_exec_link().unwrap();

    assert_eq!(ael.version(), 3);
    assert_eq!(
        ael.package_id().unwrap(),
        "Microsoft.WindowsTerminal_8wekyb3d8bbwe"
    );
    assert_eq!(
        ael.entry_point().unwrap(),
        "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"
    );
    assert_eq!(
        ael.executable().unwrap(),
        r"C:\Program Files\WindowsApps\wt.exe"
    );
    assert_eq!(ael.application_type().unwrap().unwrap(), "0");
}

#[test]
fn test_app_exec_link_three_strings() {
    let mut data = Vec::new();
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&utf16le_null("PackageId"));
    data.extend_from_slice(&utf16le_null("EntryPoint"));
    data.extend_from_slice(&utf16le_null("Executable"));
    // No application_type

    let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
    let ael = rp.as_app_exec_link().unwrap();

    assert_eq!(ael.package_id().unwrap(), "PackageId");
    assert_eq!(ael.entry_point().unwrap(), "EntryPoint");
    assert_eq!(ael.executable().unwrap(), "Executable");
    assert!(ael.application_type().is_none());
}

#[test]
fn test_app_exec_link_wrong_tag() {
    let data = 3u32.to_le_bytes();
    let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
    let err = rp.as_app_exec_link().unwrap_err();
    assert!(
        matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
            if expected == reparse_tags::APPEXECLINK && actual == reparse_tags::MOUNT_POINT)
    );
}

#[test]
fn test_app_exec_link_truncated_header() {
    let rp = make_reparse_point(reparse_tags::APPEXECLINK, &[0x03, 0x00, 0x00]);
    let err = rp.as_app_exec_link().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("too small")
    ));
}

#[test]
fn test_app_exec_link_too_few_strings() {
    let mut data = Vec::new();
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&utf16le_null("OnlyOne"));
    data.extend_from_slice(&utf16le_null("OnlyTwo"));
    // Only 2 strings — need at least 3

    let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
    let err = rp.as_app_exec_link().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("fewer than 3")
    ));
}

#[test]
fn test_app_exec_link_empty_strings() {
    let mut data = Vec::new();
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&utf16le_null(""));
    data.extend_from_slice(&utf16le_null(""));
    data.extend_from_slice(&utf16le_null(""));

    let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
    let ael = rp.as_app_exec_link().unwrap();
    assert_eq!(ael.package_id().unwrap(), "");
    assert_eq!(ael.entry_point().unwrap(), "");
    assert_eq!(ael.executable().unwrap(), "");
}

#[test]
fn test_app_exec_link_unicode_paths() {
    let mut data = Vec::new();
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&utf16le_null("パッケージ"));
    data.extend_from_slice(&utf16le_null("エントリ"));
    data.extend_from_slice(&utf16le_null("C:\\プログラム\\app.exe"));

    let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
    let ael = rp.as_app_exec_link().unwrap();
    assert_eq!(ael.package_id().unwrap(), "パッケージ");
    assert_eq!(ael.entry_point().unwrap(), "エントリ");
    assert_eq!(ael.executable().unwrap(), "C:\\プログラム\\app.exe");
}

#[test]
fn test_split_utf16le_three_strings() {
    // "A\0B\0C\0" in UTF-16LE
    let data = [
        0x41, 0x00, 0x00, 0x00, // "A" + null
        0x42, 0x00, 0x00, 0x00, // "B" + null
        0x43, 0x00, 0x00, 0x00, // "C" + null
    ];
    let parts = split_utf16le_null_terminated(&data).unwrap();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], &[0x41, 0x00]);
    assert_eq!(parts[1], &[0x42, 0x00]);
    assert_eq!(parts[2], &[0x43, 0x00]);
}

#[test]
fn test_split_utf16le_no_trailing_null() {
    // "A\0B" — second string has no null terminator
    let data = [
        0x41, 0x00, 0x00, 0x00, // "A" + null
        0x42, 0x00, // "B" without null
    ];
    let parts = split_utf16le_null_terminated(&data).unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], &[0x41, 0x00]);
    assert_eq!(parts[1], &[0x42, 0x00]);
}

#[test]
fn test_split_utf16le_empty() {
    let parts = split_utf16le_null_terminated(&[]).unwrap();
    assert!(parts.is_empty());
}

#[test]
fn test_split_utf16le_single_null() {
    // Just a null terminator — one empty string
    let data = [0x00, 0x00];
    let parts = split_utf16le_null_terminated(&data).unwrap();
    assert_eq!(parts.len(), 1);
    assert!(parts[0].is_empty());
}

#[test]
fn test_split_utf16le_odd_length_error() {
    // Odd number of bytes — invalid UTF-16LE
    let data = [0x41, 0x00, 0x00];
    let err = split_utf16le_null_terminated(&data).unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("odd number of bytes")
    ));
}

#[test]
fn test_app_exec_link_odd_length_payload() {
    // AppExecLink with odd-length string data should fail early
    let mut data = Vec::new();
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&[0x41, 0x00, 0x42]); // 3 bytes — odd
    let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
    let err = rp.as_app_exec_link().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("odd number of bytes")
    ));
}

/// Helper: build NFS reparse data with type and payload.
fn make_nfs_data(nfs_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&nfs_type.to_le_bytes());
    data.extend_from_slice(payload);
    data
}

#[test]
fn test_nfs_symbolic_link() {
    // Target = "/mnt/share" in UTF-16LE
    let target_utf16: Vec<u8> = "/mnt/share"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_LNK, &target_utf16);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();

    assert!(matches!(nfs, NtfsNfsReparsePoint::SymbolicLink { .. }));
    assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_LNK);
    assert_eq!(nfs.target_path().unwrap().unwrap(), "/mnt/share");
    assert_eq!(nfs.target_path_bytes().unwrap(), target_utf16.as_slice());
    assert!(nfs.major().is_none());
    assert!(nfs.minor().is_none());
}

#[test]
fn test_nfs_symbolic_link_empty_target() {
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_LNK, &[]);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();

    assert!(matches!(nfs, NtfsNfsReparsePoint::SymbolicLink { .. }));
    assert_eq!(nfs.target_path().unwrap().unwrap(), "");
    assert!(nfs.target_path_bytes().unwrap().is_empty());
}

#[test]
fn test_nfs_symbolic_link_unicode_target() {
    // Target = "/home/用户" in UTF-16LE
    let target_utf16: Vec<u8> = "/home/用户"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_LNK, &target_utf16);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();

    assert_eq!(nfs.target_path().unwrap().unwrap(), "/home/用户");
}

#[test]
fn test_nfs_character_device() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&5u32.to_le_bytes()); // major
    payload.extend_from_slice(&1u32.to_le_bytes()); // minor
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_CHR, &payload);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();

    assert!(matches!(
        nfs,
        NtfsNfsReparsePoint::CharacterDevice { major: 5, minor: 1 }
    ));
    assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_CHR);
    assert_eq!(nfs.major(), Some(5));
    assert_eq!(nfs.minor(), Some(1));
    assert!(nfs.target_path().is_none());
    assert!(nfs.target_path_bytes().is_none());
}

#[test]
fn test_nfs_block_device() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&8u32.to_le_bytes()); // major
    payload.extend_from_slice(&0u32.to_le_bytes()); // minor
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_BLK, &payload);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();

    assert!(matches!(
        nfs,
        NtfsNfsReparsePoint::BlockDevice { major: 8, minor: 0 }
    ));
    assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_BLK);
    assert_eq!(nfs.major(), Some(8));
    assert_eq!(nfs.minor(), Some(0));
}

#[test]
fn test_nfs_fifo() {
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_FIFO, &[]);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();

    assert!(matches!(nfs, NtfsNfsReparsePoint::Fifo));
    assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_FIFO);
    assert!(nfs.target_path().is_none());
    assert!(nfs.major().is_none());
}

#[test]
fn test_nfs_socket() {
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_SOCK, &[]);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();

    assert!(matches!(nfs, NtfsNfsReparsePoint::Socket));
    assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_SOCK);
}

#[test]
fn test_nfs_wrong_tag() {
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_FIFO, &[]);
    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let err = rp.as_nfs_reparse_point().unwrap_err();
    assert!(
        matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
            if expected == reparse_tags::NFS && actual == reparse_tags::SYMLINK)
    );
}

#[test]
fn test_nfs_truncated_header() {
    // Only 7 bytes — not enough for the 8-byte type field
    let rp = make_reparse_point(reparse_tags::NFS, &[0x00; 7]);
    let err = rp.as_nfs_reparse_point().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("too small")
    ));
}
