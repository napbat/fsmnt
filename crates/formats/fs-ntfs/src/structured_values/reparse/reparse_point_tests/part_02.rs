#[test]
fn test_nfs_unknown_type() {
    let data = make_nfs_data(0xDEAD_BEEF_CAFE_BABE, &[]);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let err = rp.as_nfs_reparse_point().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("unknown NFS")
    ));
}

#[test]
fn test_nfs_chr_truncated_device_data() {
    // Type field says CHR but only 4 bytes of device data (need 8)
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_CHR, &[0x01, 0x00, 0x00, 0x00]);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let err = rp.as_nfs_reparse_point().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("too small")
    ));
}

#[test]
fn test_nfs_blk_truncated_device_data() {
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_BLK, &[0x01, 0x00, 0x00, 0x00]);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let err = rp.as_nfs_reparse_point().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("too small")
    ));
}

#[test]
fn test_nfs_device_max_values() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::MAX.to_le_bytes());
    payload.extend_from_slice(&u32::MAX.to_le_bytes());
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_CHR, &payload);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();

    assert_eq!(nfs.major(), Some(u32::MAX));
    assert_eq!(nfs.minor(), Some(u32::MAX));
}

#[test]
fn test_nfs_symbolic_link_odd_byte_target() {
    // 3 bytes is not valid UTF-16LE — raw bytes are stored, decode fails
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_LNK, &[0x41, 0x00, 0x42]);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();
    assert_eq!(nfs.target_path_bytes().unwrap(), &[0x41, 0x00, 0x42]);
    let err = nfs.target_path().unwrap().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("odd number of bytes")
    ));
}

#[test]
fn test_nfs_chr_extra_trailing_data() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&5u32.to_le_bytes());
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&[0xFF; 16]); // extra trailing data
    let data = make_nfs_data(nfs_types::NFS_SPECFILE_CHR, &payload);
    let rp = make_reparse_point(reparse_tags::NFS, &data);
    let nfs = rp.as_nfs_reparse_point().unwrap();
    assert_eq!(nfs.major(), Some(5));
    assert_eq!(nfs.minor(), Some(1));
}

#[test]
fn test_nfs_type_constants() {
    assert_eq!(nfs_types::NFS_SPECFILE_LNK, 0x0000_0000_014B_4E4C);
    assert_eq!(nfs_types::NFS_SPECFILE_CHR, 0x0000_0000_0052_4843);
    assert_eq!(nfs_types::NFS_SPECFILE_BLK, 0x0000_0000_004B_4C42);
    assert_eq!(nfs_types::NFS_SPECFILE_FIFO, 0x0000_0000_4F46_4946);
    assert_eq!(nfs_types::NFS_SPECFILE_SOCK, 0x0000_0000_4B43_4F53);
}

// ========================================
// Roundtrip tests for from_u32 / as_u32
// ========================================

#[test]
fn test_roundtrip_known_tags() {
    let tags = [
        NtfsReparseTag::MountPoint,
        NtfsReparseTag::SymbolicLink,
        NtfsReparseTag::LxSymlink,
        NtfsReparseTag::GlobalReparse,
        NtfsReparseTag::Wof,
        NtfsReparseTag::Dedup,
        NtfsReparseTag::Nfs,
        NtfsReparseTag::AppExecLink,
        NtfsReparseTag::StorageSync,
        NtfsReparseTag::Dfs,
        NtfsReparseTag::Dfsr,
        NtfsReparseTag::Wim,
        NtfsReparseTag::Sis,
        NtfsReparseTag::Cloud,
        NtfsReparseTag::ProjFs,
        NtfsReparseTag::AfUnix,
        NtfsReparseTag::LxFifo,
        NtfsReparseTag::LxChr,
        NtfsReparseTag::LxBlk,
        NtfsReparseTag::Wci,
        NtfsReparseTag::Wci1,
        NtfsReparseTag::WciTombstone,
        NtfsReparseTag::WciLink,
        NtfsReparseTag::WciLink1,
        NtfsReparseTag::Hsm,
        NtfsReparseTag::DriveExtender,
        NtfsReparseTag::Hsm2,
        NtfsReparseTag::Csv,
        NtfsReparseTag::FilterManager,
        NtfsReparseTag::IisCache,
        NtfsReparseTag::Appxstrm,
        NtfsReparseTag::FilePlaceholder,
        NtfsReparseTag::Dfm,
        NtfsReparseTag::Unhandled,
        NtfsReparseTag::OneDrive,
        NtfsReparseTag::ProjFsTombstone,
        NtfsReparseTag::StorageSyncFolder,
    ];

    for tag in tags {
        let raw = tag.as_u32();
        let parsed = NtfsReparseTag::from_u32(raw);
        assert_eq!(tag, parsed, "Roundtrip failed for {tag:?}");
    }
}

// ========================================
// NtfsReparsePoint struct method tests
// ========================================

/// Parses a reparse point through its real `from_bytes` constructor.
/// `tag` is the 4-byte tag; `data` is the reparse data after the
/// 8-byte common header. `reparse_data_length` is set to `data.len()`.
fn parse_reparse_point(tag: u32, data: &[u8]) -> NtfsReparsePoint {
    let mut buf = Vec::new();
    buf.extend_from_slice(&tag.to_le_bytes()); // reparse_tag (offset 0)
    buf.extend_from_slice(
        &u16::try_from(data.len())
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // reparse_data_length (offset 4)
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved (offset 6)
    buf.extend_from_slice(data);
    NtfsReparsePoint::from_bytes(&buf, NtfsPosition::none()).expect("valid reparse point")
}

#[test]
fn test_reparse_point_is_microsoft_true() {
    // SYMLINK tag 0xA000_000C has the M bit (0x8000_0000) set.
    let rp = parse_reparse_point(reparse_tags::SYMLINK, &[0u8; 12]);
    assert!(rp.is_microsoft());
    assert_eq!(rp.tag(), reparse_tags::SYMLINK);
}

#[test]
fn test_reparse_point_is_microsoft_false() {
    // A third-party tag without the M bit. data_length < GUID_SIZE so
    // no GUID is consumed and parsing succeeds with empty data.
    let rp = parse_reparse_point(0x0000_0042, &[]);
    assert!(!rp.is_microsoft());
}

#[test]
fn test_reparse_point_is_name_surrogate_true() {
    // SYMLINK tag 0xA000_000C has the N bit (0x2000_0000) set.
    let rp = parse_reparse_point(reparse_tags::SYMLINK, &[0u8; 12]);
    assert!(rp.is_name_surrogate());
}

#[test]
fn test_reparse_point_is_name_surrogate_false() {
    // WOF tag 0x8000_0017 is Microsoft (M bit) but NOT a name surrogate
    // (N bit 0x2000_0000 clear). This distinguishes is_name_surrogate
    // from is_microsoft and pins the exact bit mask.
    let rp = parse_reparse_point(reparse_tags::WOF, &[]);
    assert!(rp.is_microsoft());
    assert!(!rp.is_name_surrogate());
}

#[test]
fn test_reparse_point_guid_present_for_third_party() {
    // Third-party tag (no M bit) with >= 16 bytes of data: the parser
    // consumes a GUID. Use a recognizable GUID byte pattern.
    let guid_bytes: [u8; GUID_SIZE] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let mut data = Vec::new();
    data.extend_from_slice(&guid_bytes); // GUID
    data.extend_from_slice(&[0xAA, 0xBB]); // trailing reparse data
    let rp = parse_reparse_point(0x0000_0042, &data);
    let guid = rp.guid().expect("third-party reparse point carries a GUID");
    // data1 is the first little-endian u32 of the GUID.
    assert_eq!(guid.data1(), 0x0403_0201);
    // The GUID is stripped from the remaining data.
    assert_eq!(rp.data(), &[0xAA, 0xBB]);
}

#[test]
fn test_reparse_point_guid_absent_for_microsoft() {
    // Microsoft reparse points never carry a GUID even with long data.
    let rp = parse_reparse_point(reparse_tags::SYMLINK, &[0u8; 32]);
    assert!(rp.guid().is_none());
    assert_eq!(rp.data().len(), 32);
}

// ========================================
// NtfsSymbolicLink::from_reparse_point tests
// ========================================

/// Builds symbolic link reparse data: 12-byte header + path buffer.
/// Substitute name is placed at offset 0, print name after it.
fn symlink_data(substitute: &[u8], print: &[u8], relative: bool) -> Vec<u8> {
    let sub_off = 0u16;
    let sub_len = u16::try_from(substitute.len()).expect("test value fits u16");
    let print_off = u16::try_from(substitute.len()).expect("test value fits u16");
    let print_len = u16::try_from(print.len()).expect("test value fits u16");
    let flags: u32 = if relative {
        symlink_flags::SYMLINK_FLAG_RELATIVE
    } else {
        0
    };

    let mut data = Vec::new();
    data.extend_from_slice(&sub_off.to_le_bytes()); // substitute_name_offset
    data.extend_from_slice(&sub_len.to_le_bytes()); // substitute_name_length
    data.extend_from_slice(&print_off.to_le_bytes()); // print_name_offset
    data.extend_from_slice(&print_len.to_le_bytes()); // print_name_length
    data.extend_from_slice(&flags.to_le_bytes()); // flags
    data.extend_from_slice(substitute);
    data.extend_from_slice(print);
    data
}

#[test]
fn test_symbolic_link_absolute() {
    let substitute: Vec<u8> = r"\??\C:\target"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let print: Vec<u8> = r"C:\target"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let data = symlink_data(&substitute, &print, false);
    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let sym = rp.as_symbolic_link().unwrap();

    assert_eq!(sym.substitute_name_bytes(), &substitute[..]);
    assert_eq!(sym.print_name_bytes(), &print[..]);
    assert_eq!(sym.substitute_name().unwrap(), r"\??\C:\target");
    assert_eq!(sym.print_name().unwrap(), r"C:\target");
    assert!(!sym.is_relative());
}

#[test]
fn test_symbolic_link_relative() {
    let substitute: Vec<u8> = "..\\sibling"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let print: Vec<u8> = "sibling"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let data = symlink_data(&substitute, &print, true);
    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let sym = rp.as_symbolic_link().unwrap();

    assert!(sym.is_relative());
    assert_eq!(sym.substitute_name().unwrap(), "..\\sibling");
    assert_eq!(sym.print_name().unwrap(), "sibling");
}

#[test]
fn test_symbolic_link_nonzero_offsets() {
    // Place the substitute name after the print name in the buffer so
    // a nonzero substitute_name_offset is exercised. This pins the
    // `substitute_name_offset + substitute_name_length` arithmetic.
    let print: Vec<u8> = "P".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let substitute: Vec<u8> = "TARGET".encode_utf16().flat_map(u16::to_le_bytes).collect();

    let mut data = Vec::new();
    // substitute placed after print: offset = print.len()
    data.extend_from_slice(
        &u16::try_from(print.len())
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // substitute_name_offset
    data.extend_from_slice(
        &u16::try_from(substitute.len())
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // substitute_name_length
    data.extend_from_slice(&0u16.to_le_bytes()); // print_name_offset
    data.extend_from_slice(
        &u16::try_from(print.len())
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // print_name_length
    data.extend_from_slice(&0u32.to_le_bytes()); // flags
    data.extend_from_slice(&print);
    data.extend_from_slice(&substitute);

    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let sym = rp.as_symbolic_link().unwrap();
    assert_eq!(sym.substitute_name().unwrap(), "TARGET");
    assert_eq!(sym.print_name().unwrap(), "P");
}

#[test]
fn test_symbolic_link_wrong_tag() {
    let data = symlink_data(&[0, 0], &[0, 0], false);
    let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
    let err = rp.as_symbolic_link().unwrap_err();
    assert!(
        matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
            if expected == reparse_tags::SYMLINK && actual == reparse_tags::MOUNT_POINT)
    );
}

#[test]
fn test_symbolic_link_truncated_header() {
    // 11 bytes < 12-byte symlink header.
    let rp = make_reparse_point(reparse_tags::SYMLINK, &[0u8; 11]);
    let err = rp.as_symbolic_link().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("too small")
    ));
}

#[test]
fn test_symbolic_link_substitute_beyond_buffer() {
    // substitute_name_length claims more bytes than the path buffer has.
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
    data.extend_from_slice(&100u16.to_le_bytes()); // substitute_name_length (too big)
    data.extend_from_slice(&0u16.to_le_bytes()); // print_name_offset
    data.extend_from_slice(&0u16.to_le_bytes()); // print_name_length
    data.extend_from_slice(&0u32.to_le_bytes()); // flags
    data.extend_from_slice(&[0u8; 4]); // only 4 bytes of path buffer
    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let err = rp.as_symbolic_link().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("substitute name extends")
    ));
}

#[test]
fn test_symbolic_link_print_beyond_buffer() {
    // print_name_offset + length exceeds the path buffer, but substitute
    // fits. This isolates the print-name bounds check from the substitute
    // check (distinguishing `print_name_end > path_buffer.len()`).
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
    data.extend_from_slice(&2u16.to_le_bytes()); // substitute_name_length (fits)
    data.extend_from_slice(&2u16.to_le_bytes()); // print_name_offset
    data.extend_from_slice(&100u16.to_le_bytes()); // print_name_length (too big)
    data.extend_from_slice(&0u32.to_le_bytes()); // flags
    data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 4 bytes of path buffer
    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let err = rp.as_symbolic_link().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("print name extends")
    ));
}

#[test]
fn test_symbolic_link_header_only_accepted() {
    // data.len() == SYMLINK_REPARSE_DATA_HEADER_SIZE (12): the `<` check is
    // false, so an empty-path symlink (both names zero-length at offset 0)
    // is accepted. A `< -> <=` mutant would reject len == 12.
    let data = symlink_data(&[], &[], false);
    assert_eq!(data.len(), SYMLINK_REPARSE_DATA_HEADER_SIZE);
    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let sym = rp.as_symbolic_link().unwrap();
    assert_eq!(sym.substitute_name().unwrap(), "");
    assert_eq!(sym.print_name().unwrap(), "");
    assert!(sym.substitute_name_bytes().is_empty());
}

#[test]
fn test_symbolic_link_exact_fit_boundary() {
    // print name occupies exactly the rest of the buffer: print_name_end
    // == path_buffer.len() must be accepted (boundary for `>` vs `>=`).
    let sub: Vec<u8> = "A".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let print: Vec<u8> = "BB".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let data = symlink_data(&sub, &print, false);
    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let sym = rp.as_symbolic_link().unwrap();
    assert_eq!(sym.substitute_name().unwrap(), "A");
    assert_eq!(sym.print_name().unwrap(), "BB");
}

// ========================================
// NtfsMountPoint::from_reparse_point tests
// ========================================

/// Builds mount point reparse data: 8-byte header + path buffer.
fn mount_point_data(substitute: &[u8], print: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
    data.extend_from_slice(
        &u16::try_from(substitute.len())
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // substitute_name_length
    data.extend_from_slice(
        &u16::try_from(substitute.len())
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // print_name_offset
    data.extend_from_slice(
        &u16::try_from(print.len())
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // print_name_length
    data.extend_from_slice(substitute);
    data.extend_from_slice(print);
    data
}

#[test]
fn test_mount_point_basic() {
    let substitute: Vec<u8> = r"\??\Volume{1}"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let print: Vec<u8> = r"D:\mount"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let data = mount_point_data(&substitute, &print);
    let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
    let mp = rp.as_mount_point().unwrap();

    assert_eq!(mp.substitute_name_bytes(), &substitute[..]);
    assert_eq!(mp.print_name_bytes(), &print[..]);
    assert_eq!(mp.substitute_name().unwrap(), r"\??\Volume{1}");
    assert_eq!(mp.print_name().unwrap(), r"D:\mount");
}

#[test]
fn test_mount_point_nonzero_print_offset() {
    // print name placed after substitute; pins print_name_offset +
    // print_name_length arithmetic and substitute_name_end arithmetic.
    let substitute: Vec<u8> = "AB".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let print: Vec<u8> = "CDE".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let data = mount_point_data(&substitute, &print);
    let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
    let mp = rp.as_mount_point().unwrap();
    assert_eq!(mp.substitute_name().unwrap(), "AB");
    assert_eq!(mp.print_name().unwrap(), "CDE");
}

#[test]
fn test_mount_point_header_only_accepted() {
    // data.len() == MOUNT_POINT_REPARSE_DATA_HEADER_SIZE (8): the `<` check
    // is false, so an empty-path mount point is accepted. A `< -> <=`
    // mutant would reject len == 8.
    let data = mount_point_data(&[], &[]);
    assert_eq!(data.len(), MOUNT_POINT_REPARSE_DATA_HEADER_SIZE);
    let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
    let mp = rp.as_mount_point().unwrap();
    assert_eq!(mp.substitute_name().unwrap(), "");
    assert_eq!(mp.print_name().unwrap(), "");
    assert!(mp.substitute_name_bytes().is_empty());
}

#[test]
fn test_mount_point_substitute_exact_fit() {
    // substitute_name_end == path_buffer.len() exactly (substitute fills
    // the whole buffer, print is empty at offset 0). The original `>` is
    // false (accept); a `> -> >=` mutant at line 798 would reject the
    // exact-fit case. The successful parse kills `> -> >=`.
    let substitute: Vec<u8> = "FULL".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
    data.extend_from_slice(
        &u16::try_from(substitute.len())
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // substitute_name_length
    data.extend_from_slice(&0u16.to_le_bytes()); // print_name_offset
    data.extend_from_slice(&0u16.to_le_bytes()); // print_name_length (empty)
    data.extend_from_slice(&substitute); // path buffer == substitute exactly
    let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
    let mp = rp.as_mount_point().unwrap();
    assert_eq!(mp.substitute_name().unwrap(), "FULL");
    assert_eq!(mp.print_name().unwrap(), "");
}

#[test]
fn test_mount_point_wrong_tag() {
    let data = mount_point_data(&[0, 0], &[0, 0]);
    let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
    let err = rp.as_mount_point().unwrap_err();
    assert!(
        matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
            if expected == reparse_tags::MOUNT_POINT && actual == reparse_tags::SYMLINK)
    );
}

#[test]
fn test_mount_point_truncated_header() {
    // 7 bytes < 8-byte mount point header.
    let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &[0u8; 7]);
    let err = rp.as_mount_point().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("too small")
    ));
}

#[test]
fn test_mount_point_substitute_beyond_buffer() {
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
    data.extend_from_slice(&100u16.to_le_bytes()); // substitute_name_length (too big)
    data.extend_from_slice(&0u16.to_le_bytes()); // print_name_offset
    data.extend_from_slice(&0u16.to_le_bytes()); // print_name_length
    data.extend_from_slice(&[0u8; 4]); // only 4 bytes of path buffer
    let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
    let err = rp.as_mount_point().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("substitute name extends")
    ));
}

#[test]
fn test_mount_point_print_beyond_buffer() {
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
    data.extend_from_slice(&2u16.to_le_bytes()); // substitute_name_length (fits)
    data.extend_from_slice(&2u16.to_le_bytes()); // print_name_offset
    data.extend_from_slice(&100u16.to_le_bytes()); // print_name_length (too big)
    data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 4 bytes of path buffer
    let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
    let err = rp.as_mount_point().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("print name extends")
    ));
}

// ========================================
// NtfsAppExecLink raw-bytes accessors
// ========================================

#[test]
fn test_app_exec_link_raw_bytes_accessors() {
    let mut data = Vec::new();
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&utf16le_null("Pkg"));
    data.extend_from_slice(&utf16le_null("Entry"));
    data.extend_from_slice(&utf16le_null("Exec"));
    data.extend_from_slice(&utf16le_null("AppType"));

    let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
    let ael = rp.as_app_exec_link().unwrap();

    // Raw UTF-16LE bytes (no trailing null) for each string.
    let pkg: Vec<u8> = "Pkg".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let entry: Vec<u8> = "Entry".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let exec: Vec<u8> = "Exec".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let app_type: Vec<u8> = "AppType"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();

    assert_eq!(ael.package_id_bytes(), &pkg[..]);
    assert_eq!(ael.entry_point_bytes(), &entry[..]);
    assert_eq!(ael.executable_bytes(), &exec[..]);
    assert_eq!(ael.application_type_bytes(), &app_type[..]);
}

#[test]
fn test_app_exec_link_minimum_header_size() {
    // Exactly 4 bytes (just the version, no strings) must be accepted by
    // the `data.len() < APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE` check, but
    // then rejected for having fewer than 3 strings. This pins the `<`
    // boundary (4 bytes is not "too small").
    let data = 3u32.to_le_bytes();
    let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
    let err = rp.as_app_exec_link().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidReparsePointData { reason, .. }
            if reason.contains("fewer than 3")
    ));
}

// ========================================
// split_utf16le_null_terminated termination
// ========================================

#[test]
fn test_split_utf16le_long_buffer_terminates() {
    // A multi-string buffer with explicit null terminators: asserts the
    // 2-byte-step loop walks the whole buffer and terminates promptly,
    // pinning the `i + 1 < data.len()` / `i += 2` index arithmetic.
    let mut data = Vec::new();
    for _ in 0..64 {
        data.extend_from_slice(&[0x41, 0x00, 0x00, 0x00]); // "A" + null
    }
    let parts = split_utf16le_null_terminated(&data).unwrap();
    assert_eq!(parts.len(), 64);
    for part in &parts {
        assert_eq!(*part, &[0x41, 0x00]);
    }
}

#[test]
fn test_split_utf16le_two_strings_offsets() {
    // "AB\0C\0": first string is 2 code units, splitting at byte index 4.
    // Pins start = i + 2 and the index walk position exactly.
    let data = [
        0x41, 0x00, 0x42, 0x00, 0x00, 0x00, // "AB" + null
        0x43, 0x00, 0x00, 0x00, // "C" + null
    ];
    let parts = split_utf16le_null_terminated(&data).unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], &[0x41, 0x00, 0x42, 0x00]);
    assert_eq!(parts[1], &[0x43, 0x00]);
}

#[test]
fn test_split_utf16le_high_byte_not_a_terminator() {
    // A single code unit U+0100 = bytes [0x00, 0x01]: the low byte is 0 but
    // the high byte is not, so it is NOT a U+0000 terminator. The genuine
    // check requires BOTH data[i] == 0 AND data[i + 1] == 0. A `data[i + 1]
    // -> data[i * 1]` (= data[i]) mutation would test data[i] twice, see
    // `0 == 0 && 0 == 0`, and wrongly split here. Asserting a single
    // non-empty string kills the `i + 1 -> i * 1` index mutation (1278).
    let data = [0x00, 0x01, 0x42, 0x00]; // U+0100 then 'B'
    let parts = split_utf16le_null_terminated(&data).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0], &[0x00, 0x01, 0x42, 0x00]);
}
