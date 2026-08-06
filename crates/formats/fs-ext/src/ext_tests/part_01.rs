use super::*;

#[test]
fn size_reports_blocks_times_block_size_on_clean_ext4() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("skipping: ext4.img fixture not generated");
        return;
    };
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let expected = u64::from(ext.block_size()) * ext.blocks_count;
    assert_eq!(ext.size(), expected);
    assert!(ext.size() > 0);
}

#[test]
fn size_from_saturates_on_overflow() {
    // Malformed 64-bit superblock: huge block count + 64 KiB blocks would
    // overflow u64. saturating_mul must return u64::MAX instead of panicking
    // (debug) or wrapping (release).
    let size = size_from(65_536, u64::MAX);
    assert_eq!(size, u64::MAX);
}

#[test]
fn size_from_computes_product_when_in_range() {
    assert_eq!(size_from(4096, 100), 409_600);
    assert_eq!(size_from(1024, 0), 0);
    assert_eq!(size_from(0, 1_000_000), 0);
}

#[test]
fn free_blocks_is_positive_and_less_than_total_on_clean_ext4() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("skipping: ext4.img fixture not generated");
        return;
    };
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let free = ext.free_blocks();
    assert!(free > 0, "clean fixture must have some free blocks");
    let total_blocks = ext.size() / u64::from(ext.block_size());
    assert!(free < total_blocks, "free_blocks must be less than total");
}

#[test]
fn free_bytes_equals_free_blocks_times_block_size_on_clean_ext4() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("skipping: ext4.img fixture not generated");
        return;
    };
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    assert_eq!(
        ext.free_bytes(),
        ext.free_blocks() * u64::from(ext.block_size())
    );
}

#[test]
fn free_bytes_from_saturates_on_overflow() {
    // Mirror size_from_saturates_on_overflow. 64-bit fs with ~u64::MAX free
    // blocks × 64 KiB would overflow; saturating_mul must return u64::MAX.
    assert_eq!(free_bytes_from(65_536, u64::MAX), u64::MAX);
}

#[test]
fn free_bytes_from_computes_product_when_in_range() {
    assert_eq!(free_bytes_from(4096, 100), 409_600);
    assert_eq!(free_bytes_from(1024, 0), 0);
    assert_eq!(free_bytes_from(0, 1_000_000), 0);
}

#[test]
fn surfaces_encrypt_pw_salt_and_algos_zero_on_unset() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("skipping: ext4.img fixture not generated");
        return;
    };
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    // Plain ext4.img has no fscrypt — both fields must be zero.
    assert_eq!(ext.s_encrypt_pw_salt(), [0u8; 16]);
    assert_eq!(ext.s_encrypt_algos(), [0u8; 4]);
}

#[test]
fn classical_ext4_image_reports_no_meta_bg() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("skipping: ext4.img fixture not generated");
        return;
    };
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    assert!(!ext.is_meta_bg(), "ext4.img must not have META_BG");
    assert_eq!(
        ext.total_desc_blocks(),
        ext.group_count()
            .div_ceil(ext.block_size() / u32::from(ext.desc_size)),
        "total_desc_blocks must match group_count.div_ceil(desc_per_block)"
    );
}

#[test]
fn full_mixed_mode_via_first_meta_bg_patch() {
    use fs_common::io::FsReadSeek;

    if !crate::test_support::fixture_available("ext4-meta-bg.img") {
        eprintln!("skipping: ext4-meta-bg.img fixture not generated");
        return;
    }
    let mut bytes = crate::test_support::load_image("ext4-meta-bg.img").into_inner();

    // Patch s_first_meta_bg (offset 0x104 in the superblock at byte 1024)
    // from 0 to 1. With 1 KiB blocks + first_data_block = 1, descriptor
    // block 0's classical and META_BG locations both resolve to block 2,
    // so this exercises the mixed-mode boundary without relocating data.
    let s_first_meta_bg_offset = 1024 + 0x104;
    bytes[s_first_meta_bg_offset..s_first_meta_bg_offset + 4]
        .copy_from_slice(&1u32.to_le_bytes());

    // Recompute the superblock CRC (offset 0x3FC in the SB).
    let sb: &[u8; 1024] = (&bytes[1024..2048]).try_into().unwrap();
    let new_csum = crate::checksum::compute_superblock_csum(sb);
    bytes[1024 + 0x3FC..1024 + 0x400].copy_from_slice(&new_csum.to_le_bytes());

    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open mixed-mode patch");
    assert!(ext.is_meta_bg());
    assert_eq!(ext.gdt_layout.first_meta_bg(), 1);

    // Reuse a subset of the read assertions from the integration test.
    let mut root = ext.root_directory();
    let hello = root
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup hello");
    let hello_inode = ext
        .inode(&mut cursor, hello.inode_number)
        .expect("hello inode");
    let mut hello_file = hello_inode.open_file().expect("hello file");
    let mut hello_buf = [0u8; 64];
    let n = hello_file
        .read(&mut cursor, &mut hello_buf)
        .expect("read hello");
    assert_eq!(&hello_buf[..n], b"Hello from ext4-meta-bg!\n");
}
