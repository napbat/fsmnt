use super::*;

#[test]
fn ext4_crc32c_known_value() {
    // Standard CRC32C of "123456789" = 0xE3069283
    // Raw (kernel-style) = 0xE3069283 ^ 0xFFFFFFFF = 0x1CF96D7C
    let raw = ext4_crc32c(!0, b"123456789");
    assert_eq!(raw, 0x1CF9_6D7C);
}

#[test]
fn ea_inode_hash_deterministic() {
    let seed = 0x36F1_3DEDu32;
    let data = b"hello world extended attribute value";
    let h1 = ea_inode_hash(seed, data);
    let h2 = ea_inode_hash(seed, data);
    assert_eq!(h1, h2);
    assert_ne!(h1, 0);
    // Different data produces different hash
    let h3 = ea_inode_hash(seed, b"different data");
    assert_ne!(h1, h3);
}

#[test]
fn ext4_crc32c_custom_seed() {
    let seed = 0x36F1_3DEDu32;
    let ours = ext4_crc32c(seed, b"test");
    let reference = !crc32c::crc32c_append(!seed, b"test");
    assert_eq!(ours, reference);
}

#[test]
fn seed_from_known_uuid() {
    let uuid = [0x33; 16];
    let seed = seed_from_uuid(&uuid);
    assert_ne!(seed, 0);
    // ext4.img stores s_checksum_seed=0x36F13DED
    assert_eq!(seed, 0x36F1_3DED);
}

#[test]
fn verify_superblock_round_trip() {
    let mut sb = [0u8; 1024];
    assert_eq!(verify_superblock(&sb), ChecksumState::Invalid);

    let correct = ext4_crc32c(!0, &sb[..0x3FC]);
    sb[0x3FC..0x400].copy_from_slice(&correct.to_le_bytes());
    assert_eq!(verify_superblock(&sb), ChecksumState::Valid);
}

#[test]
fn verify_group_descriptor_round_trip() {
    let seed = 0x1234_5678u32;
    let mut desc = [0u8; 32];
    desc[0..4].copy_from_slice(&100u32.to_le_bytes());

    let mut crc = ext4_crc32c(seed, &0u32.to_le_bytes());
    crc = ext4_crc32c(crc, &desc[..0x1E]);
    crc = ext4_crc32c(crc, &[0u8; 2]);
    crc = ext4_crc32c(crc, &desc[0x20..]);
    let csum = (crc & 0xFFFF) as u16;
    desc[0x1E..0x20].copy_from_slice(&csum.to_le_bytes());

    assert_eq!(
        verify_group_descriptor(seed, 0, &desc),
        ChecksumState::Valid,
    );
    desc[0] ^= 0xFF;
    assert_eq!(
        verify_group_descriptor(seed, 0, &desc),
        ChecksumState::Invalid,
    );
}

#[test]
fn verify_group_descriptor_short_buf() {
    assert_eq!(
        verify_group_descriptor(0, 0, &[0u8; 10]),
        ChecksumState::Unknown,
    );
}

#[test]
fn compute_group_descriptor_csum_crc32c_round_trip() {
    let seed = 0xABCD_EF01;
    let group = 3u32;
    let mut desc = [0u8; 64]; // 64-bit descriptor
    desc[0..4].copy_from_slice(&100u32.to_le_bytes()); // bg_block_bitmap_lo = 100
    // Leave bg_checksum (offset 0x1E..0x20) zeroed in the input.

    let csum = compute_group_descriptor_csum_crc32c(seed, group, &desc);
    desc[0x1E..0x20].copy_from_slice(&csum.to_le_bytes());
    assert_eq!(
        verify_group_descriptor(seed, group, &desc),
        ChecksumState::Valid,
    );
}

#[test]
fn verify_inode_short_buf() {
    assert_eq!(
        verify_inode(0, 1, 0, &[0u8; 64], false),
        ChecksumState::Unknown,
    );
}

#[cfg(feature = "std")]
#[test]
fn verify_ext4_fixture_superblock() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let data = std::fs::read(&path).unwrap();
    let sb: &[u8; 1024] = data[1024..2048].try_into().unwrap();
    assert_eq!(verify_superblock(sb), ChecksumState::Valid);
}

#[cfg(feature = "std")]
#[test]
fn verify_ext4_fixture_group_desc() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let data = std::fs::read(&path).unwrap();
    let seed = 0x36F1_3DEDu32;
    let desc = &data[4096..4096 + 64];
    assert_eq!(verify_group_descriptor(seed, 0, desc), ChecksumState::Valid,);
}

#[test]
fn verify_xattr_block_round_trip() {
    let seed = 0x1234_5678u32;
    let block_num = 42u64;
    let mut block = vec![0u8; 4096];
    block[0..4].copy_from_slice(&0xEA02_0000u32.to_le_bytes());
    block[4..8].copy_from_slice(&1u32.to_le_bytes());
    block[8..12].copy_from_slice(&1u32.to_le_bytes());

    let mut crc = ext4_crc32c(seed, &block_num.to_le_bytes());
    crc = ext4_crc32c(crc, &block[..0x10]);
    crc = ext4_crc32c(crc, &[0u8; 4]);
    crc = ext4_crc32c(crc, &block[0x14..]);
    block[0x10..0x14].copy_from_slice(&crc.to_le_bytes());

    assert_eq!(
        verify_xattr_block(seed, block_num, &block),
        ChecksumState::Valid,
    );

    block[0] ^= 0xFF;
    assert_eq!(
        verify_xattr_block(seed, block_num, &block),
        ChecksumState::Invalid,
    );
}

#[test]
fn verify_xattr_block_short_buf() {
    assert_eq!(verify_xattr_block(0, 0, &[0u8; 16]), ChecksumState::Unknown,);
}

#[test]
fn verify_extent_block_round_trip() {
    let seed = 0x1234_5678u32;
    let ino = 15u32;
    let generation = 7u32;
    let block_size = 4096usize;
    let mut block = vec![0u8; block_size];

    block[0..2].copy_from_slice(&0xF30Au16.to_le_bytes());
    block[2..4].copy_from_slice(&1u16.to_le_bytes());
    block[4..6].copy_from_slice(&340u16.to_le_bytes());

    let tail_off = 12 + 340 * 12;
    assert_eq!(tail_off, 4092);

    let mut crc = ext4_crc32c(seed, &ino.to_le_bytes());
    crc = ext4_crc32c(crc, &generation.to_le_bytes());
    crc = ext4_crc32c(crc, &block[..tail_off]);
    crc = ext4_crc32c(crc, &[0u8; 4]);
    block[tail_off..tail_off + 4].copy_from_slice(&crc.to_le_bytes());

    assert_eq!(
        verify_extent_block(seed, ino, generation, &block),
        ChecksumState::Valid
    );
    block[0] ^= 0xFF;
    assert_eq!(
        verify_extent_block(seed, ino, generation, &block),
        ChecksumState::Invalid
    );
}

#[test]
fn verify_extent_block_short() {
    assert_eq!(
        verify_extent_block(0, 0, 0, &[0u8; 10]),
        ChecksumState::Unknown
    );
}

#[test]
fn verify_dir_block_round_trip() {
    let seed = 0xAAAA_BBBBu32;
    let ino = 2u32;
    let generation = 0u32;
    let block_size = 4096usize;
    let mut block = vec![0u8; block_size];

    let tail_off = block_size - 12;
    block[tail_off + 4..tail_off + 6].copy_from_slice(&12u16.to_le_bytes());
    block[tail_off + 7] = 0xDE;

    // Kernel CRCs only the dirent data before the tail
    let csum_off = tail_off + 8;
    let mut crc = ext4_crc32c(seed, &ino.to_le_bytes());
    crc = ext4_crc32c(crc, &generation.to_le_bytes());
    crc = ext4_crc32c(crc, &block[..tail_off]);
    block[csum_off..csum_off + 4].copy_from_slice(&crc.to_le_bytes());

    assert_eq!(
        verify_dir_block(seed, ino, generation, &block),
        ChecksumState::Valid
    );
    block[0] ^= 0xFF;
    assert_eq!(
        verify_dir_block(seed, ino, generation, &block),
        ChecksumState::Invalid
    );
}

#[test]
fn verify_dir_block_no_tail() {
    let block = vec![0u8; 4096];
    assert_eq!(verify_dir_block(0, 0, 0, &block), ChecksumState::Unknown);
}

#[test]
fn verify_dx_root_round_trip() {
    let seed = 0x5555_6666u32;
    let ino = 100u32;
    let generation = 3u32;
    let mut block = vec![0u8; 4096];

    block[0x1D] = 8;
    block[0x20..0x22].copy_from_slice(&507u16.to_le_bytes());
    block[0x22..0x24].copy_from_slice(&5u16.to_le_bytes());

    // The dx_tail lives at the `limit` slot, not after `count`.
    let data_end = 0x20 + 5 * 8;
    let tail_off = 0x20 + 507 * 8;
    let csum_off = tail_off + 4;
    let mut crc = ext4_crc32c(seed, &ino.to_le_bytes());
    crc = ext4_crc32c(crc, &generation.to_le_bytes());
    crc = ext4_crc32c(crc, &block[..data_end]);
    crc = ext4_crc32c(crc, &block[tail_off..tail_off + 4]);
    crc = ext4_crc32c(crc, &[0u8; 4]);
    block[csum_off..csum_off + 4].copy_from_slice(&crc.to_le_bytes());

    assert_eq!(
        verify_dx_root(seed, ino, generation, &block, 5, 507),
        ChecksumState::Valid
    );
    block[0x22] ^= 0xFF;
    assert_eq!(
        verify_dx_root(seed, ino, generation, &block, 5, 507),
        ChecksumState::Invalid
    );
}

#[test]
fn verify_dx_node_round_trip() {
    let seed = 0x5555_6666u32;
    let ino = 100u32;
    let generation = 3u32;
    let mut block = vec![0u8; 4096];

    block[8..10].copy_from_slice(&507u16.to_le_bytes());
    block[10..12].copy_from_slice(&5u16.to_le_bytes());

    let data_end = 8 + 5 * 8;
    let tail_off = 8 + 507 * 8;
    let csum_off = tail_off + 4;
    let mut crc = ext4_crc32c(seed, &ino.to_le_bytes());
    crc = ext4_crc32c(crc, &generation.to_le_bytes());
    crc = ext4_crc32c(crc, &block[..data_end]);
    crc = ext4_crc32c(crc, &block[tail_off..tail_off + 4]);
    crc = ext4_crc32c(crc, &[0u8; 4]);
    block[csum_off..csum_off + 4].copy_from_slice(&crc.to_le_bytes());

    assert_eq!(
        verify_dx_node(seed, ino, generation, &block, 5, 507),
        ChecksumState::Valid
    );
    block[10] ^= 0xFF;
    assert_eq!(
        verify_dx_node(seed, ino, generation, &block, 5, 507),
        ChecksumState::Invalid
    );
}

#[test]
fn compute_dx_root_csum_round_trips_through_verify() {
    let seed = 0x1234_5678u32;
    let ino = 21u32;
    let generation = 7u32;
    let mut block = vec![0u8; 4096];
    block[0x1D] = 8;
    block[0x20..0x22].copy_from_slice(&507u16.to_le_bytes());
    block[0x22..0x24].copy_from_slice(&5u16.to_le_bytes());
    // A real dx_entry in the live region, to prove the writer covers
    // only `count` entries and the dx_tail sits at the `limit` slot.
    block[0x28..0x2C].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

    compute_dx_root_csum(seed, ino, generation, &mut block, 5, 507);
    assert_eq!(
        verify_dx_root(seed, ino, generation, &block, 5, 507),
        ChecksumState::Valid
    );
    block[0x28] ^= 0xFF;
    assert_eq!(
        verify_dx_root(seed, ino, generation, &block, 5, 507),
        ChecksumState::Invalid
    );
}

#[test]
fn compute_dx_node_csum_round_trips_through_verify() {
    let seed = 0x1234_5678u32;
    let ino = 21u32;
    let generation = 7u32;
    let mut block = vec![0u8; 4096];
    block[8..10].copy_from_slice(&508u16.to_le_bytes());
    block[10..12].copy_from_slice(&3u16.to_le_bytes());

    compute_dx_node_csum(seed, ino, generation, &mut block, 3, 508);
    assert_eq!(
        verify_dx_node(seed, ino, generation, &block, 3, 508),
        ChecksumState::Valid
    );
    block[16] ^= 0xFF;
    assert_eq!(
        verify_dx_node(seed, ino, generation, &block, 3, 508),
        ChecksumState::Invalid
    );
}

#[test]
fn verify_dx_root_all_zero_tail_is_unknown() {
    let seed = 0x5555_6666u32;
    let ino = 100u32;
    let generation = 3u32;
    let mut block = vec![0u8; 4096];

    block[0x1D] = 8;
    block[0x20..0x22].copy_from_slice(&507u16.to_le_bytes());
    block[0x22..0x24].copy_from_slice(&5u16.to_le_bytes());

    // Forensic accommodation: an all-zero dx_tail is treated as
    // "checksum absent" even though the kernel would reject it.
    assert_eq!(
        verify_dx_root(seed, ino, generation, &block, 5, 507),
        ChecksumState::Unknown
    );
}

#[test]
fn compute_superblock_csum_round_trip() {
    let mut sb = [0u8; 1024];
    // Put something recognizable in the body.
    sb[0x38] = 0x53;
    sb[0x39] = 0xEF;
    let csum = compute_superblock_csum(&sb);
    sb[0x3FC..0x400].copy_from_slice(&csum.to_le_bytes());
    assert_eq!(verify_superblock(&sb), ChecksumState::Valid);
}

#[test]
fn compute_inode_csum_round_trip_without_hi() {
    // 128-byte inode (no extended area), has_hi = false.
    let mut inode = [0u8; 128];
    inode[0] = 0x42; // some mode byte
    let seed = 0xDEAD_BEEF;
    let ino = 42u32;
    let generation = 7u32;

    let (lo, hi) = compute_inode_csum(seed, ino, generation, &inode, false);
    assert_eq!(hi, 0, "no hi slot when has_hi=false");
    inode[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
    assert_eq!(
        verify_inode(seed, ino, generation, &inode, false),
        ChecksumState::Valid,
    );
}

#[test]
fn compute_inode_csum_round_trip_with_hi() {
    // 256-byte inode with extended area, has_hi = true.
    let mut inode = [0u8; 256];
    inode[0] = 0x55;
    let seed = 0x1234_5678;
    let ino = 100u32;
    let generation = 9u32;

    let (lo, hi) = compute_inode_csum(seed, ino, generation, &inode, true);
    inode[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
    inode[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
    assert_eq!(
        verify_inode(seed, ino, generation, &inode, true),
        ChecksumState::Valid,
    );
}

#[test]
fn bitmap_csum_round_trip_16bit() {
    let seed = 0x5555_AAAA;
    let block = [0xFFu8; 1024]; // all-set bitmap for a tiny group
    let (lo, hi) = compute_bitmap_csum(seed, &block);
    assert_eq!(
        verify_bitmap_csum(seed, &block, lo, Some(hi)),
        ChecksumState::Valid,
    );
    // Lo-only (legacy 16-bit descriptor): pass None for hi, verify only lo half.
    assert_eq!(
        verify_bitmap_csum(seed, &block, lo, None),
        ChecksumState::Valid,
    );
}

#[test]
fn bitmap_csum_detects_mismatch() {
    let seed = 0;
    let block = [0u8; 1024];
    assert_eq!(
        verify_bitmap_csum(seed, &block, 0xDEAD, Some(0xBEEF)),
        ChecksumState::Invalid,
    );
}

#[test]
fn compute_group_descriptor_csum_crc16_round_trip() {
    let uuid = [0x11u8; 16];
    let group = 5u32;
    let mut desc = [0u8; 32]; // 32-bit descriptor
    desc[0..4].copy_from_slice(&200u32.to_le_bytes());

    let csum = compute_group_descriptor_csum_crc16(&uuid, group, &desc);
    desc[0x1E..0x20].copy_from_slice(&csum.to_le_bytes());
    assert_eq!(
        verify_group_descriptor_crc16(&uuid, group, &desc),
        ChecksumState::Valid,
    );
}

#[test]
fn orphan_file_block_csum_round_trip() {
    let seed = 0x1357_9BDF;
    let inum = 11u32;
    let generation = 7u32;
    let phys_block_num = 1337u64;
    let mut block = vec![0u8; 4096];
    // A couple of populated slots.
    block[0..4].copy_from_slice(&42u32.to_le_bytes());
    block[8..12].copy_from_slice(&43u32.to_le_bytes());
    // Tail magic in the right place.
    let tail = block.len() - 8;
    block[tail..tail + 4].copy_from_slice(&0x0B10_CA04_u32.to_le_bytes());

    let csum = compute_orphan_file_block_csum(seed, inum, generation, phys_block_num, &block);
    block[tail + 4..tail + 8].copy_from_slice(&csum.to_le_bytes());
    assert_eq!(
        verify_orphan_file_block(seed, inum, generation, phys_block_num, &block),
        ChecksumState::Valid,
    );
}

#[test]
fn orphan_file_block_csum_unknown_when_short() {
    let block = vec![0u8; 4];
    assert_eq!(
        verify_orphan_file_block(0, 0, 0, 0, &block),
        ChecksumState::Unknown,
    );
}

#[test]
fn compute_xattr_block_csum_round_trips_through_verify() {
    // Synthetic xattr block: set h_magic, h_blocks, leave rest zeroed.
    let block_size = 4096usize;
    let mut block = vec![0u8; block_size];
    // h_magic at 0x00..0x04 = 0xEA020000 little-endian (EXT4_XATTR_MAGIC).
    block[0..4].copy_from_slice(&0xEA02_0000u32.to_le_bytes());
    // h_refcount at 0x04..0x08 = 2.
    block[4..8].copy_from_slice(&2u32.to_le_bytes());
    // h_blocks at 0x08..0x0C = 1.
    block[8..12].copy_from_slice(&1u32.to_le_bytes());

    let seed = 0x1234_5678u32;
    let block_num = 42u64;

    let csum = compute_xattr_block_csum(seed, block_num, &block);
    // Store at offset 0x10 (h_checksum).
    block[0x10..0x14].copy_from_slice(&csum.to_le_bytes());

    assert_eq!(
        verify_xattr_block(seed, block_num, &block),
        ChecksumState::Valid
    );
}

#[test]
fn compute_xattr_block_csum_zeros_h_checksum_field_before_hashing() {
    // Two blocks identical except for stale h_checksum content should produce
    // the same compute result — the function must zero h_checksum before hashing.
    let block_size = 4096usize;
    let mut block_a = vec![0u8; block_size];
    let mut block_b = vec![0u8; block_size];

    block_a[0..4].copy_from_slice(&0xEA02_0000u32.to_le_bytes());
    block_b[0..4].copy_from_slice(&0xEA02_0000u32.to_le_bytes());
    block_a[4..8].copy_from_slice(&3u32.to_le_bytes());
    block_b[4..8].copy_from_slice(&3u32.to_le_bytes());
    block_a[8..12].copy_from_slice(&1u32.to_le_bytes());
    block_b[8..12].copy_from_slice(&1u32.to_le_bytes());

    // Stale h_checksum content in block_b only.
    block_b[0x10..0x14].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

    assert_eq!(
        compute_xattr_block_csum(0x1111_1111, 7, &block_a),
        compute_xattr_block_csum(0x1111_1111, 7, &block_b),
    );
}

#[test]
fn compute_extent_block_csum_round_trips_through_verify() {
    // Synthetic extent block: eh_magic(2) + eh_entries(2) + eh_max(2) + eh_depth(2) + eh_generation(4) = 12 bytes header.
    // Then eh_max * 12 bytes for entries/indexes. Then 4 bytes checksum.
    let eh_max: u16 = 4;
    let header_plus_entries = 12 + (eh_max as usize) * 12;
    let block_size = header_plus_entries + 4 + 16; // plus csum plus trailing padding
    let mut block = vec![0u8; block_size];

    // eh_magic at 0x00..0x02 = 0xF30A.
    block[0..2].copy_from_slice(&0xF30Au16.to_le_bytes());
    // eh_entries at 0x02..0x04 = 1.
    block[2..4].copy_from_slice(&1u16.to_le_bytes());
    // eh_max at 0x04..0x06.
    block[4..6].copy_from_slice(&eh_max.to_le_bytes());
    // eh_depth at 0x06..0x08 = 0 (leaf).
    // eh_generation at 0x08..0x0C = 0.

    let seed = 0x3333_3333u32;
    let inum = 128u32;
    let generation = 0x4444_4444u32;

    let csum = compute_extent_block_csum(seed, inum, generation, &block);
    let tail_off = 12 + (eh_max as usize) * 12;
    block[tail_off..tail_off + 4].copy_from_slice(&csum.to_le_bytes());

    assert_eq!(
        verify_extent_block(seed, inum, generation, &block),
        ChecksumState::Valid
    );
}

#[test]
fn compute_extent_block_csum_zeros_stored_csum_field_before_hashing() {
    let eh_max: u16 = 2;
    let header_plus_entries = 12 + (eh_max as usize) * 12;
    let block_size = header_plus_entries + 4 + 4;

    let mut block_a = vec![0u8; block_size];
    let mut block_b = vec![0u8; block_size];

    for b in [&mut block_a, &mut block_b] {
        b[0..2].copy_from_slice(&0xF30Au16.to_le_bytes());
        b[2..4].copy_from_slice(&1u16.to_le_bytes());
        b[4..6].copy_from_slice(&eh_max.to_le_bytes());
    }

    // Stale checksum in block_b only.
    let tail_off = 12 + (eh_max as usize) * 12;
    block_b[tail_off..tail_off + 4].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());

    assert_eq!(
        compute_extent_block_csum(0x2222_2222, 99, 0x5555_5555, &block_a),
        compute_extent_block_csum(0x2222_2222, 99, 0x5555_5555, &block_b),
    );
}

#[test]
fn compute_xattr_block_csum_inverts_verify_at_minimum_length() {
    // 32 bytes is the smallest block verify_xattr_block can accept.
    let mut block = [0u8; 32];
    block[0..4].copy_from_slice(&0xEA02_0000u32.to_le_bytes()); // h_magic
    block[4..8].copy_from_slice(&1u32.to_le_bytes()); // h_refcount
    block[8..12].copy_from_slice(&1u32.to_le_bytes()); // h_blocks

    let seed = 0xDEAD_BEEFu32;
    let block_num = 1u64;

    let csum = compute_xattr_block_csum(seed, block_num, &block);
    block[0x10..0x14].copy_from_slice(&csum.to_le_bytes());
    assert_eq!(
        verify_xattr_block(seed, block_num, &block),
        ChecksumState::Valid,
    );
}
