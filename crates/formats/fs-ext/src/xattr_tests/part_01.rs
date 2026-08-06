use super::*;

#[test]
fn namespace_prefix_known_indices() {
    assert_eq!(namespace_prefix(0), Some(""));
    assert_eq!(namespace_prefix(1), Some("user."));
    assert_eq!(namespace_prefix(2), Some("system.posix_acl_access"));
    assert_eq!(namespace_prefix(3), Some("system.posix_acl_default"));
    assert_eq!(namespace_prefix(4), Some("trusted."));
    assert_eq!(namespace_prefix(6), Some("security."));
    assert_eq!(namespace_prefix(7), Some("system."));
    assert_eq!(namespace_prefix(8), Some("system.richacl"));
}

#[test]
fn namespace_prefix_encryption_index() {
    // EXT4_XATTR_INDEX_ENCRYPTION = 9, prefix maps to "encryption."
    assert_eq!(namespace_prefix(9), Some("encryption."));
}

#[test]
fn namespace_prefix_unassigned() {
    assert_eq!(namespace_prefix(5), None);
    assert_eq!(namespace_prefix(255), None);
}

const IBODY_SIZE: usize = 96; // typical: 256 - 128 - 32

fn ibody_buf() -> Vec<u8> {
    let mut buf = vec![0u8; IBODY_SIZE];
    buf[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
    buf
}

fn write_entry(
    buf: &mut [u8],
    pos: usize,
    name_index: u8,
    name: &[u8],
    value_offs: u16,
    value_inum: u32,
    value_size: u32,
) -> usize {
    buf[pos] = (name.len()).to_le_bytes()[0];
    buf[pos + 1] = name_index;
    buf[pos + 2..pos + 4].copy_from_slice(&value_offs.to_le_bytes());
    buf[pos + 4..pos + 8].copy_from_slice(&value_inum.to_le_bytes());
    buf[pos + 8..pos + 12].copy_from_slice(&value_size.to_le_bytes());
    buf[pos + 16..pos + 16 + name.len()].copy_from_slice(name);
    align4(pos + 16 + name.len())
}

/// Place a value at the end of the free region and return its
/// offset relative to `value_base`. `tail` tracks the next free
/// byte (starts at `buf.len()`, moves downward).
fn place_value(buf: &mut [u8], data: &[u8], value_base: usize, tail: &mut usize) -> u16 {
    let start = *tail - data.len();
    buf[start..start + data.len()].copy_from_slice(data);
    *tail = start;
    u16::try_from(start - value_base ).expect("the test fixture value fits in u16")
}

#[test]
fn parse_ibody_single_user_xattr() {
    let mut buf = ibody_buf();
    let first_entry = 4usize;
    let mut tail = buf.len();
    let val = b"hello";
    let offs = place_value(&mut buf, val, first_entry, &mut tail);
    let next = write_entry(
        &mut buf,
        first_entry,
        1,
        b"greeting",
        offs,
        0,
        u32::try_from(val.len()).expect("the test fixture value fits in u32"),
    );
    buf[next] = 0;
    buf[next + 1] = 0;

    let mut out = Vec::new();
    parse_ibody_entries(&buf, 42, &mut out).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name(), "user.greeting");
    assert_eq!(out[0].value(), b"hello");
    assert!(out[0].ea_inode().is_none());
}

#[test]
fn parse_ibody_encryption_xattr_with_suffix_c() {
    let mut buf = ibody_buf();
    let first_entry = 4usize;
    let mut tail = buf.len();
    // 28-byte v1 fscrypt context as the value
    let val: Vec<u8> = (0..28u8).collect();
    let offs = place_value(&mut buf, &val, first_entry, &mut tail);
    let next = write_entry(&mut buf, first_entry, 9, b"c", offs, 0, u32::try_from(val.len()).expect("the test fixture value fits in u32"));
    buf[next] = 0;
    buf[next + 1] = 0;

    let mut out = Vec::new();
    parse_ibody_entries(&buf, 42, &mut out).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name(), "encryption.c");
    assert_eq!(out[0].value(), val.as_slice());
}

#[test]
fn parse_ibody_multiple_namespaces() {
    let big = 200usize;
    let mut buf = vec![0u8; big];
    buf[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
    let first_entry = 4usize;
    let mut tail = buf.len();

    let v1 = b"unconfined_t";
    let o1 = place_value(&mut buf, v1, first_entry, &mut tail);
    let next = write_entry(&mut buf, first_entry, 6, b"selinux", o1, 0, u32::try_from(v1.len()).expect("the test fixture value fits in u32"));

    let v2 = b"myval";
    let o2 = place_value(&mut buf, v2, first_entry, &mut tail);
    let next = write_entry(&mut buf, next, 1, b"tag", o2, 0, u32::try_from(v2.len()).expect("the test fixture value fits in u32"));

    let v3 = b"sysdata";
    let o3 = place_value(&mut buf, v3, first_entry, &mut tail);
    let next = write_entry(&mut buf, next, 7, b"data", o3, 0, u32::try_from(v3.len()).expect("the test fixture value fits in u32"));
    buf[next] = 0;
    buf[next + 1] = 0;

    let mut out = Vec::new();
    parse_ibody_entries(&buf, 10, &mut out).unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].name(), "security.selinux");
    assert_eq!(out[0].value(), b"unconfined_t");
    assert_eq!(out[1].name(), "user.tag");
    assert_eq!(out[1].value(), b"myval");
    assert_eq!(out[2].name(), "system.data");
    assert_eq!(out[2].value(), b"sysdata");
}

#[test]
fn parse_ibody_ea_inode_entry() {
    let mut buf = ibody_buf();
    let first_entry = 4usize;
    let next = write_entry(&mut buf, first_entry, 1, b"big", 0, 500, 65536);
    buf[next] = 0;
    buf[next + 1] = 0;

    let mut out = Vec::new();
    parse_ibody_entries(&buf, 42, &mut out).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name(), "user.big");
    assert!(out[0].value().is_empty());
    assert_eq!(out[0].ea_inode(), Some(500));
}

#[test]
fn parse_ibody_no_magic_returns_empty() {
    let buf = vec![0u8; IBODY_SIZE];
    let mut out = Vec::new();
    parse_ibody_entries(&buf, 42, &mut out).unwrap();
    assert!(out.is_empty());
}

#[test]
fn parse_ibody_unknown_name_index_skips_entry() {
    let mut buf = ibody_buf();
    let first_entry = 4usize;
    let mut tail = buf.len();
    let val = b"test";
    let offs = place_value(&mut buf, val, first_entry, &mut tail);
    let next = write_entry(
        &mut buf,
        first_entry,
        5,
        b"weird",
        offs,
        0,
        u32::try_from(val.len()).expect("the test fixture value fits in u32"),
    );
    buf[next] = 0;
    buf[next + 1] = 0;

    let mut out = Vec::new();
    parse_ibody_entries(&buf, 42, &mut out).unwrap();
    assert!(out.is_empty());
}

#[test]
fn find_ibody_entry_found() {
    let mut buf = ibody_buf();
    let first_entry = 4usize;
    let mut tail = buf.len();
    let val = b"hello";
    let offs = place_value(&mut buf, val, first_entry, &mut tail);
    let next = write_entry(
        &mut buf,
        first_entry,
        1,
        b"greeting",
        offs,
        0,
        u32::try_from(val.len()).expect("the test fixture value fits in u32"),
    );
    buf[next] = 0;
    buf[next + 1] = 0;

    let result = find_ibody_entry(&buf, 42, "user.greeting").unwrap();
    match result {
        XattrLookup::Found(v) => assert_eq!(v, b"hello"),
        other => panic!("expected Found, got {other:?}"),
    }
}

#[test]
fn find_ibody_entry_not_found() {
    let mut buf = ibody_buf();
    let first_entry = 4usize;
    let mut tail = buf.len();
    let val = b"hello";
    let offs = place_value(&mut buf, val, first_entry, &mut tail);
    let next = write_entry(
        &mut buf,
        first_entry,
        1,
        b"greeting",
        offs,
        0,
        u32::try_from(val.len()).expect("the test fixture value fits in u32"),
    );
    buf[next] = 0;
    buf[next + 1] = 0;

    let result = find_ibody_entry(&buf, 42, "user.other").unwrap();
    assert!(matches!(result, XattrLookup::NotFound));
}

#[test]
fn find_ibody_entry_ea_inode() {
    let mut buf = ibody_buf();
    let first_entry = 4usize;
    let next = write_entry(&mut buf, first_entry, 1, b"big", 0, 500, 65536);
    buf[next] = 0;
    buf[next + 1] = 0;

    let result = find_ibody_entry(&buf, 42, "user.big").unwrap();
    assert!(matches!(
        result,
        XattrLookup::EaInode {
            inum: 500,
            value_size: 65536,
        }
    ));
}

#[test]
fn entry_name_matches_works() {
    assert!(entry_name_matches("user.", b"greeting", "user.greeting"));
    assert!(!entry_name_matches("user.", b"greeting", "user.other"));
    assert!(!entry_name_matches("security.", b"selinux", "user.selinux"));
    assert!(entry_name_matches("", b"raw", "raw"));
    assert!(entry_name_matches(
        "system.posix_acl_access",
        b"",
        "system.posix_acl_access"
    ));
}

fn block_buf(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    buf[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // h_refcount = 1
    buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // h_blocks = 1
    buf
}

#[test]
fn parse_block_single_entry() {
    let bsize = 4096usize;
    let mut buf = block_buf(bsize);

    let val = b"block_value";
    let start = bsize - val.len();
    buf[start..start + val.len()].copy_from_slice(val);
    let offs = u16::try_from(start).expect("the test fixture value fits in u16");

    let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
    let next = write_entry(
        &mut buf,
        entries_off,
        1,
        b"attr1",
        offs,
        0,
        u32::try_from(val.len()).expect("the test fixture value fits in u32"),
    );
    buf[next] = 0;
    buf[next + 1] = 0;

    let mut out = Vec::new();
    parse_block_entries(&buf, 42, &mut out).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name(), "user.attr1");
    assert_eq!(out[0].value(), b"block_value");
}

#[test]
fn parse_block_bad_magic() {
    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

    let mut out = Vec::new();
    let err = parse_block_entries(&buf, 42, &mut out).unwrap_err();
    match err {
        ExtError::InvalidXattrBlock { inode: 42, .. } => {}
        other => panic!("expected InvalidXattrBlock, got {other:?}"),
    }
}

#[test]
fn parse_block_bad_h_blocks() {
    let mut buf = block_buf(4096);
    buf[8..12].copy_from_slice(&2u32.to_le_bytes()); // h_blocks = 2 (must be 1)

    let mut out = Vec::new();
    let err = parse_block_entries(&buf, 99, &mut out).unwrap_err();
    match err {
        ExtError::InvalidXattrBlock { inode: 99, .. } => {}
        other => panic!("expected InvalidXattrBlock, got {other:?}"),
    }
}

#[test]
fn parse_block_too_short() {
    let buf = vec![0u8; 16];
    let mut out = Vec::new();
    let err = parse_block_entries(&buf, 1, &mut out).unwrap_err();
    match err {
        ExtError::InvalidXattrBlock { inode: 1, .. } => {}
        other => panic!("expected InvalidXattrBlock, got {other:?}"),
    }
}

// ---- xattr hash primitives ----

#[test]
fn hash_entry_unsigned_matches_kernel_walk_through_for_u_dot_x() {
    // fs/ext4/xattr.c:3127-3149. Name "u.x" (0x75 0x2e 0x78), no values.
    //   hash = (0 << 5) ^ (0 >> 27) ^ 0x75 = 0x75
    //   hash = (0x75 << 5) ^ (0x75 >> 27) ^ 0x2e = 0xEA0 ^ 0x2e = 0xE8E
    //   hash = (0xE8E << 5) ^ (0xE8E >> 27) ^ 0x78 = 0x1D1C0 ^ 0x78 = 0x1D1B8
    assert_eq!(xattr_hash_entry(b"u.x", &[]), 0x0001_D1B8);
}

#[test]
fn hash_entry_unsigned_vs_signed_diverge_on_high_byte_names() {
    // Single byte 0x80; no value.
    // Unsigned: hash = 0 ^ 0x80 = 0x80
    // Signed:   (i8)0x80 = -128 → sign-extended → 0xFFFF_FF80
    assert_eq!(xattr_hash_entry(b"\x80", &[]), 0x0000_0080);
    assert_eq!(xattr_hash_entry_signed(b"\x80", &[]), 0xFFFF_FF80);
}

#[test]
fn hash_entry_walks_value_words() {
    // "x" (0x78) + 1 value word 0x1111_2222.
    //   hash = 0 ^ 0x78 = 0x78
    //   hash = (0x78 << 16) ^ (0x78 >> 16) ^ 0x1111_2222
    //        = 0x0078_0000 ^ 0x0000_0000 ^ 0x1111_2222 = 0x1169_2222
    assert_eq!(xattr_hash_entry(b"x", &[0x1111_2222]), 0x1169_2222);
}

#[test]
fn block_hash_zero_if_any_entry_hash_zero() {
    // xattr.c:3194-3196 — any zero e_hash forces h_hash = 0.
    assert_eq!(xattr_block_hash([0x0000_0001, 0, 0x0000_0002]), 0);
}

#[test]
fn block_hash_empty_is_zero() {
    assert_eq!(xattr_block_hash([0u32; 0]), 0);
}

#[test]
fn block_hash_accumulates_per_entry() {
    // hash = 0
    // e=0x1234_5678 → 0x1234_5678
    // e=0xCAFE_BABE → rotl(0x1234_5678, 16) ^ 0xCAFE_BABE
    //               = 0x5678_1234 ^ 0xCAFE_BABE = 0x9C86_A88A
    assert_eq!(xattr_block_hash([0x1234_5678, 0xCAFE_BABE]), 0x9C86_A88A);
}

// ---- verify_xattr_block_hashes ----

/// Build a block with a single inline user.attr entry whose value
/// is `value` and whose `e_hash` + `h_hash` are computed honestly.
fn build_block_with_one_inline_entry(
    bsize: usize,
    name_index: u8,
    name: &[u8],
    value: &[u8],
) -> Vec<u8> {
    let mut buf = block_buf(bsize);
    // Allocate the EXT4_XATTR_SIZE(value_size) slot at the block tail
    // and write the value bytes at the slot start. The trailing
    // 0..3 bytes are the zero-padding the kernel writes on disk.
    let padded_len = align4(value.len());
    let slot_start = bsize - padded_len;
    buf[slot_start..slot_start + value.len()].copy_from_slice(value);

    let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
    // Write the entry header first, with placeholder e_hash, then patch.
    let _next = write_entry(
        &mut buf,
        entries_off,
        name_index,
        name,
        u16::try_from(slot_start).expect("the test fixture value fits in u16"),
        0,
        u32::try_from(value.len()).expect("the test fixture value fits in u32"),
    );
    // Hash over the actual padded slot (including any padding bytes),
    // matching `verify_xattr_block_hashes`.
    let words = read_value_words(&buf[slot_start..slot_start + padded_len]);
    let e_hash = xattr_hash_entry(name, &words);
    buf[entries_off + 12..entries_off + 16].copy_from_slice(&e_hash.to_le_bytes());

    // Compute and plant h_hash.
    let h_hash = xattr_block_hash([e_hash]);
    buf[12..16].copy_from_slice(&h_hash.to_le_bytes());

    buf
}

#[test]
fn verify_block_clean_block_reports_valid() {
    let buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
    let report = verify_xattr_block_hashes(&buf, 99).unwrap();
    assert_eq!(report.block_hash, ChecksumState::Valid);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].name, "user.attr1");
    assert_eq!(report.entries[0].state, ChecksumState::Valid);
}

#[test]
fn verify_block_corrupted_value_byte_invalid_entry() {
    let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
    // Flip a byte in the value (which sits at end of block).
    let last = buf.len() - 1;
    buf[last] ^= 0x01;
    let report = verify_xattr_block_hashes(&buf, 99).unwrap();
    assert_eq!(report.entries[0].state, ChecksumState::Invalid);
    // Block hash uses the on-disk e_hash, which we didn't touch, so
    // h_hash remains Valid.
    assert_eq!(report.block_hash, ChecksumState::Valid);
}

#[test]
fn verify_block_corrupted_padding_byte_invalidates_entry() {
    // Regression for the e_hash padding bug: ext4 hashes
    // `EXT4_XATTR_SIZE(e_value_size)` bytes (fs/ext4/xattr.c:1823-1830),
    // so non-zero padding bytes in the value slot must cause the
    // computed hash to diverge from the on-disk e_hash. Earlier
    // versions of `verify_xattr_block_hashes` synthesized zero
    // padding and reported such blocks as `Valid` by mistake.
    let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
    // "hello" is 5 bytes, padded slot is 8. Slot end byte
    // (`bsize-1`) is the last byte of the padding region and was
    // planted as zero by the helper.
    let bsize = buf.len();
    buf[bsize - 1] = 0xAB;
    let report = verify_xattr_block_hashes(&buf, 99).unwrap();
    assert_eq!(report.entries[0].state, ChecksumState::Invalid);
}

#[test]
fn verify_block_corrupted_name_byte_invalid_entry() {
    let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
    let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
    // Mutate the first byte of the entry name.
    buf[entries_off + 16] ^= 0x01;
    let report = verify_xattr_block_hashes(&buf, 99).unwrap();
    assert_eq!(report.entries[0].state, ChecksumState::Invalid);
}

#[test]
fn verify_block_corrupted_on_disk_e_hash_byte_invalidates_both() {
    let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
    let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
    // Flip the on-disk e_hash low byte.
    buf[entries_off + 12] ^= 0x01;
    let report = verify_xattr_block_hashes(&buf, 99).unwrap();
    // The computed e_hash from name+value no longer matches the
    // (corrupted) on-disk value.
    assert_eq!(report.entries[0].state, ChecksumState::Invalid);
    // And since the block hash chain uses the corrupted on-disk
    // e_hash, the recomputed h_hash diverges from the (still
    // correctly-planted) h_hash header bytes.
    assert_eq!(report.block_hash, ChecksumState::Invalid);
}

#[test]
fn verify_block_corrupted_h_hash_byte_invalidates_block_only() {
    let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
    // Flip the on-disk h_hash low byte.
    buf[12] ^= 0x01;
    let report = verify_xattr_block_hashes(&buf, 99).unwrap();
    assert_eq!(report.entries[0].state, ChecksumState::Valid);
    assert_eq!(report.block_hash, ChecksumState::Invalid);
}

#[test]
fn verify_block_ea_inode_entry_reports_unknown() {
    let bsize = 4096usize;
    let mut buf = block_buf(bsize);
    let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
    // EA-inode-backed: e_value_inum nonzero, e_value_size set, no inline value.
    let _next = write_entry(&mut buf, entries_off, 1, b"big", 0, 500, 65_536);
    // Plant a nonsense on-disk e_hash; verify path should still
    // report `Unknown` because the value isn't readable inline.
    buf[entries_off + 12..entries_off + 16].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    // Plant the matching h_hash from the on-disk e_hash chain.
    let h_hash = xattr_block_hash([0xDEAD_BEEFu32]);
    buf[12..16].copy_from_slice(&h_hash.to_le_bytes());

    let report = verify_xattr_block_hashes(&buf, 7).unwrap();
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].name, "user.big");
    assert_eq!(report.entries[0].state, ChecksumState::Unknown);
    assert_eq!(report.block_hash, ChecksumState::Valid);
}

#[test]
fn verify_block_two_entry_round_trip() {
    let bsize = 4096usize;
    let mut buf = block_buf(bsize);
    let entries_off = core::mem::size_of::<RawXattrBlockHeader>();

    // Entry 1: user.a = "1"
    let v1 = b"1";
    let s1 = bsize - 4; // 4-byte slot
    buf[s1..s1 + v1.len()].copy_from_slice(v1);
    let next = write_entry(
        &mut buf,
        entries_off,
        1,
        b"a",
        u16::try_from(s1).expect("the test fixture value fits in u16"),
        0,
        u32::try_from(v1.len()).expect("the test fixture value fits in u32"),
    );
    let words1 = read_value_words(v1);
    let e_hash1 = xattr_hash_entry(b"a", &words1);
    buf[entries_off + 12..entries_off + 16].copy_from_slice(&e_hash1.to_le_bytes());

    // Entry 2: trusted.cap = "two"
    let v2 = b"two";
    let s2 = s1 - 4;
    buf[s2..s2 + v2.len()].copy_from_slice(v2);
    let entry2_pos = next;
    let _next2 = write_entry(
        &mut buf,
        entry2_pos,
        4,
        b"cap",
        u16::try_from(s2).expect("the test fixture value fits in u16"),
        0,
        u32::try_from(v2.len()).expect("the test fixture value fits in u32"),
    );
    let words2 = read_value_words(v2);
    let e_hash2 = xattr_hash_entry(b"cap", &words2);
    buf[entry2_pos + 12..entry2_pos + 16].copy_from_slice(&e_hash2.to_le_bytes());

    let h_hash = xattr_block_hash([e_hash1, e_hash2]);
    buf[12..16].copy_from_slice(&h_hash.to_le_bytes());

    let report = verify_xattr_block_hashes(&buf, 5).unwrap();
    assert_eq!(report.block_hash, ChecksumState::Valid);
    assert_eq!(report.entries.len(), 2);
    assert_eq!(report.entries[0].name, "user.a");
    assert_eq!(report.entries[0].state, ChecksumState::Valid);
    assert_eq!(report.entries[1].name, "trusted.cap");
    assert_eq!(report.entries[1].state, ChecksumState::Valid);
}

#[test]
fn parse_block_multiple_entries() {
    let bsize = 4096usize;
    let mut buf = block_buf(bsize);

    let v1 = b"val_one";
    let s1 = bsize - v1.len();
    buf[s1..s1 + v1.len()].copy_from_slice(v1);

    let v2 = b"val_two";
    let s2 = s1 - v2.len();
    buf[s2..s2 + v2.len()].copy_from_slice(v2);

    let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
    let next = write_entry(
        &mut buf,
        entries_off,
        6,
        b"selinux",
        u16::try_from(s1).expect("the test fixture value fits in u16"),
        0,
        u32::try_from(v1.len()).expect("the test fixture value fits in u32"),
    );
    let next = write_entry(&mut buf, next, 4, b"cap", u16::try_from(s2).expect("the test fixture value fits in u16"), 0, u32::try_from(v2.len()).expect("the test fixture value fits in u32"));
    buf[next] = 0;
    buf[next + 1] = 0;

    let mut out = Vec::new();
    parse_block_entries(&buf, 5, &mut out).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].name(), "security.selinux");
    assert_eq!(out[1].name(), "trusted.cap");
}
