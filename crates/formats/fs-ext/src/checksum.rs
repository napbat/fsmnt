/// Tri-state checksum validation result.
///
/// `Unknown` covers "feature not present", "checksum field absent",
/// or "not applicable" (e.g. ext2 without METADATA_CSUM).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumState {
    /// Checksum not applicable or field not present.
    Unknown,
    /// Computed checksum matches on-disk value.
    Valid,
    /// Computed checksum does not match on-disk value.
    Invalid,
}

/// Compute the kernel's raw `__crc32c_le(crc, data)`.
///
/// The `crc32c` crate's `crc32c_append(x, data)` returns
/// `!accumulate(!x, data)`. To get the raw accumulation:
/// `accumulate(crc, data) = !crc32c_append(!crc, data)`.
pub(crate) fn ext4_crc32c(crc: u32, data: &[u8]) -> u32 {
    !crc32c::crc32c_append(!crc, data)
}

/// CRC16 variant used by ext4's legacy `GDT_CSUM` group-descriptor checksum.
///
/// Polynomial: reflected 0xA001 (i.e. the ANSI CRC16 "X25" style ext4 inherits
/// from the kernel). Initial value `0xFFFF`, no final XOR. See
/// `ext4_group_desc_csum` in `fs/ext4/super.c`.
pub(crate) fn ext4_crc16(crc: u16, data: &[u8]) -> u16 {
    const POLY: u16 = 0xA001;
    let mut crc = crc;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Compute the CRC32C checksum seed from the filesystem UUID.
///
/// Standard mode: `seed = crc32c(~0, uuid)`.
pub(crate) fn seed_from_uuid(uuid: &[u8; 16]) -> u32 {
    ext4_crc32c(!0, uuid)
}

/// Validate the superblock CRC32C checksum.
///
/// The kernel CRCs `sb[0..0x3FC]` (the 1020 bytes before the
/// checksum field) starting from `~0`. The checksum field itself
/// is excluded, not zeroed.
pub(crate) fn verify_superblock(sb_buf: &[u8; 1024]) -> ChecksumState {
    let stored = u32::from_le_bytes(sb_buf[0x3FC..0x400].try_into().unwrap_or([0; 4]));
    let computed = ext4_crc32c(!0, &sb_buf[..0x3FC]);

    if computed == stored {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Compute the CRC32C checksum field for a superblock.
///
/// Inverse of [`verify_superblock`]: returns the value to store at
/// `sb_buf[0x3FC..0x400]`. Callers recomputing the superblock after an
/// in-place patch must zero the on-disk field before (or skip it, since
/// `ext4_crc32c(!0, &sb_buf[..0x3FC])` excludes the checksum field by
/// slicing).
pub(crate) fn compute_superblock_csum(sb_buf: &[u8; 1024]) -> u32 {
    ext4_crc32c(!0, &sb_buf[..0x3FC])
}

/// Validate a group descriptor CRC32C checksum (METADATA_CSUM mode).
///
/// Input: `crc32c(seed, le32(group) || desc_with_csum_zeroed)`.
/// Result truncated to 16 bits.
pub(crate) fn verify_group_descriptor(seed: u32, group: u32, desc_buf: &[u8]) -> ChecksumState {
    let csum_offset = 0x1E;
    if desc_buf.len() < csum_offset + 2 {
        return ChecksumState::Unknown;
    }

    let stored = u16::from_le_bytes([desc_buf[csum_offset], desc_buf[csum_offset + 1]]);

    let mut crc = ext4_crc32c(seed, &group.to_le_bytes());
    crc = ext4_crc32c(crc, &desc_buf[..csum_offset]);
    crc = ext4_crc32c(crc, &[0u8; 2]);
    if desc_buf.len() > csum_offset + 2 {
        crc = ext4_crc32c(crc, &desc_buf[csum_offset + 2..]);
    }
    let computed = (crc & 0xFFFF) as u16;

    if computed == stored {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Compute the METADATA_CSUM group-descriptor checksum.
///
/// Returns the 16-bit value to store at `desc_buf[0x1E..0x20]`. Input buffer
/// must already have the checksum field zeroed (or be freshly built with it
/// unset). Inverse of [`verify_group_descriptor`].
///
/// Panics if `desc_buf.len() < 0x20`.
pub(crate) fn compute_group_descriptor_csum_crc32c(seed: u32, group: u32, desc_buf: &[u8]) -> u16 {
    assert!(desc_buf.len() >= 0x20, "group descriptor buffer too short");
    let csum_offset = 0x1E;
    let mut crc = ext4_crc32c(seed, &group.to_le_bytes());
    crc = ext4_crc32c(crc, &desc_buf[..csum_offset]);
    crc = ext4_crc32c(crc, &[0u8; 2]);
    if desc_buf.len() > csum_offset + 2 {
        crc = ext4_crc32c(crc, &desc_buf[csum_offset + 2..]);
    }
    (crc & 0xFFFF) as u16
}

/// Compute the legacy `GDT_CSUM` CRC16 for a group descriptor.
///
/// Input is `crc16(0xFFFF, sb.s_uuid || le32(group) || desc_with_csum_zeroed)`.
pub(crate) fn compute_group_descriptor_csum_crc16(
    uuid: &[u8; 16],
    group: u32,
    desc_buf: &[u8],
) -> u16 {
    assert!(desc_buf.len() >= 0x20, "group descriptor buffer too short");
    let mut crc = ext4_crc16(0xFFFF, uuid);
    crc = ext4_crc16(crc, &group.to_le_bytes());
    crc = ext4_crc16(crc, &desc_buf[..0x1E]);
    crc = ext4_crc16(crc, &[0u8; 2]);
    if desc_buf.len() > 0x20 {
        crc = ext4_crc16(crc, &desc_buf[0x20..]);
    }
    crc
}

/// Validate a legacy-path (`GDT_CSUM` without METADATA_CSUM) group-descriptor checksum.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by Task 9 round-trip tests")
)]
pub(crate) fn verify_group_descriptor_crc16(
    uuid: &[u8; 16],
    group: u32,
    desc_buf: &[u8],
) -> ChecksumState {
    if desc_buf.len() < 0x20 {
        return ChecksumState::Unknown;
    }
    let stored = u16::from_le_bytes([desc_buf[0x1E], desc_buf[0x1F]]);
    let computed = compute_group_descriptor_csum_crc16(uuid, group, desc_buf);
    if computed == stored {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Validate an inode CRC32C checksum.
///
/// Input: `crc32c(seed, le32(ino) || le32(generation) || inode_with_csums_zeroed)`.
/// Low 16 bits in `l_i_checksum_lo` (osd2 at 0x7C), high 16 bits in
/// `i_checksum_hi` (extended field at 0x82, when `inode_size > 128`).
/// `has_hi`: whether `i_checksum_hi` at 0x82 is present
/// (requires `inode_size > 128` AND `i_extra_isize >= 4`).
pub(crate) fn verify_inode(
    seed: u32,
    ino: u32,
    generation: u32,
    inode_buf: &[u8],
    has_hi: bool,
) -> ChecksumState {
    if inode_buf.len() < 128 {
        return ChecksumState::Unknown;
    }

    // Read stored low 16 bits from osd2 (l_i_checksum_lo at 0x7C..0x7E)
    let lo = u16::from_le_bytes([inode_buf[0x7C], inode_buf[0x7D]]);
    let hi = if has_hi && inode_buf.len() > 0x84 {
        u16::from_le_bytes([inode_buf[0x82], inode_buf[0x83]])
    } else {
        0
    };
    let stored = u32::from(lo) | (u32::from(hi) << 16);

    let mut crc = ext4_crc32c(seed, &ino.to_le_bytes());
    crc = ext4_crc32c(crc, &generation.to_le_bytes());

    // Feed inode bytes with checksum fields zeroed:
    crc = ext4_crc32c(crc, &inode_buf[..0x7C]);
    crc = ext4_crc32c(crc, &[0u8; 2]); // zero l_i_checksum_lo
    crc = ext4_crc32c(crc, &inode_buf[0x7E..0x80.min(inode_buf.len())]);

    if inode_buf.len() > 128 {
        crc = ext4_crc32c(crc, &inode_buf[0x80..0x82]);
        if has_hi {
            crc = ext4_crc32c(crc, &[0u8; 2]); // zero i_checksum_hi
        } else {
            crc = ext4_crc32c(crc, &inode_buf[0x82..0x84.min(inode_buf.len())]);
        }
        if inode_buf.len() > 0x84 {
            crc = ext4_crc32c(crc, &inode_buf[0x84..]);
        }
    }

    let mask = if has_hi { 0xFFFF_FFFF } else { 0x0000_FFFF };

    if (crc & mask) == (stored & mask) {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Compute the inode checksum fields.
///
/// Returns `(lo, hi)` where `lo` goes to `inode_buf[0x7C..0x7E]` and, when
/// `has_hi` is true, `hi` goes to `inode_buf[0x82..0x84]`. The input buffer
/// must already have the checksum fields zeroed (or not yet populated).
///
/// Inverse of [`verify_inode`]. `inode_buf.len() >= 128` is required.
pub(crate) fn compute_inode_csum(
    seed: u32,
    ino: u32,
    generation: u32,
    inode_buf: &[u8],
    has_hi: bool,
) -> (u16, u16) {
    assert!(
        inode_buf.len() >= 128,
        "inode buffer must be at least 128 bytes"
    );

    let mut crc = ext4_crc32c(seed, &ino.to_le_bytes());
    crc = ext4_crc32c(crc, &generation.to_le_bytes());

    // Mirror verify_inode's feeding order, with both checksum slots zeroed.
    crc = ext4_crc32c(crc, &inode_buf[..0x7C]);
    crc = ext4_crc32c(crc, &[0u8; 2]); // l_i_checksum_lo
    crc = ext4_crc32c(crc, &inode_buf[0x7E..0x80.min(inode_buf.len())]);

    if inode_buf.len() > 128 {
        crc = ext4_crc32c(crc, &inode_buf[0x80..0x82]);
        if has_hi {
            crc = ext4_crc32c(crc, &[0u8; 2]); // i_checksum_hi
        } else {
            crc = ext4_crc32c(crc, &inode_buf[0x82..0x84.min(inode_buf.len())]);
        }
        if inode_buf.len() > 0x84 {
            crc = ext4_crc32c(crc, &inode_buf[0x84..]);
        }
    }

    let lo = (crc & 0xFFFF) as u16;
    let hi = if has_hi {
        ((crc >> 16) & 0xFFFF) as u16
    } else {
        0
    };
    (lo, hi)
}

/// Validate a CRC32C checksum on an xattr block.
///
/// Input: `crc32c(seed, le64(block_num) || block_with_h_checksum_zeroed)`.
/// The `h_checksum` field is at offset `0x10` (4 bytes).
pub(crate) fn verify_xattr_block(seed: u32, block_num: u64, block: &[u8]) -> ChecksumState {
    if block.len() < 32 {
        return ChecksumState::Unknown;
    }

    let stored = u32::from_le_bytes([block[0x10], block[0x11], block[0x12], block[0x13]]);

    let mut crc = ext4_crc32c(seed, &block_num.to_le_bytes());
    crc = ext4_crc32c(crc, &block[..0x10]);
    crc = ext4_crc32c(crc, &[0u8; 4]); // zeroed h_checksum
    if block.len() > 0x14 {
        crc = ext4_crc32c(crc, &block[0x14..]);
    }

    if crc == stored {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Compute the CRC32C checksum for an xattr block. Inverts
/// [`verify_xattr_block`]: stored at offset 0x10 (h_checksum), computed
/// over block bytes with h_checksum zeroed, folded over
/// (seed, block_num as u64 LE). `h_hash` at offset 0x0C is hashed as-is.
///
/// Panics if `block.len() < 32`.
pub(crate) fn compute_xattr_block_csum(seed: u32, block_num: u64, block: &[u8]) -> u32 {
    assert!(block.len() >= 32, "xattr block must be at least 32 bytes");
    let mut crc = ext4_crc32c(seed, &block_num.to_le_bytes());
    crc = ext4_crc32c(crc, &block[..0x10]);
    crc = ext4_crc32c(crc, &[0u8; 4]);
    crc = ext4_crc32c(crc, &block[0x14..]);
    crc
}

/// Compute the bitmap (block or inode) checksum halves.
///
/// Returns `(lo, hi)` where `lo` matches `bg_*_bitmap_csum_lo` and `hi`
/// matches `bg_*_bitmap_csum_hi` (populated only when the 64-bit group
/// descriptor layout carries the `_hi` field).
pub(crate) fn compute_bitmap_csum(seed: u32, block: &[u8]) -> (u16, u16) {
    let crc = ext4_crc32c(seed, block);
    let lo = (crc & 0xFFFF) as u16;
    let hi = ((crc >> 16) & 0xFFFF) as u16;
    (lo, hi)
}

/// Validate a bitmap (block or inode) checksum.
///
/// `stored_hi` is `Some(_)` for 64-bit group descriptors (which carry the
/// `_hi` half) and `None` for 32-bit descriptors or when the upper half was
/// never recorded on disk.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by Task 8 (round-trip tests)")
)]
pub(crate) fn verify_bitmap_csum(
    seed: u32,
    block: &[u8],
    stored_lo: u16,
    stored_hi: Option<u16>,
) -> ChecksumState {
    let (computed_lo, computed_hi) = compute_bitmap_csum(seed, block);
    let lo_ok = computed_lo == stored_lo;
    let hi_ok = match stored_hi {
        Some(hi) => hi == computed_hi,
        None => true,
    };
    if lo_ok && hi_ok {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Compute the EA inode value hash.
///
/// The kernel stores `crc32c(s_csum_seed, value_data)` in `i_atime` of
/// the EA inode. Used for integrity verification of externally-stored
/// xattr values.
pub(crate) fn ea_inode_hash(seed: u32, data: &[u8]) -> u32 {
    ext4_crc32c(seed, data)
}

/// Tail magic value in an orphan-file block (`EXT4_ORPHAN_BLOCK_MAGIC`).
pub(crate) const ORPHAN_FILE_MAGIC: u32 = 0x0B10CA04;

/// Compute the orphan-file block tail checksum.
///
/// Matches `ext2fs_do_orphan_file_block_csum` exactly:
/// `crc32c(seed, inum_le32, generation_le32, phys_block_le64, block[..block_size-8])`.
///
/// - `inum` is the orphan file's inode number.
/// - `generation` is the orphan file inode's `i_generation` field.
/// - `phys_block_num` is the physical filesystem block number of this block.
/// - Only `block[..block.len()-8]` is covered; the 8-byte tail struct
///   (4-byte magic + 4-byte checksum field) is excluded.
///
/// Returns the value to store at `block[block.len() - 4..]`.
///
/// Panics if `block.len() < 8`.
pub(crate) fn compute_orphan_file_block_csum(
    seed: u32,
    inum: u32,
    generation: u32,
    phys_block_num: u64,
    block: &[u8],
) -> u32 {
    assert!(
        block.len() >= 8,
        "orphan-file block must be at least 8 bytes"
    );
    let body = block.len() - 8;
    let mut crc = ext4_crc32c(seed, &inum.to_le_bytes());
    crc = ext4_crc32c(crc, &generation.to_le_bytes());
    crc = ext4_crc32c(crc, &phys_block_num.to_le_bytes());
    crc = ext4_crc32c(crc, &block[..body]);
    crc
}

/// Validate an orphan-file block tail checksum.
///
/// Does not check the tail magic — callers inspect that separately to
/// distinguish `OrphanFileTailMagicInvalid` from `OrphanFileChecksumInvalid`.
///
/// - `generation` is the orphan file inode's `i_generation` field.
/// - `phys_block_num` is the physical filesystem block number of this block.
pub(crate) fn verify_orphan_file_block(
    seed: u32,
    inum: u32,
    generation: u32,
    phys_block_num: u64,
    block: &[u8],
) -> ChecksumState {
    if block.len() < 8 {
        return ChecksumState::Unknown;
    }
    let tail = block.len() - 4;
    let stored = u32::from_le_bytes(block[tail..tail + 4].try_into().unwrap_or([0; 4]));
    let computed = compute_orphan_file_block_csum(seed, inum, generation, phys_block_num, block);
    if computed == stored {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Compute the common inode-based checksum prefix.
///
/// Many block checksums share the prefix `crc32c(seed, le32(ino) || le32(generation))`.
fn inode_crc_prefix(seed: u32, ino: u32, generation: u32) -> u32 {
    let crc = ext4_crc32c(seed, &ino.to_le_bytes());
    ext4_crc32c(crc, &generation.to_le_bytes())
}

/// Validate a CRC32C checksum on an extent tree block.
///
/// The `ext4_extent_tail` (4 bytes) sits at offset
/// `sizeof(header) + eh_max * sizeof(extent)` = `12 + eh_max * 12`.
/// Input: `seed + le32(ino) + le32(generation) + block_with_tail_zeroed`.
pub(crate) fn verify_extent_block(
    seed: u32,
    ino: u32,
    generation: u32,
    block: &[u8],
) -> ChecksumState {
    if block.len() < 12 {
        return ChecksumState::Unknown;
    }

    let eh_max = u16::from_le_bytes([block[4], block[5]]) as usize;
    let tail_off = 12 + eh_max * 12;
    if tail_off + 4 > block.len() {
        return ChecksumState::Unknown;
    }

    let stored = u32::from_le_bytes([
        block[tail_off],
        block[tail_off + 1],
        block[tail_off + 2],
        block[tail_off + 3],
    ]);

    let mut crc = inode_crc_prefix(seed, ino, generation);
    crc = ext4_crc32c(crc, &block[..tail_off]);
    crc = ext4_crc32c(crc, &[0u8; 4]); // zeroed tail checksum
    if tail_off + 4 < block.len() {
        crc = ext4_crc32c(crc, &block[tail_off + 4..]);
    }

    if crc == stored {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Compute the CRC32C tail checksum for an extent-tree block. Inverts
/// [`verify_extent_block`]. Checksum offset is `12 + eh_max * 12`
/// (immediately after the extent header and `eh_max` entries, NOT the
/// block's physical tail). Folded over (seed, inum, generation) via
/// `inode_crc_prefix`, then over block bytes with the 4-byte checksum
/// field zeroed.
///
/// Returns `0` if the block is too short to contain even the header.
/// Returns `0` if `eh_max` read from the block claims more space than
/// the block length can hold (caller must not treat the block as valid).
pub(crate) fn compute_extent_block_csum(
    seed: u32,
    inum: u32,
    generation: u32,
    block: &[u8],
) -> u32 {
    if block.len() < 12 {
        return 0;
    }
    let eh_max = u16::from_le_bytes([block[4], block[5]]) as usize;
    let tail_off = 12 + eh_max * 12;
    if tail_off + 4 > block.len() {
        return 0;
    }

    let mut crc = inode_crc_prefix(seed, inum, generation);
    crc = ext4_crc32c(crc, &block[..tail_off]);
    crc = ext4_crc32c(crc, &[0u8; 4]);
    if tail_off + 4 < block.len() {
        crc = ext4_crc32c(crc, &block[tail_off + 4..]);
    }
    crc
}

/// Validate a CRC32C checksum on a directory leaf block.
///
/// The sentinel `ext4_dir_entry_tail` occupies the last 12 bytes:
/// inode=0, rec_len=12, name_len=0, file_type=0xDE, det_checksum(4).
/// Returns `Unknown` if the sentinel is not present.
///
/// The kernel (`ext4_dirblock_csum`) CRCs only the directory entries
/// preceding the tail — the tail structure itself is excluded.
pub(crate) fn verify_dir_block(
    seed: u32,
    ino: u32,
    generation: u32,
    block: &[u8],
) -> ChecksumState {
    if block.len() < 12 {
        return ChecksumState::Unknown;
    }

    let tail_off = block.len() - 12;
    // Validate sentinel: file_type must be 0xDE
    if block[tail_off + 7] != 0xDE {
        return ChecksumState::Unknown;
    }

    let csum_off = tail_off + 8;
    let stored = u32::from_le_bytes([
        block[csum_off],
        block[csum_off + 1],
        block[csum_off + 2],
        block[csum_off + 3],
    ]);

    let crc = inode_crc_prefix(seed, ino, generation);
    let crc = ext4_crc32c(crc, &block[..tail_off]);

    if crc == stored {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Shared helper for dx block (dx_root/dx_node) checksums.
///
/// The kernel (`ext4_dx_csum`) CRCs `block[..count_limit_off + count*8]`
/// — the dirent and *live* dx_entry data — then `dx_tail.dt_reserved`
/// (4 bytes) and 4 zero bytes for the checksum field. Critically the
/// `dx_tail` itself lives at the *limit* slot, `count_limit_off +
/// limit*8`, not contiguously after the live entries: `limit` reserves
/// the tail's slot. The stored `dt_checksum` is the u32 at `tail + 4`.
fn verify_dx_tail(
    seed: u32,
    ino: u32,
    generation: u32,
    block: &[u8],
    count_limit_off: usize,
    count: u16,
    limit: u16,
) -> ChecksumState {
    let data_end = count_limit_off + usize::from(count) * 8;
    let tail_off = count_limit_off + usize::from(limit) * 8;
    let csum_off = tail_off + 4;
    if data_end > block.len() || csum_off + 4 > block.len() {
        return ChecksumState::Unknown;
    }

    let stored = u32::from_le_bytes([
        block[csum_off],
        block[csum_off + 1],
        block[csum_off + 2],
        block[csum_off + 3],
    ]);

    // Forensic accommodation: e2fsck -D reserves dx_tail space but does
    // not always populate the checksum. Treat an all-zero tail as
    // Unknown rather than Invalid.
    if stored == 0
        && block[tail_off] == 0
        && block[tail_off + 1] == 0
        && block[tail_off + 2] == 0
        && block[tail_off + 3] == 0
    {
        return ChecksumState::Unknown;
    }

    let mut crc = inode_crc_prefix(seed, ino, generation);
    crc = ext4_crc32c(crc, &block[..data_end]);
    crc = ext4_crc32c(crc, &block[tail_off..tail_off + 4]); // dt_reserved
    crc = ext4_crc32c(crc, &[0u8; 4]); // zeroed dt_checksum

    if crc == stored {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    }
}

/// Shared writer mirroring `verify_dx_tail` exactly.
fn compute_dx_tail(
    seed: u32,
    ino: u32,
    generation: u32,
    block: &mut [u8],
    count_limit_off: usize,
    count: u16,
    limit: u16,
) {
    let data_end = count_limit_off + usize::from(count) * 8;
    let tail_off = count_limit_off + usize::from(limit) * 8;
    let csum_off = tail_off + 4;
    if data_end > block.len() || csum_off + 4 > block.len() {
        return;
    }
    block[csum_off..csum_off + 4].copy_from_slice(&[0u8; 4]);
    let mut crc = inode_crc_prefix(seed, ino, generation);
    crc = ext4_crc32c(crc, &block[..data_end]);
    crc = ext4_crc32c(crc, &block[tail_off..tail_off + 4]); // dt_reserved
    crc = ext4_crc32c(crc, &[0u8; 4]);
    block[csum_off..csum_off + 4].copy_from_slice(&crc.to_le_bytes());
}

/// Validate a CRC32C checksum on an htree dx_root block.
///
/// The dx_root layout starts with real dirents and `dx_root_info`, so
/// the `DxCountLimit` is at `0x20`. The `dx_tail` is at the `limit`
/// slot. If `limit` leaves no room for the 8-byte `dx_tail`, the htree
/// was created without checksum tails and `Unknown` is returned.
pub(crate) fn verify_dx_root(
    seed: u32,
    ino: u32,
    generation: u32,
    block: &[u8],
    count: u16,
    limit: u16,
) -> ChecksumState {
    verify_dx_tail(seed, ino, generation, block, 0x20, count, limit)
}

/// Validate a CRC32C checksum on an interior htree dx_node block.
///
/// Interior dx_node blocks start with a fake 8-byte dirent, so the
/// `DxCountLimit` is at `0x08`. The `dx_tail` is at the `limit` slot.
pub(crate) fn verify_dx_node(
    seed: u32,
    ino: u32,
    generation: u32,
    block: &[u8],
    count: u16,
    limit: u16,
) -> ChecksumState {
    verify_dx_tail(seed, ino, generation, block, 0x08, count, limit)
}

/// Write the CRC32C `dx_tail` checksum into an htree dx_root block.
///
/// `count`/`limit` are the live `DxCountLimit` fields. Inverse of
/// `verify_dx_root`; counterpart to the kernel's `ext4_dx_csum_set`.
pub(crate) fn compute_dx_root_csum(
    seed: u32,
    ino: u32,
    generation: u32,
    block: &mut [u8],
    count: u16,
    limit: u16,
) {
    compute_dx_tail(seed, ino, generation, block, 0x20, count, limit);
}

/// Write the CRC32C `dx_tail` checksum into an interior htree dx_node
/// block. Inverse of `verify_dx_node`.
pub(crate) fn compute_dx_node_csum(
    seed: u32,
    ino: u32,
    generation: u32,
    block: &mut [u8],
    count: u16,
    limit: u16,
) {
    compute_dx_tail(seed, ino, generation, block, 0x08, count, limit);
}

#[cfg(test)]
mod tests {
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
        block[tail..tail + 4].copy_from_slice(&0x0B10CA04u32.to_le_bytes());

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
}
