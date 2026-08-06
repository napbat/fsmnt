use zerocopy::byteorder::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, Unaligned};

/// Superblock magic number (`0xEF53`).
pub(crate) const SUPERBLOCK_MAGIC: u16 = 0xEF53;

/// Byte offset of the primary superblock from the start of the device.
pub(crate) const SUPERBLOCK_OFFSET: u64 = 1024;

/// On-disk ext2/ext3/ext4 superblock (exactly 1024 bytes at offset 1024).
///
/// All multi-byte fields are little-endian. Fields not needed by the
/// current phase are represented as `[u8; N]` padding.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawSuperblock {
    // -- Counts and Core Layout (0x00 - 0x4F) --
    /// 0x00: Total inode count.
    pub s_inodes_count: U32<LE>,
    /// 0x04: Total block count (lower 32 bits).
    pub s_blocks_count_lo: U32<LE>,
    /// 0x08: Reserved block count (lower 32 bits).
    pub s_r_blocks_count_lo: U32<LE>,
    /// 0x0C: Free block count (lower 32 bits).
    pub s_free_blocks_count_lo: U32<LE>,
    /// 0x10: Free inode count.
    pub s_free_inodes_count: U32<LE>,
    /// 0x14: First data block (0 for >=4 KiB blocks, 1 for 1 KiB).
    pub s_first_data_block: U32<LE>,
    /// 0x18: Block size = 2^(10 + value).
    pub s_log_block_size: U32<LE>,
    /// 0x1C: Cluster size = 2^(10 + value).
    pub s_log_cluster_size: U32<LE>,
    /// 0x20: Blocks per block group.
    pub s_blocks_per_group: U32<LE>,
    /// 0x24: Clusters per block group.
    pub s_clusters_per_group: U32<LE>,
    /// 0x28: Inodes per block group.
    pub s_inodes_per_group: U32<LE>,
    /// 0x2C: Last mount time (Unix seconds, low 32 bits).
    pub s_mtime: U32<LE>,
    /// 0x30: Last write time (Unix seconds, low 32 bits).
    pub s_wtime: U32<LE>,
    /// 0x34: Mount count since last fsck.
    pub s_mnt_count: U16<LE>,
    /// 0x36: Max mounts before fsck.
    pub s_max_mnt_count: U16<LE>,
    /// 0x38: Magic number (must be 0xEF53).
    pub s_magic: U16<LE>,
    /// 0x3A: Filesystem state flags.
    pub s_state: U16<LE>,
    /// 0x3C: Error behavior code.
    pub s_errors: U16<LE>,
    /// 0x3E: Minor revision level.
    pub s_minor_rev_level: U16<LE>,
    /// 0x40: Last fsck time.
    pub s_lastcheck: U32<LE>,
    /// 0x44: Max interval between fsck runs (seconds).
    pub s_checkinterval: U32<LE>,
    /// 0x48: Creator OS code.
    pub s_creator_os: U32<LE>,
    /// 0x4C: Revision level (0 = original, 1 = dynamic).
    pub s_rev_level: U32<LE>,

    // -- Default Reservations and Dynamic Rev (0x50 - 0x67) --
    /// 0x50: Default UID for reserved blocks.
    pub s_def_resuid: U16<LE>,
    /// 0x52: Default GID for reserved blocks.
    pub s_def_resgid: U16<LE>,
    /// 0x54: First non-reserved inode.
    pub s_first_ino: U32<LE>,
    /// 0x58: On-disk inode size in bytes.
    pub s_inode_size: U16<LE>,
    /// 0x5A: Block group number hosting this superblock copy.
    pub s_block_group_nr: U16<LE>,
    /// 0x5C: Compatible feature flags.
    pub s_feature_compat: U32<LE>,
    /// 0x60: Incompatible feature flags.
    pub s_feature_incompat: U32<LE>,
    /// 0x64: Read-only compatible feature flags.
    pub s_feature_ro_compat: U32<LE>,

    // -- Identity (0x68 - 0xCB) --
    /// 0x68: 128-bit filesystem UUID.
    pub s_uuid: [u8; 16],
    /// 0x78: Volume label (null-terminated, up to 16 bytes).
    pub s_volume_name: [u8; 16],
    /// 0x88: Last mount path (null-terminated, up to 64 bytes).
    pub s_last_mounted: [u8; 64],
    /// 0xC8: Compression algorithm usage bitmap.
    pub s_algorithm_usage_bitmap: U32<LE>,

    // -- Preallocation and Reserved GDT (0xCC - 0xCF) --
    /// 0xCC: Blocks to preallocate for regular files.
    pub s_prealloc_blocks: u8,
    /// 0xCD: Blocks to preallocate for directories.
    pub s_prealloc_dir_blocks: u8,
    /// 0xCE: Reserved GDT blocks for online resize.
    pub s_reserved_gdt_blocks: U16<LE>,

    // -- Journal Parameters (0xD0 - 0x107) --
    /// 0xD0: UUID of the journal superblock.
    pub s_journal_uuid: [u8; 16],
    /// 0xE0: Journal file inode number.
    pub s_journal_inum: U32<LE>,
    /// 0xE4: External journal device number (0 = internal).
    pub s_journal_dev: U32<LE>,
    /// 0xE8: Head of orphan inode list.
    pub s_last_orphan: U32<LE>,
    /// 0xEC: HTREE hash seed (4 x u32).
    pub s_hash_seed: [U32<LE>; 4],
    /// 0xFC: Default hash algorithm for directory indexing.
    pub s_def_hash_version: u8,
    /// 0xFD: Journal backup type.
    pub s_jnl_backup_type: u8,
    /// 0xFE: Group descriptor size in bytes.
    pub s_desc_size: U16<LE>,
    /// 0x100: Default mount options.
    pub s_default_mount_opts: U32<LE>,
    /// 0x104: First meta block group.
    pub s_first_meta_bg: U32<LE>,

    /// 0x108: Filesystem creation time (low 32 bits; high byte at 0x276).
    pub s_mkfs_time: U32<LE>,
    /// 0x10C: Backup of the journal inode `i_block` (17 × u32 = 68 bytes).
    /// Read directly through `SUPERBLOCK_OFFSET + 0x10C` by the journal
    /// fallback locator; typed here so the offset is part of the layout
    /// invariant.
    pub s_jnl_blocks: [U32<LE>; 17],

    // -- 64-bit Extensions (0x150 - 0x15F) --
    /// 0x150: Total block count (upper 32 bits).
    pub s_blocks_count_hi: U32<LE>,
    /// 0x154: Reserved block count (upper 32 bits).
    pub s_r_blocks_count_hi: U32<LE>,
    /// 0x158: Free block count (upper 32 bits).
    pub s_free_blocks_count_hi: U32<LE>,
    /// 0x15C: Minimum extra inode size (bytes).
    pub s_min_extra_isize: U16<LE>,
    /// 0x15E: Desired extra inode size (bytes).
    pub s_want_extra_isize: U16<LE>,

    /// 0x160: Miscellaneous filesystem flags (e.g. signed/unsigned htree
    /// hash, test_fs marker).
    pub s_flags: U32<LE>,
    /// 0x164: RAID stride (`s_raid_stride`, blocks per disk in a stripe).
    pub s_raid_stride: U16<LE>,
    /// 0x166: MMP poll interval in seconds (`s_mmp_update_interval`).
    pub s_mmp_update_interval: U16<LE>,
    /// 0x168: Block number of the multi-mount-protection block.
    pub s_mmp_block: U64<LE>,
    /// 0x170: RAID stripe width in blocks (`s_raid_stripe_width`).
    pub s_raid_stripe_width: U32<LE>,
    /// 0x174: log2 of flex_bg group size (`s_log_groups_per_flex`).
    pub s_log_groups_per_flex: u8,

    /// 0x175: Metadata checksum algorithm (must be 1 = CRC32C).
    pub s_checksum_type: u8,

    /// 0x176: Encryption versioning level (`s_encryption_level`).
    pub s_encryption_level: u8,
    /// 0x177: Padding byte (reserved, zero on disk).
    pub s_reserved_pad: u8,
    /// 0x178: Lifetime kilobytes written counter (`s_kbytes_written`).
    pub s_kbytes_written: U64<LE>,
    /// 0x180: Active snapshot inode number (out-of-tree snapshot patch).
    pub s_snapshot_inum: U32<LE>,
    /// 0x184: Sequential snapshot ID.
    pub s_snapshot_id: U32<LE>,
    /// 0x188: Blocks reserved for the active snapshot's COW use.
    pub s_snapshot_r_blocks_count: U64<LE>,
    /// 0x190: On-disk snapshot list head inode number.
    pub s_snapshot_list: U32<LE>,
    /// 0x194: Total ext4 errors observed (`s_error_count`).
    pub s_error_count: U32<LE>,
    /// 0x198: First-error time (low 32 bits; high byte at 0x278).
    pub s_first_error_time: U32<LE>,
    /// 0x19C: First-error inode number.
    pub s_first_error_ino: U32<LE>,
    /// 0x1A0: First-error block number.
    pub s_first_error_block: U64<LE>,
    /// 0x1A8: First-error C function name (32-byte fixed buffer,
    /// `__nonstring` in the kernel — no NUL guarantee).
    pub s_first_error_func: [u8; 32],
    /// 0x1C8: First-error source line.
    pub s_first_error_line: U32<LE>,
    /// 0x1CC: Last-error time (low 32 bits; high byte at 0x279).
    pub s_last_error_time: U32<LE>,
    /// 0x1D0: Last-error inode number.
    pub s_last_error_ino: U32<LE>,
    /// 0x1D4: Last-error source line.
    pub s_last_error_line: U32<LE>,
    /// 0x1D8: Last-error block number.
    pub s_last_error_block: U64<LE>,
    /// 0x1E0: Last-error C function name (32-byte fixed buffer,
    /// `__nonstring`).
    pub s_last_error_func: [u8; 32],
    /// 0x200: Mount options string (`s_mount_opts`, 64 bytes,
    /// NUL-padded; preserve raw bytes for forensic output).
    pub s_mount_opts: [u8; 64],

    /// 0x240: Inode number of the user quota file (vfsv1 format).
    /// Zero when `RO_COMPAT_QUOTA` is clear or no user-quota tree is set.
    pub s_usr_quota_inum: U32<LE>,
    /// 0x244: Inode number of the group quota file (vfsv1 format).
    /// Zero when `RO_COMPAT_QUOTA` is clear or no group-quota tree is set.
    pub s_grp_quota_inum: U32<LE>,
    /// 0x248: Overhead clusters/blocks not available for user data
    /// (superblock copies, GDT, bitmaps, inode tables).
    pub s_overhead_clusters: U32<LE>,

    /// 0x24C: SPARSE_SUPER2 backup block groups.
    pub s_backup_bgs: [U32<LE>; 2],

    /// 0x254: Encryption algorithm codes in use (four 1-byte values).
    /// Zero on filesystems without fscrypt.
    pub s_encrypt_algos: [u8; 4],
    /// 0x258: Salt for fscrypt string-to-key derivation.
    /// Zero on filesystems without fscrypt.
    pub s_encrypt_pw_salt: [u8; 16],

    /// 0x268: Inode number of the lost+found directory (4 bytes; padding).
    _padding_268: [u8; 4],

    /// 0x26C: Inode number of the project quota file (vfsv1 format).
    /// Zero when `RO_COMPAT_PROJECT` is clear or no project-quota tree is set.
    pub s_prj_quota_inum: U32<LE>,

    /// 0x270: CRC32C checksum seed (replaces UUID-derived seed
    /// when INCOMPAT_CSUM_SEED is set).
    pub s_checksum_seed: U32<LE>,

    /// 0x274: High byte of `s_wtime` (40-bit unsigned epoch extension).
    pub s_wtime_hi: u8,
    /// 0x275: High byte of `s_mtime`.
    pub s_mtime_hi: u8,
    /// 0x276: High byte of `s_mkfs_time`.
    pub s_mkfs_time_hi: u8,
    /// 0x277: High byte of `s_lastcheck`.
    pub s_lastcheck_hi: u8,
    /// 0x278: High byte of `s_first_error_time`.
    pub s_first_error_time_hi: u8,
    /// 0x279: High byte of `s_last_error_time`.
    pub s_last_error_time_hi: u8,
    /// 0x27A: First-error kernel error code (errno value, populated on
    /// post-Linux 4.x kernels — older kernels leave this zero).
    pub s_first_error_errcode: u8,
    /// 0x27B: Last-error kernel error code.
    pub s_last_error_errcode: u8,

    /// 0x27C: Filename character encoding (UTF-8 = 1).
    pub s_encoding: U16<LE>,
    /// 0x27E: Encoding flags (bit 0 = strict mode).
    pub s_encoding_flags: U16<LE>,

    // -- Orphan File (0x280 - 0x283) --
    /// 0x280: Inode number of the orphan file. Valid only when
    /// `COMPAT_ORPHAN_FILE` is set.
    pub s_orphan_file_inum: U32<LE>,

    // -- 0x284-0x3FB: reserved padding --
    _padding_284: [u8; 376],

    /// 0x3FC: CRC32C checksum of the entire superblock.
    pub s_checksum: U32<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawSuperblock>() == 1024,
    "RawSuperblock must be exactly 1024 bytes"
);

/// One side of the superblock error-history record (first or last).
///
/// Mirrors kernel `s_first_error_*` / `s_last_error_*` field groups.
/// `func` is the raw 32-byte fixed buffer from disk (kernel marks the
/// field `__nonstring`, so it is not guaranteed NUL-terminated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtSuperblockError {
    /// 40-bit unsigned seconds since the Unix epoch
    /// (`((time_hi as u64) << 32) + time_lo`).
    pub time_seconds: u64,
    /// Inode involved in the error (0 if not applicable).
    pub inode: u32,
    /// Block involved in the error (0 if not applicable).
    pub block: u64,
    /// Source line of the C function that recorded the error.
    pub line: u32,
    /// Raw 32-byte function name buffer (no UTF-8 coercion, no NUL guarantee).
    pub func: [u8; 32],
    /// Kernel errno value (post-Linux-4.x), zero on older kernels.
    pub errcode: u8,
}

/// Forensic-relevant superblock snapshot.
///
/// Returned by [`Ext::superblock_forensics`]; captures lifetime writes,
/// mkfs/mount timestamps, the error-history pair, mount options, and the
/// error counter. All timestamps are 40-bit unsigned seconds since the
/// Unix epoch (`fs/ext4/super.c:438-440` extension formula).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtSuperblockForensics {
    /// Filesystem creation time (`s_mkfs_time` + `s_mkfs_time_hi`).
    pub mkfs_time_seconds: u64,
    /// Last mount time (`s_mtime` + `s_mtime_hi`).
    pub mtime_seconds: u64,
    /// Last write time (`s_wtime` + `s_wtime_hi`).
    pub wtime_seconds: u64,
    /// Last fsck time (`s_lastcheck` + `s_lastcheck_hi`).
    pub lastcheck_seconds: u64,
    /// Lifetime kilobytes written counter.
    pub kbytes_written: u64,
    /// Total ext4 errors observed since mkfs.
    pub error_count: u32,
    /// Raw `s_mount_opts` buffer (`__u8[64]`, NUL-padded).
    pub mount_opts: [u8; 64],
    /// First-error record. `None` when `s_first_error_time` is zero
    /// (kernel writes a nonzero time at the first recorded error).
    pub first_error: Option<ExtSuperblockError>,
    /// Last-error record. `None` when `s_last_error_time` is zero.
    pub last_error: Option<ExtSuperblockError>,
}

/// 40-bit unsigned epoch extension. Mirrors `fs/ext4/super.c:438-440`:
/// `((time64_t)(*hi) << 32) + le32_to_cpu(*lo)`.
fn extend_sb_timestamp(lo: u32, hi: u8) -> u64 {
    (u64::from(hi) << 32) + u64::from(lo)
}

impl ExtSuperblockForensics {
    /// Parse a forensic snapshot from a raw superblock view.
    pub(crate) fn from_raw(sb: &RawSuperblock) -> Self {
        let first_time = extend_sb_timestamp(sb.s_first_error_time.get(), sb.s_first_error_time_hi);
        let last_time = extend_sb_timestamp(sb.s_last_error_time.get(), sb.s_last_error_time_hi);

        let first_error = if first_time == 0 {
            None
        } else {
            Some(ExtSuperblockError {
                time_seconds: first_time,
                inode: sb.s_first_error_ino.get(),
                block: sb.s_first_error_block.get(),
                line: sb.s_first_error_line.get(),
                func: sb.s_first_error_func,
                errcode: sb.s_first_error_errcode,
            })
        };

        let last_error = if last_time == 0 {
            None
        } else {
            Some(ExtSuperblockError {
                time_seconds: last_time,
                inode: sb.s_last_error_ino.get(),
                block: sb.s_last_error_block.get(),
                line: sb.s_last_error_line.get(),
                func: sb.s_last_error_func,
                errcode: sb.s_last_error_errcode,
            })
        };

        Self {
            mkfs_time_seconds: extend_sb_timestamp(sb.s_mkfs_time.get(), sb.s_mkfs_time_hi),
            mtime_seconds: extend_sb_timestamp(sb.s_mtime.get(), sb.s_mtime_hi),
            wtime_seconds: extend_sb_timestamp(sb.s_wtime.get(), sb.s_wtime_hi),
            lastcheck_seconds: extend_sb_timestamp(sb.s_lastcheck.get(), sb.s_lastcheck_hi),
            kbytes_written: sb.s_kbytes_written.get(),
            error_count: sb.s_error_count.get(),
            mount_opts: sb.s_mount_opts,
            first_error,
            last_error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_superblock_is_1024_bytes() {
        assert_eq!(core::mem::size_of::<RawSuperblock>(), 1024);
    }

    #[test]
    fn parse_superblock_magic() {
        let mut buf = [0u8; 1024];
        buf[0x38] = 0x53;
        buf[0x39] = 0xEF;
        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(sb.s_magic.get(), 0xEF53);
    }

    #[test]
    fn parse_superblock_fields_at_correct_offsets() {
        let mut buf = [0u8; 1024];
        // s_inodes_count at 0x00
        buf[0x00..0x04].copy_from_slice(&100u32.to_le_bytes());
        // s_blocks_count_lo at 0x04
        buf[0x04..0x08].copy_from_slice(&200u32.to_le_bytes());
        // s_log_block_size at 0x18
        buf[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
        // s_inodes_per_group at 0x28
        buf[0x28..0x2C].copy_from_slice(&50u32.to_le_bytes());
        // s_magic at 0x38
        buf[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        // s_inode_size at 0x58
        buf[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());
        // s_feature_incompat at 0x60
        buf[0x60..0x64].copy_from_slice(&0x0242u32.to_le_bytes());
        // s_desc_size at 0xFE
        buf[0xFE..0x100].copy_from_slice(&64u16.to_le_bytes());
        // s_blocks_count_hi at 0x150
        buf[0x150..0x154].copy_from_slice(&1u32.to_le_bytes());

        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(sb.s_inodes_count.get(), 100);
        assert_eq!(sb.s_blocks_count_lo.get(), 200);
        assert_eq!(sb.s_log_block_size.get(), 2);
        assert_eq!(sb.s_inodes_per_group.get(), 50);
        assert_eq!(sb.s_magic.get(), 0xEF53);
        assert_eq!(sb.s_inode_size.get(), 256);
        assert_eq!(sb.s_feature_incompat.get(), 0x0242);
        assert_eq!(sb.s_desc_size.get(), 64);
        assert_eq!(sb.s_blocks_count_hi.get(), 1);
    }

    #[test]
    fn parse_superblock_orphan_file_inum_at_0x280() {
        let mut buf = [0u8; 1024];
        // s_magic at 0x38 so RawSuperblock accepts the buffer.
        buf[0x38] = 0x53;
        buf[0x39] = 0xEF;
        // s_orphan_file_inum at 0x280 = 0xDEAD_BEEF.
        buf[0x280..0x284].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(sb.s_magic.get(), 0xEF53);
        assert_eq!(sb.s_orphan_file_inum.get(), 0xDEAD_BEEF);
    }

    #[test]
    fn parse_superblock_backup_bgs_at_correct_offsets() {
        let mut buf = [0u8; 1024];
        buf[0x24C..0x250].copy_from_slice(&7u32.to_le_bytes());
        buf[0x250..0x254].copy_from_slice(&11u32.to_le_bytes());
        buf[0x270..0x274].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
        buf[0x27C..0x27E].copy_from_slice(&1u16.to_le_bytes());
        buf[0x280..0x284].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(sb.s_backup_bgs[0].get(), 7);
        assert_eq!(sb.s_backup_bgs[1].get(), 11);
        assert_eq!(sb.s_checksum_seed.get(), 0xCAFE_BABE);
        assert_eq!(sb.s_encoding.get(), 1);
        assert_eq!(sb.s_orphan_file_inum.get(), 0xDEAD_BEEF);
    }

    #[test]
    fn raw_superblock_is_still_1024_bytes_after_orphan_carveout() {
        assert_eq!(core::mem::size_of::<RawSuperblock>(), 1024);
    }

    #[test]
    fn parse_superblock_encryption_fields_at_correct_offsets() {
        let mut buf = [0u8; 1024];
        buf[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        buf[0x254..0x258].copy_from_slice(&[0x01, 0x04, 0x00, 0x00]);
        buf[0x258..0x268].copy_from_slice(&[0xAB; 16]);

        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(sb.s_encrypt_algos, [0x01, 0x04, 0x00, 0x00]);
        assert_eq!(sb.s_encrypt_pw_salt, [0xAB; 16]);
    }

    #[test]
    fn parse_forensic_field_offsets_first_block() {
        let mut buf = [0u8; 1024];
        buf[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        // 0x108..0x10C: s_mkfs_time
        buf[0x108..0x10C].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        // 0x10C..0x150: s_jnl_blocks (just test the first u32)
        buf[0x10C..0x110].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        // 0x148..0x14C: s_jnl_blocks[15]
        buf[0x148..0x14C].copy_from_slice(&0x0A0B_0C0Du32.to_le_bytes());

        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(sb.s_mkfs_time.get(), 0xAABB_CCDD);
        assert_eq!(sb.s_jnl_blocks[0].get(), 0x1234_5678);
        assert_eq!(sb.s_jnl_blocks[15].get(), 0x0A0B_0C0D);
    }

    #[test]
    fn parse_forensic_field_offsets_flags_mmp_kbytes() {
        let mut buf = [0u8; 1024];
        buf[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        // 0x160: s_flags
        buf[0x160..0x164].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        // 0x164: s_raid_stride
        buf[0x164..0x166].copy_from_slice(&8u16.to_le_bytes());
        // 0x166: s_mmp_update_interval
        buf[0x166..0x168].copy_from_slice(&60u16.to_le_bytes());
        // 0x168: s_mmp_block
        buf[0x168..0x170].copy_from_slice(&0x0011_2233_4455_6677u64.to_le_bytes());
        // 0x170: s_raid_stripe_width
        buf[0x170..0x174].copy_from_slice(&64u32.to_le_bytes());
        // 0x174: s_log_groups_per_flex
        buf[0x174] = 4;
        // 0x175: s_checksum_type
        buf[0x175] = 1;
        // 0x176: s_encryption_level
        buf[0x176] = 0;
        // 0x178: s_kbytes_written
        buf[0x178..0x180].copy_from_slice(&0x0000_DEAD_BEEF_CAFEu64.to_le_bytes());

        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(sb.s_flags.get(), 0x1234_5678);
        assert_eq!(sb.s_raid_stride.get(), 8);
        assert_eq!(sb.s_mmp_update_interval.get(), 60);
        assert_eq!(sb.s_mmp_block.get(), 0x0011_2233_4455_6677);
        assert_eq!(sb.s_raid_stripe_width.get(), 64);
        assert_eq!(sb.s_log_groups_per_flex, 4);
        assert_eq!(sb.s_checksum_type, 1);
        assert_eq!(sb.s_encryption_level, 0);
        assert_eq!(sb.s_kbytes_written.get(), 0x0000_DEAD_BEEF_CAFE);
    }

    #[test]
    fn parse_forensic_field_offsets_error_history() {
        let mut buf = [0u8; 1024];
        buf[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        buf[0x194..0x198].copy_from_slice(&7u32.to_le_bytes());
        buf[0x198..0x19C].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        buf[0x19C..0x1A0].copy_from_slice(&42u32.to_le_bytes());
        buf[0x1A0..0x1A8].copy_from_slice(&0x0000_0000_DEAD_BEEFu64.to_le_bytes());
        buf[0x1A8..0x1B7].copy_from_slice(b"ext4_iget_extra");
        buf[0x1C8..0x1CC].copy_from_slice(&5508u32.to_le_bytes());
        buf[0x1CC..0x1D0].copy_from_slice(&1_700_500_000u32.to_le_bytes());
        buf[0x1D0..0x1D4].copy_from_slice(&77u32.to_le_bytes());
        buf[0x1D4..0x1D8].copy_from_slice(&999u32.to_le_bytes());
        buf[0x1D8..0x1E0].copy_from_slice(&0x0000_BABE_DEAD_BEEFu64.to_le_bytes());
        buf[0x1E0..0x1EE].copy_from_slice(b"ext4_get_inode");

        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(sb.s_error_count.get(), 7);
        assert_eq!(sb.s_first_error_time.get(), 1_700_000_000);
        assert_eq!(sb.s_first_error_ino.get(), 42);
        assert_eq!(sb.s_first_error_block.get(), 0xDEAD_BEEF);
        assert_eq!(&sb.s_first_error_func[..15], b"ext4_iget_extra");
        assert_eq!(sb.s_first_error_line.get(), 5508);
        assert_eq!(sb.s_last_error_time.get(), 1_700_500_000);
        assert_eq!(sb.s_last_error_ino.get(), 77);
        assert_eq!(sb.s_last_error_line.get(), 999);
        assert_eq!(sb.s_last_error_block.get(), 0x0000_BABE_DEAD_BEEF);
        assert_eq!(&sb.s_last_error_func[..14], b"ext4_get_inode");
    }

    #[test]
    fn parse_forensic_field_offsets_mount_opts_and_high_bytes() {
        let mut buf = [0u8; 1024];
        buf[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        buf[0x200..0x20E].copy_from_slice(b"data=writeback");
        buf[0x274] = 1;
        buf[0x275] = 2;
        buf[0x276] = 3;
        buf[0x277] = 4;
        buf[0x278] = 5;
        buf[0x279] = 6;
        buf[0x27A] = 7;
        buf[0x27B] = 8;

        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(&sb.s_mount_opts[..14], b"data=writeback");
        assert_eq!(sb.s_wtime_hi, 1);
        assert_eq!(sb.s_mtime_hi, 2);
        assert_eq!(sb.s_mkfs_time_hi, 3);
        assert_eq!(sb.s_lastcheck_hi, 4);
        assert_eq!(sb.s_first_error_time_hi, 5);
        assert_eq!(sb.s_last_error_time_hi, 6);
        assert_eq!(sb.s_first_error_errcode, 7);
        assert_eq!(sb.s_last_error_errcode, 8);
    }

    #[test]
    fn forensics_zero_error_times_yield_none() {
        let buf = [0u8; 1024];
        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        let f = ExtSuperblockForensics::from_raw(sb);
        assert!(f.first_error.is_none());
        assert!(f.last_error.is_none());
        assert_eq!(f.error_count, 0);
        assert_eq!(f.kbytes_written, 0);
        assert_eq!(f.mkfs_time_seconds, 0);
    }

    #[test]
    fn forensics_extends_first_error_time_to_40_bit() {
        let mut buf = [0u8; 1024];
        // ((1 << 32) + 1) = 0x1_0000_0001 per fs/ext4/super.c:438-440.
        buf[0x198..0x19C].copy_from_slice(&1u32.to_le_bytes());
        buf[0x278] = 0x01;
        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        let f = ExtSuperblockForensics::from_raw(sb);
        let err = f.first_error.expect("first_error must be Some");
        assert_eq!(err.time_seconds, 0x0000_0001_0000_0001);
    }

    #[test]
    fn forensics_preserves_invalid_utf8_in_func() {
        let mut buf = [0u8; 1024];
        buf[0x198..0x19C].copy_from_slice(&100u32.to_le_bytes());
        buf[0x1A8] = 0xFF;
        buf[0x1A9] = 0xFE;
        buf[0x1AA] = 0xC0;
        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        let f = ExtSuperblockForensics::from_raw(sb);
        let err = f.first_error.unwrap();
        assert_eq!(err.func[0], 0xFF);
        assert_eq!(err.func[1], 0xFE);
        assert_eq!(err.func[2], 0xC0);
    }

    #[test]
    fn forensics_full_round_trip() {
        let mut buf = [0u8; 1024];
        buf[0x108..0x10C].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        buf[0x276] = 0;
        buf[0x178..0x180].copy_from_slice(&123_456_789u64.to_le_bytes());
        buf[0x200..0x20E].copy_from_slice(b"data=writeback");
        buf[0x194..0x198].copy_from_slice(&5u32.to_le_bytes());
        buf[0x198..0x19C].copy_from_slice(&1_600_000_000u32.to_le_bytes());
        buf[0x1A8..0x1B1].copy_from_slice(b"ext4_iget");
        buf[0x1C8..0x1CC].copy_from_slice(&5508u32.to_le_bytes());
        buf[0x27A] = 5;
        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        let f = ExtSuperblockForensics::from_raw(sb);
        assert_eq!(f.mkfs_time_seconds, 1_700_000_000);
        assert_eq!(f.kbytes_written, 123_456_789);
        assert_eq!(&f.mount_opts[..14], b"data=writeback");
        assert_eq!(f.error_count, 5);
        let err = f.first_error.unwrap();
        assert_eq!(err.time_seconds, 1_600_000_000);
        assert_eq!(&err.func[..9], b"ext4_iget");
        assert_eq!(err.line, 5508);
        assert_eq!(err.errcode, 5);
        assert!(f.last_error.is_none());
    }

    #[test]
    fn parse_superblock_quota_inum_fields_at_correct_offsets() {
        let mut buf = [0u8; 1024];
        // s_magic at 0x38 so RawSuperblock accepts the buffer.
        buf[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        buf[0x240..0x244].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        buf[0x244..0x248].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        buf[0x248..0x24C].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        buf[0x26C..0x270].copy_from_slice(&0xFACE_F00Du32.to_le_bytes());

        let sb = RawSuperblock::ref_from_bytes(&buf).unwrap();
        assert_eq!(sb.s_usr_quota_inum.get(), 0xAABB_CCDD);
        assert_eq!(sb.s_grp_quota_inum.get(), 0x1122_3344);
        assert_eq!(sb.s_overhead_clusters.get(), 0xDEAD_BEEF);
        assert_eq!(sb.s_prj_quota_inum.get(), 0xFACE_F00D);
    }
}
