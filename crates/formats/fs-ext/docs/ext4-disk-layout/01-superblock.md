<!-- ext4 Disk Layout: Superblock -->
<!-- Complete ext4_super_block structure at byte offset 1024, all fields from 0x0 through 0x3FC, state/error values, OS codes, revision levels, backup locations, and checksum formula. -->

# Superblock

## Overview

The superblock is located at **byte offset 1024** from the start of the filesystem (or the start of the partition). It is **1024 bytes** in size. All fields are **little-endian**. The magic number `0xEF53` is at offset `0x38`.

The superblock contains all filesystem-wide parameters: block size, inode count, feature flags, UUID, journal configuration, and checksum fields. It is the first structure a parser must read.

## Field Table

### Counts and Core Layout (0x0 - 0x4F)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | 4 | **s_inodes_count** | Total number of inodes in the filesystem. |
| 0x4 | 4 | **s_blocks_count_lo** | Total number of blocks in the filesystem (lower 32 bits). |
| 0x8 | 4 | **s_r_blocks_count_lo** | Number of blocks reserved for the superuser (lower 32 bits). |
| 0xC | 4 | **s_free_blocks_count_lo** | Number of free blocks (lower 32 bits). |
| 0x10 | 4 | **s_free_inodes_count** | Number of free inodes. |
| 0x14 | 4 | **s_first_data_block** | First data block. For 1 KiB block filesystems, this is 1 (the superblock occupies block 1). For larger block sizes, this is 0 (the superblock is within block 0). |
| 0x18 | 4 | **s_log_block_size** | Block size = `2^(10 + s_log_block_size)` bytes. Common values: 0 (1 KiB), 1 (2 KiB), 2 (4 KiB). |
| 0x1C | 4 | **s_log_cluster_size** | Cluster size = `2^(10 + s_log_cluster_size)` bytes. Without bigalloc, must equal `s_log_block_size`. With bigalloc, may be larger. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| 0x20 | 4 | **s_blocks_per_group** | Number of blocks per block group. Limited to `block_size * 8` (one bitmap block). |
| 0x24 | 4 | **s_clusters_per_group** | Number of clusters per block group. Without bigalloc, equals `s_blocks_per_group`. With bigalloc, equals `block_size * 8`. |
| 0x28 | 4 | **s_inodes_per_group** | Number of inodes per block group. |
| 0x2C | 4 | **s_mtime** | Last mount time (Unix timestamp, 32-bit). |
| 0x30 | 4 | **s_wtime** | Last write time (Unix timestamp, 32-bit). |
| 0x34 | 2 | **s_mnt_count** | Number of times the filesystem has been mounted since last fsck. |
| 0x36 | 2 | **s_max_mnt_count** | Maximum mount count before fsck is recommended. `0xFFFF` or `0` to disable. |
| 0x38 | 2 | **s_magic** | Magic number. Must be `0xEF53`. |
| 0x3A | 2 | **s_state** | Filesystem state. See [Filesystem State](#filesystem-state). |
| 0x3C | 2 | **s_errors** | Error behavior. See [Error Behavior](#error-behavior). |
| 0x3E | 2 | **s_minor_rev_level** | Minor revision level. |
| 0x40 | 4 | **s_lastcheck** | Time of last fsck (Unix timestamp, 32-bit). |
| 0x44 | 4 | **s_checkinterval** | Maximum interval between fsck runs (seconds). 0 to disable. |
| 0x48 | 4 | **s_creator_os** | OS that created the filesystem. See [OS Creator Codes](#os-creator-codes). |
| 0x4C | 4 | **s_rev_level** | Revision level. See [Revision Levels](#revision-levels). |

### Default Reservations and Dynamic Rev Fields (0x50 - 0x67)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x50 | 2 | **s_def_resuid** | Default UID for reserved blocks (typically 0 = root). |
| 0x52 | 2 | **s_def_resgid** | Default GID for reserved blocks (typically 0 = root). |
| 0x54 | 4 | **s_first_ino** | First non-reserved inode. In revision 0, this is fixed at 11. In revision 1+, configurable (typically 11). |
| 0x58 | 2 | **s_inode_size** | Size of each inode in bytes. In revision 0, fixed at 128. In revision 1+, configurable (typically 256). Must be a power of 2, minimum 128. |
| 0x5A | 2 | **s_block_group_nr** | Block group number of this superblock. Used to identify which copy of the superblock this is. |
| 0x5C | 4 | **s_feature_compat** | Compatible feature flags. See [02-feature-flags.md](02-feature-flags.md). |
| 0x60 | 4 | **s_feature_incompat** | Incompatible feature flags. See [02-feature-flags.md](02-feature-flags.md). |
| 0x64 | 4 | **s_feature_ro_compat** | Read-only compatible feature flags. See [02-feature-flags.md](02-feature-flags.md). |

### Identity: UUID, Volume Name, Last Mounted (0x68 - 0xC7)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x68 | 16 | **s_uuid[16]** | 128-bit filesystem UUID. Used in checksum seeds and to match external journals. |
| 0x78 | 16 | **s_volume_name[16]** | Volume label (null-terminated UTF-8 string, up to 16 bytes). |
| 0x88 | 64 | **s_last_mounted[64]** | Path where the filesystem was last mounted (null-terminated, up to 64 bytes). |
| 0xC8 | 4 | **s_algorithm_usage_bitmap** | Compression algorithm usage bitmap. Used with `INCOMPAT_COMPRESSION` (never fully implemented in the mainline kernel). |

### Preallocation and Reserved GDT (0xCC - 0xCF)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0xCC | 1 | **s_prealloc_blocks** | Number of blocks to preallocate for regular files. |
| 0xCD | 1 | **s_prealloc_dir_blocks** | Number of blocks to preallocate for directories. |
| 0xCE | 2 | **s_reserved_gdt_blocks** | Number of reserved group descriptor table blocks for online resize. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |

### Journal Parameters (0xD0 - 0x14F)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0xD0 | 16 | **s_journal_uuid[16]** | UUID of the journal superblock (for external journals). |
| 0xE0 | 4 | **s_journal_inum** | Inode number of the journal file (typically 8 for internal journals). See [10-journaling.md](10-journaling.md). |
| 0xE4 | 4 | **s_journal_dev** | Device number of the external journal device. 0 for internal journals. |
| 0xE8 | 4 | **s_last_orphan** | Head of the orphan inode list. Points to the first inode in the linked list of inodes pending deletion or truncation. See [10-journaling.md](10-journaling.md). |
| 0xEC | 16 | **s_hash_seed[4]** | Four 32-bit values used as HTREE hash seed for directory indexing. See [06-directories.md](06-directories.md). |
| 0xFC | 1 | **s_def_hash_version** | Default hash algorithm for directory indexing. See [06-directories.md](06-directories.md). |
| 0xFD | 1 | **s_jnl_backup_type** | Journal backup type. 1 = inode block mapping is stored in `s_jnl_blocks`. |
| 0xFE | 2 | **s_desc_size** | Size of group descriptor in bytes. If `INCOMPAT_64BIT` is set and this value is >= 64, then 64-byte group descriptors are in use. Otherwise, 32-byte descriptors. |
| 0x100 | 4 | **s_default_mount_opts** | Default mount options. See [02-feature-flags.md](02-feature-flags.md#default-mount-options). |
| 0x104 | 4 | **s_first_meta_bg** | First meta block group. Relevant only when `INCOMPAT_META_BG` is set. See [03-block-groups.md](03-block-groups.md). |
| 0x108 | 4 | **s_mkfs_time** | Filesystem creation time (Unix timestamp, 32-bit). |
| 0x10C | 68 | **s_jnl_blocks[17]** | Backup of the journal inode's block mapping. 17 elements of 4 bytes each. When `s_jnl_backup_type` = 1: elements 0-14 are `i_block[0..14]`, element 15 is `i_size_high`, element 16 is `i_size` (low 32 bits). |

### 64-bit Extensions (0x150 - 0x177)

These fields are valid only when `INCOMPAT_64BIT` is set.

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x150 | 4 | **s_blocks_count_hi** | High 32 bits of the total block count. Full count: `(s_blocks_count_hi << 32) \| s_blocks_count_lo`. |
| 0x154 | 4 | **s_r_blocks_count_hi** | High 32 bits of the reserved block count. |
| 0x158 | 4 | **s_free_blocks_count_hi** | High 32 bits of the free block count. |
| 0x15C | 2 | **s_min_extra_isize** | Minimum extra inode size (bytes) that all inodes must have. |
| 0x15E | 2 | **s_want_extra_isize** | Desired extra inode size (bytes) for new inodes. |
| 0x160 | 4 | **s_flags** | Miscellaneous flags. Bit 0x0001: signed directory hash in use. Bit 0x0002: unsigned directory hash in use. Bit 0x0004: test development code. |
| 0x164 | 2 | **s_raid_stride** | RAID stride in blocks. Number of blocks read/written to each disk before moving to the next disk. |
| 0x166 | 2 | **s_mmp_interval** | Multi-mount protection check interval (seconds). See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| 0x168 | 8 | **s_mmp_block** | Block number of the MMP structure. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| 0x170 | 4 | **s_raid_stripe_width** | RAID stripe width in blocks. `s_raid_stride * number_of_data_disks`. |
| 0x174 | 1 | **s_log_groups_per_flex** | Flex block group size = `2^s_log_groups_per_flex` groups. 0 to disable flex_bg. See [03-block-groups.md](03-block-groups.md). |
| 0x175 | 1 | **s_checksum_type** | Metadata checksum algorithm type. Must be 1 (CRC32C). See [09-checksumming.md](09-checksumming.md). |
| 0x176 | 2 | **s_reserved_pad** | Reserved padding. |
| 0x178 | 8 | **s_kbytes_written** | Total number of kibibytes written to the filesystem over its lifetime. |

### Snapshot and Error Tracking (0x180 - 0x1FF)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x180 | 4 | **s_snapshot_inum** | Inode number of the active snapshot. 0 if no active snapshot. |
| 0x184 | 4 | **s_snapshot_id** | Sequential ID of the active snapshot. |
| 0x188 | 8 | **s_snapshot_r_blocks_count** | Number of blocks reserved for the active snapshot's future use. |
| 0x190 | 4 | **s_snapshot_list** | Inode number of the head of the on-disk snapshot list. |
| 0x194 | 4 | **s_error_count** | Total number of filesystem errors logged. |
| 0x198 | 4 | **s_first_error_time** | Time of the first error (Unix timestamp, 32-bit). |
| 0x19C | 4 | **s_first_error_ino** | Inode number involved in the first error. |
| 0x1A0 | 8 | **s_first_error_block** | Block number involved in the first error. |
| 0x1A8 | 32 | **s_first_error_func[32]** | Name of the function where the first error occurred (null-terminated ASCII). |
| 0x1C8 | 4 | **s_first_error_line** | Line number where the first error occurred. |
| 0x1CC | 4 | **s_last_error_time** | Time of the most recent error (Unix timestamp, 32-bit). |
| 0x1D0 | 4 | **s_last_error_ino** | Inode number involved in the most recent error. |
| 0x1D4 | 4 | **s_last_error_line** | Line number where the most recent error occurred. |
| 0x1D8 | 8 | **s_last_error_block** | Block number involved in the most recent error. |
| 0x1E0 | 32 | **s_last_error_func[32]** | Name of the function where the most recent error occurred (null-terminated ASCII). |

### Mount Options, Quotas, Encryption, and Checksum Seed (0x200 - 0x273)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x200 | 64 | **s_mount_opts[64]** | Null-terminated string of mount options. |
| 0x240 | 4 | **s_usr_quota_inum** | Inode number for tracking user quotas. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| 0x244 | 4 | **s_grp_quota_inum** | Inode number for tracking group quotas. |
| 0x248 | 4 | **s_overhead_blocks** | Number of overhead blocks/clusters in the filesystem (superblocks, group descriptors, bitmaps, inode tables). |
| 0x24C | 8 | **s_backup_bgs[2]** | Two 32-bit block group numbers where superblock backups are stored when `COMPAT_SPARSE_SUPER2` is set. |
| 0x254 | 4 | **s_encrypt_algos[4]** | Encryption algorithm codes in use (four 1-byte values). See [11-allocation-and-protection.md](11-allocation-and-protection.md) for algorithm code definitions. |
| 0x258 | 16 | **s_encrypt_pw_salt[16]** | Salt for string-to-key derivation in fscrypt. |
| 0x268 | 4 | **s_lpf_ino** | Inode number of the lost+found directory. |
| 0x26C | 4 | **s_prj_quota_inum** | Inode number for tracking project quotas. Requires `RO_COMPAT_PROJECT`. |
| 0x270 | 4 | **s_checksum_seed** | CRC32C checksum seed. Used instead of `crc32c(~0, s_uuid)` when `INCOMPAT_CSUM_SEED` is set. Allows UUID changes without rewriting all checksums. |

### Timestamp High Bytes, Error Codes, Encoding, and Orphan File (0x274 - 0x283)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x274 | 1 | **s_wtime_hi** | High 8 bits of `s_wtime`. |
| 0x275 | 1 | **s_mtime_hi** | High 8 bits of `s_mtime`. |
| 0x276 | 1 | **s_mkfs_time_hi** | High 8 bits of `s_mkfs_time`. |
| 0x277 | 1 | **s_lastcheck_hi** | High 8 bits of `s_lastcheck`. |
| 0x278 | 1 | **s_first_error_time_hi** | High 8 bits of `s_first_error_time`. |
| 0x279 | 1 | **s_last_error_time_hi** | High 8 bits of `s_last_error_time`. |
| 0x27A | 1 | **s_first_error_errcode** | First error code byte. |
| 0x27B | 1 | **s_last_error_errcode** | Most recent error code byte. |
| 0x27C | 2 | **s_encoding** | Filename character encoding (for example, UTF-8). Used for casefolded directories (`INCOMPAT_CASEFOLD`). |
| 0x27E | 2 | **s_encoding_flags** | Filename encoding flags (for example, strict mode). |
| 0x280 | 4 | **s_orphan_file_inum** | Inode number of the orphan file. Used when `COMPAT_ORPHAN_FILE` is set. See [10-journaling.md](10-journaling.md). |

### Reserved and Checksum (0x284 - 0x3FF)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x284 | 376 | **s_reserved[94]** | Reserved for future expansion (94 x 4-byte words). Must be zero. |
| 0x3FC | 4 | **s_checksum** | CRC32C checksum of the entire superblock. See [Superblock Checksum](#superblock-checksum). |

## Filesystem State

The **s_state** field at offset `0x3A` indicates the current filesystem state:

| Value | Name | Description |
|-------|------|-------------|
| `0x0001` | EXT4_VALID_FS | Filesystem was cleanly unmounted. |
| `0x0002` | EXT4_ERROR_FS | Errors have been detected. |
| `0x0004` | EXT4_ORPHAN_FS | Orphan inodes are being recovered. |

These values are bitmask flags and can be combined. A cleanly unmounted filesystem has `s_state = 0x0001`. On mount, the kernel clears `EXT4_VALID_FS`; on clean unmount, it sets it again. If `EXT4_VALID_FS` is not set, the filesystem was not cleanly unmounted and may need journal replay or fsck.

## Error Behavior

The **s_errors** field at offset `0x3C` controls what the kernel does when it detects a filesystem error:

| Value | Name | Description |
|-------|------|-------------|
| 1 | EXT4_ERRORS_CONTINUE | Continue as if nothing happened. |
| 2 | EXT4_ERRORS_RO | Remount the filesystem read-only. |
| 3 | EXT4_ERRORS_PANIC | Trigger a kernel panic. |

## OS Creator Codes

The **s_creator_os** field at offset `0x48` identifies the OS that created the filesystem:

| Value | OS |
|-------|----|
| 0 | Linux |
| 1 | GNU Hurd |
| 2 | Masix |
| 3 | FreeBSD |
| 4 | Lites |

The creator OS affects interpretation of the OSD1 and OSD2 unions in inodes. See [04-inodes.md](04-inodes.md).

## Revision Levels

The **s_rev_level** field at offset `0x4C` indicates the filesystem revision:

| Value | Name | Description |
|-------|------|-------------|
| 0 | EXT4_GOOD_OLD_REV | Original ext2 format. Inodes are fixed at 128 bytes. No dynamic features — all feature flag fields are ignored. `s_first_ino` is fixed at 11. |
| 1 | EXT4_DYNAMIC_REV | Dynamic revision. Variable inode sizes (via `s_inode_size`), feature flags are active, and `s_first_ino` is configurable. All ext3 and ext4 filesystems use this revision. |

A parser encountering revision 0 must not interpret any feature flags, `s_inode_size`, or fields beyond the original ext2 superblock layout.

## Superblock Backup Locations

The superblock is always present in block group 0. Backup copies are stored in other block groups for redundancy.

### Traditional sparse_super (`RO_COMPAT_SPARSE_SUPER`)

Backup copies are stored in block groups whose group number is:
- **0** (primary)
- **1**
- A **power of 3**: 3, 9, 27, 81, 243, ...
- A **power of 5**: 5, 25, 125, 625, ...
- A **power of 7**: 7, 49, 343, 2401, ...

Without `SPARSE_SUPER`, every block group contains a superblock backup (wasteful for large filesystems).

### sparse_super2 (`COMPAT_SPARSE_SUPER2`)

Only two backup locations, explicitly stored in `s_backup_bgs[2]` at offset `0x24C`. This minimizes wasted space and simplifies the backup search.

## Superblock Checksum

When `RO_COMPAT_METADATA_CSUM` is enabled, the **s_checksum** field at offset `0x3FC` contains a CRC32C checksum computed as:

```
s_checksum = crc32c(~0, s_uuid, 16)
s_checksum = crc32c(s_checksum, superblock_bytes_with_s_checksum_zeroed, 1024)
```

The seed is initialized by computing CRC32C over the filesystem UUID. Then the entire 1024-byte superblock (with `s_checksum` set to zero) is checksummed using that seed.

If `INCOMPAT_CSUM_SEED` is set, `s_checksum_seed` at offset `0x270` is used directly as the seed instead of computing it from the UUID. This allows the filesystem UUID to be changed without rewriting all metadata checksums.
