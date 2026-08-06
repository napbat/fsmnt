<!-- ext4 Disk Layout: Feature Flags -->
<!-- Complete compat, incompat, and ro_compat feature flag tables with hex values, descriptions, and version detection decision tree. -->

# Feature Flags

## Overview

Feature flags are the primary mechanism for detecting filesystem version and capabilities. There are no explicit ext2/ext3/ext4 version numbers; a parser must check these bitmasks before interpreting any other structure.

The three categories enforce a compatibility contract:

- **Compatible** flags can be safely ignored by an unaware implementation.
- **Incompatible** flags indicate on-disk format changes that an unaware implementation cannot handle. The filesystem must not be mounted.
- **Read-only compatible** flags indicate features that are safe to read but unsafe to write without understanding.

All three bitmasks are stored in the superblock. See [01-superblock.md](01-superblock.md) for field locations.

## Compatible Features (`s_feature_compat`, offset 0x5C)

| Flag | Value | Name | Description |
|------|-------|------|-------------|
| DIR_PREALLOC | `0x0001` | `EXT4_FEATURE_COMPAT_DIR_PREALLOC` | Directory preallocation. Preallocate `s_prealloc_dir_blocks` blocks when creating a new directory. |
| IMAGIC_INODES | `0x0002` | `EXT4_FEATURE_COMPAT_IMAGIC_INODES` | AFS server "imagic" inodes. Effectively unused in mainline Linux. |
| HAS_JOURNAL | `0x0004` | `EXT4_FEATURE_COMPAT_HAS_JOURNAL` | Filesystem has a journal. This is the defining feature of ext3+. The journal inode is `s_journal_inum`. See [10-journaling.md](10-journaling.md). |
| EXT_ATTR | `0x0008` | `EXT4_FEATURE_COMPAT_EXT_ATTR` | Extended attributes are supported. See [07-extended-attributes.md](07-extended-attributes.md). |
| RESIZE_INODE | `0x0010` | `EXT4_FEATURE_COMPAT_RESIZE_INODE` | Special inode 7 exists for online filesystem resizing. Reserved GDT blocks are present. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| DIR_INDEX | `0x0020` | `EXT4_FEATURE_COMPAT_DIR_INDEX` | Directories may use hash tree (htree/dx_tree) indexing for fast lookups. See [06-directories.md](06-directories.md). |
| LAZY_BG | `0x0040` | `EXT4_FEATURE_COMPAT_LAZY_BG` | Lazy block group initialization. **Never implemented in the kernel.** The actual lazy initialization mechanism uses `RO_COMPAT_GDT_CSUM` or `RO_COMPAT_METADATA_CSUM` combined with `bg_flags`. See [03-block-groups.md](03-block-groups.md). |
| EXCLUDE_INODE | `0x0080` | `EXT4_FEATURE_COMPAT_EXCLUDE_INODE` | Exclude inode (snapshot-related). Not used in mainline. |
| EXCLUDE_BITMAP | `0x0100` | `EXT4_FEATURE_COMPAT_EXCLUDE_BITMAP` | Exclude bitmap (snapshot-related). Not used in mainline. |
| SPARSE_SUPER2 | `0x0200` | `EXT4_FEATURE_COMPAT_SPARSE_SUPER2` | Only two superblock backups, at block groups specified in `s_backup_bgs[2]`. Replaces the traditional sparse_super algorithm. See [01-superblock.md](01-superblock.md#superblock-backup-locations). |
| FAST_COMMIT | `0x0400` | `EXT4_FEATURE_COMPAT_FAST_COMMIT` | Fast commit journaling is enabled. The journal reserves `s_num_fc_blocks` blocks for lightweight logical operation records. See [jbd2/04-fast-commits.md](../jbd2/04-fast-commits.md). |
| STABLE_INODES | `0x0800` | `EXT4_FEATURE_COMPAT_STABLE_INODES` | Inode numbers and UUID are stable and will not change. Required for fscrypt policy version 2 (per-file keys derived from inode number). See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| ORPHAN_FILE | `0x1000` | `EXT4_FEATURE_COMPAT_ORPHAN_FILE` | Dedicated orphan file exists at `s_orphan_file_inum`. Replaces the legacy `s_last_orphan` linked list for better concurrency. See [10-journaling.md](10-journaling.md). |

## Incompatible Features (`s_feature_incompat`, offset 0x60)

| Flag | Value | Name | Description |
|------|-------|------|-------------|
| COMPRESSION | `0x0001` | `EXT4_FEATURE_INCOMPAT_COMPRESSION` | Filesystem uses compression. **Never fully implemented in mainline Linux.** Some e2fsprogs support exists. A parser seeing this flag should refuse to interpret compressed data. |
| FILETYPE | `0x0002` | `EXT4_FEATURE_INCOMPAT_FILETYPE` | Directory entries store a file type field (`file_type` byte in `ext4_dir_entry_2`). Nearly all modern filesystems have this set. See [06-directories.md](06-directories.md). |
| RECOVER | `0x0004` | `EXT4_FEATURE_INCOMPAT_RECOVER` | The journal contains uncommitted transactions that need replay. Set on mount, cleared after successful recovery. A forensic parser seeing this flag knows the filesystem may be inconsistent. See [10-journaling.md](10-journaling.md). |
| JOURNAL_DEV | `0x0008` | `EXT4_FEATURE_INCOMPAT_JOURNAL_DEV` | This device is an external journal device (not a regular filesystem). The journal superblock is at block 1. See [jbd2/01-superblock.md](../jbd2/01-superblock.md). |
| META_BG | `0x0010` | `EXT4_FEATURE_INCOMPAT_META_BG` | Meta block groups. The group descriptor table is distributed rather than centralized, enabling very large filesystems. Groups starting at `s_first_meta_bg` use the meta_bg layout. See [03-block-groups.md](03-block-groups.md). |
| EXTENTS | `0x0040` | `EXT4_FEATURE_INCOMPAT_EXTENTS` | Files may use extent trees instead of indirect block maps. This is the defining on-disk feature of ext4. See [05-data-mapping.md](05-data-mapping.md). |
| 64BIT | `0x0080` | `EXT4_FEATURE_INCOMPAT_64BIT` | 64-bit block numbers. Enables filesystems larger than 2^32 blocks. Group descriptors expand to 64 bytes (`s_desc_size` >= 64). Superblock fields `s_blocks_count_hi`, `s_r_blocks_count_hi`, `s_free_blocks_count_hi` become valid. |
| MMP | `0x0100` | `EXT4_FEATURE_INCOMPAT_MMP` | Multiple mount protection. The MMP block (`s_mmp_block`) is periodically updated to detect concurrent mounts. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| FLEX_BG | `0x0200` | `EXT4_FEATURE_INCOMPAT_FLEX_BG` | Flexible block groups. Groups are clustered into flex groups of `2^s_log_groups_per_flex` groups with metadata packed into the first group. See [03-block-groups.md](03-block-groups.md). |
| EA_INODE | `0x0400` | `EXT4_FEATURE_INCOMPAT_EA_INODE` | Extended attribute values may be stored in dedicated inodes (EA inodes) when they exceed one block. See [07-extended-attributes.md](07-extended-attributes.md). |
| DIRDATA | `0x1000` | `EXT4_FEATURE_INCOMPAT_DIRDATA` | Directory entries may contain additional data. **Never implemented in the kernel.** |
| CSUM_SEED | `0x2000` | `EXT4_FEATURE_INCOMPAT_CSUM_SEED` | The superblock field `s_checksum_seed` stores the checksum seed directly, instead of deriving it from `crc32c(~0, s_uuid)`. Allows UUID changes without rewriting all metadata checksums. See [09-checksumming.md](09-checksumming.md). |
| LARGEDIR | `0x4000` | `EXT4_FEATURE_INCOMPAT_LARGEDIR` | Directories may have more than 2^16 subdirectories. Hash tree depth extended from 2 to 3 levels. See [06-directories.md](06-directories.md). |
| INLINE_DATA | `0x8000` | `EXT4_FEATURE_INCOMPAT_INLINE_DATA` | Small files and directories may store data directly in the inode (in the `i_block` array and/or ibody extended attribute space). See [05-data-mapping.md](05-data-mapping.md). |
| ENCRYPT | `0x10000` | `EXT4_FEATURE_INCOMPAT_ENCRYPT` | Per-file/per-directory encryption (fscrypt). Encrypted inodes have `ENCRYPT_FL` set in `i_flags`. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| CASEFOLD | `0x20000` | `EXT4_FEATURE_INCOMPAT_CASEFOLD` | Case-insensitive directory lookups. Directories with `CASEFOLD_FL` perform case-insensitive filename matching using the encoding specified in `s_encoding`. See [06-directories.md](06-directories.md). |

## Read-Only Compatible Features (`s_feature_ro_compat`, offset 0x64)

| Flag | Value | Name | Description |
|------|-------|------|-------------|
| SPARSE_SUPER | `0x0001` | `EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER` | Superblock backups exist only in groups 0, 1, and groups that are powers of 3, 5, or 7. Without this flag, every group has a backup (wasteful). See [01-superblock.md](01-superblock.md#superblock-backup-locations). |
| LARGE_FILE | `0x0002` | `EXT4_FEATURE_RO_COMPAT_LARGE_FILE` | At least one file is larger than 2 GiB. Enables the `i_size_high` field in inodes (upper 32 bits of file size) and the interpretation of `i_blocks_lo` in 512-byte units with `i_blocks_high` for the upper bits. |
| BTREE_DIR | `0x0004` | `EXT4_FEATURE_RO_COMPAT_BTREE_DIR` | B-tree indexed directories. **Unused** — htree (hash tree) indexing is used instead and is indicated by `COMPAT_DIR_INDEX`. This flag is historic and never functional. |
| HUGE_FILE | `0x0008` | `EXT4_FEATURE_RO_COMPAT_HUGE_FILE` | Files may use `i_blocks` counts in units of filesystem blocks (not 512-byte sectors) when `EXT4_HUGE_FILE_FL` is set in `i_flags`. Enables files larger than 2 TiB of allocated blocks. |
| GDT_CSUM | `0x0010` | `EXT4_FEATURE_RO_COMPAT_GDT_CSUM` | Group descriptor checksums are present (`bg_checksum`). Uses CRC16 of UUID + group number + descriptor. Also enables lazy block group initialization via `bg_flags`. Mutually exclusive with `METADATA_CSUM`. See [03-block-groups.md](03-block-groups.md). |
| DIR_NLINK | `0x0020` | `EXT4_FEATURE_RO_COMPAT_DIR_NLINK` | Directories may have more than 65000 hard links. When a directory's link count exceeds 64999, it is set to 1 and the kernel tracks the count internally. |
| EXTRA_ISIZE | `0x0040` | `EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE` | Inodes have extra fields beyond the 128-byte base (`i_extra_isize` > 0). Required for extended timestamps (nanoseconds, Y2038), `i_crtime`, and other extended inode fields. See [04-inodes.md](04-inodes.md). |
| HAS_SNAPSHOT | `0x0080` | `EXT4_FEATURE_RO_COMPAT_HAS_SNAPSHOT` | Filesystem has snapshots. **Not implemented in mainline Linux.** |
| QUOTA | `0x0100` | `EXT4_FEATURE_RO_COMPAT_QUOTA` | Journaled quota support (quota data tracked in dedicated inodes `s_usr_quota_inum` and `s_grp_quota_inum`). See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| BIGALLOC | `0x0200` | `EXT4_FEATURE_RO_COMPAT_BIGALLOC` | Cluster-based allocation. Block bitmaps track clusters instead of blocks. `s_log_cluster_size` may differ from `s_log_block_size`. See [00-introduction.md](00-introduction.md#cluster-sizing) and [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| METADATA_CSUM | `0x0400` | `EXT4_FEATURE_RO_COMPAT_METADATA_CSUM` | Metadata CRC32C checksums enabled for all structures (superblock, group descriptors, inodes, extent blocks, directory blocks, xattr blocks, MMP block). Mutually exclusive with `GDT_CSUM`. See [09-checksumming.md](09-checksumming.md). |
| REPLICA | `0x0800` | `EXT4_FEATURE_RO_COMPAT_REPLICA` | Filesystem replication. **Not implemented in mainline Linux.** |
| READONLY | `0x1000` | `EXT4_FEATURE_RO_COMPAT_READONLY` | Filesystem is intrinsically read-only. Used for snapshot/seed filesystems. The kernel refuses to mount it read-write. |
| PROJECT | `0x2000` | `EXT4_FEATURE_RO_COMPAT_PROJECT` | Project quota tracking. Inodes carry a project ID (`i_projid`) and may inherit it from their parent directory (`PROJINHERIT_FL`). `s_prj_quota_inum` holds the project quota inode. See [04-inodes.md](04-inodes.md) and [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| VERITY | `0x8000` | `EXT4_FEATURE_RO_COMPAT_VERITY` | fs-verity file integrity support (Linux 5.4+). Verity-enabled inodes have `VERITY_FL` set and contain a Merkle tree appended after file data. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| ORPHAN_PRESENT | `0x10000` | `EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT` | The orphan file may contain live entries that need processing during recovery. Set when orphan inodes are added to the orphan file; cleared after recovery completes. See [10-journaling.md](10-journaling.md). |

## Default Mount Options

The **s_default_mount_opts** field at offset `0x100` in the superblock stores a bitmask of default mount options applied automatically when the filesystem is mounted:

| Flag | Value | Name | Description |
|------|-------|------|-------------|
| DEBUG | `0x0001` | `EXT4_DEFM_DEBUG` | Enable debug output. |
| BSDGROUPS | `0x0002` | `EXT4_DEFM_BSDGROUPS` | New files inherit the group ID of the containing directory (BSD semantics). |
| XATTR_USER | `0x0004` | `EXT4_DEFM_XATTR_USER` | User-space extended attributes enabled (`user.*` namespace). |
| ACL | `0x0008` | `EXT4_DEFM_ACL` | POSIX access control lists enabled. |
| UID16 | `0x0010` | `EXT4_DEFM_UID16` | 16-bit UID/GID compatibility mode. |
| JMODE_DATA | `0x0020` | `EXT4_DEFM_JMODE_DATA` | Journal mode: data journaling. All data written to journal before final location. |
| JMODE_ORDERED | `0x0040` | `EXT4_DEFM_JMODE_ORDERED` | Journal mode: ordered. Data flushed to disk before metadata journal commit. (Default) |
| JMODE_WBACK | `0x0060` | `EXT4_DEFM_JMODE_WBACK` | Journal mode: writeback. No data ordering guarantees. |
| NOBARRIER | `0x0100` | `EXT4_DEFM_NOBARRIER` | Disable write barriers. |
| BLOCK_VALIDITY | `0x0200` | `EXT4_DEFM_BLOCK_VALIDITY` | Track metadata blocks in an internal tree to detect filesystem corruption when data blocks overlap with metadata. |
| DISCARD | `0x0400` | `EXT4_DEFM_DISCARD` | Issue TRIM/DISCARD commands to the underlying device when blocks are freed. |
| NODELALLOC | `0x0800` | `EXT4_DEFM_NODELALLOC` | Disable delayed allocation. Blocks are allocated immediately on write rather than deferred to writeback. |

**Note:** `JMODE_DATA`, `JMODE_ORDERED`, and `JMODE_WBACK` use bits 0x0020 and 0x0040 as a two-bit field: 0x0020 = data, 0x0040 = ordered, 0x0060 = writeback. Only one journal mode should be set.

## Version Detection Decision Tree

A parser can determine the filesystem variant using the following steps:

```
1. Read magic number at offset 0x38
   - Not 0xEF53 → not ext2/ext3/ext4

2. Check s_rev_level (offset 0x4C)
   - 0 (EXT4_GOOD_OLD_REV) → ext2 revision 0
     Fixed 128-byte inodes, no feature flags, no journal.
     Stop here.
   - 1 (EXT4_DYNAMIC_REV) → continue

3. Check s_feature_compat for HAS_JOURNAL (0x0004)
   - Not set → ext2 (dynamic revision, with feature flags but no journal)
   - Set → has journal, continue

4. Check s_feature_incompat for EXTENTS (0x0040)
   - Not set → ext3
     Journal but no extent trees. Uses indirect block maps.
   - Set → ext4, continue

5. Check s_feature_incompat for 64BIT (0x0080)
   - Not set → ext4 (32-bit mode, max ~16 TiB with 4 KiB blocks)
   - Set → ext4 (64-bit mode, max ~1 EiB with 4 KiB blocks)

6. Check s_feature_ro_compat for METADATA_CSUM (0x0400)
   - Not set → ext4 without metadata checksums (older ext4)
   - Set → ext4 modern (CRC32C checksums on all metadata)
```

This tree is a practical guide for identification. Real filesystems may have unusual flag combinations (e.g., ext3 with extents enabled for some files, or ext4 without a journal). The feature flags themselves are authoritative; the ext2/ext3/ext4 label is a convenience.
