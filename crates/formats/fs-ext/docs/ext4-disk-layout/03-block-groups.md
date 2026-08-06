<!-- ext4 Disk Layout: Block Groups -->
<!-- Block group descriptors (32-byte and 64-byte), block group flags, flex_bg, meta_bg, lazy initialization, bitmaps, and group descriptor checksums. -->

# Block Groups

## Overview

The filesystem is divided into fixed-size block groups. Each group contains its own block bitmap, inode bitmap, inode table, and data blocks. This structure improves locality: a file's data blocks and its inode tend to reside in the same group.

Group size is `s_blocks_per_group` blocks (typically 32768 blocks = 128 MiB with 4 KiB blocks). The number of block groups is:

```
num_groups = ceil(s_blocks_count / s_blocks_per_group)
```

The group descriptor table is an array of `ext4_group_desc` structures, one per block group, stored immediately after the superblock (and its replicas) in each group that contains a superblock copy.

## Block Group Descriptor (32-byte Base)

The base descriptor is always present. All fields are little-endian.

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | 4 | **bg_block_bitmap_lo** | Lower 32 bits of the block bitmap block number. |
| 0x4 | 4 | **bg_inode_bitmap_lo** | Lower 32 bits of the inode bitmap block number. |
| 0x8 | 4 | **bg_inode_table_lo** | Lower 32 bits of the inode table's first block number. |
| 0xC | 2 | **bg_free_blocks_count_lo** | Lower 16 bits of the free block count in this group. |
| 0xE | 2 | **bg_free_inodes_count_lo** | Lower 16 bits of the free inode count in this group. |
| 0x10 | 2 | **bg_used_dirs_count_lo** | Lower 16 bits of the directory count in this group. |
| 0x12 | 2 | **bg_flags** | Block group flags. See [Block Group Flags](#block-group-flags). |
| 0x14 | 4 | **bg_exclude_bitmap_lo** | Lower 32 bits of the snapshot exclusion bitmap block (not used in mainline). |
| 0x18 | 2 | **bg_block_bitmap_csum_lo** | Lower 16 bits of the block bitmap checksum. See [09-checksumming.md](09-checksumming.md). |
| 0x1A | 2 | **bg_inode_bitmap_csum_lo** | Lower 16 bits of the inode bitmap checksum. |
| 0x1C | 2 | **bg_itable_unused_lo** | Lower 16 bits of the count of unused inodes in this group. Used to optimize inode allocation and to skip zero-reading uninitialized inode table entries. |
| 0x1E | 2 | **bg_checksum** | Group descriptor checksum. See [Group Descriptor Checksum](#group-descriptor-checksum). |

## Block Group Descriptor (64-byte Extension)

When `INCOMPAT_64BIT` is set and `s_desc_size >= 64`, each descriptor is extended with the following fields. These provide the high 16 or 32 bits needed for 64-bit block addressing.

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x20 | 4 | **bg_block_bitmap_hi** | Upper 32 bits of the block bitmap block number. |
| 0x24 | 4 | **bg_inode_bitmap_hi** | Upper 32 bits of the inode bitmap block number. |
| 0x28 | 4 | **bg_inode_table_hi** | Upper 32 bits of the inode table's first block number. |
| 0x2C | 2 | **bg_free_blocks_count_hi** | Upper 16 bits of the free block count. |
| 0x2E | 2 | **bg_free_inodes_count_hi** | Upper 16 bits of the free inode count. |
| 0x30 | 2 | **bg_used_dirs_count_hi** | Upper 16 bits of the directory count. |
| 0x32 | 2 | **bg_itable_unused_hi** | Upper 16 bits of the unused inode count. |
| 0x34 | 4 | **bg_exclude_bitmap_hi** | Upper 32 bits of the snapshot exclusion bitmap block. |
| 0x38 | 2 | **bg_block_bitmap_csum_hi** | Upper 16 bits of the block bitmap checksum. |
| 0x3A | 2 | **bg_inode_bitmap_csum_hi** | Upper 16 bits of the inode bitmap checksum. |
| 0x3C | 4 | **bg_reserved** | Reserved (padding to 64 bytes). |

To form a full 64-bit block address:

```
bg_block_bitmap = (bg_block_bitmap_hi << 32) | bg_block_bitmap_lo
bg_inode_bitmap = (bg_inode_bitmap_hi << 32) | bg_inode_bitmap_lo
bg_inode_table  = (bg_inode_table_hi  << 32) | bg_inode_table_lo
```

## Block Group Flags

The **bg_flags** field at offset `0x12` in the group descriptor is a bitmask:

| Flag | Value | Name | Description |
|------|-------|------|-------------|
| INODE_UNINIT | `0x0001` | `EXT4_BG_INODE_UNINIT` | The inode table for this group has not been initialized. Inode bitmap entries for uninitialized inodes should be treated as free. The kernel will zero the inode table on first use. |
| BLOCK_UNINIT | `0x0002` | `EXT4_BG_BLOCK_UNINIT` | The block bitmap for this group has not been initialized. All blocks (except those used by metadata) should be treated as free. |
| INODE_ZEROED | `0x0004` | `EXT4_BG_INODE_ZEROED` | The inode table has been zero-initialized. This flag confirms that unallocated inode slots contain zeroes and do not contain stale data from a previous filesystem. |

## Lazy Block Group Initialization

Lazy initialization avoids writing zeroes to every inode table and bitmap at mkfs time, dramatically speeding up filesystem creation for large devices.

**The enabling mechanism is `RO_COMPAT_GDT_CSUM` or `RO_COMPAT_METADATA_CSUM` combined with `bg_flags`.** The `COMPAT_LAZY_BG` flag (0x0040) was proposed but **never implemented in the kernel**. A parser must not rely on `COMPAT_LAZY_BG` to detect lazy initialization.

When `GDT_CSUM` or `METADATA_CSUM` is set:

1. **bg_flags** can indicate `INODE_UNINIT` and/or `BLOCK_UNINIT`.
2. **bg_itable_unused** tracks how many inodes at the end of the group's inode table have never been used. The kernel initializes inode table blocks on demand when inodes are allocated.
3. The group descriptor checksum (`bg_checksum`) covers the flags and counters, ensuring consistency.

A parser encountering `INODE_UNINIT` should treat uninitialized inode table entries as zeroed. Encountering `BLOCK_UNINIT` means the block bitmap has not been written and all non-metadata blocks are free.

## Flexible Block Groups (flex_bg)

When `INCOMPAT_FLEX_BG` is set, consecutive block groups are clustered into **flex groups**. The number of groups per flex group is:

```
groups_per_flex = 2 ^ s_log_groups_per_flex
```

Within a flex group, the block bitmaps, inode bitmaps, and inode tables for all member groups are packed into the **first group** of the flex group. This concentrates metadata into a contiguous region, reducing seek time and improving allocation performance.

The block bitmap, inode bitmap, and inode table locations are stored in each group's descriptor (`bg_block_bitmap`, `bg_inode_bitmap`, `bg_inode_table`). With flex_bg, these may all point to blocks within the first group rather than their own group.

Data blocks in non-first groups gain the space that would otherwise be consumed by bitmaps and inode tables, resulting in larger contiguous data regions.

## Meta Block Groups (meta_bg)

When `INCOMPAT_META_BG` is set, the filesystem is partitioned into **meta block groups**. This layout replaces the traditional centralized group descriptor table for groups starting at `s_first_meta_bg`.

In the traditional layout, the entire group descriptor table is stored in every group that has a superblock backup. This limits filesystem size because the group descriptor table must fit within the blocks available in a single group.

In the meta_bg layout, each meta block group contains only the group descriptors for its own range of groups. A meta block group is a set of block groups whose descriptors fit within a single block:

```
groups_per_metablock_group = block_size / descriptor_size
```

Within each meta block group, the group descriptors are stored in the **first**, **second**, and **last** groups (for redundancy, mirroring the superblock backup pattern). All other groups in the meta block group have no group descriptor copies.

This allows the filesystem to scale beyond the size limit imposed by a single group descriptor table block.

## Block and Inode Bitmaps

Each block group has two bitmap blocks:

- **Block bitmap**: One block where bit N (counting from 0) indicates whether block N in this group is allocated (1) or free (0).
- **Inode bitmap**: One block where bit N indicates whether inode N+1 in this group is allocated (1) or free (0). Bit 0 corresponds to the first inode in the group.

The bitmap block locations are stored in the group descriptor (`bg_block_bitmap_lo/hi` and `bg_inode_bitmap_lo/hi`). With `flex_bg`, bitmap blocks may reside in a different group than the one they describe.

### Bitmap Checksums

When `RO_COMPAT_METADATA_CSUM` is enabled, each bitmap has a checksum stored in the group descriptor:

- **Block bitmap**: `bg_block_bitmap_csum_lo` (and `bg_block_bitmap_csum_hi` for 64-byte descriptors).
- **Inode bitmap**: `bg_inode_bitmap_csum_lo` (and `bg_inode_bitmap_csum_hi` for 64-byte descriptors).

The checksum is computed as:

```
checksum = crc32c(seed, bitmap_block_bytes, block_size)
```

Where `seed` is the filesystem checksum seed (from UUID or `s_checksum_seed`). For 32-byte descriptors, only the lower 16 bits are stored. For 64-byte descriptors, the full 32 bits are available across the `_lo` and `_hi` fields.

See [09-checksumming.md](09-checksumming.md) for the complete checksum formula.

## Group Descriptor Checksum

The **bg_checksum** field at offset `0x1E` provides integrity verification for the group descriptor. Two checksum modes exist, and they are **mutually exclusive**:

### Mode 1: GDT_CSUM (without METADATA_CSUM)

When `RO_COMPAT_GDT_CSUM` is set but `RO_COMPAT_METADATA_CSUM` is not:

```
bg_checksum = crc16(~0, s_uuid, 16)
bg_checksum = crc16(bg_checksum, group_number_le32, 4)
bg_checksum = crc16(bg_checksum, descriptor_bytes_with_bg_checksum_zeroed, desc_size)
```

The algorithm is CRC16 (CRC-CCITT). The checksum covers the filesystem UUID, the group number as a little-endian 32-bit integer, and the entire group descriptor with the `bg_checksum` field set to zero.

### Mode 2: METADATA_CSUM

When `RO_COMPAT_METADATA_CSUM` is set:

```
checksum = crc32c(seed, group_number_le32, 4)
checksum = crc32c(checksum, descriptor_bytes_with_bg_checksum_zeroed, desc_size)
bg_checksum = checksum & 0xFFFF
```

The algorithm is CRC32C, using the filesystem checksum seed (derived from UUID or `s_checksum_seed`). The result is **truncated to 16 bits** to fit the `bg_checksum` field.

`GDT_CSUM` and `METADATA_CSUM` must not both be set. If `METADATA_CSUM` is present, it supersedes `GDT_CSUM` for all group descriptor checksum operations.
