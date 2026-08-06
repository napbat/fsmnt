<!-- ext4 Disk Layout: Introduction -->
<!-- Glossary, endianness, block/cluster sizing, version history, feature flags overview, filesystem limits, and block group layout. Read this first to understand terms used throughout the ext4 docs. -->

# Introduction

## Glossary

| Term | Definition |
|------|-----------|
| **Block** | The fundamental allocation unit of an ext4 filesystem. All on-disk addresses are expressed as block numbers. Size is configurable at format time (1 KiB, 2 KiB, or 4 KiB; up to 64 KiB theoretically). |
| **Block Group** | A contiguous range of blocks that share a block bitmap, inode bitmap, and inode table. The filesystem is divided into block groups to improve data locality. Each group contains `s_blocks_per_group` blocks. |
| **Cluster** | The allocation unit when bigalloc (`RO_COMPAT_BIGALLOC`) is enabled. One cluster spans multiple blocks. Without bigalloc, cluster size equals block size. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| **Inode** | A fixed-size record that stores all metadata for a single file, directory, symlink, or special file. Contains ownership, permissions, timestamps, size, and pointers to data blocks. Inode numbers start at 1. |
| **Extent** | A contiguous range of physical blocks mapped to a contiguous range of logical blocks within a file. Extents replace the legacy direct/indirect block map in ext4. See [05-data-mapping.md](05-data-mapping.md). |
| **Superblock** | A 1024-byte structure at byte offset 1024 containing all filesystem-wide parameters: block size, inode count, feature flags, UUID, journal location, and more. See [01-superblock.md](01-superblock.md). |
| **Feature Flag** | A bit in one of three superblock bitmasks that indicates a filesystem capability. Feature flags are the sole mechanism for version detection. See [02-feature-flags.md](02-feature-flags.md). |
| **Logical Block Number (LBN)** | A block number relative to the start of a file (block 0 = first block of the file). Mapped to physical block numbers via block maps or extent trees. |
| **Flex Group** | A group of `2^s_log_groups_per_flex` consecutive block groups whose metadata (bitmaps, inode tables) is packed into the first group. Improves metadata locality. Requires `INCOMPAT_FLEX_BG`. |
| **Meta Block Group** | A partitioning scheme where block group descriptors for a range of groups fit within a single block, enabling filesystems larger than the traditional group descriptor table allows. Requires `INCOMPAT_META_BG`. |

## Endianness

All ext4 on-disk structures are **little-endian**.

The jbd2 journal layer uses **big-endian** for its own structures, with one exception: fast commit TLV entries are little-endian because they are defined by ext4, not jbd2. See [jbd2/00-introduction.md](../jbd2/00-introduction.md) for details.

## Block Sizing

Block size is computed from the superblock field `s_log_block_size`:

```
block_size = 2 ^ (10 + s_log_block_size)
```

| `s_log_block_size` | Block Size |
|--------------------|-----------|
| 0 | 1024 bytes (1 KiB) |
| 1 | 2048 bytes (2 KiB) |
| 2 | 4096 bytes (4 KiB) |
| 6 | 65536 bytes (64 KiB) |

The formula supports arbitrary values, but the Linux kernel limits block size to the system page size (typically 4 KiB on x86_64, 64 KiB on some ARM64 configurations). The most common block size is 4 KiB.

When block size is 1 KiB, the superblock occupies block 1 (byte offset 1024). For all other block sizes, the superblock occupies the first part of block 0 (byte offset 1024, with bytes 0-1023 unused by ext4 but available for a boot sector).

## Cluster Sizing

When `RO_COMPAT_BIGALLOC` is enabled, allocation operates on clusters instead of individual blocks. Cluster size is computed from the superblock field `s_log_cluster_size`:

```
cluster_size = 2 ^ (10 + s_log_cluster_size)
```

The cluster-to-block ratio is:

```
blocks_per_cluster = 2 ^ (s_log_cluster_size - s_log_block_size)
```

When bigalloc is not enabled, `s_log_cluster_size` must equal `s_log_block_size`, meaning each cluster is exactly one block.

With bigalloc enabled, block bitmaps track clusters rather than individual blocks, and `s_clusters_per_group` replaces `s_blocks_per_group` for allocation accounting. See [11-allocation-and-protection.md](11-allocation-and-protection.md) for details.

## Version History

The ext filesystem family uses a single on-disk format with incremental feature additions. Version detection is driven entirely by superblock feature flags, not explicit version numbers.

| Version | Year | Key Additions |
|---------|------|---------------|
| **ext2** | 1993 | Base format: block groups, inodes, direct/indirect block maps, superblock, group descriptors. No journal. |
| **ext3** | 2001 | Adds journaling via jbd (journal block device). Feature flag: `COMPAT_HAS_JOURNAL`. Three journal modes: data, ordered, writeback. Htree directories. |
| **ext4** | 2008 | Extents (`INCOMPAT_EXTENTS`), 64-bit block addressing (`INCOMPAT_64BIT`), nanosecond timestamps, metadata checksums (`RO_COMPAT_METADATA_CSUM`), flexible block groups (`INCOMPAT_FLEX_BG`), inline data (`INCOMPAT_INLINE_DATA`), encryption (`INCOMPAT_ENCRYPT`), delayed allocation, multiblock allocator, persistent preallocation. |

A filesystem formatted as ext2 with no feature flags set is ext2 revision 0. Adding `COMPAT_HAS_JOURNAL` makes it ext3-compatible. Adding `INCOMPAT_EXTENTS` and other ext4 features makes it ext4. The kernel mounts the filesystem according to the feature flags it finds, regardless of what the user labels it.

## Feature Flag Mechanism

Feature flags are stored in three 32-bit bitmasks in the superblock:

| Bitmask | Superblock Field | Semantics |
|---------|-----------------|-----------|
| **Compatible** (`s_feature_compat`) | Offset 0x5C | Features that are safe to ignore. A filesystem with unknown compat flags can be mounted read-write without risk. The implementation simply will not use the unknown feature. |
| **Incompatible** (`s_feature_incompat`) | Offset 0x60 | Features that change the on-disk format in ways that an unaware implementation cannot safely handle. A filesystem with unknown incompat flags must not be mounted at all. |
| **Read-Only Compatible** (`s_feature_ro_compat`) | Offset 0x64 | Features that an unaware implementation can safely read but must not write. A filesystem with unknown ro_compat flags can be mounted read-only. |

This three-tier mechanism provides forward and backward compatibility without explicit version numbers. A parser must check all three bitmasks before interpreting any other structure. See [02-feature-flags.md](02-feature-flags.md) for complete flag tables.

## Filesystem Limits

### 32-bit Mode (without `INCOMPAT_64BIT`)

| Item | 1 KiB Block | 2 KiB Block | 4 KiB Block | 64 KiB Block |
|------|-------------|-------------|-------------|--------------|
| Max filesystem blocks | 2^32 | 2^32 | 2^32 | 2^32 |
| Max filesystem size | 4 TiB | 8 TiB | 16 TiB | 256 TiB |
| Blocks per group | 8192 | 16384 | 32768 | 524288 |
| Max block groups | 524288 | 262144 | 131072 | 8192 |
| Max inodes | 2^32 | 2^32 | 2^32 | 2^32 |
| Max file size (block map) | 16 GiB | 256 GiB | 4 TiB | 64 TiB |
| Max file size (extents) | 4 TiB | 8 TiB | 16 TiB | 256 TiB |

### 64-bit Mode (with `INCOMPAT_64BIT`)

| Item | 1 KiB Block | 2 KiB Block | 4 KiB Block | 64 KiB Block |
|------|-------------|-------------|-------------|--------------|
| Max filesystem blocks | 2^48 | 2^48 | 2^48 | 2^48 |
| Max filesystem size | 256 PiB | 512 PiB | 1 EiB | 16 EiB |
| Blocks per group | 8192 | 16384 | 32768 | 524288 |
| Max block groups | 2^(48)/BPG | 2^(48)/BPG | 2^(48)/BPG | 2^(48)/BPG |
| Max inodes | 2^32 | 2^32 | 2^32 | 2^32 |
| Max file size (extents) | 256 PiB | 512 PiB | 16 TiB | 256 TiB |

**Notes:**
- Inode count is always limited to 2^32 because inode numbers are 32-bit in all structures.
- Blocks per group is limited by the block bitmap: one block of bitmap bits = `block_size * 8` blocks.
- The block map (direct/indirect) uses 32-bit block pointers, so it cannot address blocks beyond 2^32 regardless of 64-bit mode. Extents use 48-bit physical block numbers.
- The 64-bit mode limit of 2^48 blocks comes from the extent tree's 48-bit physical block addressing (16-bit high + 32-bit low).
- Max file size with extents is limited to 2^32 logical blocks (the `ee_block` field is 32-bit), so max file size = `2^32 * block_size`.

## Block Group Layout

A filesystem is divided into block groups. Each group (except possibly the last) contains `s_blocks_per_group` blocks. The on-disk layout of a block group is:

```
+-------------------------------------------------------------------+
| Block Group 0                                                     |
+--------+--------+--------+--------+--------+--------+-------------+
| Pad    | Super  | Group  | Resv'd | Block  | Inode  | Inode       |
| 1024B  | Block  | Desc   | GDT    | Bitmap | Bitmap | Table       |
| (boot) | 1 blk  | N blks | blocks | 1 blk  | 1 blk  | M blks     |
+--------+--------+--------+--------+--------+--------+-------------+
|                          Data Blocks                              |
+-------------------------------------------------------------------+
```

| Region | Size | Description |
|--------|------|-------------|
| Padding | 1024 bytes | Present only in block group 0. Allows an x86 boot sector and partition table at the start of the device. The superblock always starts at byte offset 1024. |
| Superblock | 1 block | Filesystem-wide parameters. Present in group 0 and backup groups (see [01-superblock.md](01-superblock.md) for backup location rules). |
| Group Descriptors | Variable | Array of `ext4_group_desc` structures, one per block group. Replicated in all groups that contain a superblock backup. See [03-block-groups.md](03-block-groups.md). |
| Reserved GDT Blocks | `s_reserved_gdt_blocks` blocks | Space reserved for online filesystem growth. Present only in groups that contain a superblock backup. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| Block Bitmap | 1 block | Bit N set indicates block N in this group is allocated. |
| Inode Bitmap | 1 block | Bit N set indicates inode N in this group is allocated. |
| Inode Table | `(s_inodes_per_group * s_inode_size) / block_size` blocks | Array of inode structures for this group. |
| Data Blocks | Remaining blocks | File and directory data. |

**Block groups without a superblock backup** omit the superblock, group descriptor table, and reserved GDT blocks. Their layout starts directly with the block bitmap.

**With `INCOMPAT_FLEX_BG`**, the bitmaps and inode tables for several consecutive groups are packed into the first group of each flex group. The data block region of non-first groups expands to fill the freed space. Block and inode bitmap locations are stored in the group descriptor (`bg_block_bitmap`, `bg_inode_bitmap`, `bg_inode_table`) and need not follow the traditional order.

**With `INCOMPAT_META_BG`**, the group descriptor table is distributed differently. See [03-block-groups.md](03-block-groups.md) for details.
