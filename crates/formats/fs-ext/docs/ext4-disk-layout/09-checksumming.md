<!-- Checksumming -->
<!-- CRC32C metadata checksums: seed computation, per-structure formulas, and checksum field locations. -->

# Metadata Checksumming

Ext4 metadata checksumming protects on-disk structures against silent corruption. The feature
uses CRC32C (Castagnoli polynomial, `0x1EDC6F41`) and is enabled by the read-only compatible
feature flag `RO_COMPAT_METADATA_CSUM` (see [02-feature-flags.md](02-feature-flags.md)).

When enabled, the superblock field **s_checksum_type** (offset `0x175`) must be `1` (CRC32C).
No other algorithm is implemented in the kernel despite values 2 (MD5) and 3 (SHA1) appearing
in early wiki drafts.

## Checksum Seed

The checksum seed is the starting CRC value fed into every per-structure checksum computation.
Two modes exist:

1. **Standard mode**: `seed = crc32c(~0, s_uuid)` — the CRC32C of the filesystem UUID
   with an initial value of `0xFFFFFFFF`.

2. **Stored seed mode** (when `INCOMPAT_CSUM_SEED` is set): `seed = s_checksum_seed`
   (offset `0x270`). This allows changing the filesystem UUID without recomputing every
   checksum on disk. The kernel stores `crc32c(~0, original_uuid)` in **s_checksum_seed**
   at mkfs time.

A parser must check `INCOMPAT_CSUM_SEED` first. If set, read the seed directly from
**s_checksum_seed**. Otherwise, compute it from **s_uuid**.

## Per-Structure Checksums

Each metadata structure has a checksum field at a defined location. The input to the CRC32C
function varies by structure type. All checksums are little-endian on disk.

### Superblock

| Property | Value |
|----------|-------|
| Field | **s_checksum** |
| Offset | `0x3FC` (last 4 bytes of the 1024-byte superblock) |
| Size | 4 bytes (`__le32`) |
| Algorithm | CRC32C |

**Input**: The filesystem UUID (16 bytes) followed by the entire 1024-byte superblock with the
**s_checksum** field (bytes `0x3FC`..`0x3FF`) zeroed.

**Computation**:
```
csum = crc32c(~0, s_uuid)
csum = crc32c(csum, superblock_bytes_with_checksum_zeroed)
```

The superblock checksum does not use the seed — it feeds the UUID directly as the first input
with an initial CRC of `~0`. This is because the superblock checksum must be verifiable before
the seed is known.

### Group Descriptors

| Property | Value |
|----------|-------|
| Field | **bg_checksum** |
| Offset | `0x1E` within `ext4_group_desc` |
| Size | 2 bytes (`__le16`) |
| Algorithm | Depends on feature flags (see below) |

Two checksum modes exist depending on which feature flags are active:

**(a) GDT_CSUM without METADATA_CSUM** (`RO_COMPAT_GDT_CSUM` set, `RO_COMPAT_METADATA_CSUM` clear):

Uses CRC16 (CCITT polynomial). Input: the filesystem UUID (16 bytes) + the block group number
as a little-endian `__le32` (4 bytes) + the entire group descriptor with **bg_checksum** zeroed.

```
bg_checksum = crc16(~0, s_uuid || le32(group_number) || descriptor_with_csum_zeroed)
```

**(b) METADATA_CSUM** (`RO_COMPAT_METADATA_CSUM` set):

Uses CRC32C with the checksum seed. Input: seed + block group number as `__le32` + entire group
descriptor with **bg_checksum** zeroed. The 32-bit CRC32C result is truncated to 16 bits (low
16 bits stored).

```
csum = crc32c(seed, le32(group_number) || descriptor_with_csum_zeroed)
bg_checksum = csum & 0xFFFF
```

When `METADATA_CSUM` is set, `GDT_CSUM` is implicitly superseded.

### Block and Inode Bitmaps

| Property | Value |
|----------|-------|
| Fields | **bg_block_bitmap_csum_lo** + **bg_block_bitmap_csum_hi** (block bitmap) |
| | **bg_inode_bitmap_csum_lo** + **bg_inode_bitmap_csum_hi** (inode bitmap) |
| Location | In `ext4_group_desc` (see [03-block-groups.md](03-block-groups.md)) |
| Size | 16-bit `_lo` in base descriptor; 16-bit `_hi` in 64-byte extension |
| Algorithm | CRC32C |

**Input**: seed + the entire bitmap (one block of data).

```
csum = crc32c(seed, bitmap_bytes)
```

**Truncation rules**:
- If the group descriptor is 32 bytes (`s_desc_size <= 32` or 64BIT feature not set), only the
  low 16 bits are stored in `*_csum_lo`. The `*_csum_hi` fields do not exist.
- If the group descriptor is 64 bytes, the full 32-bit checksum is split: low 16 bits in
  `*_csum_lo`, high 16 bits in `*_csum_hi`.

### Inodes

| Property | Value |
|----------|-------|
| Fields | **l_i_checksum_lo** (in osd2 union, offset `0x7C` within inode) |
| | **i_checksum_hi** (extended field, offset `0x82` within inode) |
| Size | 16 bits each; combined 32-bit checksum |
| Algorithm | CRC32C |

**Input**: seed + inode number as `__le32` + inode generation (**i_generation**) as `__le32` +
the entire inode (at **s_inode_size** bytes) with both checksum fields zeroed.

```
csum = crc32c(seed, le32(ino) || le32(i_generation) || inode_with_csums_zeroed)
```

**l_i_checksum_lo** stores the low 16 bits. **i_checksum_hi** stores the high 16 bits and is
only present when `s_inode_size > 128` and `i_extra_isize >= 4` (i.e., the extended inode
fields exist past offset `0x80`). If the inode is 128 bytes, only the low 16 bits are stored.

See [04-inodes.md](04-inodes.md) for inode field layouts and the osd2 union definition.

### Extent Tree Blocks

| Property | Value |
|----------|-------|
| Field | **eb_checksum** in `ext4_extent_tail` |
| Location | Last 4 bytes of an extent tree block (external blocks only) |
| Size | 4 bytes (`__le32`) |
| Algorithm | CRC32C |

**Input**: seed + inode number as `__le32` + inode generation (**i_generation**) as `__le32` +
the entire extent block (one filesystem block).

```
csum = crc32c(seed, le32(ino) || le32(i_generation) || extent_block_bytes)
```

The `ext4_extent_tail` structure is placed at the end of an external extent tree block. Its
position is calculated as: `block_start + sizeof(ext4_extent_header) + eh_max * sizeof(ext4_extent or ext4_extent_idx)`.
See [05-data-mapping.md](05-data-mapping.md) for extent tree structure.

The in-inode extent tree (root node stored in **i_block[15]**) is covered by the inode checksum,
not by a separate extent tail checksum.

### Directory Leaf Blocks

| Property | Value |
|----------|-------|
| Field | **det_checksum** in `ext4_dir_entry_tail` |
| Location | Last 12 bytes of a directory data block |
| Size | 4 bytes (`__le32`) |
| Algorithm | CRC32C |

**Input**: seed + inode number (directory inode) as `__le32` + inode generation
(**i_generation**) as `__le32` + the entire directory block (one filesystem block).

```
csum = crc32c(seed, le32(ino) || le32(i_generation) || dir_block_bytes)
```

The `ext4_dir_entry_tail` is a sentinel directory entry with **inode** = 0, **rec_len** = 12,
**name_len** = 0, **file_type** = `0xDE`. It consumes the last 12 bytes of the block. The
checksum covers the entire block including the tail entry itself (with **det_checksum** zeroed
during computation). See [06-directories.md](06-directories.md) for directory entry formats.

### Hash Tree (dx) Nodes

| Property | Value |
|----------|-------|
| Field | **dt_checksum** in `dx_tail` |
| Location | End of a hash tree block, after the last valid `dx_entry` |
| Size | 4 bytes (`__le32`) within the 8-byte `dx_tail` structure |
| Algorithm | CRC32C |

**Input**: seed + inode number (directory inode) as `__le32` + inode generation
(**i_generation**) as `__le32` + all valid `dx_entry` records in the block + the `dx_tail`
structure (with **dt_checksum** zeroed).

```
csum = crc32c(seed, le32(ino) || le32(i_generation) || dx_entries || dx_tail_with_csum_zeroed)
```

The `dx_tail` structure is 8 bytes: **dt_reserved** (4 bytes) + **dt_checksum** (4 bytes). It
is placed immediately after the last `dx_entry` in the block. The count of valid entries is
given by the `count` field in the `dx_countlimit` structure at the start of the entry array.
See [06-directories.md](06-directories.md) for hash tree formats.

### Extended Attribute Blocks

| Property | Value |
|----------|-------|
| Field | **h_checksum** in `ext4_xattr_header` |
| Offset | `0x10` within the xattr block header |
| Size | 4 bytes (`__le32`) |
| Algorithm | CRC32C |

**Input**: seed + block number as `__le32` (or `__le64` when 64BIT feature is set) + the entire
xattr block with **h_checksum** zeroed.

```
csum = crc32c(seed, le32(block_number) || xattr_block_with_csum_zeroed)
```

In-inode extended attributes (ibody xattrs) do not have a separate checksum — they are covered
by the inode checksum. See [07-extended-attributes.md](07-extended-attributes.md) for xattr
storage formats.

### MMP Block

| Property | Value |
|----------|-------|
| Field | **mmp_checksum** |
| Offset | `0x3FC` (last 4 bytes of the 1024-byte MMP block) |
| Size | 4 bytes (`__le32`) |
| Algorithm | CRC32C |

**Input**: seed + the entire MMP block (1024 bytes) with **mmp_checksum** zeroed.

```
csum = crc32c(seed, mmp_block_with_csum_zeroed)
```

See [11-allocation-and-protection.md](11-allocation-and-protection.md) for the `mmp_struct`
field layout.

## Checksum Summary Table

| Structure | Checksum field | Width | Input prefix | Input body |
|-----------|---------------|-------|--------------|------------|
| Superblock | s_checksum (`0x3FC`) | 32 bit | s_uuid | SB with csum zeroed |
| Group descriptor | bg_checksum (`0x1E`) | 16 bit | seed + group# | descriptor with csum zeroed |
| Block bitmap | bg_block_bitmap_csum_lo/hi | 16/32 bit | seed | entire bitmap |
| Inode bitmap | bg_inode_bitmap_csum_lo/hi | 16/32 bit | seed | entire bitmap |
| Inode | l_i_checksum_lo + i_checksum_hi | 16/32 bit | seed + ino + generation | inode with csums zeroed |
| Extent block | eb_checksum | 32 bit | seed + ino + generation | entire extent block |
| Directory leaf | det_checksum | 32 bit | seed + ino + generation | entire dir block |
| Hash tree node | dt_checksum | 32 bit | seed + ino + generation | dx_entries + dx_tail |
| Xattr block | h_checksum | 32 bit | seed + block# | xattr block with csum zeroed |
| MMP block | mmp_checksum (`0x3FC`) | 32 bit | seed | MMP block with csum zeroed |

## Relationship to jbd2 Checksumming

Ext4 metadata checksums and jbd2 journal checksums are independent systems. The journal has its
own checksum evolution across three generations (COMPAT_CHECKSUM, CSUM_V2, CSUM_V3), using
CRC32C for per-block and per-tag checksums within the journal log.

A parser verifying ext4 metadata checksums does not need to understand jbd2 checksums, and vice
versa. The two systems protect different data: ext4 checksums protect filesystem metadata at its
final on-disk location; jbd2 checksums protect journal log entries during replay.

See [../jbd2/05-checksumming.md](../jbd2/05-checksumming.md) for journal checksum details.
