<!-- ext4 Disk Layout: Data Mapping -->
<!-- Block maps, extent trees, inline data, and symlink targets — interpreting the i_block[15] array. -->

## Data Mapping

The 60-byte `i_block[EXT4_N_BLOCKS]` array (15 x 4-byte entries, inode offset 0x28) is the
branching point for all data addressing in ext4. Its interpretation depends on the inode's type and
flags.

### Interpretation Order

Check **i_mode** first: if the file type is `S_IFLNK` (symlink) and `i_size <= 60`, the array
contains a raw symlink target path (not block pointers or extent headers). Otherwise check
**i_flags**:

| Condition | Interpretation |
|---|---|
| `i_mode & 0xF000 == 0xA000` and `i_size <= 60` | Short symbolic link — raw path bytes in `i_block[0..14]` |
| `i_flags & EXTENTS_FL` (0x80000) | Extent tree root embedded in `i_block` |
| `i_flags & INLINE_DATA_FL` (0x10000000) | Inline data stored in `i_block` |
| Neither flag set | Legacy block map (direct/indirect pointers) |

### Block Map (Direct/Indirect)

The legacy addressing scheme uses 32-bit block pointers. Each pointer is a `__le32` filesystem
block number. A zero pointer indicates a hole (sparse region — reads return zeros).

| Entry | Role | Logical Blocks Covered |
|---|---|---|
| `i_block[0]` | Direct pointer | Block 0 |
| `i_block[1]` | Direct pointer | Block 1 |
| `i_block[2]` | Direct pointer | Block 2 |
| `i_block[3]` | Direct pointer | Block 3 |
| `i_block[4]` | Direct pointer | Block 4 |
| `i_block[5]` | Direct pointer | Block 5 |
| `i_block[6]` | Direct pointer | Block 6 |
| `i_block[7]` | Direct pointer | Block 7 |
| `i_block[8]` | Direct pointer | Block 8 |
| `i_block[9]` | Direct pointer | Block 9 |
| `i_block[10]` | Direct pointer | Block 10 |
| `i_block[11]` | Direct pointer | Block 11 |
| `i_block[12]` | Single indirect | Blocks 12–1035 |
| `i_block[13]` | Double indirect | Blocks 1036–1049611 |
| `i_block[14]` | Triple indirect | Blocks 1049612–1074791436 |

**Direct pointers** (entries 0–11): each entry is a 4-byte block number pointing directly to a data
block. This covers the first 12 blocks of the file.

**Single indirect** (entry 12): points to a block containing an array of `__le32` block pointers.
At 4 KiB block size, one indirect block holds `4096 / 4 = 1024` entries, covering blocks 12
through 1035.

**Double indirect** (entry 13): points to a block of indirect pointers, each of which points to a
block of direct pointers. Capacity: `1024 * 1024 = 1048576` blocks, covering blocks 1036
through 1049611.

**Triple indirect** (entry 14): adds a third level of indirection. Capacity:
`1024 * 1024 * 1024 = 1073741824` blocks, covering blocks 1049612 through 1074791436.

All pointers are 4-byte `__le32` values (32-bit block numbers only). This limits block map
addressing to 2^32 blocks. At 4 KiB block size, the maximum file size via block maps is
approximately 4 TiB. Extent trees remove this limitation via 48-bit physical block numbers.

**Max file size formula** (block map, block size `b`):

```
entries_per_block = b / 4
max_blocks = 12 + entries_per_block + entries_per_block^2 + entries_per_block^3
max_file_size = max_blocks * b
```

### Symbolic Links

**Short symlinks:** When `i_mode & 0xF000 == 0xA000` (S_IFLNK) and `i_size <= 60`, the
target path is stored directly in `i_block[0..14]` as raw bytes. The 60 bytes of the `i_block`
array are reinterpreted as a character buffer, not as block pointers or extent structures. The
path is `i_size` bytes long and is not necessarily null-terminated on disk (though the kernel
null-terminates when reading).

**Long symlinks:** When `i_size > 60`, the target path is stored in data blocks addressed via
the block map or extent tree, depending on **i_flags**. The `i_block` array is interpreted
normally (as block pointers or an extent tree root).

**Encrypted symlinks:** When `ENCRYPT_FL` (0x800) is set on a symlink inode, the target is
stored as ciphertext. Short encrypted symlinks store the ciphertext in `i_block`; long encrypted
symlinks use data blocks. The ciphertext length may differ from the plaintext target length due
to encryption padding.

### Extent Tree

Extent trees replace block maps for files on ext4 filesystems with the `EXTENTS` feature
(INCOMPAT_EXTENTS, 0x40). The tree maps contiguous ranges of logical blocks to contiguous
ranges of physical blocks, providing efficient addressing for large and non-fragmented files.

The extent tree root is embedded in the `i_block` array (60 bytes). Each node in the tree
consists of a header followed by entries. Interior nodes contain index entries; leaf nodes
contain extent entries. An optional tail carries a checksum.

#### `ext4_extent_header` (12 bytes)

Every extent tree node (root, interior, leaf) begins with this header.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 2 | `__le16` | **eh_magic** | Magic number: `0xF30A`. Must be verified before interpreting the node. |
| 0x2 | 2 | `__le16` | **eh_entries** | Number of valid entries following the header. |
| 0x4 | 2 | `__le16` | **eh_max** | Maximum number of entries that could follow the header. Depends on available space. |
| 0x6 | 2 | `__le16` | **eh_depth** | Depth of this node in the tree. `0` = leaf node (entries are `ext4_extent`). `> 0` = interior node (entries are `ext4_extent_idx`). |
| 0x8 | 4 | `__le32` | **eh_generation** | Generation of the tree. Used by Lustre but not the mainline kernel. |

#### `ext4_extent_idx` (12 bytes) — Interior Node Entry

Each index entry in an interior node points to a child node one level deeper.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **ei_block** | Logical block number covered by this index entry. The subtree rooted at the child node covers logical blocks starting at **ei_block**. |
| 0x4 | 4 | `__le32` | **ei_leaf_lo** | Lower 32 bits of the physical block number of the child node. |
| 0x8 | 2 | `__le16` | **ei_leaf_hi** | Upper 16 bits of the physical block number. Combined with **ei_leaf_lo** for a 48-bit physical block address: `(ei_leaf_hi << 32) | ei_leaf_lo`. |
| 0xA | 2 | `__u16` | **ei_unused** | Unused. |

#### `ext4_extent` (12 bytes) — Leaf Node Entry

Each extent in a leaf node maps a contiguous range of logical blocks to physical blocks.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **ee_block** | First logical block number that this extent covers. |
| 0x4 | 2 | `__le16` | **ee_len** | Number of blocks covered by this extent. If `ee_len <= 32768`, the extent is **initialized** (contains valid data). If `ee_len > 32768`, the extent is **uninitialized** (preallocated, reads return zeros) and the actual length is `ee_len - 32768`. Maximum initialized length: 32768 blocks. Maximum uninitialized length: 32768 blocks. |
| 0x6 | 2 | `__le16` | **ee_start_hi** | Upper 16 bits of the 48-bit physical block number. |
| 0x8 | 4 | `__le32` | **ee_start_lo** | Lower 32 bits of the physical block number. Physical start: `(ee_start_hi << 32) | ee_start_lo`. |

#### `ext4_extent_tail` (4 bytes)

Present at the end of an extent tree block when metadata checksums are enabled
(RO_COMPAT_METADATA_CSUM). Not present in the in-inode root node (the inode's own
checksum covers it).

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **eb_checksum** | CRC32C checksum of this extent tree block. Input: checksum seed + inode number + inode generation + entire extent block. See [09-checksumming.md](09-checksumming.md). |

#### Extent Tree Layout

**In-inode root:** The `i_block` array provides 60 bytes. The header consumes 12 bytes, leaving
room for `(60 - 12) / 12 = 4` entries. No `ext4_extent_tail` in the inode (the inode checksum
covers the root).

**External tree blocks:** A full filesystem block is available. The header consumes 12 bytes.
The tail consumes 4 bytes when checksums are enabled. Entry capacity:

```
with checksums:    (block_size - 12 - 4) / 12
without checksums: (block_size - 12) / 12
```

At 4 KiB block size with checksums: `(4096 - 12 - 4) / 12 = 340` entries per block.

**Maximum depth:** 5 levels of index nodes below the root header, for a total tree height of 6
(root + 5 index levels + leaf level, where the root at depth 5 points to index nodes at depth 4,
down to leaves at depth 0). In practice, even very large files rarely exceed depth 2. A depth-1
tree (root with 4 index entries, each pointing to a leaf block with 340 extents) can address
`4 * 340 * 32768 = 44,564,480` blocks (approximately 170 GiB at 4 KiB block size).

### Inline Data

Enabled by INCOMPAT_INLINE_DATA (0x8000). Small files store their contents directly in the
inode, avoiding any block allocation.

**In i_block (up to 60 bytes):** When `i_size <= 60`, the file data occupies the `i_block` array.
The `INLINE_DATA_FL` flag (0x10000000) is set in **i_flags**. No block pointers or extent
headers exist — the 60 bytes are raw file content.

**In xattr space (up to ~160 bytes):** When the file exceeds 60 bytes but is still small enough,
the additional data is stored in an extended attribute named `system.data` (name index 7) in the
inode body xattr space. See [07-extended-attributes.md](07-extended-attributes.md). The total
inline capacity depends on `s_inode_size` and `i_extra_isize`:

```
total_capacity = 60 + (s_inode_size - 128 - i_extra_isize - 4 - 16)
```

Where 4 bytes are the xattr ibody header and 16 bytes are the minimum xattr entry overhead.
With default 256-byte inodes and `i_extra_isize = 32`: `60 + (256 - 128 - 32 - 4 - 16) = 136`
bytes. Typical capacity is approximately 160 bytes depending on inode configuration.

Files that outgrow inline capacity are converted to extent-mapped files on the next write.

### Inline Directories

Directories can also use inline data. The `i_block` array is reinterpreted as follows:

**First 4 bytes** (offset 0x28 in the inode): `__le32` parent directory inode number. This
replaces the `.` and `..` entries that would normally appear at the start of a directory block.

**Remaining 56 bytes** (offset 0x2C–0x63): array of `ext4_dir_entry_2` structures packed in
the same format as regular directory entries. See [06-directories.md](06-directories.md).

**Extended attribute space:** When the directory outgrows 56 bytes, additional entries are stored
in the `system.data` xattr in the inode body, using the same packed entry format.

Inline directories do not use per-entry checksums. The inode's own checksum
(`l_i_checksum_lo` + `i_checksum_hi`) covers all inline content. Hash trees (htree) are not
used with inline directories.
