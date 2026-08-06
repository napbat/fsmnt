<!-- ext4 Disk Layout: Directories -->
<!-- Linear directory entries, hash tree (htree) indexing, checksums, casefold, and encrypted directory handling. -->

## Directories

Directories are files whose data blocks contain linked lists of directory entries. Two core
formats exist: **linear** (classic linked-list) and **hash tree** (htree, for indexed lookups).
Encrypted and casefolded directories add a hash suffix structure to selected entries.

All multi-byte fields are little-endian.

### Linear Entries

#### `ext4_dir_entry` — Legacy (No File Type)

Used when INCOMPAT_FILETYPE is **not** set (ext2 revision 0). Rarely seen on modern
filesystems.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **inode** | Inode number of the referenced file. `0` = deleted or unused entry. |
| 0x4 | 2 | `__le16` | **rec_len** | Total size of this directory entry in bytes, including all fields and name padding. Always a multiple of 4. |
| 0x6 | 2 | `__le16` | **name_len** | Length of the file name in bytes (no null terminator). |
| 0x8 | var | `char[]` | **name** | File name, `name_len` bytes. Not null-terminated on disk. Padded to a 4-byte boundary within `rec_len`. |

#### `ext4_dir_entry_2` — Modern (With File Type)

Used when INCOMPAT_FILETYPE is set (all ext3/ext4 filesystems). The `name_len` field is
split into separate `name_len` and `file_type` bytes.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **inode** | Inode number of the referenced file. `0` = deleted or unused entry. |
| 0x4 | 2 | `__le16` | **rec_len** | Total size of this directory entry in bytes. Always a multiple of 4. |
| 0x6 | 1 | `__u8` | **name_len** | Length of the file name in bytes. |
| 0x7 | 1 | `__u8` | **file_type** | File type code (see table below). |
| 0x8 | var | `char[]` | **name** | File name, `name_len` bytes. Not null-terminated. |

**File type codes:**

| Value | Type | Description |
|---|---|---|
| 0 | `EXT4_FT_UNKNOWN` | Unknown file type |
| 1 | `EXT4_FT_REG_FILE` | Regular file |
| 2 | `EXT4_FT_DIR` | Directory |
| 3 | `EXT4_FT_CHRDEV` | Character device |
| 4 | `EXT4_FT_BLKDEV` | Block device |
| 5 | `EXT4_FT_FIFO` | FIFO (named pipe) |
| 6 | `EXT4_FT_SOCK` | Socket |
| 7 | `EXT4_FT_SYMLINK` | Symbolic link |

#### Entry Packing

**rec_len** is always a multiple of 4. The minimum size of a valid entry is 8 bytes (header) +
the name length rounded up to a 4-byte boundary.

The last entry in a block absorbs all remaining space by setting **rec_len** to extend to the end
of the block. This means `rec_len` can be much larger than the actual entry content.

**Deleted entries:** The kernel sets **inode** to `0` and merges the deleted entry's space into the
preceding entry by increasing the predecessor's **rec_len**. The name bytes of deleted entries
may remain on disk, which is forensically significant.

#### `ext4_extended_dir_entry_2` — Dirent Hash Suffix (8 bytes)

Appended immediately after the **name** field in `ext4_dir_entry_2` for directories that are
**both encrypted and casefolded**. The suffix is included within **rec_len**. Not used for `.`
or `..` entries.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **hash** | Major hash of the directory entry name. |
| 0x4 | 4 | `__le32` | **minor_hash** | Minor hash of the directory entry name. |

This structure allows the kernel to perform case-insensitive lookups in encrypted directories
without decrypting every entry. The hashes are computed from the casefolded, encrypted name.

#### `ext4_dir_entry_tail` — Checksum Sentinel (12 bytes)

Present as the last entry in a directory leaf block when metadata checksums are enabled
(RO_COMPAT_METADATA_CSUM). Disguised as a directory entry to maintain backward
compatibility with older implementations that ignore entries with `inode == 0`.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **det_reserved_zero1** | Must be `0` (looks like an unused inode number). |
| 0x4 | 2 | `__le16` | **det_rec_len** | Must be `12`. |
| 0x6 | 1 | `__u8` | **det_reserved_zero2** | Must be `0` (name_len). |
| 0x7 | 1 | `__u8` | **det_reserved_ft** | Must be `0xDE` (file_type). This magic value distinguishes the tail from a regular deleted entry. |
| 0x8 | 4 | `__le32` | **det_checksum** | CRC32C checksum of this directory leaf block. Input: checksum seed + inode number + inode generation + entire directory block. See [09-checksumming.md](09-checksumming.md). |

### Hash Tree (htree)

Hash tree directories provide O(1) lookup by hashing file names and indexing into a B-tree
structure. The hash tree is layered on top of the linear entry format: leaf blocks still contain
`ext4_dir_entry_2` entries, but interior blocks contain index structures that map hash values
to leaf blocks.

Hash tree structures are stored within the directory's data blocks. The root is always in block
0 of the directory file. The tree is transparent to readers that do not understand htree — block
0 begins with valid `.` and `..` entries, so a linear scan still works (just slower).

#### `dx_root` — Hash Tree Root Block

Block 0 of an htree directory. Embeds the dot/dotdot entries required for linear compatibility,
followed by the tree metadata and root index entries.

| Offset | Size | Description |
|---|---|---|
| 0x0 | 12 | **Dot entry** — `ext4_dir_entry_2` for `.` with `inode` = this directory's inode, `rec_len = 12`, `name_len = 1`, `file_type = 2`. |
| 0xC | var | **Dotdot entry** — `ext4_dir_entry_2` for `..` with `rec_len = block_size - 12`. The large `rec_len` hides the rest of the block from linear scanners. |

Immediately after the dotdot entry's name (at a fixed offset within the dotdot entry's padding):

**`dx_root_info`:**

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **reserved_zero** | Must be `0`. |
| 0x4 | 1 | `__u8` | **hash_version** | Hash algorithm used. See Hash Algorithms table below. |
| 0x5 | 1 | `__u8` | **info_length** | Length of this info structure: `0x8`. |
| 0x6 | 1 | `__u8` | **indirect_levels** | Depth of the hash tree. `0` = root points directly to leaf blocks. `1` = one level of `dx_node` between root and leaves. Max `2` normally, max `3` with INCOMPAT_LARGEDIR. |
| 0x7 | 1 | `__u8` | **unused_flags** | Must be `0`. |

Following `dx_root_info`:

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 2 | `__le16` | **limit** | Maximum number of `dx_entry` entries that fit in this block (including the root entry). |
| 0x2 | 2 | `__le16` | **count** | Actual number of `dx_entry` entries (including the root entry). |
| 0x4 | 4 | `__le32` | **block** | Block number of the leaf/node for hash values less than the first `dx_entry`'s hash. This is block 0's "leftmost child." |

Followed by `count - 1` `dx_entry` structures.

#### `dx_node` — Hash Tree Interior Node

Used at intermediate levels between the root and leaf blocks. Disguised as a directory block
with a fake entry for backward compatibility.

| Offset | Size | Description |
|---|---|---|
| 0x0 | 8+ | **Fake entry** — `ext4_dir_entry_2` with `inode = 0`, `rec_len = block_size` (absorbs entire block for linear scanners). |

After the fake entry:

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 2 | `__le16` | **limit** | Maximum number of `dx_entry` entries in this block. |
| 0x2 | 2 | `__le16` | **count** | Actual number of `dx_entry` entries. |
| 0x4 | 4 | `__le32` | **block** | Block number for hash values below the first `dx_entry`'s hash. |

Followed by `count - 1` `dx_entry` structures.

#### `dx_entry` (8 bytes)

Each entry maps a hash value boundary to a child block number.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **hash** | Hash value. All directory entries in the pointed-to block have hashes >= this value and < the next `dx_entry`'s hash. |
| 0x4 | 4 | `__le32` | **block** | Block number within the directory file (relative to the directory's block 0, not a filesystem block number). Points to either a `dx_node` (if `indirect_levels > 0` at this depth) or a leaf block containing `ext4_dir_entry_2` entries. |

#### `dx_tail` (8 bytes)

Present at the end of a `dx_root` or `dx_node` block when metadata checksums are enabled.
Located immediately after the last possible `dx_entry` slot (at offset `limit * 8` from the
first `dx_entry`).

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **dt_reserved** | Reserved, must be `0`. |
| 0x4 | 4 | `__le32` | **dt_checksum** | CRC32C checksum. Input: checksum seed + inode number + inode generation + all valid `dx_entry` structures + tail. See [09-checksumming.md](09-checksumming.md). |

### Hash Algorithms

The hash algorithm is specified per-directory in `dx_root_info.hash_version` and per-filesystem
as a default in `s_def_hash_version`. The hash seed is `s_hash_seed[4]` (16 bytes in the
superblock).

| Value | Name | Description |
|---|---|---|
| 0 | `DX_HASH_LEGACY` | Legacy hash. Weak distribution; only used on very old filesystems. |
| 1 | `DX_HASH_HALF_MD4` | Half MD4 hash. Signed character comparison. |
| 2 | `DX_HASH_TEA` | TEA (Tiny Encryption Algorithm) hash. Signed character comparison. |
| 3 | `DX_HASH_LEGACY_UNSIGNED` | Legacy hash with unsigned character comparison. |
| 4 | `DX_HASH_HALF_MD4_UNSIGNED` | Half MD4 with unsigned character comparison. Default on modern filesystems. |
| 5 | `DX_HASH_TEA_UNSIGNED` | TEA with unsigned character comparison. |
| 6 | `DX_HASH_SIPHASH` | SipHash. Used exclusively for directories that are **both encrypted and casefolded**. |

**Signed vs. unsigned:** Hash algorithms 0–2 treat filename bytes as signed characters during
hashing. This causes locale-dependent behavior for bytes >= 0x80. Algorithms 3–5 use unsigned
comparison, which is locale-independent and preferred.

**SipHash:** `DX_HASH_SIPHASH` (6) is not a general-purpose directory hash. It is used only
when a directory has both `ENCRYPT_FL` and `CASEFOLD_FL` set. In this case, the kernel
computes SipHash over the casefolded, encrypted name using a per-directory key derived from
the filesystem's encryption context. Non-encrypted casefolded directories use the standard
`hash_version` (typically half MD4 unsigned or TEA unsigned) with the casefolded name as
input.

### Tree Depth Limits

**Normal:** Maximum 2 levels of `dx_node` blocks between the root and leaf blocks
(`indirect_levels` max = 2).

**With INCOMPAT_LARGEDIR** (0x4000): Maximum 3 levels (`indirect_levels` max = 3). This
flag was added to support directories with very large numbers of entries.

At 4 KiB block size with 3 levels, a hash tree can index millions of directory entries.

### Casefolded Directories

Enabled by INCOMPAT_CASEFOLD (0x20000). Provides case-insensitive filename lookups at the
filesystem level.

**Superblock fields:**
- **s_encoding** (`__le16`, offset 0x27C): Unicode encoding identifier. Currently only
  UTF-8 is supported (value from `encoding.h`).
- **s_encoding_flags** (`__le16`, offset 0x27E): Encoding flags. Bit 0 (`EXT4_ENC_STRICT_MODE_FL`)
  controls strict mode — when set, the filesystem rejects filenames that are not valid in the
  configured encoding.

**Lookup behavior:** When `CASEFOLD_FL` is set on a directory inode, filename comparisons
use Unicode casefolding rules defined by **s_encoding**. For hash tree directories, hashes are
computed from the **normalized/casefolded** form of the name, not the original on-disk name.

**Interaction with encryption:** Directories that are both encrypted and casefolded use
`DX_HASH_SIPHASH` and store `ext4_extended_dir_entry_2` hash suffixes after the name in
each dirent (except `.` and `..`). This allows hash-based lookup without decrypting every
entry's name.
