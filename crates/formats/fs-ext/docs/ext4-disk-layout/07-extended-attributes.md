<!-- ext4 Disk Layout: Extended Attributes -->
<!-- In-inode and block-based xattr storage, entry format, name indices, EA_INODE for large values. -->

## Extended Attributes

Extended attributes (xattrs) store arbitrary name-value pairs associated with an inode. Two
storage locations exist: **in-inode** (after the fixed inode fields, within the inode record) and
**in a separate block** (referenced by `i_file_acl`). When reading, in-inode xattrs are checked
first. When both locations contain entries, they form a combined namespace — names must be
unique across both.

All multi-byte fields are little-endian.

### In-Inode Extended Attributes

Xattrs stored in the inode body occupy the space between the end of the inode's extended fields
and the end of the inode record. This space exists only when `s_inode_size > 128` (EXT2_GOOD_OLD_INODE_SIZE)
and `i_extra_isize > 0`.

**Location:** Byte offset `128 + i_extra_isize` from the start of the inode on disk. This is
immediately after the last extended inode field (e.g., after `i_projid` in a fully populated
256-byte inode).

**Available space:** `s_inode_size - 128 - i_extra_isize` bytes. With default 256-byte inodes
and `i_extra_isize = 32`: `256 - 128 - 32 = 96` bytes.

#### `ext4_xattr_ibody_header` (4 bytes)

The first 4 bytes of the in-inode xattr area form the header.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **h_magic** | Magic number: `0xEA020000`. Must match before interpreting ibody xattrs. If absent or mismatched, no in-inode xattrs exist. |

The header is followed immediately by an array of `ext4_xattr_entry` structures. Entries are
sorted by (**e_name_index**, **e_name**). The entry list is terminated by a zero-filled entry
(all fields zero) or by reaching the end of the available space.

**Value storage (in-inode):** Values are stored at the end of the inode xattr space, growing
downward. The **e_value_offs** field in each entry is the byte offset of the value from the
**first entry** (not from the header or the inode start).

### Block Extended Attributes

A single shared block can store xattrs for one or more inodes. The block is referenced by
**i_file_acl_lo** (inode offset 0x68). On Linux with 64-bit mode, the upper 16 bits come from
**l_i_file_acl_high** (OSD2 offset 0x74). The combined value is the filesystem block number
of the xattr block.

#### `ext4_xattr_header` (32 bytes)

The xattr block begins with this header.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 4 | `__le32` | **h_magic** | Magic number: `0xEA020000`. |
| 0x4 | 4 | `__le32` | **h_refcount** | Reference count. The block can be shared by multiple inodes that have identical xattr sets. Value >= 1. |
| 0x8 | 4 | `__le32` | **h_blocks** | Number of disk blocks used. Currently always `1`. |
| 0xC | 4 | `__le32` | **h_hash** | Hash of all xattrs in this block. Used for deduplication — inodes with the same xattr set share the same block. |
| 0x10 | 4 | `__le32` | **h_checksum** | CRC32C checksum when metadata checksums are enabled. Input: checksum seed + block number + entire xattr block with **h_checksum** zeroed. See [09-checksumming.md](09-checksumming.md). Set to `0` when checksums are not enabled. |
| 0x14 | 12 | — | **reserved** | Reserved. Must be zero. |

The header is followed by an array of `ext4_xattr_entry` structures, sorted by
(**e_name_index**, **e_name**). The entry list is terminated by a zero-filled entry.

**Value storage (block):** Values are stored at the end of the block, growing downward from
`block_size`. The **e_value_offs** field is the byte offset from the **start of the block**
(not from the first entry, unlike in-inode xattrs).

### Xattr Entry Format

#### `ext4_xattr_entry` (minimum 16 bytes)

Each entry describes one extended attribute. Entries are variable-length due to the inline
name. They are 4-byte aligned.

| Offset | Size | Type | Name | Description |
|---|---|---|---|---|
| 0x0 | 1 | `__u8` | **e_name_len** | Length of the attribute name suffix in bytes. |
| 0x1 | 1 | `__u8` | **e_name_index** | Name index (prefix selector). See Name Indices table. The full attribute name is the prefix from the index concatenated with **e_name**. |
| 0x2 | 2 | `__le16` | **e_value_offs** | Byte offset of the value. For block xattrs: offset from block start. For ibody xattrs: offset from first entry. |
| 0x4 | 4 | `__le32` | **e_value_inum** | Inode number storing the value when using EA_INODE. `0` = value is stored inline (at **e_value_offs**). Non-zero = value is in a separate inode. See EA_INODE section. |
| 0x8 | 4 | `__le32` | **e_value_size** | Size of the attribute value in bytes. |
| 0xC | 4 | `__le32` | **e_hash** | Hash of the attribute name and value. Used for block deduplication. |
| 0x10 | var | `char[]` | **e_name** | Attribute name suffix, `e_name_len` bytes. Not null-terminated. The entry is padded to a 4-byte boundary after the name. |

The total entry size is `16 + e_name_len`, rounded up to the next multiple of 4.

### Name Indices

The **e_name_index** field selects a well-known prefix that is prepended to **e_name** to form
the full attribute name. This saves space by avoiding repetitive prefix storage.

| Index | Prefix | Description |
|---|---|---|
| 0 | (none) | No prefix. The full name is exactly **e_name**. |
| 1 | `user.` | User-defined attributes. |
| 2 | `system.posix_acl_access` | POSIX access ACL. **e_name** is empty (the prefix is the complete name). |
| 3 | `system.posix_acl_default` | POSIX default ACL. **e_name** is empty. |
| 4 | `trusted.` | Trusted attributes (root-only access). |
| 6 | `security.` | Security labels (SELinux, AppArmor, etc.). |
| 7 | `system.` | System attributes. Used specifically for inline data (`system.data`). See [05-data-mapping.md](05-data-mapping.md). |
| 8 | `system.richacl` | Rich ACL (SuSE extension). Not present in mainline kernel. |

Index 5 is not assigned.

### Large Xattr Values (EA_INODE)

When a value is too large to fit in the xattr block (limited to `block_size - 32` bytes of
combined value storage), it can be stored in a separate inode. This requires the
INCOMPAT_EA_INODE feature.

**Detection:** `e_value_inum != 0` in the xattr entry. The value is stored as the data content
of the inode identified by **e_value_inum**. That inode has `EA_INODE_FL` (0x200000) set in
its **i_flags**.

**EA inode field overloading:** Several standard inode fields are repurposed in EA_INODE inodes:

| Inode Field | EA_INODE Usage |
|---|---|
| **i_atime** | CRC32C checksum of the xattr value. Used to verify value integrity. |
| **i_ctime** + **i_version** | Combined as a 64-bit reference count. Tracks how many parent inodes reference this EA inode. When the count reaches zero, the EA inode can be freed. |
| **i_mtime** + **i_generation** | Legacy back-reference to the owning inode. In older implementations, this stored the inode number and generation of the parent. Newer kernels use the reference count mechanism instead. |

**Value size:** The value occupies `e_value_size` bytes starting at the beginning of the EA
inode's data. The EA inode's `i_size` equals `e_value_size`.
