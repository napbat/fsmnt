<!-- ext4 Disk Layout: Inodes -->
<!-- Complete ext4_inode structure (base + extended fields), i_mode values, i_flags, OSD1/OSD2 unions, special inode numbers, and inode location calculation. -->

# Inodes

## Overview

An inode is a fixed-size record that stores all metadata for a single filesystem object (file, directory, symlink, device node, FIFO, or socket). Inodes are stored in per-group inode tables.

**Base size:** 128 bytes (`EXT2_GOOD_OLD_INODE_SIZE`). This is the original ext2 format, sufficient for basic metadata and the 60-byte `i_block` array.

**Extended size:** Typically 256 bytes, controlled by `s_inode_size` in the superblock. The extra space (bytes 128 through `s_inode_size - 1`) holds extended timestamp fields, creation time, version, project ID, and in-inode extended attributes.

Inode numbers start at **1** (not 0). Inode 0 is never used and indicates "no inode" in directory entries.

## Inode Location Calculation

To find the on-disk byte offset of a given inode number `ino`:

```
block_group = (ino - 1) / s_inodes_per_group
index       = (ino - 1) % s_inodes_per_group
byte_offset = bg_inode_table * block_size + index * s_inode_size
```

Where `bg_inode_table` is the inode table start block from the group descriptor of `block_group`. With `flex_bg`, the inode table may reside in a different block group than `block_group`.

## Base Fields (0x0 - 0x7F)

These 128 bytes are always present in every inode.

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | 2 | **i_mode** | File type and permissions. See [File Mode](#file-mode-i_mode). |
| 0x2 | 2 | **i_uid** | Lower 16 bits of the owner UID. |
| 0x4 | 4 | **i_size_lo** | Lower 32 bits of the file size in bytes. |
| 0x8 | 4 | **i_atime** | Last access time (Unix timestamp, signed 32-bit seconds). See [08-timestamps.md](08-timestamps.md). |
| 0xC | 4 | **i_ctime** | Last inode change time (Unix timestamp, signed 32-bit seconds). Metadata changes (permissions, ownership, link count) update this field. |
| 0x10 | 4 | **i_mtime** | Last data modification time (Unix timestamp, signed 32-bit seconds). |
| 0x14 | 4 | **i_dtime** | Deletion time. Set when the file is unlinked (deleted). Also used as the next-inode pointer in the legacy orphan inode linked list. See [08-timestamps.md](08-timestamps.md) and [10-journaling.md](10-journaling.md). |
| 0x18 | 2 | **i_gid** | Lower 16 bits of the owner GID. |
| 0x1A | 2 | **i_links_count** | Hard link count. When this reaches 0 and `i_dtime` is set, the inode is fully deleted. For directories with `RO_COMPAT_DIR_NLINK`, a value of 1 means the count exceeded 64999 and is tracked internally. |
| 0x1C | 4 | **i_blocks_lo** | Lower 32 bits of the block count. In 512-byte sector units by default. With `HUGE_FILE` and `EXT4_HUGE_FILE_FL` set in `i_flags`, the units are filesystem blocks instead. |
| 0x20 | 4 | **i_flags** | Inode flags. See [Inode Flags](#inode-flags-i_flags). |
| 0x24 | 4 | **osd1** | OS-dependent value 1. See [OSD1 Union](#osd1-union). |
| 0x28 | 60 | **i_block[15]** | Block mapping array (15 x 4 bytes = 60 bytes). Interpretation depends on file type and inode flags. See [05-data-mapping.md](05-data-mapping.md). |
| 0x64 | 4 | **i_generation** | File version / generation number. Used by NFS to detect stale file handles. Also used as part of the inode checksum input. |
| 0x68 | 4 | **i_file_acl_lo** | Lower 32 bits of the block number of the extended attribute block. See [07-extended-attributes.md](07-extended-attributes.md). |
| 0x6C | 4 | **i_size_high** | Upper 32 bits of the file size. For regular files, valid when `RO_COMPAT_LARGE_FILE` is set. For directories, this is `i_dir_acl` (unused in ext4). |
| 0x70 | 4 | **i_obso_faddr** | Obsolete fragment address. Always 0 in ext4. |
| 0x74 | 12 | **osd2** | OS-dependent value 2 (12 bytes). See [OSD2 Union](#osd2-union). |

## Extended Fields (0x80 - 0x9F)

Present when `s_inode_size > 128` and `i_extra_isize > 0`. The **i_extra_isize** field specifies the number of bytes used by extended fields beyond the base 128-byte inode (not counting the in-inode xattr space that follows).

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x80 | 2 | **i_extra_isize** | Number of bytes of extended inode fields in use, starting from offset 0x82. Minimum: 0. Typical values: 28 (up to `i_projid`) or 32 (includes all current fields). |
| 0x82 | 2 | **i_checksum_hi** | Upper 16 bits of the inode checksum. Lower 16 bits are in `l_i_checksum_lo` (osd2, Linux). See [09-checksumming.md](09-checksumming.md). |
| 0x84 | 4 | **i_ctime_extra** | Extra change time bits. Bits 0-1: epoch extension. Bits 2-31: nanosecond component. See [08-timestamps.md](08-timestamps.md). |
| 0x88 | 4 | **i_mtime_extra** | Extra modification time bits. Same format as `i_ctime_extra`. |
| 0x8C | 4 | **i_atime_extra** | Extra access time bits. Same format as `i_ctime_extra`. |
| 0x90 | 4 | **i_crtime** | File creation time (Unix timestamp, signed 32-bit seconds). Only in extended inodes. Not updated by normal file operations. |
| 0x94 | 4 | **i_crtime_extra** | Extra creation time bits. Same format as `i_ctime_extra`. |
| 0x98 | 4 | **i_version_hi** | Upper 32 bits of the inode version. Lower 32 bits are in `osd1` (Linux: `l_i_version`). Used for NFS and change detection. |
| 0x9C | 4 | **i_projid** | Project ID for project quota tracking. Requires `RO_COMPAT_PROJECT`. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |

After the extended fields (at offset `EXT2_GOOD_OLD_INODE_SIZE + i_extra_isize`, i.e., `128 + i_extra_isize`), the remaining space up to `s_inode_size` is available for in-inode extended attributes. See [07-extended-attributes.md](07-extended-attributes.md).

## File Mode (`i_mode`)

The **i_mode** field at offset `0x0` encodes both the file type and access permissions in a 16-bit value.

### File Type (upper 4 bits)

Extract with: `file_type = i_mode & 0xF000`

| Value | Name | Description |
|-------|------|-------------|
| `0x1000` | S_IFIFO | Named pipe (FIFO). |
| `0x2000` | S_IFCHR | Character device. |
| `0x4000` | S_IFDIR | Directory. |
| `0x6000` | S_IFBLK | Block device. |
| `0x8000` | S_IFREG | Regular file. |
| `0xA000` | S_IFLNK | Symbolic link. |
| `0xC000` | S_IFSOCK | Unix domain socket. |

### Special Permission Bits

| Value | Name | Description |
|-------|------|-------------|
| `0x0200` | S_ISVTX | Sticky bit. On directories, only the file owner can delete/rename entries. |
| `0x0400` | S_ISGID | Set-group-ID. On executables, the process runs with the file's GID. On directories, new files inherit the directory's GID. |
| `0x0800` | S_ISUID | Set-user-ID. On executables, the process runs with the file's UID. |

### Permission Bits

| Value | Name | Description |
|-------|------|-------------|
| `0x0001` | S_IXOTH | Others: execute. |
| `0x0002` | S_IWOTH | Others: write. |
| `0x0004` | S_IROTH | Others: read. |
| `0x0008` | S_IXGRP | Group: execute. |
| `0x0010` | S_IWGRP | Group: write. |
| `0x0020` | S_IRGRP | Group: read. |
| `0x0040` | S_IXUSR | Owner: execute. |
| `0x0080` | S_IWUSR | Owner: write. |
| `0x0100` | S_IRUSR | Owner: read. |

## Inode Flags (`i_flags`)

The **i_flags** field at offset `0x20` is a 32-bit bitmask. These flags control how the kernel and filesystem tools handle the file.

| Flag | Value | Name | Description |
|------|-------|------|-------------|
| SECRM_FL | `0x00000001` | `EXT4_SECRM_FL` | Secure deletion (not implemented). Overwrite file data on delete. |
| UNRM_FL | `0x00000002` | `EXT4_UNRM_FL` | Record for undelete (not implemented). |
| COMPR_FL | `0x00000004` | `EXT4_COMPR_FL` | File is compressed (not implemented in mainline). |
| SYNC_FL | `0x00000008` | `EXT4_SYNC_FL` | Synchronous updates. All writes are immediately flushed to disk. |
| IMMUTABLE_FL | `0x00000010` | `EXT4_IMMUTABLE_FL` | File is immutable. Cannot be modified, deleted, renamed, or linked. |
| APPEND_FL | `0x00000020` | `EXT4_APPEND_FL` | Append only. Data can only be written at the end. |
| NODUMP_FL | `0x00000040` | `EXT4_NODUMP_FL` | Do not include in filesystem dumps (`dump` command). |
| NOATIME_FL | `0x00000080` | `EXT4_NOATIME_FL` | Do not update access time (`i_atime`). |
| DIRTY_FL | `0x00000100` | `EXT4_DIRTY_FL` | Dirty (compressed file, not implemented). |
| COMPRBLK_FL | `0x00000200` | `EXT4_COMPRBLK_FL` | Compressed blocks (not implemented). |
| NOCOMPR_FL | `0x00000400` | `EXT4_NOCOMPR_FL` | Do not compress (not implemented). |
| ENCRYPT_FL | `0x00000800` | `EXT4_ENCRYPT_FL` | File is encrypted. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| INDEX_FL | `0x00001000` | `EXT4_INDEX_FL` | Directory uses hash tree index. Same bit as IMAGIC_FL for non-directories. |
| IMAGIC_FL | `0x00002000` | `EXT4_IMAGIC_FL` | AFS server imagic inode (not used in mainline). |
| JOURNAL_DATA_FL | `0x00004000` | `EXT4_JOURNAL_DATA_FL` | File data must be journaled (journal mode: data). |
| NOTAIL_FL | `0x00008000` | `EXT4_NOTAIL_FL` | File tail should not be merged (not used by ext4; relevant to Reiserfs). |
| DIRSYNC_FL | `0x00010000` | `EXT4_DIRSYNC_FL` | Directory modifications are synchronous. |
| TOPDIR_FL | `0x00020000` | `EXT4_TOPDIR_FL` | Top of directory hierarchy. Hint for block allocator. |
| HUGE_FILE_FL | `0x00040000` | `EXT4_HUGE_FILE_FL` | `i_blocks_lo` uses filesystem block units instead of 512-byte sectors. Requires `RO_COMPAT_HUGE_FILE`. |
| EXTENTS_FL | `0x00080000` | `EXT4_EXTENTS_FL` | File uses extent tree for block mapping. See [05-data-mapping.md](05-data-mapping.md). |
| VERITY_FL | `0x00100000` | `EXT4_VERITY_FL` | File has fs-verity enabled. A Merkle tree is appended after the file data. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| EA_INODE_FL | `0x00200000` | `EXT4_EA_INODE_FL` | Inode is used to store a large extended attribute value. See [07-extended-attributes.md](07-extended-attributes.md). |
| DAX_FL | `0x02000000` | `EXT4_DAX_FL` | Inode uses DAX (direct access, bypass page cache). For persistent memory devices. |
| INLINE_DATA_FL | `0x10000000` | `EXT4_INLINE_DATA_FL` | Inode has inline data stored in `i_block` and/or ibody xattr space. See [05-data-mapping.md](05-data-mapping.md). |
| PROJINHERIT_FL | `0x20000000` | `EXT4_PROJINHERIT_FL` | Directory: new child inodes inherit this directory's project ID. Requires `RO_COMPAT_PROJECT`. |
| CASEFOLD_FL | `0x40000000` | `EXT4_CASEFOLD_FL` | Directory uses case-insensitive filename lookups. Requires `INCOMPAT_CASEFOLD`. See [06-directories.md](06-directories.md). |
| RESERVED_FL | `0x80000000` | `EXT4_RESERVED_FL` | Reserved for ext4 library use. |

### Aggregate Masks

| Mask | Value | Description |
|------|-------|-------------|
| User-visible | `0x705BDFFF` | Flags visible to user-space via `FS_IOC_GETFLAGS`. |
| User-modifiable | `0x604BC0FF` | Flags that can be set by user-space via `FS_IOC_SETFLAGS` (subject to permission checks). |

## OSD1 Union

The **osd1** field at offset `0x24` (4 bytes) is interpreted based on `s_creator_os`:

### Linux (`s_creator_os` = 0)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x24 | 4 | **l_i_version** | Lower 32 bits of the inode version number. Combined with `i_version_hi` (extended field) for the full 64-bit version. |

### GNU Hurd (`s_creator_os` = 1)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x24 | 4 | **h_i_translator** | Block number of the Hurd translator for this inode. |

### Masix (`s_creator_os` = 2)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x24 | 4 | **m_i_reserved** | Reserved. |

## OSD2 Union

The **osd2** field at offset `0x74` (12 bytes) is interpreted based on `s_creator_os`:

### Linux (`s_creator_os` = 0)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x74 | 2 | **l_i_blocks_high** | Upper 16 bits of the 512-byte block count (or filesystem-block count when `HUGE_FILE_FL` is set). Combined with `i_blocks_lo` for the full 48-bit count. |
| 0x76 | 2 | **l_i_file_acl_high** | Upper 16 bits of the extended attribute block number. Combined with `i_file_acl_lo` for the full 48-bit block number. |
| 0x78 | 2 | **l_i_uid_high** | Upper 16 bits of the owner UID. Combined with `i_uid` for the full 32-bit UID. |
| 0x7A | 2 | **l_i_gid_high** | Upper 16 bits of the owner GID. Combined with `i_gid` for the full 32-bit GID. |
| 0x7C | 2 | **l_i_checksum_lo** | Lower 16 bits of the inode checksum. Upper 16 bits are in `i_checksum_hi` (extended field). See [09-checksumming.md](09-checksumming.md). |
| 0x7E | 2 | **l_i_reserved** | Reserved. |

### GNU Hurd (`s_creator_os` = 1)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x74 | 2 | **h_i_reserved1** | Reserved. |
| 0x76 | 2 | **h_i_mode_high** | Upper 16 bits of the file mode (Hurd supports 32-bit mode). |
| 0x78 | 2 | **h_i_uid_high** | Upper 16 bits of the owner UID. |
| 0x7A | 2 | **h_i_gid_high** | Upper 16 bits of the owner GID. |
| 0x7C | 4 | **h_i_author** | Author ID (Hurd concept: the user who wrote the file, distinct from owner). |

### Masix (`s_creator_os` = 2)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x74 | 2 | **m_i_reserved1** | Reserved. |
| 0x76 | 2 | **m_i_file_acl_high** | Upper 16 bits of the extended attribute block number. |
| 0x78 | 8 | **m_i_reserved2[2]** | Reserved (two 32-bit words). |

## Special Inode Numbers

Certain inode numbers are reserved for filesystem metadata and special purposes:

| Inode | Name | Description |
|-------|------|-------------|
| 0 | — | Does not exist. Used as a sentinel value (e.g., deleted directory entries have `inode = 0`). |
| 1 | **Defective blocks** | Tracks bad blocks on the device. |
| 2 | **Root directory** | The filesystem root directory (`/`). Always inode 2. |
| 3 | **User quota** | User quota data file (`s_usr_quota_inum` typically points here). |
| 4 | **Group quota** | Group quota data file (`s_grp_quota_inum` typically points here). |
| 5 | **Boot loader** | Boot loader inode. |
| 6 | **Undelete directory** | Undelete directory (not implemented in mainline). |
| 7 | **Reserved GDT / resize** | Reserved group descriptors inode. Used for online filesystem resize. See [11-allocation-and-protection.md](11-allocation-and-protection.md). |
| 8 | **Journal** | Journal inode (`s_journal_inum` typically points here). See [10-journaling.md](10-journaling.md). |
| 9 | **Exclude / snapshots** | Exclude inode (snapshot-related, not used in mainline). |
| 10 | **Replica** | Replica inode (not used in mainline). |
| 11 | **First user inode** | First non-reserved inode (default value of `s_first_ino`). Typically the `lost+found` directory. |

In revision 0 filesystems, `s_first_ino` is fixed at 11. In revision 1+, `s_first_ino` can be configured at format time but is almost always 11.
