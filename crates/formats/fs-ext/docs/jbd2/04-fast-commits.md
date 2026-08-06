<!-- jbd2: Fast Commits -->
<!-- TLV format, tag types, payload structures, replay idempotence -->

# jbd2: Fast Commits

Fast commits (INCOMPAT_FAST_COMMIT, `0x20`) provide a lightweight alternative to full block-copy
journaling. Instead of writing entire filesystem blocks, fast commits record **logical operations**
as tag-length-value (TLV) entries. This reduces journal I/O for common operations like file
creation, hard linking, unlinking, and extent addition.

## Overview

The fast commit area occupies **s_num_fc_blocks** blocks at the end of the journal, outside the
main circular log buffer. These blocks are not part of the normal transaction flow. Fast commit
blocks are written sequentially within this reserved area.

Fast commits complement, not replace, full journal commits. A fast commit captures incremental
changes between full commits. On recovery, full journal replay runs first, then fast commit
replay applies any additional operations recorded after the last full commit.

## TLV header: ext4_fc_tl

Every TLV entry begins with a 4-byte header:

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__le16` | fc_tag | Tag type identifying the operation. See [Tag types](#tag-types). |
| 0x2 | `__le16` | fc_len | Length of the value payload in bytes (does not include the 4-byte TLV header itself). |

**Little-endian exception:** The TLV header and all fast commit payload structures use
**little-endian** byte order. This is because fast commits are defined by ext4 (which is
little-endian), not by jbd2 (which is big-endian). A parser must switch endianness when
transitioning between the main journal and the fast commit area.

## Tag types

| Tag value | Constant | Payload | Description |
|-----------|----------|---------|-------------|
| 1 | EXT4_FC_TAG_HEAD | `ext4_fc_head` | Transaction boundary. Marks the beginning of a fast commit transaction. Contains the transaction ID. |
| 2 | EXT4_FC_TAG_ADD_RANGE | `ext4_fc_add_range` | Add an extent to a file. Contains an inode number and extent descriptor (logical block, physical block, length). |
| 3 | EXT4_FC_TAG_DEL_RANGE | `ext4_fc_del_range` | Delete a logical block range from a file. Contains an inode number and the logical offset range to remove. |
| 4 | EXT4_FC_TAG_CREAT | `ext4_fc_dentry_info` | Create a new directory entry. Contains the parent inode number, child inode number, and filename. |
| 5 | EXT4_FC_TAG_LINK | `ext4_fc_dentry_info` | Create a hard link. Same payload as CREAT. |
| 6 | EXT4_FC_TAG_UNLINK | `ext4_fc_dentry_info` | Remove a directory entry. Same payload as CREAT. |
| 7 | EXT4_FC_TAG_INODE | (full inode data) | Full inode metadata update. The payload contains the inode number followed by the on-disk inode structure. |
| 8 | EXT4_FC_TAG_PAD | (none) | Padding. Unused bytes filling the remainder of a fast commit block. The parser skips **fc_len** bytes. |
| 9 | EXT4_FC_TAG_TAIL | `ext4_fc_tail` | End of a fast commit transaction. Contains the transaction ID and a CRC32 checksum covering all TLV entries in this transaction. |

## Payload structures

### ext4_fc_head

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__le32` | fc_features | Feature flags (reserved, currently zero). |
| 0x4 | `__le32` | fc_tid | Transaction ID for this fast commit sequence. |

### ext4_fc_add_range

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__le32` | fc_ino | Inode number of the file receiving the extent. |
| 0x4 | varies | fc_ex | Extent descriptor. Contains the logical block offset, physical block address, and length of the added extent. Uses the ext4 on-disk extent format (`ext4_extent`). |

### ext4_fc_del_range

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__le32` | fc_ino | Inode number of the file losing the range. |
| 0x4 | `__le32` | fc_lblk | Starting logical block of the range to delete. |
| 0x8 | `__le32` | fc_len | Number of logical blocks to delete. |

### ext4_fc_dentry_info

Used by EXT4_FC_TAG_CREAT, EXT4_FC_TAG_LINK, and EXT4_FC_TAG_UNLINK:

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__le32` | fc_parent_ino | Parent directory inode number. |
| 0x4 | `__le32` | fc_ino | Child inode number (the file being created, linked, or unlinked). |
| 0x8 | `__u8` | fc_dname_len | Length of the filename in bytes. |
| 0x9 | `__u8[fc_dname_len]` | fc_dname | Filename bytes (not null-terminated). |

### ext4_fc_tail

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__le32` | fc_tid | Transaction ID. Must match the **fc_tid** from the corresponding EXT4_FC_TAG_HEAD. |
| 0x4 | `__le32` | fc_crc | CRC32 checksum of all TLV entries in this fast commit transaction, from HEAD through the entry preceding this TAIL. |

## Replay idempotence

Fast commit replay must be **idempotent**: applying the same log twice produces the same
filesystem state. Each operation is designed so that applying it to an already-applied state is a
no-op:

- **ADD_RANGE** on an already-present extent with matching parameters does nothing.
- **DEL_RANGE** on a range that is already absent does nothing.
- **CREAT/LINK** for a directory entry that already exists with the correct inode does nothing.
- **UNLINK** for a directory entry that is already absent does nothing.
- **INODE** overwrites the inode metadata unconditionally (inherently idempotent).

## Fast commit recovery

Fast commit replay occurs **after** full journal recovery:

1. Full journal transactions are replayed first (see
   [02-transactions.md](02-transactions.md)).
2. The fast commit area (last **s_num_fc_blocks** blocks of the journal) is scanned for TLV
   entries.
3. For each fast commit transaction delimited by HEAD and TAIL tags:
   - Verify that the TAIL's **fc_crc** matches the computed CRC32 of the preceding entries.
   - Verify that HEAD and TAIL **fc_tid** values match.
   - Apply each operation in order.
4. If a fast commit transaction is incomplete (missing TAIL tag, CRC mismatch, or fc_tid
   mismatch), discard it and all subsequent fast commit data. The filesystem state from full
   journal recovery stands.

Fast commits are an optimization for runtime performance. A forensic parser benefits from fast
commit data because it provides a finer-grained record of filesystem operations (individual
creates, links, unlinks, and extent changes) compared to the opaque block-level copies in full
transactions.
