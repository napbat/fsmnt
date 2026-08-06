<!-- Journaling -->
<!-- Ext4-side journal linkage: feature flags, superblock fields, journal modes, orphan handling, and recovery. -->

# Journaling

The journal provides crash consistency by writing metadata (and optionally data) changes to a
log before committing them to their final locations. Ext4 references the journal through
superblock fields and feature flags. This file documents the ext4 side of the journal interface.

Raw transaction formats (descriptor blocks, data blocks, commit blocks, revocation blocks, fast
commits) are documented in the jbd2 subtree:
- [../jbd2/02-transactions.md](../jbd2/02-transactions.md) for transaction structure
- [../jbd2/04-fast-commits.md](../jbd2/04-fast-commits.md) for fast commit TLV format

## Feature Flag

`COMPAT_HAS_JOURNAL` (`0x4`) in **s_feature_compat**. When set, the filesystem has an
associated journal. When clear, the filesystem operates in ext2-style mode with no journal and
no crash consistency guarantees beyond fsck.

See [02-feature-flags.md](02-feature-flags.md) for the complete feature flag reference.

## Internal Journal

Most ext4 filesystems use an internal journal stored as a regular file within the filesystem
itself.

| Superblock field | Offset | Description |
|-----------------|--------|-------------|
| **s_journal_inum** | `0xE0` | Inode number of the journal file (typically inode 8) |

The journal inode is special inode 8 ("Journal inode") as listed in
[04-inodes.md](04-inodes.md). Its data blocks contain the jbd2 log. The journal inode's block
mapping (direct blocks, extent tree, or indirect blocks) locates the journal data on disk.

## External Journal

When the journal resides on a separate block device, two superblock fields identify it:

| Superblock field | Offset | Description |
|-----------------|--------|-------------|
| **s_journal_dev** | `0xE4` | Device number of the external journal block device |
| **s_journal_uuid** | `0xD0` | UUID used to locate the external journal superblock |

An external journal device has its own ext4 superblock at byte offset 1024 (containing the
journal UUID), followed by the jbd2 journal superblock at block 1. The filesystem matches
**s_journal_uuid** against the external device's UUID to bind the correct journal.

See [../jbd2/00-introduction.md](../jbd2/00-introduction.md) for internal vs external journal
layout.

## Journal Inode Backup

The superblock stores a backup of the journal inode's block mapping for recovery scenarios
where the inode table itself is damaged.

| Superblock field | Offset | Size | Description |
|-----------------|--------|------|-------------|
| **s_jnl_backup_type** | `0x108` | 4 bytes | Backup type (1 = block mapping backup stored in s_jnl_blocks) |
| **s_jnl_blocks[17]** | `0x10C` | 68 bytes | Backup of journal inode block mapping |

When **s_jnl_backup_type** = 1, the 17-element array **s_jnl_blocks** contains a copy of the
journal inode's block mapping fields. The element mapping (from kernel `fs/ext4/ext4.h`):

| Element | Content |
|---------|---------|
| `s_jnl_blocks[0]` .. `s_jnl_blocks[11]` | Direct block pointers (`i_block[0]`..`i_block[11]`) |
| `s_jnl_blocks[12]` | Single indirect block pointer (`i_block[12]`) |
| `s_jnl_blocks[13]` | Double indirect block pointer (`i_block[13]`) |
| `s_jnl_blocks[14]` | Triple indirect block pointer (`i_block[14]`) |
| `s_jnl_blocks[15]` | Journal inode **i_size_high** (high 32 bits) |
| `s_jnl_blocks[16]` | Journal inode **i_size** (low 32 bits) |

Elements 0 through 14 mirror the 15-element **i_block** array from the journal inode. Elements
15 and 16 store the journal file size so the journal extent can be located without reading the
inode table.

When the journal uses extents (EXTENTS_FL set on the journal inode), the **i_block** array
contains an extent tree header and root entries rather than direct block pointers, and the
backup stores those bytes verbatim.

## Journal Modes

The default journal mode is stored in **s_default_mount_opts** (offset `0x100` in the
superblock). Three mode flags control data journaling behavior:

| Flag | Value | Name | Description |
|------|-------|------|-------------|
| JMODE_DATA | `0x20` | Journal data mode | All file data and metadata written to journal before commit. Safest but slowest. |
| JMODE_ORDERED | `0x40` | Ordered mode | File data flushed to disk before associated metadata journal commit. Default for most systems. |
| JMODE_WBACK | `0x60` | Writeback mode | No data ordering guarantees. Metadata journaled; data may be written in any order. Fastest but risk of stale data after crash. |

These flags are stored in **s_default_mount_opts** and can be overridden by mount-time options
(`data=journal`, `data=ordered`, `data=writeback`). A forensic parser examining
**s_default_mount_opts** sees the filesystem's configured default, not necessarily the mode
active at crash time.

## Orphan Handling

Orphaned inodes are files or directories that have been unlinked (or truncated) but were still
open at the time of a crash. On recovery, these pending operations must be completed. Two
mechanisms exist:

### Legacy Orphan List

The original orphan tracking mechanism uses a singly-linked list threaded through inode fields:

| Field | Location | Description |
|-------|----------|-------------|
| **s_last_orphan** | Superblock offset `0xE8` | Inode number of the most recently orphaned inode (list head) |
| **i_dtime** | Inode offset `0x14` | Next orphan inode number in the chain (repurposed as a link pointer while on the orphan list) |

The kernel adds orphaned inodes by writing the current **s_last_orphan** value into the new
orphan's **i_dtime** field, then updating **s_last_orphan** to point to the new orphan. This
forms a singly-linked list:

```
s_last_orphan -> inode_A.i_dtime -> inode_B.i_dtime -> 0 (end)
```

On recovery, the kernel (or fsck) walks from **s_last_orphan** through **i_dtime** links,
completing deletions (if `i_links_count == 0`) or truncations (if `i_links_count > 0`).

The legacy orphan list requires a superblock write for every orphan addition, which serializes
unlink operations. This is the motivation for the orphan file mechanism.

See [04-inodes.md](04-inodes.md) for **i_dtime** and [08-timestamps.md](08-timestamps.md) for
how **i_dtime** is repurposed.

### Orphan File

A newer mechanism (Linux 5.15+) uses a dedicated inode to store orphan records without
modifying the superblock on every unlink.

| Feature flag | Value | Description |
|-------------|-------|-------------|
| `COMPAT_ORPHAN_FILE` | `0x1000` | Filesystem has an orphan file |
| `RO_COMPAT_ORPHAN_PRESENT` | `0x10000` | Orphan file may contain live entries requiring recovery |

| Superblock field | Offset | Description |
|-----------------|--------|-------------|
| **s_orphan_file_inum** | `0x280` | Inode number of the orphan file |

The orphan file's data blocks contain arrays of orphaned inode numbers (`__le32` entries). Each
block is structured as:

| Region | Content |
|--------|---------|
| Body | Array of `__le32` inode numbers (0 = unused slot) |
| Tail (last 8 bytes) | Magic (`0x0B10CA04`, 4 bytes) + per-block checksum (4 bytes) |

The magic value `0x0B10CA04` marks a valid orphan file block tail. The per-block checksum is
CRC32C of the checksum seed + block contents (with checksum zeroed).

**`RO_COMPAT_ORPHAN_PRESENT`** is set when the orphan file may contain live (non-zero) inode
entries. This flag tells a recovery tool that the orphan file must be scanned. It is cleared
after successful orphan processing. A forensic parser seeing this flag knows that orphaned
inodes may exist and the filesystem was not cleanly unmounted.

The orphan file eliminates the superblock bottleneck — multiple CPUs can add orphans to
different blocks concurrently.

## Journal Recovery

| Feature flag | Value | Description |
|-------------|-------|-------------|
| `INCOMPAT_RECOVER` | `0x4` | Journal contains uncommitted transactions that need replay |

When **INCOMPAT_RECOVER** is set in **s_feature_incompat**, the journal log contains
transactions that have not been checkpointed to their final filesystem locations. The kernel
sets this flag when the journal is opened for writing and clears it after successful recovery.

A forensic parser encountering this flag knows:
1. The filesystem may be in an inconsistent state.
2. Metadata on disk may not reflect the most recent committed transactions.
3. The journal must be replayed to reconstruct the true filesystem state.

Recovery walks the journal from **s_start** (in the jbd2 superblock) with sequence number
**s_sequence**, replaying committed transactions and honoring revocation records. See
[../jbd2/02-transactions.md](../jbd2/02-transactions.md) for replay mechanics and
[../jbd2/03-revocation.md](../jbd2/03-revocation.md) for revocation semantics.

## Relationship to jbd2

Ext4 owns the decision of what to journal and when. jbd2 owns the transaction format, log
layout, and replay logic. The boundary is:

| Responsibility | Owner |
|---------------|-------|
| Feature flags for journal presence | ext4 (`COMPAT_HAS_JOURNAL`) |
| Journal inode and device fields | ext4 (superblock fields) |
| Journal modes (data/ordered/writeback) | ext4 (mount options) |
| Orphan tracking | ext4 (superblock + inode fields) |
| Transaction format (descriptor/data/commit/revoke) | jbd2 ([../jbd2/02-transactions.md](../jbd2/02-transactions.md)) |
| Fast commit TLV format | jbd2/ext4 ([../jbd2/04-fast-commits.md](../jbd2/04-fast-commits.md)) |
| Journal superblock and log layout | jbd2 ([../jbd2/01-superblock.md](../jbd2/01-superblock.md)) |
| Journal checksumming | jbd2 ([../jbd2/05-checksumming.md](../jbd2/05-checksumming.md)) |
