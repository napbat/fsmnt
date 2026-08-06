<!-- Forensic Artifacts -->
<!-- Synthesis: forensic recovery patterns and analysis techniques spanning multiple ext4/jbd2 structures. -->

# Forensic Artifacts

This file describes forensic recovery patterns and analysis techniques that span multiple
ext4/jbd2 structures. It references the relevant structure documentation rather than
reproducing field layouts. Each section links to the file(s) containing the underlying
on-disk format details.

## Version Detection

Determining whether a filesystem is ext2, ext3, or ext4 is the first step in forensic
analysis. There is no explicit version number field. Version detection is driven entirely by
feature flags in the superblock.

**Procedure:**

1. Read the superblock at byte offset 1024. Verify the magic number `0xEF53` at offset `0x38`.
2. Check **s_rev_level** (offset `0x4C`):
   - `0` = ext2 revision 0. Fixed 128-byte inodes, no feature flags. No further detection needed.
   - `1` = dynamic revision. Proceed to feature flag inspection.
3. Read **s_feature_compat** (`0x5C`), **s_feature_incompat** (`0x60`), **s_feature_ro_compat** (`0x64`).

**Decision tree:**

| Condition | Filesystem |
|-----------|-----------|
| No feature flags (rev 0) | ext2 (original) |
| `COMPAT_HAS_JOURNAL` (`0x4`) set, no `INCOMPAT_EXTENTS` | ext3 |
| `INCOMPAT_EXTENTS` (`0x40`) set | ext4 |
| `INCOMPAT_64BIT` (`0x2`) set | ext4 with 64-bit addressing |
| `RO_COMPAT_METADATA_CSUM` (`0x400`) set | ext4 (modern, checksummed) |
| `INCOMPAT_INLINE_DATA` (`0x8000`) set | ext4 (inline data support) |

A filesystem with `COMPAT_HAS_JOURNAL` but without `INCOMPAT_EXTENTS` is functionally ext3.
A filesystem without `COMPAT_HAS_JOURNAL` and without extent/64-bit flags is functionally
ext2 (revision 1 with dynamic inodes).

See [02-feature-flags.md](02-feature-flags.md) for complete flag tables and the version
detection guide.

## Deleted File Recovery -- Orphan Tracking

When a file is deleted, its inode may remain on disk with recoverable metadata and data
pointers until the inode and data blocks are reallocated. Two orphan tracking mechanisms
provide structured access to recently deleted files.

### Legacy Orphan List

Walk the linked list starting at **s_last_orphan** (superblock offset `0xE8`). Each orphan
inode's **i_dtime** field (offset `0x14`) serves as the next pointer in the chain. The list
terminates at inode number 0.

For each orphan inode:
- **i_links_count** == 0: the file was deleted (unlinked). Complete the deletion.
- **i_links_count** > 0: the file was being truncated. Complete the truncation.

Deleted inodes with **i_dtime** != 0 and **i_links_count** == 0 are candidates for recovery.
Their block maps or extent trees may still point to data blocks, provided those blocks have not
been reallocated to other files.

See [04-inodes.md](04-inodes.md) for inode fields and special inode numbers.
See [10-journaling.md](10-journaling.md#legacy-orphan-list) for the orphan list threading
mechanism.

### Orphan File

On filesystems with `COMPAT_ORPHAN_FILE` (`0x1000`), orphan inode numbers are stored in a
dedicated file referenced by **s_orphan_file_inum**. When `RO_COMPAT_ORPHAN_PRESENT`
(`0x10000`) is set, the orphan file may contain live (non-zero) entries that need processing.

A forensic tool should scan the orphan file's data blocks for non-zero inode numbers. Each
non-zero entry identifies an orphan inode that was pending deletion or truncation at the time
of the crash.

See [10-journaling.md](10-journaling.md#orphan-file) for orphan file format and block
structure.

## Deleted File Recovery -- Journal Replay

The journal contains verbatim copies of metadata blocks from before and after each transaction.
Descriptor block tags map journal data blocks to their filesystem destination block numbers.
By walking old journal transactions, a forensic tool can recover previous states of:

- **Inodes**: prior values of size, timestamps, block pointers, and link counts
- **Directory entries**: filenames that existed before deletion
- **Extent trees**: previous data block mappings
- **Extended attributes**: prior security labels and metadata

Replaying journal transactions backward in time reconstructs the filesystem state at
progressively earlier points. The forensic window is limited by journal size — once the
circular log wraps, older transactions are overwritten.

See [../jbd2/02-transactions.md](../jbd2/02-transactions.md) for descriptor block and data
block formats.

## Deleted File Recovery -- Unallocated Scanning

Block and inode bitmaps identify which blocks and inodes are currently free.

**Block-level carving**: free blocks (bitmap bit = 0) may contain remnants of deleted files.
Traditional file carving techniques (signature-based scanning) can recover file fragments from
unallocated block regions.

**Inode-level scanning**: free inodes (inode bitmap bit = 0) may still contain stale metadata
from their previous allocation. An inode with **i_dtime** set and valid-looking fields (mode,
size, block pointers) is a candidate for recovery analysis.

**Lazy initialization**: when `bg_flags` includes `BLOCK_UNINIT` or `INODE_UNINIT`, the
corresponding bitmap/inode table for that block group was never initialized. Uninitialized
regions contain no recoverable user data.

See [03-block-groups.md](03-block-groups.md) for bitmap layout, group descriptor flags, and
lazy initialization.

## Timestamp Analysis

Inode timestamps enable forensic timeline reconstruction:

| Timestamp | Field | Resolution | Description |
|-----------|-------|-----------|-------------|
| Access time | **i_atime** + **i_atime_extra** | Nanosecond (ext4) or second (ext2/ext3) | Last file access |
| Change time | **i_ctime** + **i_ctime_extra** | Nanosecond (ext4) or second (ext2/ext3) | Last inode metadata change |
| Modification time | **i_mtime** + **i_mtime_extra** | Nanosecond (ext4) or second (ext2/ext3) | Last file data modification |
| Creation time | **i_crtime** + **i_crtime_extra** | Nanosecond (ext4 only) | Original file creation |
| Deletion time | **i_dtime** | Second only (no extra field) | When the file was deleted |

**Anomaly detection:**
- **crtime > mtime**: creation time after modification time suggests timestamp manipulation or
  file copy (the copy preserves mtime but gets a new crtime).
- **Inconsistent nanosecond fields**: zero nanoseconds on ext4 inodes that should have them
  may indicate tool-generated timestamps.
- **i_dtime set but i_links_count > 0**: inode is on the orphan list (pending truncation), not
  actually deleted.

**Superblock timestamps** provide system-level timeline context:

| Field | Description |
|-------|-------------|
| **s_mtime** | Last mount time |
| **s_wtime** | Last write time |
| **s_lastcheck** | Last fsck time |
| **s_mkfs_time** | Filesystem creation time |
| **s_first_error_time** | Time of first detected error |
| **s_last_error_time** | Time of most recent error |

All superblock timestamps are 32-bit seconds with no extended fields, subject to Y2038
overflow.

See [08-timestamps.md](08-timestamps.md) for timestamp encoding/decoding rules and the
extended timestamp format.

## Slack Space

Slack space — regions of allocated storage that are not actively used by file data — is a
common source of forensic artifacts.

### Within-Block Slack

When a file's size is not a multiple of the block size, the final block contains slack between
the end of file data and the end of the block. For example, a 5000-byte file on a 4096-byte
block filesystem occupies two blocks, with 3192 bytes of slack in the second block. This slack
may contain remnants of previously deleted files if the block was reused.

### Within-Entry Slack

Directory entries use **rec_len** to specify the total entry size, which is always a multiple
of 4 bytes. The gap between the actual entry content (`8 + name_len` bytes, rounded up) and
**rec_len** is slack space. Deleted entries are absorbed into the preceding entry's
**rec_len**, leaving the deleted entry's bytes intact in the slack region. This is the
primary mechanism for recovering deleted filenames from directory blocks.

See [06-directories.md](06-directories.md) for directory entry packing and deletion mechanics.

### Within-Inode Slack

Extended inodes (typically 256 bytes) may have unused space between the end of active fields
and the inode boundary. Specifically:

- Between the end of extended inode fields (`128 + i_extra_isize`) and the start of in-inode
  xattr space: if no ibody xattrs exist, this region is slack.
- Between the end of in-inode xattr entries and the inode size boundary.

This slack can contain remnants of previous xattr values or prior inode field states.

## Journal as Forensic Timeline

Journal commit blocks contain timestamps (**h_commit_sec**, **h_commit_nsec**) that record
when each transaction was committed. These timestamps provide a partial ordering of filesystem
changes that is independent of file-level timestamps (which can be manipulated).

**Forensic applications:**
- Correlate journal commit times with inode timestamp changes to detect backdating or
  timestamp tampering.
- Reconstruct the sequence of filesystem modifications leading up to a crash or incident.
- Identify the approximate time window during which a deleted file's metadata was overwritten.

**Fast commits** (when `INCOMPAT_FAST_COMMIT` is set on the journal) provide finer-grained
operation records. Each fast commit TLV entry records a specific operation (file creation,
extent addition, unlink) that can be correlated with the enclosing transaction's commit
timestamp.

**Journal wrap-around**: the journal is a fixed-size circular buffer. Older transactions are
overwritten as new ones are appended. The forensic window depends on journal size (typically
128 MiB) and filesystem write activity. Heavy write workloads may overwrite relevant
transactions within minutes.

See [../jbd2/02-transactions.md](../jbd2/02-transactions.md) for commit block timestamps.
See [../jbd2/04-fast-commits.md](../jbd2/04-fast-commits.md) for fast commit TLV format.

## Extended Attribute Artifacts

Extended attributes store security-relevant metadata that persists across normal file
operations:

| Xattr namespace | Forensic relevance |
|-----------------|-------------------|
| `security.selinux` | SELinux security context (mandatory access control label) |
| `security.fscrypt` | Encryption policy reference (algorithm, key identifier) |
| `security.capability` | File capabilities (privilege escalation indicator) |
| `system.posix_acl_access` | POSIX access control list |
| `system.posix_acl_default` | Default ACL for new files in a directory |
| `user.*` | Application-defined metadata |

Xattrs stored in external blocks (referenced by **i_file_acl**) may persist after file
deletion if the xattr block is shared (refcount > 1) with other inodes or has not been
reallocated. In-inode xattrs are lost when the inode is overwritten.

EA_INODE entries (large xattr values stored in dedicated inodes) have additional forensic
artifacts: **i_atime** stores the value checksum, and **i_ctime** + **i_version** form a
64-bit reference count.

See [07-extended-attributes.md](07-extended-attributes.md) for xattr storage formats,
name indices, and EA_INODE semantics.
