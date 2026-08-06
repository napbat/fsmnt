# ext2/ext3/ext4 Filesystem Reference

Reference documentation for the ext filesystem family on-disk format, synthesized from the [ext4 wiki Disk Layout](https://archive.kernel.org/oldwiki/ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout.html), [kernel.org ext4 docs](https://docs.kernel.org/filesystems/ext4/), Linux kernel headers (`fs/ext4/ext4.h`, `include/linux/jbd2.h`), and e2fsprogs source. Where sources conflict, kernel headers are authoritative.

## Subtrees

| Directory | What to find here |
|-----------|-------------------|
| `ext4-disk-layout/` | ext4-owned on-disk structures: superblock, block groups, inodes, data mapping, directories, extended attributes, timestamps, checksums, features. Also covers how ext4 references the journal (feature flags, inode/device fields, orphan handling). |
| `jbd2/` | Journal-owned on-disk transaction formats: superblock, descriptor/data/commit/revocation blocks, fast commits, checksum evolution. All jbd2 structures are **big-endian** (opposite of ext4). |

**Boundary rule:** `ext4-disk-layout/` owns ext4 structures and journal linkage. `jbd2/` owns transaction formats. Cross-links between subtrees, not duplicated definitions.

## Quick Start

1. Start with `ext4-disk-layout/00-introduction.md` for terminology, endianness, block sizing, and version history
2. Read `ext4-disk-layout/01-superblock.md` + `ext4-disk-layout/02-feature-flags.md` for version detection — feature flags are the parser's first decision point
3. For journal parsing, start with `jbd2/00-introduction.md`, then `jbd2/01-superblock.md`
