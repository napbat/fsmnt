# ext4 Disk Layout Reference

On-disk format documentation for the ext2/ext3/ext4 filesystem family. The parser is ext4-first — ext2 and ext3 are feature subsets detected via superblock flags.

## Files

| File | What to find here |
|------|-------------------|
| `00-introduction.md` | **Glossary**, endianness (little-endian), block/cluster sizing formulas, ext2/ext3/ext4 version history, feature flag mechanism (3 categories), filesystem limits tables (32-bit and 64-bit mode), block group layout diagram |
| `01-superblock.md` | **`ext4_super_block`** — all fields from offset 0x0 through 0x3FC (magic 0xEF53), filesystem state/error behavior, OS creator codes, revision levels, backup locations (sparse_super, sparse_super2), superblock checksum |
| `02-feature-flags.md` | **Feature flag tables** — all compat/incompat/ro_compat flags with hex values and descriptions, default mount options, version detection decision tree (ext2 vs ext3 vs ext4) |
| `03-block-groups.md` | **`ext4_group_desc`** — 32-byte base + 64-byte extension, block group flags, flex_bg, meta_bg, lazy BG initialization, block/inode bitmaps, group descriptor checksum (CRC16 and CRC32C modes) |
| `04-inodes.md` | **`ext4_inode`** — base (0x0–0x7F) and extended (0x80–0x9C) fields, `i_mode` (permissions + file type), `i_flags` (all flags including VERITY_FL, CASEFOLD_FL), OSD1/OSD2 unions, special inode numbers (0–11), inode calculation formula |
| `05-data-mapping.md` | **`i_block[15]`** interpretation — direct/indirect block maps, symbolic links in i_block, extent tree (`ext4_extent_header`/`_idx`/`_extent`/`_tail`, magic 0xF30A), inline data, inline directories |
| `06-directories.md` | **Directory entries** — linear (`ext4_dir_entry`, `ext4_dir_entry_2`), file type codes, encrypted+casefolded hash suffix (`ext4_extended_dir_entry_2`), checksum tail, hash tree (`dx_root`/`dx_node`/`dx_entry`/`dx_tail`), hash algorithms (legacy through SipHash), casefold |
| `07-extended-attributes.md` | **Extended attributes** — in-inode (`ext4_xattr_ibody_header`), block-based (`ext4_xattr_header`), entry format (`ext4_xattr_entry`), name indices, large xattr values (EA_INODE) |
| `08-timestamps.md` | **Timestamps** — base 32-bit (atime/ctime/mtime/dtime), extended fields (nanoseconds + epoch bits), exact kernel decode rules, creation time (crtime), Y2038 handling, superblock timestamps |
| `09-checksumming.md` | **Metadata checksumming** — CRC32C seed computation, per-structure checksum formulas for superblock, group descriptors, bitmaps, inodes, extents, directories, htree, xattrs, MMP |
| `10-journaling.md` | **Ext4-side journal linkage** — HAS_JOURNAL flag, internal/external journal fields, journal inode backup (`s_jnl_blocks`), journal modes, orphan handling (legacy list + orphan file), INCOMPAT_RECOVER. Raw formats in [jbd2/](../jbd2/README.md) |
| `11-allocation-and-protection.md` | **MMP** (`mmp_struct`), **encryption** (fscrypt algorithm codes), **verity** (Merkle tree), **bigalloc** (cluster allocation), **resize inode** (reserved GDT), **quotas** |
| `12-forensic-artifacts.md` | **Forensic synthesis** — version detection, deleted file recovery (orphan tracking, journal replay, unallocated scanning), timestamp analysis, slack space, journal as timeline, xattr artifacts. Links to structure docs, no duplicated layouts. |

## Quick Lookup

| Question | File |
|----------|------|
| How to detect ext2 vs ext3 vs ext4? | `02-feature-flags.md` |
| Superblock magic number and location? | `01-superblock.md` |
| Block group descriptor fields? | `03-block-groups.md` |
| Inode field at offset X? | `04-inodes.md` |
| How does the extent tree work? | `05-data-mapping.md` |
| Block map (direct/indirect) layout? | `05-data-mapping.md` |
| Short symlink storage? | `05-data-mapping.md` |
| Directory entry format? | `06-directories.md` |
| Hash tree (htree) structure? | `06-directories.md` |
| Casefolded directory behavior? | `06-directories.md` |
| Where are xattrs stored? | `07-extended-attributes.md` |
| Timestamp precision and Y2038? | `08-timestamps.md` |
| How is CRC32C computed for inodes? | `09-checksumming.md` |
| How does ext4 reference the journal? | `10-journaling.md` |
| Orphan inode recovery? | `10-journaling.md` |
| Encryption algorithm codes? | `11-allocation-and-protection.md` |
| fs-verity Merkle tree layout? | `11-allocation-and-protection.md` |
| Deleted file recovery techniques? | `12-forensic-artifacts.md` |
| Forensic timeline from journal? | `12-forensic-artifacts.md` |
