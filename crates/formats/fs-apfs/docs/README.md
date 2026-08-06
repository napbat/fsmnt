# APFS Filesystem Reference

Reference documentation for the Apple File System (APFS) on-disk format, used to
build the `no_std`-compatible `fs-apfs` parser crate. Follows the same pattern as
the NTFS reference docs (`crates/fs-ntfs/docs/`) and the ext docs
(`crates/fs-ext/docs/`).

## Contents

| Path | What to find here |
|------|-------------------|
| `apfs-reference/` | The official **Apple File System Reference** (Apple Inc., 2020-06-22), split into one Markdown file per chapter. The authoritative on-disk structure layouts. See `apfs-reference/README.md`. |
| `third-party/` | Vendored community documentation — currently libyal's *Analysis of APFS* (GNU FDL). |
| `references.md` | Annotated index of all sources, official and community, ranked by usefulness for the parser. |

## Quick Start

1. Read `apfs-reference/00-introduction.md` for the layered design — the
   container layer vs. the file-system layer, and physical/ephemeral/virtual
   objects. APFS is fundamentally different from NTFS, FAT, and ext: it is a
   copy-on-write, B-tree, multi-volume container format.
2. Read `apfs-reference/04-container.md` then `apfs-reference/06-volumes.md` —
   mounting walks the container superblock to the volume superblocks.
3. Read `apfs-reference/13-b-trees.md` — every file-system record lives in a
   B-tree, so B-tree traversal is the parser's core primitive.
4. Consult `references.md` whenever the official spec is ambiguous; the
   community sources document observed behavior the spec leaves implicit.
