# APFS Documentation Sources

Apple File System is a proprietary format. Apple publishes a single on-disk
format reference; everything else is community reverse-engineering. This file
indexes the material gathered for the `fs-apfs` parser, ranked by usefulness.

## Primary source

### Apple File System Reference (official)

- **Location:** [`apfs-reference/`](apfs-reference/) — split into per-chapter
  Markdown; original PDF kept as `apfs-reference/Apple-File-System-Reference.pdf`.
- **Revision:** 2020-06-22 (the most recent Apple has published).
- **Coverage:** Authoritative for on-disk structure layouts of every container-
  and file-system-layer type. Light on parsing *algorithms* and edge cases — it
  documents structures, not procedures.
- **Licensing caveat:** Apple's copyright notice authorizes storing the document
  for personal use and printing personal copies; it does **not** grant
  redistribution rights the way Microsoft's Open Specification Promise covers
  the MS-FSCC docs vendored in `fs-ntfs`. Confirm with the project owner before
  this directory is published in a public repository.

## Community reverse-engineering (cross-check the official spec against these)

### libfsapfs — *Analysis of APFS* (Joachim Metz / libyal)

- **Location:** [`third-party/libfsapfs-apfs-format.asciidoc`](third-party/libfsapfs-apfs-format.asciidoc)
  (vendored verbatim) — kept as AsciiDoc; GitHub renders it, and it is licensed
  under the GNU Free Documentation License v1.3 (redistribution permitted).
- **Repo:** <https://github.com/libyal/libfsapfs>
- **Why it matters:** A forensics-oriented format specification that fills gaps
  in Apple's document — observed field values, compression formats, B-tree
  traversal detail, and notes from analyzing real test images. libyal's libraries
  are a long-standing reference point for digital forensics tooling. The most
  useful companion to the official spec for this project.

### apfs-fuse (sgan81)

- **Repo:** <https://github.com/sgan81/apfs-fuse>
- **Why it matters:** The most complete open-source read-only APFS
  implementation (C++). Best reference for *parsing logic* the spec omits:
  LZFSE/LZVN/zlib decompression of compressed files, B-tree walking, encryption
  handling. Read it for "how", read Apple's spec for "what".

### linux-apfs-rw + apfsprogs (linux-apfs)

- **Module:** <https://github.com/linux-apfs/linux-apfs-rw> — Linux kernel module
  (read-write, experimental). Actively maintained.
- **Tools:** <https://github.com/linux-apfs/apfsprogs> — userspace tools,
  notably `apfsck`, a strict consistency checker.
- **Why it matters:** `apfsck` encodes the on-disk *invariants* (what a valid
  filesystem must satisfy). Invaluable for writing validation in a forensic
  parser and for understanding which fields are load-bearing.

### "Decoding the APFS file system" — Hansen & Toolan

- **Citation:** Kurt H. Hansen, Fergus Toolan. *Decoding the APFS file system.*
  Digital Investigation, vol. 22 (2017), pp. 107–132.
- **Why it matters:** Peer-reviewed forensic analysis published before Apple's
  reference existed. Useful for the forensic framing — deleted-file recovery,
  timestamps, snapshot artifacts — and historical context on early APFS.

### Jonathan Levin — newosxbook.com

- **Site:** <http://newosxbook.com> — *\*OS Internals* books and the `fsleuth`
  APFS inspection tool.
- **Why it matters:** Deep coverage of how macOS/iOS actually use APFS (volume
  roles, the system/data volume split, sealed system volumes). Context for the
  *meaning* of structures rather than their layout.

## Notes for the parser

- The split between Apple's spec ("what") and apfs-fuse / libfsapfs ("how and
  observed reality") mirrors the `fs-ext` split between the ext4 disk-layout docs
  and the kernel/e2fsprogs source.
- When sources conflict, prefer Apple's spec for structure layout and the
  community sources for behavior and edge cases — and record the discrepancy in
  code comments.
