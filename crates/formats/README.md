# formats

Home of filesystem-format parser crates (NTFS, FAT32, ext, APFS, …).

Each crate in this directory parses one on-disk format and exposes a portable
parser API. The parsers depend on the first-party, `no_std`-capable
`fsmnt-parser-core` foundation; they do not depend on the std-based mount
interfaces.

Mount integration lives in `fsmnt-drivers`, whose adapters implement
`fsmnt_core::TargetFilesystem` and `fsmnt_device::FilesystemDriver`.

Crates here are workspace members (`crates/formats/*`) and follow the same
rules as every other member: workspace-inherited lints and dependencies,
standard Cargo layout, no file over 1000 lines.
