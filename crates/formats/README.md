# formats

Home of filesystem-format parser crates (NTFS, FAT32, ext, APFS, …).

Each crate in this directory parses one on-disk format and exposes it as a
mountable filesystem by implementing `fsmnt_core::TargetFilesystem`, wired
into device mounting via a `fsmnt_device::FilesystemDriver` adapter.

Crates here are workspace members (`crates/formats/*`) and follow the same
rules as every other member: workspace-inherited lints and dependencies,
standard Cargo layout, no file over 1000 lines.
