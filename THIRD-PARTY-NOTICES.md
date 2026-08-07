# Third-party notices

`fsmnt` is licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
Some components under `crates/formats/` derive from third-party projects. Those
portions remain under the copyright of their original authors, reproduced here
as their licenses require.

## fs-ntfs

`crates/formats/fs-ntfs` derives from the **`ntfs`** crate by Colin Finck.

- Upstream: <https://github.com/ColinFinck/ntfs>
- Upstream license: `MIT OR Apache-2.0` — the same dual license this workspace
  uses, so the terms carry over unchanged.

```
Copyright 2021 Colin Finck <colin@reactos.org>
```

The vendored copy has been modified for this workspace: it parses through the
first-party `fsmnt-parser-core` reader and error traits rather than upstream's
own I/O abstraction, and follows this repository's lint, documentation, and
file-length rules.

## nt-compression

`crates/formats/nt-compression/tests/lzxpress_compat.rs` uses cross-compatibility
test vectors from **`rust-lzxpress`**.

- Upstream: <https://github.com/MagnetForensics/rust-lzxpress>
- Upstream license: MIT

```
Copyright (c) 2021 Comae Technologies
```

Only the test vectors are reused; the LZNT1, XPRESS, XPRESS Huffman, LZX,
LZX CAB, and LZXD decoders in this crate are independent implementations.

## Format documentation

The reference documentation under `crates/formats/*/docs/` describes on-disk
formats specified or documented by third parties. It is derived from published
specifications and public source, cited inline in each document — notably the
Linux kernel (`fs/btrfs`, `fs/ext4`) for Btrfs and ext, Apple's *Apple File
System Reference* for APFS, and Microsoft's open specifications (MS-FSCC,
MS-EFSR, MS-PATCH) for NTFS. These describe formats; they are not code from
those projects.

## Dependencies

Crates consumed from crates.io keep their own licenses, which are not
reproduced here. Generate a complete dependency-license report with
[`cargo-about`](https://github.com/EmbarkStudios/cargo-about) or audit them
with [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny):

```sh
cargo deny check licenses
```
