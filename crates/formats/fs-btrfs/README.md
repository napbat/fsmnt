# fs-btrfs

`fs-btrfs` is a safe, read-only Btrfs parser. Its default build is `no_std`
with `alloc`; the `std` feature adds zlib, LZO, and Zstandard decompression.
The crate forbids unsafe Rust.

## Validation model

Fixed-width records use typed little-endian layouts with compile-time size
checks. Variable-length records use checked arithmetic and bounded slices.
The parser verifies:

- superblock-mirror identity, checksum, geometry, features, and SYSTEM chunks,
  selecting the newest valid generation across the 64 KiB, 64 MiB, and
  256 GiB mirror locations;
- typed historical root backups, with automatic read-only rollback when the
  live root or chunk tree is corrupt;
- chunk types, profiles, stripe geometry, and non-overlapping logical ranges;
- tree-block checksums, identity, generation, owner, level, key ordering,
  pointers, and packed leaf-item boundaries;
- inode, root, directory, extent, and checksum-item invariants; and
- extent-tree-v2 global-root sets and block-group assignments; and
- data checksums, including per-block-group global checksum roots and retrying
  healthy replicas after checksum failures.

These checks follow the Linux Btrfs tree checker and the documented on-disk
format:

- <https://github.com/torvalds/linux/blob/master/fs/btrfs/tree-checker.c>
- <https://github.com/torvalds/linux/blob/master/fs/btrfs/disk-io.c>
- <https://github.com/torvalds/linux/blob/master/fs/btrfs/volumes.c>
- <https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html>

## Deliberate scope

- A pending fsync tree log is projected over committed filesystem trees,
  including creates, overwrites, holes, truncation, extension, deletion,
  rename, directory authoritative ranges, and logged data checksums.
- Multi-device reads support single, DUP, RAID0, RAID1, RAID1C3, RAID1C4,
  RAID10, RAID5, and RAID6 chunks. Missing members are accepted when the
  chunk profile remains readable; RAID5/6 data is reconstructed from P/Q
  parity, including checksum-driven recovery from silent corruption.
- Read-only seed devices, writable sprouts, and chained seed layers are
  resolved by device UUID even when filesystem-local device IDs overlap.
- Extent-tree-v2 loads every extent, checksum, and free-space global root and
  selects checksums through typed block-group-tree items.
- If live-tree initialization fails, valid embedded backup roots are tried from
  newest to oldest. Recovery can pair a historical filesystem root with either
  the current chunk tree or its matching historical chunk tree.
- RAID-stripe-tree and remap-tree layouts remain rejected through their
  incompatibility feature bits.

`read_file_range` performs bounded sparse, uncompressed, and compressed reads.
The compatibility `read_file` helper still returns a complete `Vec`; mount
backends use the bounded interface instead.

## Verification

Run the crate in both capability modes and exercise its real generated
fixtures:

```powershell
cargo check -p fs-btrfs --no-default-features
cargo test -p fs-btrfs --all-features
```

The structure-aware libFuzzer target covers raw and canonical mutations of
superblocks, SYSTEM chunks, ordinary chunks, tree blocks, metadata items,
file extents, and all supported compression decoders:

```powershell
.\scripts\run_btrfs_fuzz.ps1 -Runs 100000 -MaxLength 131072
cargo bench -p fs-btrfs --features fuzzing --bench parser
```
