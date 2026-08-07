# fs-btrfs

`fs-btrfs` is a safe, read-only Btrfs parser. Its default build is `no_std`
with `alloc`; the `std` feature adds zlib, LZO, and Zstandard decompression.
The crate forbids unsafe Rust.

## Validation model

Fixed-width records use typed little-endian layouts with compile-time size
checks. Variable-length records use checked arithmetic and bounded slices.
The parser verifies:

- primary-superblock identity, checksum, geometry, features, and SYSTEM chunks;
- chunk types, profiles, stripe geometry, and non-overlapping logical ranges;
- tree-block checksums, identity, generation, owner, level, key ordering,
  pointers, and packed leaf-item boundaries;
- inode, root, directory, extent, and checksum-item invariants; and
- data checksums, including retrying healthy replicas after checksum failures.

These checks follow the Linux Btrfs tree checker and the documented on-disk
format:

- <https://github.com/torvalds/linux/blob/master/fs/btrfs/tree-checker.c>
- <https://github.com/torvalds/linux/blob/master/fs/btrfs/disk-io.c>
- <https://github.com/torvalds/linux/blob/master/fs/btrfs/volumes.c>
- <https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html>

## Deliberate scope

- Only committed trees are exposed; the write-ahead log is not replayed.
- Opening currently reads the primary superblock and does not recover from a
  backup superblock mirror.
- Multi-device filesystems require every declared member. Seed-device chains
  and degraded RAID5/6 parity reconstruction are not implemented.
- RAID5/6 data stripes are mapped directly when every member is healthy.
- Extent-tree-v2, RAID-stripe-tree, and remap-tree layouts are rejected through
  their incompatibility feature bits.
- `read_file` returns a complete `Vec`, so callers should inspect inode size
  before requesting files that are too large for their memory budget.

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
