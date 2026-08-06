# fs-apfs test fixtures

APFS fixture images for the `fs-apfs` integration tests
(`crates/fs-apfs/tests/fixture.rs`).

The images are **not committed**. They are reproducible from
`gen-fixtures.sh`, and the integration tests skip any fixture that is
absent — a checkout without them still builds and passes `cargo test`.

## Generating the fixtures

APFS images cannot be created without OS tooling. Two routes:

### Linux

```sh
sudo crates/fs-apfs/testdata/gen-fixtures.sh
```

Requires `mkapfs` (from [`linux-apfs/apfsprogs`]) to create the images and
the `apfs` kernel module (from [`linux-apfs/linux-apfs-rw`]) to mount and
populate them. Root is needed only for the loopback mount.

### macOS

```sh
hdiutil create -size 32m -fs APFS -volname Test -layout NONE apfs
diskutil image attach apfs.dmg            # mount, copy files in, detach
```

then rename the resulting raw image to `apfs.img`.

`apfs-multi-volume.img` can **only** be produced on macOS: `mkapfs`
writes a single volume per container, so a second volume must be added
with `diskutil apfs addVolume <container> APFS Data`. Its integration
test skips when the fixture is absent, so the Linux route still leaves a
green build.

[`linux-apfs/apfsprogs`]: https://github.com/linux-apfs/apfsprogs
[`linux-apfs/linux-apfs-rw`]: https://github.com/linux-apfs/linux-apfs-rw

## Fixtures and the APFS features they exercise

| Image | Features |
|-------|----------|
| `apfs.img` | Plain case-sensitive single-volume container; a directory, a regular file, a large multi-extent file, a symlink, and a user xattr. |
| `apfs-case-insensitive.img` | Case-insensitive + normalization-insensitive volume — hashed directory keys. |
| `apfs-multi-volume.img` | A container with two volumes, exercising volume enumeration and selection. macOS-only — see above. |

When adding a fixture, give its files distinctive per-block byte patterns
so a mis-mapped extent is caught by content comparison rather than hidden
by coincidental zeros.

## Crash-repro fixtures

A reproducer for any APFS fuzzer finding (see `fuzz/fuzz_targets/apfs/`)
should be committed here as `crash-<target>-<id>.bin` and covered by a
regression test, so a fixed crash never silently returns.
