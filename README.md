# fsmnt

[![CI](https://github.com/napbat/fsmnt/actions/workflows/ci.yml/badge.svg)](https://github.com/napbat/fsmnt/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Cross-platform **read-only** virtual mounting for filesystem images and block
devices. `fsmnt` parses on-disk filesystems in pure Rust and presents them as
a browsable volume, so files can be inspected and copied with ordinary OS
tools — no kernel driver for the guest filesystem required, and nothing is
ever written back to the source.

| Platform      | Mount backend | Mount target              |
|---------------|---------------|---------------------------|
| Linux / macOS | FUSE          | directory mountpoint      |
| Windows       | Dokan         | drive letter or directory |

## Supported filesystems

| Filesystem   | Notes                                                            |
|--------------|------------------------------------------------------------------|
| NTFS         | NTFS 3.x, as used from Windows 2000 through Windows 11           |
| FAT12/16/32  |                                                                  |
| exFAT        |                                                                  |
| ext2/3/4     | optional fscrypt decryption and fs-verity; journal and orphan replay applied as overlays, never to the source |
| APFS         | containers with multiple volumes, selectable by name, role, or index |
| Btrfs        | subvolumes, single/DUP/RAID0/1/1C3/1C4/10/5/6 profiles, zlib/LZO/Zstd compression, seed devices |
| BitLocker    | unlocks to the NTFS volume inside (recovery password or `.BEK`)  |

Partition tables (GPT and MBR) and bare unpartitioned filesystems are both
handled, and filesystem type is auto-detected from the boot sector.

## Prerequisites

- **Linux** — a FUSE implementation (`fuse3` and its user-space tools).
- **macOS** — [macFUSE](https://macfuse.io/).
- **Windows** — [Dokan](https://dokan-dev.github.io/).

Reading raw block devices needs privileges. `fsmnt` first tries direct access
and, when that is denied, obtains a read-only handle from the elevated
`fsmnt-proxy-server` helper — start it with `sudo fsmnt-proxy-server` (Unix)
or as Administrator (Windows) and normal user-level commands keep working.

## CLI

```sh
cargo build --release        # binary at target/release/fsmnt
```

### Inspect a machine's disks

```sh
fsmnt drives                 # list physical drives with size, bus, and access state
fsmnt partitions 0           # list partitions on drive 0, with detected filesystem
```

Drive IDs are what `fsmnt drives` prints: `0` on Windows, `sda` on Linux,
`disk2` on macOS.

### Mount a partition from a device

```sh
fsmnt mount-device 0 Z: --partition 1
fsmnt mount-device sda /mnt/evidence --partition 1
```

By default this opens the operating system's logical view of the partition,
which means an OS-unlocked encrypted volume can be read without supplying its
key again. Useful flags:

- `--raw` — bypass logical volumes and read physical partition members
  directly. Members of a multi-device filesystem are discovered across all
  host drives automatically; add ones outside platform enumeration with
  `--member DRIVE:PARTITION` (repeatable).
- `--volume ID` — pick a specific logical volume when automatic selection is
  ambiguous.
- `--fstab [PATH]` — read the guest's `/etc/fstab` (or `PATH`) and compose the
  child mounts it describes into a single namespace.

### Mount an image file

```sh
fsmnt mount-image disk.img Z:
fsmnt mount-image disk.img /mnt/img --offset 1048576
```

The image must start at the filesystem itself; for a full partitioned-disk
image, pass the partition's byte offset with `--offset`.

### Choosing what to expose

`--fs-root SELECTOR` picks which filesystem-owned tree to mount, using one
syntax across formats. Which selectors apply depends on how the format is
organized; an unsupported one is rejected with an error rather than ignored.

| Selector       | Meaning                                  | Accepted by  |
|----------------|------------------------------------------|--------------|
| `default`      | the filesystem's own default root        | all          |
| `top-level`    | the topmost tree, above any default      | Btrfs        |
| `path:PATH`    | by path, e.g. `path:root/snapshot`       | Btrfs        |
| `id:NUMBER`    | by filesystem-assigned id (subvolume id) | Btrfs        |
| `index:NUMBER` | by position in the container             | APFS         |
| `name:NAME`    | by name, e.g. `name:Macintosh HD - Data` | APFS         |
| `role:ROLE`    | by volume role, e.g. `role:data`         | APFS         |

The single-volume formats (NTFS, FAT, exFAT, ext, BitLocker) take `default`
only.

### BitLocker

```sh
fsmnt mount-image bde.img Z: --recovery-password 123456-...-654321
fsmnt mount-device 0 Z: --partition 2 --bek-file startup.bek
```

Volumes whose protection is suspended unlock via the clear key with no
credentials.

### Mount a host directory

```sh
fsmnt mount ./export Z: --volname Evidence
```

Exposes an ordinary directory as a read-only volume — handy for testing the
mount backends without a disk image.

All mount commands block until Ctrl+C and unmount on exit.

## Library

```rust
use fsmnt::device::HostDriveId;
use fsmnt::{HostDrives, drivers, mount, open_device_partition};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let drive = HostDriveId::new("0");
    let registry = drivers::default_registry();
    let opened = open_device_partition::<HostDrives>(&drive, 0, &registry)?;
    mount(opened.filesystem, "Z:", "ntfs", "Evidence", opened.size_bytes, || {})?;
    Ok(())
}
```

`fsmnt_core::TargetFilesystem` is the trait a mountable filesystem implements,
and `fsmnt_device::DriverRegistry` is the plug-in point — register your own
`FilesystemDriver` alongside or instead of the built-in ones and hand the
registry to `open_device_partition`.

## Workspace layout

The root package `fsmnt` is the umbrella library plus a thin CLI. Members live
under `crates/`:

| Crate | Role |
|-------|------|
| `fsmnt-core` | `TargetFilesystem` trait, entry/metadata types, host-directory backend, fstab namespaces |
| `fsmnt-parser-core` | `no_std` parser foundation: reader/error traits, boot-sector detection, GPT/MBR |
| `fsmnt-device` | block-device abstraction, disk layout, partition readers, driver registry |
| `fsmnt-device-windows` / `-linux` / `-macos` | per-OS drive enumeration, raw opening, logical-volume resolution |
| `fsmnt-proxy` | privileged handle-passing helper and its elevated server |
| `fsmnt-fuse` / `fsmnt-dokan` | mount backends |
| `fsmnt-drivers` | adapters binding the format parsers to `TargetFilesystem` |
| `fsmnt-testkit` | cross-crate test readers, fixtures, synthetic block devices |
| `fsmnt-fuzz` | libFuzzer targets ([details](crates/fsmnt-fuzz/README.md)) |
| `crates/formats/*` | the format parsers themselves ([details](crates/formats/README.md)) |

The parsers (`fs-ntfs`, `fs-fat`, `fs-exfat`, `fs-ext`, `fs-apfs`, `fs-btrfs`,
`nt-compression`) are `no_std` by default with `std` behind a feature;
`nt-bitlocker` is std-only. Platform crates self-gate and compile to empty
libraries elsewhere, so a workspace-wide build succeeds on every OS.

## Development

The Rust toolchain and `prek` are managed by [mise](https://mise.jdx.dev/);
git hooks by [prek](https://github.com/j178/prek).

```sh
mise install   # pinned Rust toolchain and prek
prek install   # git pre-commit hooks
```

Before considering a change complete:

```sh
cargo fmt --all -- --check
prek run --all-files      # includes the clippy gate
cargo test --workspace
```

Clippy pedantic and `missing_docs` are denied workspace-wide, every dependency
is declared once in `[workspace.dependencies]`, and no `.rs` file may exceed
1000 lines. See [AGENTS.md](AGENTS.md) for the full house rules.

Most test fixtures are generated by each crate's `testdata/gen-fixtures.sh`
and are gitignored, so fixture-backed tests skip themselves when the images
are absent; tracked canonical fixtures and recorded fuzz regressions under
`crashes/` always run.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.

Some parsers under `crates/formats/` derive from third-party projects under the
same dual license — notably `fs-ntfs`, which derives from Colin Finck's
[`ntfs`](https://github.com/ColinFinck/ntfs) crate. Their original copyright
notices are preserved in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work shall be dual licensed as above, without any
additional terms or conditions.
