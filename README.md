# fsmnt

[![CI](https://github.com/napbat/fsmnt/actions/workflows/ci.yml/badge.svg)](https://github.com/napbat/fsmnt/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Cross-platform **read-only** virtual mounting for raw, Expert Witness Format
(EWF), VHD, and VHDX filesystem images and block devices. `fsmnt` parses
on-disk filesystems in pure Rust and presents them as a browsable volume, so
files can be inspected and copied with ordinary OS tools — no kernel driver
for the guest filesystem required, and nothing is ever written back to the
source.

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

## Read-only guarantees

fsmnt never writes to a source. Images and devices are opened read-only,
and the volume is presented write-protected (Dokan `WRITE_PROTECT`, FUSE
`ro`); the parsers have no write paths at all. Two points that matter for
evidence handling:

- **Journals are never replayed onto the source.** If an ext volume has a
  dirty journal (`INCOMPAT_RECOVER`) or pending orphans
  (`RO_COMPAT_ORPHAN_PRESENT`), the recovery is computed into an
  in-memory overlay and reads are served through it; the image bytes —
  including the free space that deleted-record carving depends on — are
  untouched. This is the "recovered" view; pass `--no-journal-replay` to
  see the on-disk state exactly as it sits (the equivalent of SQLite's
  `immutable=1`), for instance to compare against a carving tool. NTFS,
  FAT, exFAT, APFS and Btrfs have no replay step. BitLocker decrypts in
  memory only.
- **A mount only succeeds when the volume is usable.** Detection refuses
  ext *backup* superblocks (they carry their block-group number, primaries
  carry 0), and the ext driver reads the root directory before it reports
  success — so an offset that merely lands on a superblock copy partway
  into a partition fails with a message naming the backup's group instead
  of mounting an empty volume that could be misread as "no data".

## Prerequisites

- **Linux** — a FUSE implementation (`fuse3` and its user-space tools).
- **macOS** — [macFUSE](https://macfuse.io/).
- **Windows** — [Dokan](https://dokan-dev.github.io/).

Reading raw block devices needs privileges. `fsmnt` first tries direct access
and, when that is denied, obtains a read-only handle from the elevated
`fsmnt-proxy-server` helper — start it with `sudo fsmnt-proxy-server` (Unix)
or as Administrator (Windows) and normal user-level commands keep working.

## Install

### With mise

Every tagged release publishes prebuilt archives to
[GitHub Releases](https://github.com/napbat/fsmnt/releases), so
[mise](https://mise.jdx.dev/) can install `fsmnt` like any other tool through
its `github` backend — no Rust toolchain needed:

```sh
mise use -g github:napbat/fsmnt          # latest release, on PATH everywhere
mise use github:napbat/fsmnt@0.1.0       # pin a version in this project's mise.toml
```

Or declare it in a `mise.toml` and use it from tasks; mise installs it on
first use. The `[tools]` key is the backend spec, `"github:napbat/fsmnt"`,
and the value is the version — or give it a short name with an `[alias]`:

```toml
[alias]
fsmnt = "github:napbat/fsmnt"

[tools]
fsmnt = "latest"          # or "0.1.0"; same as "github:napbat/fsmnt" = "latest"

[tasks.mount-evidence]
description = "Mount the evidence image read-only"
run = "fsmnt mount-image evidence.E01 /mnt/evidence --partition 2"
```

The archive contains both `fsmnt` and `fsmnt-proxy-server`, and both land on
PATH. Archives are built for Linux (x86_64, aarch64; glibc ≥ 2.35), macOS
(Intel and Apple Silicon), and Windows (x86_64), and each carries a signed
build-provenance attestation that mise verifies by default. The
[prerequisites](#prerequisites) above still apply at run time — the mount
backend (FUSE / macFUSE / Dokan) is not bundled.

mise hides releases younger than its
[`minimum_release_age`](https://mise.jdx.dev/configuration/settings.html#minimum_release_age)
(default 24 h) from `latest`, so a just-published version resolves only the
next day. To pick it up immediately, pin the version (`@0.1.0`) or exempt
this tool from the cooldown — per project:

```toml
[tools]
"github:napbat/fsmnt" = { version = "latest", minimum_release_age = "0" }
```

or once, globally: `mise settings add minimum_release_age_excludes github:napbat/fsmnt`.

### From source

```sh
cargo build --release        # binaries at target/release/fsmnt and fsmnt-proxy-server
```

To install straight from git instead (the crate is not on crates.io because
the Windows backend depends on a git revision of `dokan`):

```sh
cargo install --git https://github.com/napbat/fsmnt --locked fsmnt fsmnt-proxy
```

`fsmnt` is the CLI, `fsmnt-proxy` provides `fsmnt-proxy-server`. Building on
macOS needs macFUSE installed (fuser links against it); Linux needs no extra
libraries (the pure-Rust FUSE mount talks to `fusermount3` at run time), and
Windows compiles the bundled Dokan sources with MSVC.

## CLI

### Inspect a machine's disks

```sh
fsmnt drives                 # list physical drives with size, bus, and access state
fsmnt partitions 0           # list partitions on drive 0, with detected filesystem
fsmnt partitions disk.bin    # same listing for a disk image, with GPT names
```

Drive IDs are what `fsmnt drives` prints: `0` on Windows, `sda` on Linux,
`disk2` on macOS. `partitions` takes either a drive ID or the path to a raw,
EWF, VHD, or VHDX image; anything that names an existing file, contains a
path separator, or has a file extension is read as an image.

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
fsmnt partitions disk.bin                     # see what a whole-disk image holds
fsmnt mount-image disk.bin Z: --partition 3
fsmnt mount-image evidence.E01 /mnt/evidence --partition 2
fsmnt mount-image "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\Win11-dev.vhdx" Z: --partition 3
fsmnt mount-image disk.img /mnt/img --offset 1048576
```

Raw images, EWF v1/v2 physical evidence (`.E01`/`.Ex01`), legacy VHD, and VHDX
are detected automatically. Pass the first EWF segment; sibling segments are
discovered and decoded as one logical media stream. Fixed, dynamic, and
differencing VHD/VHDX images are decoded by the repository-native readers;
`.avhd` and `.avhdx` checkpoint parents are resolved from their container
locators. Sparse blocks and VHDX log entries are read or replayed on demand,
without attaching the image or writing to any layer.

A whole-disk image — a typical Hyper-V system disk, an eMMC or SD-card dump —
does not start at a filesystem. List what it contains with
`fsmnt partitions IMAGE`, which prints each partition's ordinal, GPT name,
type, size, byte offset, and detected filesystem, then mount one by its
ordinal with `--partition N`. The filesystem is bounded to that partition's
extent, and the numbering matches `mount-device --partition`. `--offset`
remains for raw media no partition table describes; it always addresses
decoded virtual media, not container storage.

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
only; any other selector is rejected at open time with
`filesystem driver "ext" does not support root selector …`, so `--fs-root`
is effectively a Btrfs/APFS option (its `--help` says so).

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
registry to `open_device_partition` or `open_image`. `ImageOpenOptions` selects
either a partition ordinal or an offset in decoded media, plus the
filesystem-owned root; `image_layout` returns the same enumeration the
`partitions` command prints, so a listed ordinal is what `with_partition`
takes. Every container
implements the object-safe `fsmnt_device::ImageContainer` trait, so raw, EWF,
VHD, and VHDX readers share one typed virtual-media boundary. The umbrella
open functions return `OpenImageError`, retaining the failed path, decoded
offset, detected layout, and underlying container or filesystem error.

## Workspace layout

The root package `fsmnt` is the umbrella library plus a thin CLI. Members live
under `crates/`:

| Crate | Role |
|-------|------|
| `fsmnt-core` | `TargetFilesystem` trait, entry/metadata types, host-directory backend, fstab namespaces |
| `fsmnt-parser-core` | `no_std` parser foundation: reader/error traits, boot-sector detection, GPT/MBR |
| `fsmnt-device` | block-device abstraction, raw/EWF/VHD/VHDX image readers, disk layout, partition readers, driver registry |
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

### Releasing

Releases are cut by pushing a `v<version>` tag. [CI](.github/workflows/ci.yml)
runs its usual checks on the tag and, alongside them, a `build` job that
produces one archive per platform and keeps them as workflow artifacts. When
that whole run is green, the [release workflow](.github/workflows/release.yml)
downloads the archives and publishes them as the GitHub release for the tag —
which is what `mise use github:napbat/fsmnt` installs. A tag whose checks fail
never ships.

```sh
# 1. bump [workspace.package].version in Cargo.toml, then let Cargo.lock follow
cargo update --workspace
git commit -am "release v0.2.0"
# 2. tag and push — the tag must equal v<version> or CI refuses to build it
git tag v0.2.0
git push origin main v0.2.0
```

A `-rc1`-style suffix publishes a GitHub pre-release, which mise's `latest`
ignores. To exercise the build matrix without releasing, run CI manually
(`gh workflow run ci.yml --ref <branch>`): the `build` job also runs on
`workflow_dispatch` and leaves the archives as workflow artifacts, with no
release created.

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
