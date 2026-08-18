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
  into a partition fails with a message naming the backup's group, and the
  byte offset the filesystem actually starts at, instead of mounting an
  empty volume that could be misread as "no data". Where a copy is what you
  want — because the primary is damaged — `--backup-superblock GROUP` asks
  for it explicitly, and `--salvage` opens a volume whose directory tree is
  unusable; see [Damaged ext metadata](#damaged-ext-metadata-backup-superblocks-and-salvage).
  Both read through the same read-only path: the backup bytes are
  substituted in memory, never written back.

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
fsmnt scan disk.bin          # find filesystems the partition table does not mention
```

Drive IDs are what `fsmnt drives` prints: `0` on Windows, `sda` on Linux,
`disk2` on macOS. `partitions` takes either a drive ID or the path to a raw,
EWF, VHD, or VHDX image; anything that names an existing file, contains a
path separator, or has a file extension is read as an image. `scan` takes an
image only — see [Damaged and partial images](#damaged-and-partial-images).

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
fsmnt mount-image disk.img /mnt/img --offset 1M        # the same offset, written for humans
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

### Damaged and partial images

Acquisitions are not always whole, and the partition table is not always
right. Three things help when the image and its table disagree.

**Find filesystems the table does not mention.** `fsmnt scan IMAGE` reads the
decoded media once and reports every offset that starts a filesystem, ready
to paste into `--offset`:

```sh
fsmnt scan dump.bin
fsmnt scan dump.bin --stride 512      # search harder: filesystems off a 4 KiB boundary
```

```
        OFFSET         SECTOR  TYPE                           SIZE  NOTE
             0             0s  GptPartitioned                    -  partition table; list it with `fsmnt partitions`
     270532608        528384s  Ext                          3.3 GB  4 backup superblocks (groups 1, 3, 7, 9)
     903872512       1765376s  Ext                          2.2 GB  1 backup superblock (group 1)
    3625975808       7081984s  Ext                          1.5 GB  5 backup superblocks (groups 1, 3, 5, 7, 9)
```

Each hit is classified with the same probes a mount uses, and the size shown
is what the structure claims for itself. ext scatters backup superblocks
through a filesystem, each stamped with its block group; `scan` folds them
into the filesystem they belong to as corroboration rather than listing them
as separate finds. A backup whose primary is gone — an overwritten partition
front — is reported on its own, naming the offset its filesystem started at,
which is the offset to try. Hits inside a filesystem whose size is known are
suppressed so a multi-gigabyte partition does not report every stray `0xAA55`
in its file data; ext superblocks are exempt, because one inside another
filesystem's claimed extent means the extent is wrong.

**Write offsets the way your notes have them.** `--offset` takes plain bytes,
binary multiples (`K`/`M`/`G`/`T`, or the explicit `KiB`/`MiB`/`GiB`/`TiB`),
decimal ones (`KB`/`MB`/`GB`/`TB`), and sector counts with an `s` suffix.
These all name the same byte:

```sh
fsmnt mount-image dump.bin Z: --offset 270532608
fsmnt mount-image dump.bin Z: --offset 258MiB
fsmnt mount-image dump.bin Z: --offset 528384s     # sectors of --sector-size (512 by default)
```

**Say what a sector is.** `--sector-size BYTES` (a power of two of at least
512, on `mount-image`, `partitions`, and `scan`) sets both the unit for an
`s`-suffixed offset and the unit the image's own GPT or MBR is read in. A
dump of a 4Kn drive keeps its GPT header at byte 4096 and counts entry LBAs
in 4096-byte units, so reading it as 512-byte sectors puts every partition at
one-eighth of its real offset — when it finds the table at all. Without the
flag, `fsmnt` tries 512-byte sectors, and if they turn up no partition table
it retries at 4096 and says so:

```
dump.bin: raw image, 512 GB, sector size 4096 (auto-detected)
```

**See what the image is missing.** `fsmnt partitions IMAGE` marks partitions
the file does not fully carry, instead of reporting them as unreadable:

```
   9  android_system           Linux filesystem             3.3 GB      270532608  Ext
  10  android_vendor           Linux filesystem             1.5 GB     3625975808  Ext  TRUNCATED (134 MB missing)
  11  android_cache            Linux filesystem             2.2 GB     5198839808  beyond end of image
```

Mounting one of those still works whenever the front of the filesystem is
there, so the shortfall is stated up front rather than surfacing later as
per-file read errors:

```
warning: filesystem claims 3.32 GB but only 3.32 GB are present in the image (3 MB missing); reads past that point will fail
```

The same warning covers `mount-device` when a filesystem claims more than its
partition provides. It is a comparison between what the filesystem's own
superblock says and what the selected window holds — a *missing* tail, not a
corrupt one. When the front is missing too, the mount is refused instead: the
ext driver reads the root directory before reporting success (see
[Read-only guarantees](#read-only-guarantees)), and an offset that lands on a
backup superblock is rejected by name.

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

### Damaged ext metadata: backup superblocks and salvage

ext2/3/4 keep a copy of the superblock, and of the whole group-descriptor
table, in later block groups — with `sparse_super`, in groups 1, 3, 5, 7,
9, 25, 27, 49, 81, … Two flags put those copies to work, and two error
messages point you at them.

```sh
fsmnt mount-image dump.bin Z: --offset 270532608 --backup-superblock 1
fsmnt mount-image dump.bin Z: --partition 10 --salvage
fsmnt mount-device 0 Z: --partition 2 --salvage
```

`--backup-superblock GROUP` opens the volume through group `GROUP`'s copy
instead of the primary at the start — the same escape hatch as
`e2fsck -b`, for a wiped, overwritten, or bad-sectored first block. The
copy is validated before use (it has to name that group and its own
geometry has to place the group where the copy was found), and the
superblock plus the descriptor table that follows it are presented at the
primary locations for the duration of the mount; nothing is written back.
On a `META_BG` filesystem the descriptor blocks are scattered rather than
kept in one backup run, so only the superblock is substituted.

Two messages tell you when to reach for it:

- An offset that lands on a *copy* is refused, and says where the real
  start is — computed from the geometry the copy itself records:

  ```text
  offset 404749312 in "dump.bin" holds an ext backup superblock (block group 1);
  the filesystem starts at offset 270532608 — mount that, or list partitions with …
  ```

- An offset with *nothing* readable at it is probed one block group
  further in, so a destroyed primary is told apart from a wrong offset:

  ```text
  no filesystem at offset 0 in "system.bin", but an ext backup superblock for it
  exists at 134217728 (group 1); retry with `--backup-superblock 1`
  ```

`--salvage` handles the other failure: metadata that is fine, but a
directory tree that is not. mkfs places directories at the end of an
Android system or vendor image, so a truncated dump keeps most file
*content* while losing the tree that names it — and fsmnt otherwise
refuses to mount, because a volume whose root cannot be listed would
present as empty. With `--salvage` it mounts anyway and adds a synthetic
top-level directory:

```text
Z:\.fsmnt-salvage\inode-229      # every in-use inode, by number
Z:\.fsmnt-salvage\inode-105\...  # recovered directories list their real names
```

The entries come from sweeping the inode tables of every readable block
group — regular files and directories that are still linked and not
deleted — and reads go through the ordinary inode path, so extents, block
maps and inline data all behave normally. A block group whose inode table
is past the end of a truncated image simply contributes nothing. The
sweep runs on the first listing of `.fsmnt-salvage`, so a mount that never
opens it costs nothing, and whatever of the real tree still works is
served alongside it as usual.

Both flags are ext-only; another driver rejects them rather than quietly
ignoring the request. They combine with `--partition`, `--offset` and
`--no-journal-replay`.

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

### Unmounting

Mount commands block for as long as the volume exists. Ctrl+C unmounts and
exits — as do `SIGTERM` and `SIGHUP` on Unix, and closing the console,
logging off, or shutting down on Windows.

From another shell, or from a script, the mountpoint is enough:

```sh
fsmnt unmount Z:                  # `umount` works too
fsmnt unmount /mnt/evidence
```

The volume is released and the blocked mount command returns. On Windows
this also restores a mountpoint directory left behind by a mount process
that was killed: `taskkill /F` is `TerminateProcess`, which no program can
intercept, so the directory keeps a dangling reparse point that reports
"a device which does not exist was specified" for every access until
`fsmnt unmount` clears it.

To mount without a process to babysit, add `--detach` to any mount command.
The mount moves to a background process and the command returns as soon as
the volume is usable, or fails if it does not come up within 30 seconds:

```sh
fsmnt mount-image disk.img Z: --detach
fsmnt mount-image evidence.E01 Y: --detach --offset 1048576
fsmnt unmount Z: && fsmnt unmount Y:
```

Run the command without `--detach` to see why a mount failed — the
background process has no console to report to.

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
partition-table sector size and the filesystem-owned root; `image_layout`
(and `image_layout_with_sector_size`) returns the same enumeration the
`partitions` command prints, so a listed ordinal is what `with_partition`
takes, and each `ImagePartition` carries the `missing_bytes` the image is
short of its declared extent. `scan_image` backs the `scan` command, returning
`ScanHit`s with their folded ext backup superblocks. `OpenedImage` and
`OpenedPartition` report `truncated_by`, the bytes the opened filesystem
claims that its window does not hold — `missing_filesystem_bytes` is the same
comparison on its own. Every container
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
