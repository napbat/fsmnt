# fsmnt

[![CI](https://github.com/napbat/fsmnt/actions/workflows/ci.yml/badge.svg)](https://github.com/napbat/fsmnt/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Cross-platform **read-only** virtual mounting for raw, Expert Witness Format
(EWF), VHD, and VHDX filesystem images and block devices. `fsmnt` parses
on-disk filesystems in Rust — the parsers themselves are pure Rust; the one
native library in the binary is libzstd, for Btrfs zstd-compressed extents —
and presents them as a browsable volume, so files can be inspected and
copied with ordinary OS tools — no kernel driver for the guest filesystem
required, and nothing is ever written back to the source.

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
| ext2/3/4     | fscrypt decryption with `--fscrypt-key` (Android FBE) and fs-verity; journal and orphan replay applied as overlays, never to the source |
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
  FAT32, exFAT and NTFS volumes whose sector 0 is dead are opened through
  their backup boot sectors automatically. All of these read through the
  same read-only path: the backup bytes are substituted in memory, never
  written back — and every such fallback is announced as a `warn:` line
  (see [Damaged and partial images](#damaged-and-partial-images)).

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
run = "fsmnt mount evidence.E01 /mnt/evidence --partition 2"
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

```sh
fsmnt drives                     # list the physical drives on this machine
fsmnt partitions SOURCE          # list the partitions of a drive or a disk image
fsmnt scan SOURCE                # find filesystems no partition table mentions
fsmnt mount SOURCE MOUNTPOINT    # mount a directory, a disk image, or a drive
fsmnt unmount MOUNTPOINT         # release it again (`umount` works too)
```

One `mount` for all three kinds of source, and one spelling of `SOURCE` for
every command. (`mount-image` and `mount-device` were earlier, separate
commands with drifting option sets; they are gone, and everything they could
do is an option of `fsmnt mount`.)

### SOURCE — one grammar everywhere

- **a directory** — exposed as a volume of its own (`mount` only);
- **a disk image** — raw, EWF (`.E01`/`.Ex01`, first segment), VHD, or VHDX;
- **a drive** — the ID `fsmnt drives` prints (`0` on Windows, `sda` on Linux,
  `disk2` on macOS) or its operating-system device path
  (`\\.\PhysicalDrive0`, `\\?\PhysicalDrive0`, `/dev/sda`, `/dev/nvme0n1`,
  `/dev/disk2`, `/dev/rdisk2`), normalised to that ID.

Resolved in this order: an existing directory is a directory; an existing
file is an image; a device path is a drive; anything left that contains a
path separator or has a file extension is an image — so a mistyped path
fails as "cannot open image" rather than as "no such drive" — and a bare
token is a drive ID.

Say it outright when the guess would be wrong. `--image` never touches the
filesystem, so a path that is not there yet still fails *as an image*;
`--drive` accepts a device path and normalises it; `--dir` (on `mount` only)
takes a directory and says so if it is not one. The three are mutually
exclusive. `partitions` and `scan` refuse a directory outright.

### Inspect a machine's disks

```sh
fsmnt drives                 # physical drives with size, bus, and access state
fsmnt partitions 0           # the partitions of drive 0
fsmnt partitions disk.bin    # the same table for a disk image
fsmnt scan disk.bin          # filesystems the partition table does not mention
```

`partitions` prints one table shape for both kinds of source, so a drive and
an image acquired from it can be compared line for line: `#`, `NAME` (GPT
only), `TYPE`, `SIZE`, `OFFSET`, `FILESYSTEM` — plus, for a drive, a
trailing `VOLUME` column naming the operating-system volume(s) laid over
each partition and where they are mounted. That column is where the
`--volume ID` value comes from; it reads `-` when there is none, or when
volume discovery is not permitted here.

```
0: drive (Samsung SSD 990 PRO 2TB), 2.0 TB, sector size 512
GPT partition table
   #  NAME                  TYPE                  SIZE         OFFSET  FILESYSTEM  VOLUME
   0  EFI system partition  EFI System          104 MB        1048576  Fat32       \\?\Volume{5f2…}\
   1  Basic data partition  Microsoft basic da  1.9 TB      316669952  Ntfs        \\?\Volume{a71…}\ (C:)
```

The header line names the source and its size, the sector size the table was
read in (and whether that was auto-detected), the kind of table, and where
its entries came from — the media's own table, its GPT backup header, or a
scan. The footer says how to mount one of the entries.

### Mount

```sh
fsmnt mount ./export Z: --volname Evidence               # a host directory
fsmnt mount disk.img Z:                                  # an image that is one filesystem
fsmnt mount disk.bin Z: --partition 3                    # one partition of a whole-disk image
fsmnt mount evidence.E01 /mnt/evidence --partition 2
fsmnt mount "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\Win11-dev.vhdx" Z: --partition 3
fsmnt mount 0 Z: --partition 1                           # a partition of a drive
fsmnt mount sda /mnt/evidence --partition 1
fsmnt mount disk.img /mnt/img --offset 1048576
fsmnt mount disk.img /mnt/img --offset 1M                # the same offset, written for humans
```

**Where the filesystem is** — three answers, identical for an image and a
drive:

- `--partition N` counts non-empty partition-table entries from 0, exactly as
  `fsmnt partitions SOURCE` lists them, and bounds the filesystem to that
  extent.
- `--offset SIZE` opens raw media at a byte offset, for media no partition
  table describes. On a drive the offset is *physical*: it counts from the
  first byte of the drive, past any logical volume the operating system has
  laid over it, so `--volume` is refused alongside it.
- `--scan --partition N` counts the filesystems a scan of the media finds
  instead of the entries of any table (see
  [Damaged and partial images](#damaged-and-partial-images)).

With none of them, the source must itself start with a filesystem: an
unpartitioned image or drive is mounted whole, and a partitioned one is
refused by name.

```
error: 0 contains a GPT partition table; select a partition with `--partition N` (see `fsmnt partitions 0`)
```

**Behaviour change:** `mount-device` used to default to partition 0, which on
a modern disk is the EFI system partition. Nothing defaults now — say which
partition you mean.

**Which options apply to which source.** An option used against a source kind
it was not written for is an error naming both — `--raw applies to drives;
disk.bin is a disk image` — rather than being quietly ignored.

| option | directory | image | drive |
|---|:---:|:---:|:---:|
| `--partition N` | – | ✓ | ✓ |
| `--offset SIZE` | – | ✓ | ✓ |
| `--scan`, `--stride BYTES` | – | ✓ | ✓ |
| `--sector-size BYTES` | – | ✓ | ✓ |
| `--raw`, `--volume ID`, `--member DRIVE:PARTITION` | – | – | ✓ |
| `--fstab [PATH]` | – | ✓ | ✓ |
| `--recovery-password`, `--bek-file` | – | ✓ | ✓ |
| `--fs-root`, `--no-journal-replay`, `--backup-superblock`, `--salvage`, `--best-effort-reads` | – | ✓ | ✓ |
| `--fscrypt-key SPEC` | – | ✓ | ✓ |
| `--volname NAME`, `--fsname NAME` | ✓ | ✓ | ✓ |
| `--detach` | ✓ | ✓ | ✓ |

`--volname` defaults to the directory name, the image file stem, or the drive
model; `--fsname` to `fsmnt-dir` for a directory and to the detected
filesystem (`ntfs`, `fat32`, `extfs`, …) for an image or a drive.

**Reading a drive.** A drive partition is opened through the operating
system's logical view of it by default, which means an OS-unlocked encrypted
volume can be read without supplying its key again.

- `--raw` bypasses that and reads the physical partition members directly.
  Members of a multi-device filesystem are discovered across all host drives
  automatically; add ones outside platform enumeration with
  `--member DRIVE:PARTITION` (repeatable).
- `--volume ID` picks one logical volume when automatic selection is
  ambiguous. `fsmnt partitions DRIVE` prints the IDs in its `VOLUME` column.

**Reassembling a guest's tree.** `--fstab [PATH]` reads the selected root's
`/etc/fstab` (or `PATH`) and composes the child mounts it describes into a
single namespace, attaching them shallow-to-deep so `/boot/efi` lands inside
`/boot`. On a drive the siblings are the partitions of every host drive; in
an image they are the other partitions of the same image — which is the
usual case, since a Linux VM's VHDX carries the whole tree. Sources are
matched by UUID, because the device path a volume had when the system last
ran is not the path it has anywhere else. On a drive the composer needs a
partition ordinal, so `--fstab` does not combine with `--offset` there.

```sh
fsmnt mount linux-vm.vhdx /mnt/guest --partition 2 --fstab
fsmnt mount 0 /mnt/guest --partition 2 --fstab /etc/fstab.forensic
```

**Images.** Raw images, EWF v1/v2 physical evidence (`.E01`/`.Ex01`), legacy
VHD, and VHDX are detected automatically. Pass the first EWF segment; sibling
segments are discovered and decoded as one logical media stream. Fixed,
dynamic, and differencing VHD/VHDX images are decoded by the
repository-native readers; `.avhd` and `.avhdx` checkpoint parents are
resolved from their container locators. Sparse blocks and VHDX log entries
are read or replayed on demand, without attaching the image or writing to any
layer.

### Damaged and partial images

Acquisitions are not always whole, and the partition table is not always
right. Three things help when the media and its table disagree — and, since
a drive with a wiped table and an image of one are the same forensic
situation, all three work on either.

**Find filesystems the table does not mention.** `fsmnt scan SOURCE` reads
the media once and reports every offset that starts a filesystem, ready to
paste into `--offset`:

```sh
fsmnt scan dump.bin
fsmnt scan dump.bin --stride 512      # search harder: filesystems off a 4 KiB boundary
fsmnt scan 0                          # the same search over a live drive
```

```
   #          OFFSET         SECTOR  TYPE                           SIZE  NOTE
   -               0             0s  GptPartitioned                    -  partition table; list it with `fsmnt partitions`
   0       270532608        528384s  Ext                          3.3 GB  4 backup superblocks (groups 1, 3, 7, 9)
   1       903872512       1765376s  Ext                          2.2 GB  1 backup superblock (group 1)
   2      3625975808       7081984s  Ext                          1.5 GB  5 backup superblocks (groups 1, 3, 5, 7, 9)
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

A magic number on its own is not enough to call something a start. An ext
primary superblock counts as one only when the group descriptor table that
has to follow it is there and — on any filesystem that carries descriptor
checksums — verifies; a start is then accepted only once the root inode that
descriptor table points at reads as a directory, which is the next thing a
mount does and the one step a journalled copy of blocks 0 and 1 — table and
all — cannot fake. `55 AA` counts as a partition table only when its four
entries describe extents a partitioner could have written. That matters on a
real image: an ext4 journal records whole blocks, so a busy filesystem holds
dozens of pristine-looking copies of its own superblock, and a multi-gigabyte
medium meets a coincidental boot signature every few megabytes. What fails
these tests is still reported, as what it actually is and on one line: the
superblock copies become a single row naming how many there are and the range
they span, and orphan backup superblocks that agree on where their filesystem
began become a single row too. When that computed start falls *before* byte
zero, the row says so — the medium is a slice that begins partway inside a
filesystem, and the bytes in front of it were never acquired.

**Or let the scan stand in for the table — labelled as such.** `partitions
SOURCE --scan` ignores whatever table the media carries and prints a
partition table *reconstructed* from a scan, and `mount SOURCE MOUNTPOINT
--scan --partition N` mounts by that numbering (both take `--stride`; the
numbers in `scan`'s `#` column are the same ones):

```
SYNTHETIC partition table — reconstructed by scanning the media every 4096 bytes for filesystem starts. No table was read from the disk image: sizes are what each filesystem claims for itself, there are no names or type GUIDs, and the numbers hold only for this disk image scanned with this stride.
   #  TYPE (from scan)      SIZE         OFFSET  FILESYSTEM
   0  Ext (scan)          3.3 GB      270532608  Ext
   1  Ext (scan)          2.2 GB      903872512  Ext
   2  Ext (scan)          1.5 GB     3625975808  Ext  TRUNCATED (121 MB missing)
```

The word *synthetic* is deliberate and it follows the data around: the
listing says it, the mount emits a `warn:` line saying which numbering the
ordinal came from, and library callers get it as a typed value —
`ImageLayout::origin` and `DriveLayout::origin` are a `LayoutOrigin`
(`Table`, `BackupTable`, `Scan { stride }`, or `None`), the kind is
`LayoutKind::Scanned`, and a volume opened by ordinal carries
`OpenedImage::layout_origin` / `OpenedPartition::layout_origin` — so nothing
downstream can mistake a scan-built table for one the media carried. A
filesystem the scan knows only from a backup superblock is an entry too, at
the start the copy implies; mounting it produces the `--backup-superblock`
guidance rather than nothing.

**Write offsets the way your notes have them.** `--offset` takes plain bytes,
binary multiples (`K`/`M`/`G`/`T`, or the explicit `KiB`/`MiB`/`GiB`/`TiB`),
decimal ones (`KB`/`MB`/`GB`/`TB`), and sector counts with an `s` suffix.
These all name the same byte:

```sh
fsmnt mount dump.bin Z: --offset 270532608
fsmnt mount dump.bin Z: --offset 258MiB
fsmnt mount dump.bin Z: --offset 528384s     # sectors of --sector-size (512 by default)
```

**Say what a sector is.** `--sector-size BYTES` (a power of two of at least
512, on `mount`, `partitions`, and `scan`) sets both the unit for an
`s`-suffixed offset and the unit the GPT or MBR is read in. A dump of a 4Kn
drive keeps its GPT header at byte 4096 and counts entry LBAs in 4096-byte
units, so reading it as 512-byte sectors puts every partition at one-eighth
of its real offset — when it finds the table at all. The same applies to a
live 4Kn drive the operating system reports as 512e, or the reverse. Without
the flag, an image tries 512-byte sectors, retries at 4096 if they turn up no
partition table, and says so; a drive uses the geometry it reports.

```
dump.bin: raw image, 512 GB, sector size 4096 (auto-detected)
```

**See what the media is missing.** `fsmnt partitions SOURCE` marks partitions
the file does not fully carry, instead of reporting them as unreadable:

```
   9  android_system           Linux filesystem             3.3 GB      270532608  Ext
  10  android_vendor           Linux filesystem             1.5 GB     3625975808  Ext  TRUNCATED (134 MB missing)
  11  android_cache            Linux filesystem             2.2 GB     5198839808  beyond end of media
```

Mounting one of those still works whenever the front of the filesystem is
there, so the shortfall is stated up front rather than surfacing later as
per-file read errors:

```
warn: filesystem claims 3.32 GB but only 3.32 GB are present in the image (3 MB missing); reads past that point will fail
```

The same warning covers a drive partition when a filesystem claims more than
its partition provides. It is a comparison between what the filesystem's own
superblock says and what the selected window holds — a *missing* tail, not a
corrupt one. When the front is missing too, the mount is refused instead: the
ext driver reads the root directory before reporting success (see
[Read-only guarantees](#read-only-guarantees)), and an offset that lands on a
backup superblock is rejected by name.

**Read what is there, even past the damage.** By default a read that the
source cannot satisfy — a block past the end of a truncated dump, a sector
that errors on a failing drive — fails, and with it the whole file. That is
the right default (zeros are not data), but it makes a file that is 90 %
present entirely uncopyable. `--best-effort-reads` serves such bytes as zeros
instead, so what exists can be copied out, and reports what it substituted
when the mount ends — distinct bytes, each counted once however often the
filesystem re-read them:

```sh
fsmnt mount dump.bin Z: --partition 10 --salvage --best-effort-reads
```

```
warn: best-effort reads are on — data the source cannot provide is served as zeros; a summary follows when the volume is unmounted
…
warn: best-effort reads: 59 MB of the media that was read was not there and came back as zeros — 59 MB past the end of the source, 0 bytes in sectors that failed to read (0 read error(s))
```

On the truncated `android_vendor` above this turns 197 readable salvage
entries into all 402 — the last 121 MB of the partition is simply not in
the file, and now the files that reach into it read with a zero tail rather
than not at all. The window becomes the partition's *declared* extent, so a
filesystem whose data runs past the dump's end can still be walked. On a
device the same flag rides over bad sectors one 512-byte sector at a time.

**A wiped partition table has a backup too.** GPT writes a second header into
the last sector of the disk and the entry array just before it. When the
front of a medium is gone — `dd` over the first sectors, a bootloader
mishap, an acquisition that started late — `partitions` and `--partition`
read the table from that copy (validated by signature, header CRC, and its
own recorded position) and say so:

```
GPT partition table (recovered from the backup header in the last sector; the primary header at the front of the disk image is damaged)
```

A protective MBR whose GPT header at LBA 1 is gone is treated the same way
rather than as an MBR disk with one `0xEE` partition. Only a medium that is
truncated at the end as well loses both copies — and then `scan` still finds
the filesystems themselves.

**Boot sectors have backups too.** FAT32 keeps sectors 0–2 again at sector
6, exFAT keeps its whole 12-sector boot region again at sector 12, and NTFS
mirrors its boot sector into the last sector of the volume. When sector 0
no longer classifies as any filesystem but one of those copies does, `fsmnt`
detects the volume from the copy and opens it through the copy — presented
at sector 0 in memory for the duration of the mount, nothing written — and
says so:

```
warn: primary boot sector is not a valid exFAT boot region; opened through the backup copy at byte 6144 (6144 bytes) — the view reflects that copy
```

FAT12/16 have no backup boot sector, so a damaged one stays unrecoverable
here.

**What fsmnt tells you.** Every departure from a plain open is reported as a
`warn:` line on stderr before the volume appears — a backup boot sector or
superblock standing in for the primary, a journal replayed into the overlay,
replay declined on a dirty volume, salvage mode, best-effort reads, a
synthetic or backup-derived partition table — so a scripted mount's log
records under what conditions the evidence was viewed, even at `-q`. Library
users get the driver's own list from `TargetFilesystem::notices()`, and
everything else through `tracing`. See [Logging](#logging).

**Large files, damaged files.** Files are read in chunks at the position
the OS asks for (every driver implements a positioned read), so copying a
multi-gigabyte file out of an image costs one pass — not one full re-read
per chunk — and an inode that lies about its size (a corrupt one on a
damaged volume can claim petabytes) fails just that read instead of taking
the mounted volume down with an allocation failure.

**Not covered.** A missing segment of an EWF set (`.E02` absent from an
`.E01` chain) still fails at open — the EWF decoder needs every segment.
NTFS's `$MFT` mirror and FAT's second FAT copy are not consulted when the
first copy is damaged, and a damaged FAT12/16 boot sector has no backup.
Directory blocks that are corrupt (rather than missing) fail that listing;
`--salvage` still reaches the files below them on ext.

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
fsmnt mount dump.bin Z: --offset 270532608 --backup-superblock 1
fsmnt mount dump.bin Z: --partition 10 --salvage
fsmnt mount 0 Z: --partition 2 --salvage
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

### File-based encryption (fscrypt / Android FBE)

fscrypt is Linux's per-file encryption — what Android calls FBE, and what
its `/data` has used since Android 10. It encrypts file *contents* and the
*names* inside encrypted directories, and nothing else: the tree, the
sizes, the timestamps and the block layout are all plaintext, and the
master keys are deliberately not on the volume.

So a `/data` image mounts perfectly well with no keys at all — and that is
the trap. Without them you get:

- names in the kernel's no-key form, `base64url(fscrypt_nokey_name)` —
  byte-for-byte what a kernel `readdir()` shows on a keyless mount, e.g.
  `AAAAAAAAAAArjx7aAMADDNHGcN-v-GWz`;
- an error on every read of an encrypted file, naming the key it wants;
- and, before the volume appears, a census of the keys the volume is
  asking for:

```text
warn: filesystem uses fscrypt (file-based encryption); no keys registered — encrypted
      names appear in the kernel's no-key form and encrypted files cannot be read
warn: fscrypt key identifier 3ea377eeb5b5b06a8dbf7d48fa2c5bc6: v2, AES-256-XTS/AES-256-CTS,
      PAD_16 — NOT registered; e.g. /data/data, /media/0, /system_ce/0 (+41 more)
```

The census walks three levels down from the mounted root (bounded, and
never fatal), which is where Android puts its policies — `data/<pkg>`,
`user_de/0`, `system_ce/0`, `media/0`, `misc_ce/0`, `vendor_ce/0`. Each
line names one distinct policy: its key, its ciphers, its flags
(`IV_INO_LBLK_64`, `DIRECT_KEY`, casefold, sub-block data units), whether
a supplied key covers it, and where it applies.

`--fscrypt-key SPEC` supplies a master key, and repeats:

```sh
fsmnt mount data.img Z: --fscrypt-key @user0-ce.key
fsmnt mount data.img Z: --fscrypt-key 4f2a…8c --fscrypt-key @user10-ce.key
fsmnt mount data.img Z: --fscrypt-key v1:aabbccddeeff0011:@legacy-de.key
```

| spec | meaning |
|---|---|
| `<HEX>` or `v2:<HEX>` | a v2 master key, 16–64 bytes as 32–128 hex digits |
| `v1:<DESCRIPTOR>:<HEX>` | a v1 master key; `DESCRIPTOR` is the 16 hex digits the policy stores, and the key must be 64 bytes |
| `@<PATH>` | in place of `<HEX>` in either form: read the raw key bytes from a file |

A v2 key needs no identifier — the kernel derives the 16-byte identifier
from the key itself (HKDF-SHA512), and so does fsmnt, which is how the
census can tell you whether what you supplied is what the volume wants. A
v1 policy stores an operator-chosen descriptor instead, so a v1 key has to
be told which one it answers to. Keys never appear in a log line: only
their lengths, and the descriptors and identifiers the volume already
stores in the clear.

The workspace's own fscrypt fixture makes the whole loop runnable — its
master keys are SHA-512 of fixed labels:

```sh
python3 -c 'import hashlib,sys; sys.stdout.buffer.write(hashlib.sha512(b"tracium-fscrypt-v2-fixture").digest())' > v2.key
fsmnt mount crates/formats/fs-ext/testdata/ext4-fscrypt.img Z: --fscrypt-key @v2.key
# warn: fscrypt key identifier 3ea377eeb5b5b06a8dbf7d48fa2c5bc6: v2, AES-256-XTS/AES-256-CTS,
#       PAD_16 — registered; e.g. /v2_dir
cat Z:\v2_dir\hello.txt   # "v2 hello"
```

Frankly: these are the raw master keys, not a PIN or a password. On
Android they are the bytes vold hands the kernel keyring, recoverable
from a live rooted device (`keyctl`, `fscryptctl`) or from
`/data/unencrypted/key` plus `/data/misc/vold/user_keys` **only where the
wrapping keymaster is software**. Android 12+ binds those keys to the
TEE or StrongBox, and a TEE-wrapped key cannot be unwrapped from the
image alone — no amount of offline work on the dump will produce it. Where
a device-side unwrap service exists, the underlying parser supports
handing it wrapped blobs; fsmnt's command line does not expose that path.

fscrypt is not an ext4 feature but a VFS one — f2fs, UBIFS and Ceph store
the same policies — so `--fscrypt-key` is written against fscrypt rather
than against ext. Today ext2/3/4 is the fscrypt-capable driver fsmnt
ships, and a key handed to any other driver is ignored rather than
refused, so one key set can be passed to a whole-device mount.

### BitLocker

```sh
fsmnt mount bde.img Z: --recovery-password 123456-...-654321
fsmnt mount 0 Z: --partition 2 --bek-file startup.bek
```

Volumes whose protection is suspended unlock via the clear key with no
credentials.

### Logging

stdout carries the command's *product* only: the `drives`, `partitions` and
`scan` tables, and the mount lifecycle lines a script may key on (`Volume
mounted at Z:. …`, `Unmounted.`, `Unmounted Z:.`). Everything else — what was
detected where, driver notices, warnings, the best-effort summary, the final
error — goes to stderr as one line per event, `level: message key=value`:

```
info: detected Ntfs at offset 316669952 in raw image disk.bin
warn: filesystem claims 1.90 TB but only 1.43 TB are present in the image (471 GB missing); reads past that point will fail
info: mounting ntfs volume at Z:
```

| flag | effect |
|---|---|
| *(none)* | progress and outcomes (`info`) |
| `-v` | plus the decisions inside the library, each line prefixed with the module it came from (`debug`) |
| `-vv` | plus every operation a mounted volume serves (`trace`) |
| `-q` | warnings and errors only |
| `--log-file PATH` | append the same lines to `PATH` as well, without colour |
| `FSMNT_LOG` | `tracing` `EnvFilter` directives (`debug`, `fsmnt_device=trace,info`); overrides `-v`/`-q` |

The flags are global: `fsmnt -v partitions disk.bin` and
`fsmnt partitions disk.bin -v` are the same command. Colour appears only when
stderr is a terminal, and never in the log file. `--log-file` survives
`--detach`, so a mount that failed in the background can still say why.
`fuser` and `ewf` report through the `log` crate; those records arrive in the
same stream under the same filter.

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

To mount without a process to babysit, add `--detach` to a mount command.
The mount moves to a background process and the command returns as soon as
the volume is usable, or fails if it does not come up within 30 seconds:

```sh
fsmnt mount disk.img Z: --detach
fsmnt mount evidence.E01 Y: --detach --offset 1048576 --log-file evidence.log
fsmnt unmount Z: && fsmnt unmount Y:
```

The background process has no console to report to, so give it a
`--log-file` — or re-run in the foreground — to see why a mount failed.

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
registry to `open_device_partition` or `open_image`.

Every way of saying *where* a filesystem is has a matching pair, one for an
image and one for a drive, and both go through the same enumeration — so an
image acquired from a drive and the drive itself number their partitions
identically:

| to say | image | drive |
|---|---|---|
| what is on it | `image_layout` | `drive_layout` |
| what is *really* on it | `scan_image` | `scan_drive` |
| open the N-th table entry | `ImageOpenOptions::with_partition` | `open_device_partition` |
| open the N-th filesystem a scan finds | `ImageOpenOptions::with_scan` | `PartitionOpenOptions::with_scan` |
| open at a byte offset | `ImageOpenOptions::with_offset` | `open_device_at_offset` |
| read the table in 4 KiB sectors | `ImageOpenOptions::with_sector_size` | `PartitionOpenOptions::with_sector_size` |
| compose a guest's fstab | `open_image_with_fstab` | `open_device_partition_with_fstab` |

`image_layout` (and `image_layout_with_options`) returns the same enumeration
the `partitions` command prints, so a listed ordinal is what `with_partition`
takes, and each `LayoutPartition` carries the `missing_bytes` the medium is
short of its declared extent. However a volume was located, the result says
so: `OpenedImage::layout_origin` and `OpenedPartition::layout_origin` are a
`LayoutOrigin` — the media's own table, its GPT backup, a `Scan { stride }`,
or a bare byte offset. `OpenedImage` and `OpenedPartition` also report
`truncated_by`, the bytes the opened filesystem claims that its window does
not hold — `missing_filesystem_bytes` is the same comparison on its own.
Every container implements the object-safe `fsmnt_device::ImageContainer`
trait, so raw, EWF, VHD, and VHDX readers share one typed virtual-media
boundary. The umbrella open functions return `OpenImageError`, retaining the
failed path, decoded offset, detected layout, and underlying container or
filesystem error.

Diagnostics reach library users through
[`tracing`](https://docs.rs/tracing): every first-party crate emits events —
`debug` for the decisions inside (which table was read and how, which driver
claimed the media, which logical volume was chosen), `info` for progress and
outcomes, `warn` for anything a record has to keep — and none of them prints
to stdout or stderr on its own. Install any subscriber to see them; the CLI's
is in `src/cli/logging.rs`.

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
