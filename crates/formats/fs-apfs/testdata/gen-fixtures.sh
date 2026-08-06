#!/usr/bin/env bash
#
# Generates the APFS fixture images used by the fs-apfs integration tests
# (crates/fs-apfs/tests/fixture.rs).
#
# The images are NOT committed to the repository: they are reproducible
# from this script. A checkout without them still builds and tests — the
# integration tests skip any fixture that is absent.
#
# Requirements (Linux):
#   - mkapfs            from linux-apfs/apfsprogs   (creates APFS images)
#   - the apfs kernel module from linux-apfs/linux-apfs-rw (to populate them)
#   - root, for the loopback mount used to copy files in
#
# On macOS the same images can be produced with `hdiutil create` and
# `diskutil`; see testdata/README.md for that route.
#
# Usage:  sudo crates/fs-apfs/testdata/gen-fixtures.sh

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

block_size=4096

if ! command -v mkapfs >/dev/null 2>&1; then
  echo "error: mkapfs not found — build it from linux-apfs/apfsprogs" >&2
  exit 1
fi

# make_image NAME SIZE_MIB EXTRA_MKAPFS_ARGS...
#
# Creates a zero-filled image of SIZE_MIB mebibytes and formats it as an
# APFS container with one volume.
make_image() {
  local name="$1" size_mib="$2"
  shift 2
  echo "generating $name.img (${size_mib} MiB)"
  rm -f "$name.img"
  truncate -s "${size_mib}M" "$name.img"
  mkapfs -b "$block_size" "$@" "$name.img"
}

# populate IMAGE  — mounts the image and writes a small distinctive tree.
#
# Each file is filled with a per-file byte pattern so a mis-mapped extent
# is caught by content comparison rather than masked by coincidental zeros.
populate() {
  local img="$1" mnt
  mnt="$(mktemp -d)"
  mount -t apfs -o loop,ro=0 "$img" "$mnt"
  trap 'umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true' RETURN
  mkdir -p "$mnt/dir"
  printf 'hello apfs\n' >"$mnt/hello.txt"
  head -c 70000 /dev/zero | tr '\0' 'A' >"$mnt/dir/large.bin"
  ln -s hello.txt "$mnt/link"
  setfattr -n user.note -v evidence "$mnt/hello.txt" 2>/dev/null || true
  sync
}

# A plain case-sensitive single-volume container. mkapfs creates a
# case-insensitive volume by default; -s makes the volume case-sensitive.
make_image apfs 32 -s
populate apfs.img

# A case-insensitive, normalization-insensitive volume (the macOS
# default) — mkapfs's behaviour with no -s/-z flags.
make_image apfs-case-insensitive 32
populate apfs-case-insensitive.img

# The multi-volume fixture (apfs-multi-volume.img) is not generated here:
# mkapfs writes exactly one volume per container, and apfsprogs has no
# tool to add another, so a second `mkapfs` run only reformats the image.
# Produce it on macOS with `diskutil apfs addVolume` — see README.md. Its
# integration test skips when the fixture is absent.

echo "generated APFS fixtures in $here"
