#!/usr/bin/env bash
set -euo pipefail

# Generate deterministic ext2/ext3/ext4 test fixture images.
# Requirements: e2fsprogs (mkfs.ext2, mkfs.ext3, mkfs.ext4, debugfs)
#
# E2FSPROGS_FAKE_TIME pins filesystem timestamps (e2fsprogs >= 1.45.7).
# File *content* is always deterministic; on-disk timestamps are pinned
# when this env var is honoured by the toolchain.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export E2FSPROGS_FAKE_TIME=1700000000

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

# --- helper: build the common file tree in a staging directory ---
build_common_tree() {
    local dir="$1"
    local variant="$2"

    mkdir -p "$dir"
    printf 'Hello from %s!\n' "$variant" > "$dir/hello.txt"

    mkdir -p "$dir/subdir"
    printf 'Nested file\n' > "$dir/subdir/nested.txt"

    mkdir -p "$dir/empty_dir"

    ln -s "hello.txt" "$dir/short_link"

    mkdir -p "$dir/deep/a/b/c/d"
    printf 'Deep file\n' > "$dir/deep/a/b/c/d/deep_file.txt"
}

# --- helper: long symlink target (> 60 bytes, forces slow symlink) ---
make_long_link() {
    local dir="$1"
    local target
    target="/subdir/nested.txt/padding-to-exceed-sixty-bytes-threshold-for-slow-symlink"
    ln -s "$target" "$dir/long_link"
}

# --- helper: build a large directory that triggers htree indexing ---
make_htree_dir() {
    local dir="$1"
    mkdir -p "$dir/htree_dir"
    for i in $(seq -w 1 500); do
        printf 'file %s\n' "$i" > "$dir/htree_dir/file_$i.txt"
    done
}

# ===================================================================
# ext2.img — revision 0, 512 KiB, 1 KiB blocks (rev 0 default), no journal
# ===================================================================
echo "==> Building ext2.img"
EXT2_STAGE="$STAGING/ext2"
build_common_tree "$EXT2_STAGE" "ext2"

dd if=/dev/zero of=ext2.img bs=1K count=512 status=none
# e2fsprogs 1.47.1 removed `-r 0` in favour of `-E revision=0`, and older
# releases (Ubuntu 24.04's 1.47.0, i.e. GitHub's ubuntu-latest) reject the
# extended option. Probe with a dry run and use whichever this mke2fs takes;
# both yield the same revision-0 layout.
EXT2_REV0=(-E revision=0)
if ! mkfs.ext2 -q -n "${EXT2_REV0[@]}" ext2.img >/dev/null 2>&1; then
    EXT2_REV0=(-r 0)
fi
mkfs.ext2 -q \
    "${EXT2_REV0[@]}" \
    -U "11111111-1111-1111-1111-111111111111" \
    -d "$EXT2_STAGE" \
    ext2.img

# ===================================================================
# ext2-no-filetype.img — ext2 with INCOMPAT_FILETYPE disabled.
# Uses dynamic revision defaults so FILETYPE can be explicitly toggled.
# ===================================================================
echo "==> Building ext2-no-filetype.img"
EXT2_NO_FT_STAGE="$STAGING/ext2-no-filetype"
build_common_tree "$EXT2_NO_FT_STAGE" "ext2-no-filetype"

dd if=/dev/zero of=ext2-no-filetype.img bs=1M count=8 status=none
mkfs.ext2 -q \
    -O ^filetype \
    -U "12121212-1212-1212-1212-121212121212" \
    -b 1024 \
    -d "$EXT2_NO_FT_STAGE" \
    ext2-no-filetype.img

# ===================================================================
# ext3.img — revision 1, 8 MiB, 4 KiB blocks, journal
# ===================================================================
echo "==> Building ext3.img"
EXT3_STAGE="$STAGING/ext3"
build_common_tree "$EXT3_STAGE" "ext3"
make_long_link "$EXT3_STAGE"
make_htree_dir "$EXT3_STAGE"

dd if=/dev/zero of=ext3.img bs=1M count=16 status=none
mkfs.ext3 -q \
    -O dir_index \
    -U "22222222-2222-2222-2222-222222222222" \
    -b 4096 \
    -d "$EXT3_STAGE" \
    ext3.img
# Convert htree_dir to btree index format (mkfs doesn't trigger it on copy)
e2fsck -f -D -y ext3.img > /dev/null 2>&1 || true

# ===================================================================
# ext4.img — 16 MiB, 4 KiB blocks, modern features + inline data
# ===================================================================
echo "==> Building ext4.img"
EXT4_STAGE="$STAGING/ext4"
build_common_tree "$EXT4_STAGE" "ext4"
make_long_link "$EXT4_STAGE"

# Sparse source file: 100 bytes at offset 0, 100 bytes at offset 8192
dd if=/dev/zero of="$EXT4_STAGE/sparse_file" bs=1 count=100 status=none
dd if=/dev/zero of="$EXT4_STAGE/sparse_file" bs=1 count=100 seek=8192 \
    conv=notrunc status=none

# Multi-block file: 8 KiB of non-zero bytes → 2 full 4 KiB data blocks.
# Used as the truncate-fixture target (truncate-unlink sets i_size=0,
# truncate-partial sets i_size=4097 — both leave extents past the cutoff).
# Non-zero content prevents mkfs/e2fsck from eliding the blocks as sparse.
python3 -c "import sys; sys.stdout.buffer.write(b'\xAB\xCD' * 4096)" \
    > "$EXT4_STAGE/multiblock.bin"

make_htree_dir "$EXT4_STAGE"

# Phase 1: create the image WITHOUT inline_data so existing files
# remain block-backed (extents).  mkfs -d with inline_data would
# convert every small file to inline, breaking tests that depend on
# block-backed reads.
dd if=/dev/zero of=ext4.img bs=1M count=16 status=none
mkfs.ext4 -q \
    -U "33333333-3333-3333-3333-333333333333" \
    -b 4096 \
    -I 256 \
    -O extents,64bit,flex_bg,extra_isize,metadata_csum,dir_nlink,dir_index,ea_inode \
    -d "$EXT4_STAGE" \
    ext4.img
# Convert htree_dir to btree index format (mkfs doesn't trigger it on copy)
e2fsck -f -D -y ext4.img > /dev/null 2>&1 || true

# Phase 2: enable inline_data feature and create inline fixtures via
# debugfs.  This keeps existing inodes block-backed while adding
# deterministic inline test content.
#
# Inline files and symlinks at root level are safe for walk_dir —
# it lists them but never reads their content or enters them.
# The inline directory is unlinked from root after creation so that
# walk_dir doesn't try to enumerate it (the code rejects inline
# directories at entries()-time; Task 8 will add support).  Tests
# access it by inode number.
INLINE_SHORT_TMP="$STAGING/inline_short"
INLINE_OVERFLOW_TMP="$STAGING/inline_overflow"
INLINE_TINY_TMP="$STAGING/inline_tiny"
# Short inline file: 40 bytes, fits entirely in i_block[0..60]
printf '==%036d==' 0 > "$INLINE_SHORT_TMP"
# Overflow inline file: 100 bytes, 60 in i_block + 40 in system.data
python3 -c "import sys; sys.stdout.buffer.write(b'OVER' * 25)" \
    > "$INLINE_OVERFLOW_TMP"
# Content for inline_dir/tiny.txt
printf 'tiny' > "$INLINE_TINY_TMP"
# Inline symlink target (> 60 bytes, overflows into system.data)
INLINE_SYM_TARGET="/some/very/long/path/that/exceeds/sixty/bytes/for-inline-symlink-test"

debugfs -w ext4.img <<DEBUGFS
feature inline_data
write $INLINE_SHORT_TMP inline_short
write $INLINE_OVERFLOW_TMP inline_overflow
symlink /inline_symlink $INLINE_SYM_TARGET
mkdir /inline_dir
cd /inline_dir
write $INLINE_TINY_TMP tiny.txt
cd /
DEBUGFS

# Capture inline_dir inode number before unlinking.
INLINE_DIR_INODE="$(debugfs -R "stat inline_dir" ext4.img 2>&1 \
    | grep -oP '^Inode:\s+\K[0-9]+')"

# Unlink inline_dir from root so walk_dir doesn't encounter it.
debugfs -w ext4.img <<'DEBUGFS'
unlink inline_dir
DEBUGFS

# --- Verify inline data flags (INLINE_DATA_FL = 0x10000000) ---
echo "==> Verifying inline data flags in ext4.img"

verify_inline() {
    local path="$1"
    local label="$2"
    local stat_output
    stat_output="$(debugfs -R "stat $path" ext4.img 2>&1)"
    local flags
    flags="$(echo "$stat_output" \
        | grep -oP 'Flags:\s+\K0x[0-9a-fA-F]+')"
    if [ -z "$flags" ]; then
        echo "FAIL: $label ($path): could not parse inode flags"
        echo "$stat_output"
        exit 1
    fi
    if (( (flags & 0x10000000) == 0 )); then
        echo "FAIL: $label ($path): flags=$flags, missing INLINE_DATA_FL"
        echo "$stat_output"
        exit 1
    fi
    echo "  OK: $label ($path) flags=$flags"
}

verify_inline "inline_short"    "short inline file (40 B)"
verify_inline "inline_overflow"  "overflow inline file (100 B)"
verify_inline "inline_symlink"   "inline symlink (${#INLINE_SYM_TARGET} B target)"

# Verify inline_dir by inode number (unlinked from root).
if [ -z "$INLINE_DIR_INODE" ]; then
    echo "FAIL: could not determine inline_dir inode number"
    exit 1
fi
dir_stat="$(debugfs -R "stat <$INLINE_DIR_INODE>" ext4.img 2>&1)"
dir_flags="$(echo "$dir_stat" | grep -oP 'Flags:\s+\K0x[0-9a-fA-F]+')"
if (( (dir_flags & 0x10000000) == 0 )); then
    echo "FAIL: inline_dir (inode $INLINE_DIR_INODE): flags=$dir_flags, missing INLINE_DATA_FL"
    echo "$dir_stat"
    exit 1
fi
echo "  OK: inline directory (inode $INLINE_DIR_INODE) flags=$dir_flags"

# ===================================================================
# Extended attributes (xattrs) — add to ext4.img
# ===================================================================
echo "==> Adding xattr test fixtures to ext4.img"

# File with a few ibody xattrs (fits in inode)
XATTR_IBODY_TMP="$STAGING/xattr_ibody_content"
printf 'ibody xattr test' > "$XATTR_IBODY_TMP"

# File that will get an external xattr block.  With 256-byte inodes
# and i_extra_isize=32 the ibody region is only 96 bytes (including
# the 4-byte magic).  We fill it with several entries whose combined
# entry+value size exceeds that budget so debugfs must allocate an
# external xattr block.
XATTR_BLOCK_TMP="$STAGING/xattr_block_content"
printf 'block xattr test' > "$XATTR_BLOCK_TMP"

# Generate large-value temporary files for block-overflow xattrs.
# Each value is 60 bytes — four entries like this already exceed the
# ~92-byte ibody capacity once entry headers + names are counted.
for i in 1 2 3 4 5; do
    printf '%060d' "$i" > "$STAGING/xattr_val_$i"
done

debugfs -w ext4.img <<DEBUGFS
write $XATTR_IBODY_TMP xattr_ibody
write $XATTR_BLOCK_TMP xattr_block
ea_set /xattr_ibody user.greeting hello
ea_set /xattr_ibody user.tag important
ea_set /xattr_ibody security.selinux unconfined_t
ea_set -f $STAGING/xattr_val_1 /xattr_block user.attr1
ea_set -f $STAGING/xattr_val_2 /xattr_block user.attr2
ea_set -f $STAGING/xattr_val_3 /xattr_block user.attr3
ea_set -f $STAGING/xattr_val_4 /xattr_block user.attr4
ea_set -f $STAGING/xattr_val_5 /xattr_block user.attr5
DEBUGFS

# --- Verify ibody xattrs ---
echo "==> Verifying xattr fixtures"
XATTR_LIST="$(debugfs -R "ea_list /xattr_ibody" ext4.img 2>&1)"
echo "  xattr_ibody xattrs: $XATTR_LIST"

# --- Verify xattr_block has an external xattr block (i_file_acl != 0) ---
XATTR_BLOCK_STAT="$(debugfs -R "stat /xattr_block" ext4.img 2>&1)"
FILE_ACL="$(echo "$XATTR_BLOCK_STAT" | grep -oP 'File ACL:\s+\K[0-9]+')"
echo "  xattr_block i_file_acl: ${FILE_ACL:-0}"
if [ "${FILE_ACL:-0}" = "0" ]; then
    echo "FAIL: xattr_block must have an external xattr block (i_file_acl != 0)"
    echo "      The xattr values may not be large enough to overflow ibody."
    echo "$XATTR_BLOCK_STAT"
    exit 1
fi
echo "  OK: xattr_block has external xattr block at block ${FILE_ACL}"

XATTR_BLOCK_LIST="$(debugfs -R "ea_list /xattr_block" ext4.img 2>&1)"
echo "  xattr_block xattrs: $XATTR_BLOCK_LIST"

# ===================================================================
# EA_INODE xattr — value stored in a separate inode
# ===================================================================
echo "==> Adding EA_INODE xattr test fixture to ext4.img"

EA_INODE_FILE_TMP="$STAGING/ea_inode_content"
printf 'ea inode host' > "$EA_INODE_FILE_TMP"

# Create a 4096-byte xattr value (exceeds block_size - 32 = 4064).
# This forces debugfs to store the value in a separate EA inode and
# matches the value size asserted in the test fixture.
EA_INODE_VAL_TMP="$STAGING/ea_inode_val"
python3 -c "import sys; sys.stdout.buffer.write(b'X' * 4096)" \
    > "$EA_INODE_VAL_TMP"

debugfs -w ext4.img <<DEBUGFS
write $EA_INODE_FILE_TMP ea_inode_file
ea_set -f $EA_INODE_VAL_TMP /ea_inode_file user.big_value
DEBUGFS

# Verify the EA inode was created
echo "==> Verifying EA_INODE fixture"
EA_INODE_LIST="$(debugfs -R "ea_list /ea_inode_file" ext4.img 2>&1)"
echo "  ea_inode_file xattrs: $EA_INODE_LIST"

# Add a second EA_INODE host file (same big xattr value).  Used as the
# second reference in ea-multi and ea-partial fixtures after byte-patching
# its e_value_inum to share ea_inode_file's EA inode.
EA_INODE_FILE2_TMP="$STAGING/ea_inode_content2"
printf 'ea inode host 2' > "$EA_INODE_FILE2_TMP"

debugfs -w ext4.img <<DEBUGFS
write $EA_INODE_FILE2_TMP ea_inode_file2
ea_set -f $EA_INODE_VAL_TMP /ea_inode_file2 user.big_value
DEBUGFS

echo "==> Verifying EA_INODE fixture 2"
EA_INODE_LIST2="$(debugfs -R "ea_list /ea_inode_file2" ext4.img 2>&1)"
echo "  ea_inode_file2 xattrs: $EA_INODE_LIST2"

# ===================================================================
# Final checksum repair — debugfs mutations invalidate metadata
# checksums. e2fsck -D also rebuilds htree indexes with dx_tail
# checksums and adds dir_entry_tail sentinels to directory blocks.
# ===================================================================
echo "==> Repairing checksums on ext4.img"
e2fsck -f -D -y ext4.img > /dev/null 2>&1 || true

# ===================================================================
# Resolve inode numbers needed for legacy-orphan fixtures.
# ===================================================================
HELLO_INODE="$(debugfs -R "stat /hello.txt" ext4.img 2>&1 \
    | grep -oP '^Inode:\s+\K[0-9]+')"
if [ -z "$HELLO_INODE" ]; then
    echo "FAIL: could not resolve /hello.txt inode number"
    exit 1
fi

XATTR_IBODY_INODE="$(debugfs -R "stat /xattr_ibody" ext4.img 2>&1 \
    | grep -oP '^Inode:\s+\K[0-9]+')"
XATTR_BLOCK_INODE="$(debugfs -R "stat /xattr_block" ext4.img 2>&1 \
    | grep -oP '^Inode:\s+\K[0-9]+')"

TRUNCATE_TARGET_INODE="$(debugfs -R "stat /multiblock.bin" ext4.img 2>&1 \
    | grep -oP '^Inode:\s+\K[0-9]+')"
if [ -z "$TRUNCATE_TARGET_INODE" ]; then
    echo "FAIL: could not resolve /multiblock.bin inode number"
    exit 1
fi

EA_INODE_FILE_INODE="$(debugfs -R "stat /ea_inode_file" ext4.img 2>&1 \
    | grep -oP '^Inode:\s+\K[0-9]+')"
if [ -z "$EA_INODE_FILE_INODE" ]; then
    echo "FAIL: could not resolve /ea_inode_file inode number"
    exit 1
fi

EA_INODE_FILE2_INODE="$(debugfs -R "stat /ea_inode_file2" ext4.img 2>&1 \
    | grep -oP '^Inode:\s+\K[0-9]+')"
if [ -z "$EA_INODE_FILE2_INODE" ]; then
    echo "FAIL: could not resolve /ea_inode_file2 inode number"
    exit 1
fi

# ext4.img is built with -b 4096.
BLOCK_SIZE=4096

export HELLO_INODE XATTR_IBODY_INODE XATTR_BLOCK_INODE
export TRUNCATE_TARGET_INODE BLOCK_SIZE
export EA_INODE_FILE_INODE EA_INODE_FILE2_INODE

# ===================================================================
# Deterministic dirty fixtures — single-bit OR on superblock features.
#
# Only sets clean-state gates (INCOMPAT_RECOVER, RO_COMPAT_ORPHAN_PRESENT).
# Never touches structural feature bits. s_checksum is recomputed so the
# on-disk superblock remains internally consistent.
# ===================================================================

python3 - <<'PY'
import struct, shutil, os

_POLY = 0x82F63B78
_TABLE = []
for n in range(256):
    c = n
    for _ in range(8):
        c = (c >> 1) ^ _POLY if c & 1 else c >> 1
    _TABLE.append(c)

def ext4_crc32c(data: bytes, seed: int = 0xFFFFFFFF) -> int:
    c = seed & 0xFFFFFFFF
    for b in data:
        c = (c >> 8) ^ _TABLE[(c ^ b) & 0xFF]
    return c & 0xFFFFFFFF

SB_OFFSET = 1024
SB_LEN = 1024
S_FEATURE_INCOMPAT = 0x60
S_FEATURE_RO_COMPAT = 0x64
S_CHECKSUM = 0x3FC

INCOMPAT_RECOVER = 0x0000_0004
RO_COMPAT_ORPHAN_PRESENT = 0x0001_0000

def patch(src: str, dst: str, set_incompat: int = 0, set_ro_compat: int = 0) -> None:
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))

        if set_incompat:
            cur = struct.unpack_from("<I", sb, S_FEATURE_INCOMPAT)[0]
            struct.pack_into("<I", sb, S_FEATURE_INCOMPAT, cur | set_incompat)

        if set_ro_compat:
            cur = struct.unpack_from("<I", sb, S_FEATURE_RO_COMPAT)[0]
            struct.pack_into("<I", sb, S_FEATURE_RO_COMPAT, cur | set_ro_compat)

        csum = ext4_crc32c(bytes(sb[:S_CHECKSUM]))
        struct.pack_into("<I", sb, S_CHECKSUM, csum)

        f.seek(SB_OFFSET)
        f.write(bytes(sb))

print("==> Building ext4-dirty-empty.img (RECOVER set, s_start=0 empty journal)")
patch("ext4.img", "ext4-dirty-empty.img", set_incompat=INCOMPAT_RECOVER)

print("==> Building ext4-dirty-orphan.img (RECOVER + ORPHAN_PRESENT)")
patch(
    "ext4.img",
    "ext4-dirty-orphan.img",
    set_incompat=INCOMPAT_RECOVER,
    set_ro_compat=RO_COMPAT_ORPHAN_PRESENT,
)

print("Note: ext4-dirty-v3.img requires manual generation on a Linux VM.")
print("See docs/superpowers/specs/2026-04-22-fs-ext-journal-recovery-design.md for")
print("the fixture requirements (CSUM_V3, 64BIT, REVOKE, committed transactions).")

# ===================================================================
# Legacy-orphan fixtures — inode chain via i_dtime next-pointer.
# ===================================================================
import os, struct, shutil

I_LINKS_COUNT_OFFSET = 0x1A
I_DTIME_OFFSET = 0x14
I_GENERATION_OFFSET = 0x64
I_CHECKSUM_LO_OFFSET = 0x7C
I_CHECKSUM_HI_OFFSET = 0x82

def locate_inode(image_path: str, inum: int) -> tuple[int, int]:
    """Return (inode_byte_offset, inode_size) for a given inum."""
    with open(image_path, "rb") as f:
        f.seek(SB_OFFSET)
        sb = f.read(SB_LEN)
        inodes_per_group = struct.unpack_from("<I", sb, 0x28)[0]
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        block_size = 1024 << struct.unpack_from("<I", sb, 0x18)[0]
        group = (inum - 1) // inodes_per_group
        index_in_group = (inum - 1) % inodes_per_group
        # desc size: 64 bytes when INCOMPAT_64BIT (0x80) is set, else 32
        gdt_offset = (
            (group * 64)
            if (struct.unpack_from("<I", sb, 0x60)[0] & 0x80)
            else (group * 32)
        )
        first_data_block = struct.unpack_from("<I", sb, 0x14)[0]
        gdt_block_base = (first_data_block + 1) * block_size
        f.seek(gdt_block_base + gdt_offset + 0x08)
        inode_table_lo = struct.unpack("<I", f.read(4))[0]
        inode_table_block = inode_table_lo
    return (inode_table_block * block_size + index_in_group * inode_size, inode_size)

def inode_checksum(
    uuid: bytes, inum: int, inode_bytes: bytearray, has_hi: bool
) -> tuple[int, int]:
    seed = ext4_crc32c(uuid)
    crc = ext4_crc32c(struct.pack("<I", inum), seed=seed)
    crc = ext4_crc32c(
        struct.pack("<I", struct.unpack_from("<I", inode_bytes, I_GENERATION_OFFSET)[0]),
        seed=crc,
    )
    buf = bytearray(inode_bytes)
    buf[I_CHECKSUM_LO_OFFSET:I_CHECKSUM_LO_OFFSET + 2] = b"\x00\x00"
    if has_hi and len(buf) > I_CHECKSUM_HI_OFFSET + 1:
        buf[I_CHECKSUM_HI_OFFSET:I_CHECKSUM_HI_OFFSET + 2] = b"\x00\x00"
    crc = ext4_crc32c(bytes(buf), seed=crc)
    lo = crc & 0xFFFF
    hi = (crc >> 16) & 0xFFFF if has_hi else 0
    return (lo, hi)

def patch_legacy_orphan(src: str, dst: str, chain: list[tuple[int, int, int]]) -> None:
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        has_hi = inode_size > 128

        head, _, _ = chain[0]
        struct.pack_into("<I", sb, 0xE8, head)
        csum = ext4_crc32c(bytes(sb[:0x3FC]))
        struct.pack_into("<I", sb, 0x3FC, csum)
        f.seek(SB_OFFSET)
        f.write(bytes(sb))

    for (inum, links_count, next_inum) in chain:
        with open(dst, "r+b") as f:
            (inode_off, _) = locate_inode(dst, inum)
            f.seek(inode_off)
            inode = bytearray(f.read(inode_size))
            struct.pack_into("<H", inode, I_LINKS_COUNT_OFFSET, links_count)
            struct.pack_into("<I", inode, I_DTIME_OFFSET, next_inum)
            (lo, hi) = inode_checksum(uuid, inum, inode, has_hi)
            struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, lo)
            if has_hi:
                struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, hi)
            f.seek(inode_off)
            f.write(bytes(inode))

def patch_orphan_truncate(
    src: str,
    dst: str,
    chain: list[tuple[int, int, int, int]],
) -> None:
    """Build a Level-3 truncate fixture.

    For each (inum, links_count, next_inum, new_size) entry:
    - Sets INCOMPAT_RECOVER + RO_COMPAT_ORPHAN_PRESENT and s_last_orphan on
      the superblock (pointing at the chain head).
    - Patches i_links_count, i_dtime (next-pointer), and i_size_lo/i_size_hi
      on the inode, then recomputes the inode checksum.

    The extent tree is left intact so the apply phase can free blocks past
    the new i_size during truncate completion.
    """
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))

        cur = struct.unpack_from("<I", sb, S_FEATURE_INCOMPAT)[0]
        struct.pack_into("<I", sb, S_FEATURE_INCOMPAT, cur | INCOMPAT_RECOVER)
        cur = struct.unpack_from("<I", sb, S_FEATURE_RO_COMPAT)[0]
        struct.pack_into("<I", sb, S_FEATURE_RO_COMPAT, cur | RO_COMPAT_ORPHAN_PRESENT)

        head_inum = chain[0][0]
        struct.pack_into("<I", sb, 0xE8, head_inum)

        csum = ext4_crc32c(bytes(sb[:S_CHECKSUM]))
        struct.pack_into("<I", sb, S_CHECKSUM, csum)
        f.seek(SB_OFFSET)
        f.write(bytes(sb))

    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb_ro = f.read(SB_LEN)
        uuid = bytes(sb_ro[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb_ro, 0x58)[0]
        has_hi = inode_size > 128

    for (inum, links_count, next_inum, new_size) in chain:
        with open(dst, "r+b") as f:
            (inode_off, _) = locate_inode(dst, inum)
            f.seek(inode_off)
            inode = bytearray(f.read(inode_size))
            struct.pack_into("<H", inode, I_LINKS_COUNT_OFFSET, links_count)
            struct.pack_into("<I", inode, I_DTIME_OFFSET, next_inum)
            struct.pack_into("<I", inode, 0x04, new_size & 0xFFFFFFFF)
            struct.pack_into("<I", inode, 0x6C, (new_size >> 32) & 0xFFFFFFFF)
            (lo, hi) = inode_checksum(uuid, inum, inode, has_hi)
            struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, lo)
            if has_hi:
                struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, hi)
            f.seek(inode_off)
            f.write(bytes(inode))

HELLO = int(os.environ["HELLO_INODE"])
XATTR_IBODY = int(os.environ["XATTR_IBODY_INODE"])
XATTR_BLOCK = int(os.environ["XATTR_BLOCK_INODE"])

print("==> Building ext4-dirty-legacy-unlink.img")
patch_legacy_orphan("ext4.img", "ext4-dirty-legacy-unlink.img",
    chain=[(HELLO, 0, 0)])

print("==> Building ext4-dirty-legacy-truncate.img")
patch_legacy_orphan("ext4.img", "ext4-dirty-legacy-truncate.img",
    chain=[(HELLO, 1, 0)])

print("==> Building ext4-dirty-legacy-cycle.img")
patch_legacy_orphan("ext4.img", "ext4-dirty-legacy-cycle.img",
    chain=[(HELLO, 0, XATTR_IBODY), (XATTR_IBODY, 0, HELLO)])

print("==> Building ext4-dirty-legacy-multi.img")
patch_legacy_orphan("ext4.img", "ext4-dirty-legacy-multi.img",
    chain=[(HELLO, 0, XATTR_IBODY), (XATTR_IBODY, 0, XATTR_BLOCK),
           (XATTR_BLOCK, 0, 0)])

TARGET = int(os.environ["TRUNCATE_TARGET_INODE"])
BLOCK_SIZE = int(os.environ["BLOCK_SIZE"])

print("==> Building ext4-dirty-orphan-truncate-unlink.img")
patch_orphan_truncate("ext4.img", "ext4-dirty-orphan-truncate-unlink.img",
    chain=[(TARGET, 0, 0, 0)])

print("==> Building ext4-dirty-orphan-truncate-partial.img")
patch_orphan_truncate("ext4.img", "ext4-dirty-orphan-truncate-partial.img",
    chain=[(TARGET, 1, 0, BLOCK_SIZE + 1)])

# ===================================================================
# EA-cascade orphan fixtures — Level-3 EA_INODE cascade scenarios.
# ===================================================================

I_FLAGS_OFFSET = 0x20
I_SIZE_LO_OFFSET = 0x04
I_ATIME_OFFSET = 0x08
EA_INODE_FL = 0x00200000

XATTR_MAGIC_INT = 0xEA020000


def resolve_ea_inode_from_host(path: str, host_inum: int) -> int:
    """Return the EA inum referenced by the host's first non-zero e_value_inum entry."""
    with open(path, "rb") as f:
        f.seek(SB_OFFSET)
        sb = f.read(SB_LEN)
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        (inode_off, _) = locate_inode(path, host_inum)
        f.seek(inode_off)
        inode = f.read(inode_size)
    i_extra_isize = struct.unpack_from("<H", inode, 0x80)[0]
    ibody_off = 128 + i_extra_isize
    magic = struct.unpack_from("<I", inode, ibody_off)[0]
    if magic != XATTR_MAGIC_INT:
        raise RuntimeError(f"host inode {host_inum} has no ibody xattrs (magic=0x{magic:08X})")
    pos = ibody_off + 4
    while pos + 16 <= inode_size:
        e_name_len = inode[pos]
        if e_name_len == 0:
            break
        e_value_inum = struct.unpack_from("<I", inode, pos + 4)[0]
        if e_value_inum != 0:
            return e_value_inum
        pos += (16 + e_name_len + 3) & ~3
    raise RuntimeError(f"no EA_INODE reference found in host inode {host_inum}")


def patch_ea_inode_refcount(dst: str, ea_inum: int, refcount: int) -> None:
    """Patch an EA_INODE's refcount using the repo's i_ctime + osd1 encoding.

    refcount = (i_ctime as u64) << 32 | (osd1 as u64).
    Offsets: i_ctime at 0x0C (high 32), osd1 at 0x24 (low 32).
    Recomputes the inode checksum afterward.
    """
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        has_hi = inode_size > 128

        (inode_off, _) = locate_inode(dst, ea_inum)
        f.seek(inode_off)
        inode = bytearray(f.read(inode_size))

        hi = (refcount >> 32) & 0xFFFFFFFF
        lo = refcount & 0xFFFFFFFF
        struct.pack_into("<I", inode, 0x0C, hi)  # i_ctime
        struct.pack_into("<I", inode, 0x24, lo)  # osd1 (l_i_version)

        (c_lo, c_hi) = inode_checksum(uuid, ea_inum, inode, has_hi)
        struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, c_lo)
        if has_hi:
            struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, c_hi)
        f.seek(inode_off)
        f.write(bytes(inode))


def patch_inode_flags(dst: str, inum: int, clear_bits: int = 0, set_bits: int = 0) -> None:
    """Clear and/or set bits in an inode's i_flags (offset 0x20). Recomputes checksum."""
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        has_hi = inode_size > 128

        (inode_off, _) = locate_inode(dst, inum)
        f.seek(inode_off)
        inode = bytearray(f.read(inode_size))

        flags = struct.unpack_from("<I", inode, I_FLAGS_OFFSET)[0]
        flags = (flags & ~clear_bits) | set_bits
        struct.pack_into("<I", inode, I_FLAGS_OFFSET, flags)

        (c_lo, c_hi) = inode_checksum(uuid, inum, inode, has_hi)
        struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, c_lo)
        if has_hi:
            struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, c_hi)
        f.seek(inode_off)
        f.write(bytes(inode))


def patch_inode_size_lo(dst: str, inum: int, new_size: int) -> None:
    """Patch only i_size_lo (offset 0x04) of an inode. Recomputes checksum."""
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        has_hi = inode_size > 128

        (inode_off, _) = locate_inode(dst, inum)
        f.seek(inode_off)
        inode = bytearray(f.read(inode_size))

        struct.pack_into("<I", inode, I_SIZE_LO_OFFSET, new_size & 0xFFFFFFFF)

        (c_lo, c_hi) = inode_checksum(uuid, inum, inode, has_hi)
        struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, c_lo)
        if has_hi:
            struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, c_hi)
        f.seek(inode_off)
        f.write(bytes(inode))


def patch_inode_atime(dst: str, inum: int, new_atime: int) -> None:
    """Patch i_atime (offset 0x08) of an inode. Recomputes checksum."""
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        has_hi = inode_size > 128

        (inode_off, _) = locate_inode(dst, inum)
        f.seek(inode_off)
        inode = bytearray(f.read(inode_size))

        struct.pack_into("<I", inode, I_ATIME_OFFSET, new_atime & 0xFFFFFFFF)

        (c_lo, c_hi) = inode_checksum(uuid, inum, inode, has_hi)
        struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, c_lo)
        if has_hi:
            struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, c_hi)
        f.seek(inode_off)
        f.write(bytes(inode))


def patch_host_xattr_ea_inum(dst: str, host_inum: int, new_ea_inum: int) -> None:
    """Redirect the first non-zero e_value_inum in the host's ibody xattr to new_ea_inum.

    Used to make two host inodes share a single EA inode.  Rewrites the
    xattr entry bytes in-place and recomputes the host inode checksum.
    """
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        has_hi = inode_size > 128

        (inode_off, _) = locate_inode(dst, host_inum)
        f.seek(inode_off)
        inode = bytearray(f.read(inode_size))

    i_extra_isize = struct.unpack_from("<H", inode, 0x80)[0]
    ibody_off = 128 + i_extra_isize
    magic = struct.unpack_from("<I", inode, ibody_off)[0]
    if magic != XATTR_MAGIC_INT:
        raise RuntimeError(f"host inode {host_inum}: no ibody xattrs (magic=0x{magic:08X})")

    pos = ibody_off + 4
    patched = False
    while pos + 16 <= inode_size:
        e_name_len = inode[pos]
        if e_name_len == 0:
            break
        e_value_inum = struct.unpack_from("<I", inode, pos + 4)[0]
        if e_value_inum != 0:
            struct.pack_into("<I", inode, pos + 4, new_ea_inum)
            patched = True
            break
        pos += (16 + e_name_len + 3) & ~3
    if not patched:
        raise RuntimeError(f"host inode {host_inum}: no EA_INODE entry found to redirect")

    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])

        (c_lo, c_hi) = inode_checksum(uuid, host_inum, inode, has_hi)
        struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, c_lo)
        if has_hi:
            struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, c_hi)
        (inode_off, _) = locate_inode(dst, host_inum)
        f.seek(inode_off)
        f.write(bytes(inode))


def build_ea_orphan_fixture(
    src: str,
    dst: str,
    host_inum: int,
    next_inum: int = 0,
    links_count: int = 0,
) -> None:
    """Build a single-host EA-orphan fixture with INCOMPAT_RECOVER + ORPHAN_PRESENT.

    Copies src → dst, sets the superblock orphan-state flags and s_last_orphan,
    then patches host_inum: i_links_count=links_count, i_dtime=next_inum.
    """
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))

        cur = struct.unpack_from("<I", sb, S_FEATURE_INCOMPAT)[0]
        struct.pack_into("<I", sb, S_FEATURE_INCOMPAT, cur | INCOMPAT_RECOVER)
        cur = struct.unpack_from("<I", sb, S_FEATURE_RO_COMPAT)[0]
        struct.pack_into("<I", sb, S_FEATURE_RO_COMPAT, cur | RO_COMPAT_ORPHAN_PRESENT)

        struct.pack_into("<I", sb, 0xE8, host_inum)

        csum = ext4_crc32c(bytes(sb[:S_CHECKSUM]))
        struct.pack_into("<I", sb, S_CHECKSUM, csum)
        f.seek(SB_OFFSET)
        f.write(bytes(sb))

    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb_ro = f.read(SB_LEN)
        uuid = bytes(sb_ro[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb_ro, 0x58)[0]
        has_hi = inode_size > 128

    with open(dst, "r+b") as f:
        (inode_off, _) = locate_inode(dst, host_inum)
        f.seek(inode_off)
        inode = bytearray(f.read(inode_size))
        struct.pack_into("<H", inode, I_LINKS_COUNT_OFFSET, links_count)
        struct.pack_into("<I", inode, I_DTIME_OFFSET, next_inum)
        (lo, hi) = inode_checksum(uuid, host_inum, inode, has_hi)
        struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, lo)
        if has_hi:
            struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, hi)
        f.seek(inode_off)
        f.write(bytes(inode))


HOST = int(os.environ["EA_INODE_FILE_INODE"])
HOST2 = int(os.environ["EA_INODE_FILE2_INODE"])

# Resolve EA inodes from the base image.
EA_INUM = resolve_ea_inode_from_host("ext4.img", HOST)
EA_INUM2 = resolve_ea_inode_from_host("ext4.img", HOST2)
print(f"  EA inode resolution: ea_inode_file host={HOST} ea={EA_INUM}, "
      f"ea_inode_file2 host={HOST2} ea={EA_INUM2}")

# --- Fixture 1: ea-cascade ---
# Host orphaned (links=0), EA refcount=1.  Apply cascades to free the EA inode.
print("==> Building ext4-dirty-orphan-ea-cascade.img")
build_ea_orphan_fixture("ext4.img", "ext4-dirty-orphan-ea-cascade.img",
    host_inum=HOST)

# --- Fixture 2: ea-multi ---
# Two hosts share EA inode (refcount=2), both orphaned.
# Apply: decrement twice → 0 → cascade-free.
print("==> Building ext4-dirty-orphan-ea-multi.img")
build_ea_orphan_fixture("ext4.img", "ext4-dirty-orphan-ea-multi.img",
    host_inum=HOST, next_inum=HOST2)
patch_host_xattr_ea_inum("ext4-dirty-orphan-ea-multi.img", HOST2, EA_INUM)
patch_ea_inode_refcount("ext4-dirty-orphan-ea-multi.img", EA_INUM, 2)
# Also orphan HOST2 (it's the tail of the chain, next=0).
with open("ext4-dirty-orphan-ea-multi.img", "r+b") as f:
    f.seek(SB_OFFSET)
    sb_ro = f.read(SB_LEN)
    uuid = bytes(sb_ro[0x68:0x78])
    inode_size = struct.unpack_from("<H", sb_ro, 0x58)[0]
    has_hi = inode_size > 128
with open("ext4-dirty-orphan-ea-multi.img", "r+b") as f:
    (inode_off, _) = locate_inode("ext4-dirty-orphan-ea-multi.img", HOST2)
    f.seek(inode_off)
    inode = bytearray(f.read(inode_size))
    struct.pack_into("<H", inode, I_LINKS_COUNT_OFFSET, 0)
    struct.pack_into("<I", inode, I_DTIME_OFFSET, 0)
    (lo, hi) = inode_checksum(uuid, HOST2, inode, has_hi)
    struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, lo)
    if has_hi:
        struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, hi)
    f.seek(inode_off)
    f.write(bytes(inode))

# --- Fixture 3: ea-partial ---
# Two hosts share EA inode (refcount=2), only HOST orphaned.
# Apply: decrement once → refcount=1, no cascade.
print("==> Building ext4-dirty-orphan-ea-partial.img")
build_ea_orphan_fixture("ext4.img", "ext4-dirty-orphan-ea-partial.img",
    host_inum=HOST)
patch_host_xattr_ea_inum("ext4-dirty-orphan-ea-partial.img", HOST2, EA_INUM)
patch_ea_inode_refcount("ext4-dirty-orphan-ea-partial.img", EA_INUM, 2)

# --- Fixture 4: ea-missing-flag ---
# HOST orphaned; EA inode's EA_INODE_FL bit cleared.
# Apply: stops with EaInodeMissingFlag.
print("==> Building ext4-dirty-orphan-ea-missing-flag.img")
build_ea_orphan_fixture("ext4.img", "ext4-dirty-orphan-ea-missing-flag.img",
    host_inum=HOST)
patch_inode_flags("ext4-dirty-orphan-ea-missing-flag.img", EA_INUM,
    clear_bits=EA_INODE_FL)

# --- Fixture 5: ea-size-mismatch ---
# HOST orphaned; EA inode's i_size_lo patched to 4096+100=4196 (≠ e_value_size=4096).
# Apply: stops with EaInodeSizeMismatch.
print("==> Building ext4-dirty-orphan-ea-size-mismatch.img")
build_ea_orphan_fixture("ext4.img", "ext4-dirty-orphan-ea-size-mismatch.img",
    host_inum=HOST)
patch_inode_size_lo("ext4-dirty-orphan-ea-size-mismatch.img", EA_INUM, 4096 + 100)

# --- Fixture 6: ea-refcount-zero ---
# HOST orphaned; EA inode refcount patched to 0.
# Apply: stops with EaInodeRefcountZero.
print("==> Building ext4-dirty-orphan-ea-refcount-zero.img")
build_ea_orphan_fixture("ext4.img", "ext4-dirty-orphan-ea-refcount-zero.img",
    host_inum=HOST)
patch_ea_inode_refcount("ext4-dirty-orphan-ea-refcount-zero.img", EA_INUM, 0)

# --- Fixture 7: ea-checksum-invalid ---
# HOST orphaned; EA inode's i_atime (value hash field for METADATA_CSUM) corrupted.
# We write a bogus value and then recompute the *inode* checksum so the inode
# itself is structurally valid — but the EA value hash in i_atime no longer
# matches the actual value bytes, which the apply logic checks.
print("==> Building ext4-dirty-orphan-ea-checksum-invalid.img")
build_ea_orphan_fixture("ext4.img", "ext4-dirty-orphan-ea-checksum-invalid.img",
    host_inum=HOST)
patch_inode_atime("ext4-dirty-orphan-ea-checksum-invalid.img", EA_INUM, 0xDEADBEEF)


def patch_ea_inode_ibody_xattr(dst: str, ea_inum: int) -> None:
    """Plant EXT4_XATTR_MAGIC in the EA inode's ibody region.

    Writes 0xEA020000 at (128 + i_extra_isize) so that the parser populates
    ibody_xattr_data and ea_inode_has_ibody_xattrs returns true.
    Recomputes the inode checksum afterward.
    """
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        has_hi = inode_size > 128

        (inode_off, _) = locate_inode(dst, ea_inum)
        f.seek(inode_off)
        inode = bytearray(f.read(inode_size))
        i_extra_isize = struct.unpack_from("<H", inode, 0x80)[0]
        ibody_off = 128 + i_extra_isize

        # Write EXT4_XATTR_MAGIC at the start of the ibody region.
        struct.pack_into("<I", inode, ibody_off, 0xEA020000)

        (c_lo, c_hi) = inode_checksum(uuid, ea_inum, inode, has_hi)
        struct.pack_into("<H", inode, I_CHECKSUM_LO_OFFSET, c_lo)
        if has_hi:
            struct.pack_into("<H", inode, I_CHECKSUM_HI_OFFSET, c_hi)
        f.seek(inode_off)
        f.write(bytes(inode))


def patch_ea_inode_external_xattr_block(
    dst: str, ea_inum: int, xattr_host_inum: int, new_refcount: int
) -> int:
    """Point ea_inum's i_file_acl_lo at xattr_host_inum's xattr block and set
    that block's h_refcount to new_refcount. Returns the xattr block number.

    Recomputes both the xattr block's h_checksum and the EA inode's checksum.
    """
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        has_hi = inode_size > 128
        block_size = 1024 << struct.unpack_from("<I", sb, 0x18)[0]
        seed = ext4_crc32c(bytes(uuid))

        # Read xattr host's i_file_acl_lo to get the xattr block number.
        (host_off, _) = locate_inode(dst, xattr_host_inum)
        f.seek(host_off)
        host_inode = bytearray(f.read(inode_size))
        xattr_block_num = struct.unpack_from("<I", host_inode, 0x68)[0]
        if xattr_block_num == 0:
            raise RuntimeError(f"host inode {xattr_host_inum} has no external xattr block")

        # Patch EA inode to point at the same xattr block.
        (ea_off, _) = locate_inode(dst, ea_inum)
        f.seek(ea_off)
        ea_inode = bytearray(f.read(inode_size))
        struct.pack_into("<I", ea_inode, 0x68, xattr_block_num)  # i_file_acl_lo

        (c_lo, c_hi) = inode_checksum(uuid, ea_inum, ea_inode, has_hi)
        struct.pack_into("<H", ea_inode, I_CHECKSUM_LO_OFFSET, c_lo)
        if has_hi:
            struct.pack_into("<H", ea_inode, I_CHECKSUM_HI_OFFSET, c_hi)
        f.seek(ea_off)
        f.write(bytes(ea_inode))

        # Patch xattr block h_refcount at offset 0x04 and recompute h_checksum.
        block_off = xattr_block_num * block_size
        f.seek(block_off)
        xattr_block = bytearray(f.read(block_size))
        struct.pack_into("<I", xattr_block, 0x04, new_refcount)  # h_refcount

        # Recompute h_checksum: seed(CRC32C(uuid)) → block_num LE u64 →
        # block[..0x10] (h_checksum zeroed) → 4 zero bytes → block[0x14..].
        xattr_block[0x10:0x14] = b"\x00\x00\x00\x00"
        crc = ext4_crc32c(struct.pack("<Q", xattr_block_num), seed=seed)
        crc = ext4_crc32c(bytes(xattr_block[:0x10]), seed=crc)
        crc = ext4_crc32c(b"\x00\x00\x00\x00", seed=crc)
        crc = ext4_crc32c(bytes(xattr_block[0x14:]), seed=crc)
        struct.pack_into("<I", xattr_block, 0x10, crc)

        f.seek(block_off)
        f.write(bytes(xattr_block))

        return xattr_block_num


def patch_xattr_block_refcount(dst: str, xattr_host_path: str, new_refcount: int) -> int:
    """Patch the h_refcount of the xattr block referenced by xattr_host_path.

    Looks up the host inode via debugfs, reads i_file_acl_lo to get the
    block number, writes new_refcount at offset 0x04 in the block, and
    recomputes h_checksum.  Returns the xattr block number.
    """
    import re, subprocess
    with open(dst, "r+b") as f:
        f.seek(SB_OFFSET)
        sb = bytearray(f.read(SB_LEN))
        uuid = bytes(sb[0x68:0x78])
        inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        block_size = 1024 << struct.unpack_from("<I", sb, 0x18)[0]
        seed = ext4_crc32c(bytes(uuid))

        stat_out = subprocess.check_output(
            ["debugfs", "-R", f"stat {xattr_host_path}", dst],
            stderr=subprocess.DEVNULL,
        ).decode()
        m = re.search(r"^Inode:\s+(\d+)", stat_out, re.MULTILINE)
        if not m:
            raise RuntimeError(f"debugfs stat could not resolve inum for {xattr_host_path}")
        host_inum = int(m.group(1))

        (host_off, _) = locate_inode(dst, host_inum)
        f.seek(host_off)
        host_inode = f.read(inode_size)
        xattr_block_num = struct.unpack_from("<I", host_inode, 0x68)[0]
        if xattr_block_num == 0:
            raise RuntimeError(f"{xattr_host_path} has no external xattr block")

        block_off = xattr_block_num * block_size
        f.seek(block_off)
        xattr_block = bytearray(f.read(block_size))
        struct.pack_into("<I", xattr_block, 0x04, new_refcount)  # h_refcount

        # Recompute h_checksum: seed(CRC32C(uuid)) → block_num LE u64 →
        # block[..0x10] (h_checksum zeroed) → 4 zero bytes → block[0x14..].
        xattr_block[0x10:0x14] = b"\x00\x00\x00\x00"
        crc = ext4_crc32c(struct.pack("<Q", xattr_block_num), seed=seed)
        crc = ext4_crc32c(bytes(xattr_block[:0x10]), seed=crc)
        crc = ext4_crc32c(b"\x00\x00\x00\x00", seed=crc)
        crc = ext4_crc32c(bytes(xattr_block[0x14:]), seed=crc)
        struct.pack_into("<I", xattr_block, 0x10, crc)

        f.seek(block_off)
        f.write(bytes(xattr_block))
        return xattr_block_num


# --- Fixture 8: nested-ref ---
# HOST orphaned; EA inode 536 carries ibody XATTR_MAGIC so
# ea_inode_has_ibody_xattrs returns true → EaInodeNestedReference stop.
print("==> Building ext4-dirty-orphan-ea-nested-ref.img")
build_ea_orphan_fixture("ext4.img", "ext4-dirty-orphan-ea-nested-ref.img",
    host_inum=HOST)
patch_ea_inode_ibody_xattr("ext4-dirty-orphan-ea-nested-ref.img", EA_INUM)

# --- Fixture 9: shared-xattr ---
# HOST orphaned; EA inode 536 has i_file_acl pointing at /xattr_block's block
# with h_refcount=2 → EaInodeSharedXattrBlock stop.
print("==> Building ext4-dirty-orphan-ea-shared-xattr.img")
build_ea_orphan_fixture("ext4.img", "ext4-dirty-orphan-ea-shared-xattr.img",
    host_inum=HOST)
patch_ea_inode_external_xattr_block(
    "ext4-dirty-orphan-ea-shared-xattr.img",
    EA_INUM,
    XATTR_BLOCK,
    new_refcount=2,
)

# ===================================================================
# Shared-xattr-block orphan fixtures — Level-3 §6 items 10-13.
# Host: /xattr_block (external xattr block, h_refcount varies).
# ===================================================================

# --- Fixture 10: exclusive (h_refcount stays at 1) ---
# Host orphaned; xattr block h_refcount=1.
# Apply produces FreeBlock action (block bit cleared in bitmap).
print("==> Building ext4-dirty-orphan-shared-xattr-exclusive.img")
build_ea_orphan_fixture(
    "ext4.img",
    "ext4-dirty-orphan-shared-xattr-exclusive.img",
    host_inum=XATTR_BLOCK,
)
# h_refcount is already 1 after mkfs — no patch needed.

# --- Fixture 11: shared (h_refcount=2, one host orphaned → decrements to 1) ---
# Apply produces SetRefcount { new_refcount: 1 }.
print("==> Building ext4-dirty-orphan-shared-xattr-shared.img")
build_ea_orphan_fixture(
    "ext4.img",
    "ext4-dirty-orphan-shared-xattr-shared.img",
    host_inum=XATTR_BLOCK,
)
patch_xattr_block_refcount(
    "ext4-dirty-orphan-shared-xattr-shared.img",
    "/xattr_block",
    2,
)

# --- Fixture 12: refcount-zero ---
# Host orphaned; xattr block h_refcount patched to 0.
# Apply produces SharedXattrBlockRefcountZero stop.
print("==> Building ext4-dirty-orphan-shared-xattr-refcount-zero.img")
build_ea_orphan_fixture(
    "ext4.img",
    "ext4-dirty-orphan-shared-xattr-refcount-zero.img",
    host_inum=XATTR_BLOCK,
)
patch_xattr_block_refcount(
    "ext4-dirty-orphan-shared-xattr-refcount-zero.img",
    "/xattr_block",
    0,
)

# --- Fixture 13: refcount-overflow ---
# Host orphaned; xattr block h_refcount patched to 0x8000_0000
# (above EXT4_XATTR_REFCOUNT_MAX = 0x4000_0000).
# Apply produces SharedXattrBlockRefcountOverflow stop.
print("==> Building ext4-dirty-orphan-shared-xattr-refcount-overflow.img")
build_ea_orphan_fixture(
    "ext4.img",
    "ext4-dirty-orphan-shared-xattr-refcount-overflow.img",
    host_inum=XATTR_BLOCK,
)
patch_xattr_block_refcount(
    "ext4-dirty-orphan-shared-xattr-refcount-overflow.img",
    "/xattr_block",
    0x8000_0000,
)
PY

# ===================================================================
# ext4-quota.img — RO_COMPAT_QUOTA + RO_COMPAT_PROJECT, all three
# quota inodes populated. Used by the quota-tree parser tests.
# Patcher injects extra dqblk records into the user/group leaf
# blocks so the iterator sees more than mkfs's root-only entries.
# ===================================================================
echo "==> Building ext4-quota.img"
dd if=/dev/zero of=ext4-quota.img bs=1M count=8 status=none
mkfs.ext4 -q \
    -U "55555555-5555-5555-5555-555555555555" \
    -L quota \
    -O quota \
    -E quotatype=usrquota:grpquota:prjquota \
    ext4-quota.img

python3 - <<'PY'
import struct

IMG = "ext4-quota.img"
SB_OFFSET = 1024
SB_LEN = 1024
QBLK_SIZE = 1024
DQDH_SIZE = 16
DQBLK_SIZE = 72

def read_sb_field_u32(sb: bytes, off: int) -> int:
    return struct.unpack_from("<I", sb, off)[0]

def read_sb_field_u16(sb: bytes, off: int) -> int:
    return struct.unpack_from("<H", sb, off)[0]

def locate_inode(image_path: str, inum: int) -> tuple[int, int, int]:
    """Return (inode_byte_offset, inode_size, fs_block_size)."""
    with open(image_path, "rb") as f:
        f.seek(SB_OFFSET)
        sb = f.read(SB_LEN)
    inodes_per_group = read_sb_field_u32(sb, 0x28)
    inode_size = read_sb_field_u16(sb, 0x58)
    block_size = 1024 << read_sb_field_u32(sb, 0x18)
    group = (inum - 1) // inodes_per_group
    index_in_group = (inum - 1) % inodes_per_group
    incompat = read_sb_field_u32(sb, 0x60)
    desc_size = 64 if (incompat & 0x80) else 32
    first_data_block = read_sb_field_u32(sb, 0x14)
    gdt_offset = group * desc_size
    gdt_block_base = (first_data_block + 1) * block_size
    with open(image_path, "rb") as f:
        f.seek(gdt_block_base + gdt_offset + 0x08)
        inode_table_lo = struct.unpack("<I", f.read(4))[0]
    return (inode_table_lo * block_size + index_in_group * inode_size,
            inode_size, block_size)

def quota_inum(field_offset: int) -> int:
    with open(IMG, "rb") as f:
        f.seek(SB_OFFSET + field_offset)
        return struct.unpack("<I", f.read(4))[0]

def file_byte_image_offset(image_path: str, inum: int,
                           file_byte_offset: int) -> int:
    """Map a byte offset in a depth-zero extent file to the image."""
    (off, isize, fs_block_size) = locate_inode(image_path, inum)
    with open(image_path, "rb") as f:
        f.seek(off + 0x28)  # i_block
        i_block = f.read(60)
    # extent header: u16 magic, u16 entries, u16 max, u16 depth, u32 generation
    magic, entries, _max, depth, _gen = struct.unpack_from(
        "<HHHHI", i_block, 0)
    assert magic == 0xF30A, f"expected ext4 extent magic, got {magic:#x}"
    assert depth == 0, "expected depth-zero extent inode for quota tree"

    logical_block, block_offset = divmod(file_byte_offset, fs_block_size)
    for index in range(entries):
        # ext4_extent: u32 ee_block, u16 ee_len, u16 ee_start_hi,
        # u32 ee_start_lo.
        ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from(
            "<IHHI", i_block, 12 + index * 12)
        extent_len = ee_len - 0x8000 if ee_len > 0x8000 else ee_len
        if ee_block <= logical_block < ee_block + extent_len:
            physical_start = (ee_start_hi << 32) | ee_start_lo
            physical_block = physical_start + logical_block - ee_block
            return physical_block * fs_block_size + block_offset

    raise AssertionError(
        f"quota file offset {file_byte_offset} is not extent-mapped")

def patch_quota_leaf(image_path: str, inum: int, leaf_qblk: int,
                     records: list[tuple[int, dict]]) -> None:
    """Append `records` to the leaf at quota-block `leaf_qblk` of the
    quota file at `inum`. Each record is (id, fields) where fields is a
    dict with optional keys curinodes, curspace, isoftlimit, ihardlimit,
    bsoftlimit, bhardlimit, btime, itime."""
    leaf_byte_off = file_byte_image_offset(
        image_path, inum, leaf_qblk * QBLK_SIZE)
    with open(image_path, "r+b") as f:
        f.seek(leaf_byte_off)
        leaf = bytearray(f.read(QBLK_SIZE))
        # dqdh_entries at offset 8 (u16).
        existing = struct.unpack_from("<H", leaf, 8)[0]
        slot = existing
        for (rec_id, fields) in records:
            entry_off = DQDH_SIZE + slot * DQBLK_SIZE
            assert entry_off + DQBLK_SIZE <= QBLK_SIZE, "leaf overflow"
            struct.pack_into("<I", leaf, entry_off + 0x00, rec_id)
            struct.pack_into("<I", leaf, entry_off + 0x04, 0)  # dqb_pad
            struct.pack_into("<Q", leaf, entry_off + 0x08,
                             fields.get("ihardlimit", 0))
            struct.pack_into("<Q", leaf, entry_off + 0x10,
                             fields.get("isoftlimit", 0))
            struct.pack_into("<Q", leaf, entry_off + 0x18,
                             fields.get("curinodes", 0))
            struct.pack_into("<Q", leaf, entry_off + 0x20,
                             fields.get("bhardlimit", 0))
            struct.pack_into("<Q", leaf, entry_off + 0x28,
                             fields.get("bsoftlimit", 0))
            struct.pack_into("<Q", leaf, entry_off + 0x30,
                             fields.get("curspace", 0))
            struct.pack_into("<Q", leaf, entry_off + 0x38,
                             fields.get("btime", 0))
            struct.pack_into("<Q", leaf, entry_off + 0x40,
                             fields.get("itime", 0))
            slot += 1
        struct.pack_into("<H", leaf, 8, slot)
        f.seek(leaf_byte_off)
        f.write(bytes(leaf))

# Quota inum offsets in the superblock.
USR_INUM_OFF = 0x240
GRP_INUM_OFF = 0x244
PRJ_INUM_OFF = 0x26C

usr = quota_inum(USR_INUM_OFF)
grp = quota_inum(GRP_INUM_OFF)
prj = quota_inum(PRJ_INUM_OFF)
assert usr != 0 and grp != 0 and prj != 0, \
    f"expected all three quota inums set; got usr={usr} grp={grp} prj={prj}"

# mkfs.ext4 produces 6 quota-blocks per file with the leaf at qblock 5.
LEAF_QBLK = 5

# usrquota: inject UID 1000 (typical usage) and 1001 (limits set).
patch_quota_leaf(IMG, usr, LEAF_QBLK, [
    (1000, dict(curinodes=5, curspace=12_345_678,
                bsoftlimit=1024, bhardlimit=2048)),
    (1001, dict(curinodes=1, curspace=4096)),
])
# grpquota: inject GID 2000 and 2001.
patch_quota_leaf(IMG, grp, LEAF_QBLK, [
    (2000, dict(curinodes=2, curspace=8192,
                isoftlimit=10, ihardlimit=20)),
    (2001, dict(curinodes=3, curspace=12288)),
])
# prjquota: leave the lone root entry mkfs writes (project ID 0).
PY

# ===================================================================
# ext4-meta-bg.img — META_BG layout, ^FLEX_BG, ^64BIT, metadata_csum on
# Sized for >= 2 metagroups (~40 MiB at -b 1024 -g 1024).
# ===================================================================
echo "==> Building ext4-meta-bg.img"
EXT4_META_BG_STAGE="$STAGING/ext4-meta-bg"
build_common_tree "$EXT4_META_BG_STAGE" "ext4-meta-bg"
make_long_link "$EXT4_META_BG_STAGE"

dd if=/dev/zero of=ext4-meta-bg.img bs=1M count=40 status=none
mkfs.ext4 -q \
    -U "44444444-4444-4444-4444-444444444444" \
    -b 1024 -g 1024 \
    -O 'meta_bg,^flex_bg,^64bit,^resize_inode,metadata_csum' \
    -L meta_bg \
    -d "$EXT4_META_BG_STAGE" \
    ext4-meta-bg.img

# ===================================================================
# ext4-fscrypt.img -- fscrypt v1 + v2 + v2-casefold encrypted dirs.
# Requires sudo + losetup + e4crypt (kernel fscrypt support); skipped
# otherwise. The image is committed to git; this builder regenerates
# it on demand. See README-fscrypt.md for the file layout.
# ===================================================================
build_fscrypt_fixture() {
    local img="ext4-fscrypt.img"
    local uuid="55555555-5555-5555-5555-555555555555"

    if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
        echo "==> Skipping ext4-fscrypt.img (need sudo + loop device + e4crypt; run with proper privileges to generate)"
        return 0
    fi
    if ! command -v losetup >/dev/null 2>&1 \
       || ! command -v e4crypt >/dev/null 2>&1 \
       || ! command -v python3 >/dev/null 2>&1; then
        echo "==> Skipping ext4-fscrypt.img (need sudo + loop device + e4crypt; run with proper privileges to generate)"
        return 0
    fi

    local sudo_cmd=""
    if [ "$(id -u)" -ne 0 ]; then
        sudo_cmd="sudo -n"
        if ! $sudo_cmd true >/dev/null 2>&1; then
            echo "==> Skipping ext4-fscrypt.img (need sudo + loop device + e4crypt; run with proper privileges to generate)"
            return 0
        fi
    fi

    # Adiantum may be a kernel module — try to load before checking.
    # Note: `adiantum(xchacha12,aes)` is a template that the kernel only
    # instantiates on first fscrypt request, so /proc/crypto won't list
    # it pre-flight. Probe for the loadable `adiantum` module instead.
    $sudo_cmd modprobe adiantum 2>/dev/null || true
    if ! { [ -d /sys/module/adiantum ] \
        || grep -qE '^name[[:space:]]*:[[:space:]]*adiantum' /proc/crypto; }; then
        echo "==> Skipping ext4-fscrypt.img (kernel lacks Adiantum support; modprobe failed)"
        return 0
    fi

    echo "==> Building $img"

    # If a previous run failed mid-flight the image may still have a loop
    # device attached and possibly a mountpoint. Detach any loop bound to
    # the image path so mkfs.ext4 doesn't refuse with "is mounted".
    if [ -f "$img" ]; then
        local img_abs
        img_abs="$(realpath "$img")"
        for stale_loop in $($sudo_cmd losetup -j "$img_abs" 2>/dev/null | cut -d: -f1); do
            stale_mounts=$($sudo_cmd findmnt -nr -o TARGET --source "$stale_loop" 2>/dev/null || true)
            for stale_mnt in $stale_mounts; do
                $sudo_cmd umount "$stale_mnt" 2>/dev/null || true
            done
            $sudo_cmd losetup -d "$stale_loop" 2>/dev/null || true
        done
    fi

    dd if=/dev/zero of="$img" bs=1M count=8 status=none
    # `stable_inodes` unlocks IV_INO_LBLK_64 / IV_INO_LBLK_32 policies
    # (kernel `supported_iv_ino_lblk_policy` requires `has_stable_inodes`
    # to return true so the FS promises not to renumber inodes).
    mkfs.ext4 -q \
        -O encrypt,casefold,filetype,extent,64bit,flex_bg,metadata_csum,stable_inodes,^has_journal \
        -E encoding=utf8 \
        -U "$uuid" \
        -N 256 \
        "$img"

    local mnt
    mnt="$(mktemp -d)"
    local loop
    loop="$($sudo_cmd losetup -fP --show "$img")"
    # shellcheck disable=SC2064
    trap "$sudo_cmd umount '$mnt' 2>/dev/null || true; \
          $sudo_cmd losetup -d '$loop' 2>/dev/null || true; \
          rm -rf '$mnt'" RETURN
    $sudo_cmd mount "$loop" "$mnt"

    # Drive policy setup + file population from a Python helper that
    # invokes the FS_IOC_ADD_ENCRYPTION_KEY / FS_IOC_SET_ENCRYPTION_POLICY
    # ioctls directly. Master keys are deterministic SHA-512 derivations
    # of the strings below (see README-fscrypt.md).
    $sudo_cmd env MNT="$mnt" python3 - <<'PY'
import ctypes
import fcntl
import hashlib
import hmac
import os
import struct
import sys

MNT = os.environ["MNT"]

FS_IOC_ADD_ENCRYPTION_KEY    = 0xC0506617  # _IOWR('f', 23, fscrypt_add_key_arg)
FS_IOC_SET_ENCRYPTION_POLICY = 0x800C6613  # _IOR('f', 19, fscrypt_policy)

FSCRYPT_POLICY_V1 = 0
FSCRYPT_POLICY_V2 = 2
FSCRYPT_KEY_DESCRIPTOR_SIZE = 8
FSCRYPT_KEY_IDENTIFIER_SIZE = 16
FSCRYPT_MAX_KEY_SIZE = 64
FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR = 1
FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER = 2
FSCRYPT_MODE_AES_256_XTS = 1
FSCRYPT_MODE_AES_256_CTS = 4
FSCRYPT_MODE_AES_128_CBC = 5
FSCRYPT_MODE_AES_128_CTS = 6
FSCRYPT_MODE_SM4_XTS = 7
FSCRYPT_MODE_SM4_CTS = 8
FSCRYPT_MODE_ADIANTUM = 9
FSCRYPT_MODE_AES_256_HCTR2 = 10
FSCRYPT_POLICY_FLAGS_PAD_16 = 0x02
FSCRYPT_POLICY_FLAG_DIRECT_KEY = 0x04
FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 = 0x08
FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 = 0x10


def derive_master_key(label):
    return hashlib.sha512(label.encode()).digest()[:FSCRYPT_MAX_KEY_SIZE]


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha512).digest()


def hkdf_expand(prk, info, length):
    n = (length + 63) // 64
    t = b""
    out = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        out += t
    return out[:length]


def fscrypt_v2_identifier(master_key):
    salt = b"\x00" * 64
    info = b"fscrypt\x00" + bytes([1])  # HKDF_CONTEXT_KEY_IDENTIFIER
    prk = hkdf_extract(salt, master_key)
    return hkdf_expand(prk, info, FSCRYPT_KEY_IDENTIFIER_SIZE)


def add_key(mount_fd, key_spec_type, raw_key, descriptor_or_id=b""):
    # struct fscrypt_key_specifier { __u32 type; __u32 __reserved;
    #     union { __u8 reserved[32]; __u8 descriptor[8]; __u8 identifier[16]; } u; }
    # Total size: 4 + 4 + 32 = 40.
    spec = bytearray(40)
    struct.pack_into("<I", spec, 0, key_spec_type)
    if descriptor_or_id:
        spec[8 : 8 + len(descriptor_or_id)] = descriptor_or_id
    # struct fscrypt_add_key_arg { fscrypt_key_specifier key_spec;
    #     __u32 raw_size; __u32 key_id; __u32 __reserved[8]; __u8 raw[]; }
    # Header = 40 + 4 + 4 + 32 = 80 bytes; followed by raw_size key bytes.
    arg = bytearray(80 + len(raw_key))
    arg[0:40] = spec
    struct.pack_into("<I", arg, 40, len(raw_key))
    arg[80:] = raw_key
    buf = ctypes.create_string_buffer(bytes(arg), len(arg))
    fcntl.ioctl(mount_fd, FS_IOC_ADD_ENCRYPTION_KEY, buf, True)
    out = bytes(buf.raw)
    # Kernel fills in the identifier for v2 keys (offset 8, 16 bytes).
    return out[8 : 8 + FSCRYPT_KEY_IDENTIFIER_SIZE]


def set_v1_policy(dir_fd, descriptor):
    # struct fscrypt_policy_v1 { __u8 version; __u8 contents_encryption_mode;
    #     __u8 filenames_encryption_mode; __u8 flags; __u8 master_key_descriptor[8]; }
    pol = struct.pack(
        "<BBBB8s",
        FSCRYPT_POLICY_V1,
        FSCRYPT_MODE_AES_256_XTS,
        FSCRYPT_MODE_AES_256_CTS,
        FSCRYPT_POLICY_FLAGS_PAD_16,
        descriptor,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


def set_v2_policy(dir_fd, identifier):
    # struct fscrypt_policy_v2 { __u8 version; __u8 contents_encryption_mode;
    #     __u8 filenames_encryption_mode; __u8 flags;
    #     __u8 log2_data_unit_size; __u8 __reserved[3];
    #     __u8 master_key_identifier[16]; }
    pol = struct.pack(
        "<BBBBB3s16s",
        FSCRYPT_POLICY_V2,
        FSCRYPT_MODE_AES_256_XTS,
        FSCRYPT_MODE_AES_256_CTS,
        FSCRYPT_POLICY_FLAGS_PAD_16,
        0,
        b"\x00\x00\x00",
        identifier,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


def set_v1_adiantum_policy(dir_fd, descriptor):
    # struct fscrypt_policy_v1 { __u8 version; __u8 contents_encryption_mode;
    #     __u8 filenames_encryption_mode; __u8 flags; __u8 master_key_descriptor[8]; }
    # Kernel `fscrypt_valid_enc_modes_v1` whitelists (ADIANTUM, ADIANTUM) on v1.
    pol = struct.pack(
        "<BBBB8s",
        FSCRYPT_POLICY_V1,
        FSCRYPT_MODE_ADIANTUM,
        FSCRYPT_MODE_ADIANTUM,
        FSCRYPT_POLICY_FLAGS_PAD_16,
        descriptor,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


def set_v2_adiantum_policy(dir_fd, identifier):
    pol = struct.pack(
        "<BBBBB3s16s",
        FSCRYPT_POLICY_V2,
        FSCRYPT_MODE_ADIANTUM,
        FSCRYPT_MODE_ADIANTUM,
        FSCRYPT_POLICY_FLAGS_PAD_16,
        0,
        b"\x00\x00\x00",
        identifier,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


def set_v2_iv_ino_lblk_policy(dir_fd, identifier, extra_flag):
    # Inline-crypto modes: AES-256-XTS contents + AES-256-CBC-CTS filenames,
    # with the additional IV_INO_LBLK_64 or IV_INO_LBLK_32 flag set on top
    # of PAD_16.
    pol = struct.pack(
        "<BBBBB3s16s",
        FSCRYPT_POLICY_V2,
        FSCRYPT_MODE_AES_256_XTS,
        FSCRYPT_MODE_AES_256_CTS,
        FSCRYPT_POLICY_FLAGS_PAD_16 | extra_flag,
        0,
        b"\x00\x00\x00",
        identifier,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


def set_v2_sm4_policy(dir_fd, identifier):
    # v2 + (SM4-XTS contents, SM4-CBC-CTS filenames). Per kernel
    # `fscrypt_valid_enc_modes_v2` (lines 88-90) — SM4 is v2-only and
    # the kernel needs CONFIG_CRYPTO_SM4 to accept the policy.
    pol = struct.pack(
        "<BBBBB3s16s",
        FSCRYPT_POLICY_V2,
        FSCRYPT_MODE_SM4_XTS,
        FSCRYPT_MODE_SM4_CTS,
        FSCRYPT_POLICY_FLAGS_PAD_16,
        0,
        b"\x00\x00\x00",
        identifier,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


def set_v2_xts_hctr2_policy(dir_fd, identifier):
    # v2 + (AES-256-XTS contents, AES-256-HCTR2 filenames). Per kernel
    # `fscrypt_valid_enc_modes_v2` (lines 84-86), this is the only
    # fscrypt-supported HCTR2 pair: HCTR2 is the wide-block FILENAMES
    # cipher. Requires kernel ≥ 6.0 with CONFIG_CRYPTO_HCTR2 (and
    # typically CONFIG_CRYPTO_POLYVAL).
    pol = struct.pack(
        "<BBBBB3s16s",
        FSCRYPT_POLICY_V2,
        FSCRYPT_MODE_AES_256_XTS,
        FSCRYPT_MODE_AES_256_HCTR2,
        FSCRYPT_POLICY_FLAGS_PAD_16,
        0,
        b"\x00\x00\x00",
        identifier,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


def set_v2_aes128_policy(dir_fd, identifier):
    # v2 + (AES-128-CBC contents, AES-128-CTS filenames). Kernel
    # `fscrypt_valid_enc_modes_v1` (line 73-75) whitelists the pair, and
    # `_v2` falls through to `_v1`. AES-128-CBC contents under fscrypt
    # is `essiv(cbc(aes))`: per-block CBC IV =
    # AES-256-ECB(SHA-256(content_key))(plain_iv).
    pol = struct.pack(
        "<BBBBB3s16s",
        FSCRYPT_POLICY_V2,
        FSCRYPT_MODE_AES_128_CBC,
        FSCRYPT_MODE_AES_128_CTS,
        FSCRYPT_POLICY_FLAGS_PAD_16,
        0,
        b"\x00\x00\x00",
        identifier,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


def set_v2_direct_key_policy(dir_fd, identifier):
    # v2 + (Adiantum, Adiantum) + DIRECT_KEY (per kernel
    # `supported_direct_key_modes`: contents_mode == filenames_mode AND
    # mode->ivsize >= 24 — Adiantum's 32-byte ivsize qualifies, AES-XTS
    # does not).
    pol = struct.pack(
        "<BBBBB3s16s",
        FSCRYPT_POLICY_V2,
        FSCRYPT_MODE_ADIANTUM,
        FSCRYPT_MODE_ADIANTUM,
        FSCRYPT_POLICY_FLAGS_PAD_16 | FSCRYPT_POLICY_FLAG_DIRECT_KEY,
        0,
        b"\x00\x00\x00",
        identifier,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


def set_v2_dus_policy(dir_fd, identifier, log2_data_unit_size):
    # AES-256-XTS contents + AES-256-CBC-CTS filenames with a non-default
    # log2_data_unit_size — requires kernel ≥ 6.7.
    pol = struct.pack(
        "<BBBBB3s16s",
        FSCRYPT_POLICY_V2,
        FSCRYPT_MODE_AES_256_XTS,
        FSCRYPT_MODE_AES_256_CTS,
        FSCRYPT_POLICY_FLAGS_PAD_16,
        log2_data_unit_size,
        b"\x00\x00\x00",
        identifier,
    )
    fcntl.ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, pol)


mk_v1 = derive_master_key("tracium-fscrypt-v1-fixture")
mk_v1_adiantum = derive_master_key("tracium-fscrypt-v1-adiantum-fixture")
mk_v2 = derive_master_key("tracium-fscrypt-v2-fixture")
mk_v2_cf = derive_master_key("tracium-fscrypt-v2-casefold-fixture")
mk_v2_adiantum = derive_master_key("tracium-fscrypt-v2-adiantum-fixture")
mk_v2_iv64 = derive_master_key("tracium-fscrypt-v2-iv-ino-lblk-64-fixture")
mk_v2_iv32 = derive_master_key("tracium-fscrypt-v2-iv-ino-lblk-32-fixture")
mk_v2_dus512 = derive_master_key("tracium-fscrypt-v2-dus512-fixture")
mk_v2_direct_key = derive_master_key("tracium-fscrypt-v2-direct-key-fixture")
mk_v2_aes128 = derive_master_key("tracium-fscrypt-v2-aes128-fixture")
mk_v2_sm4 = derive_master_key("tracium-fscrypt-v2-sm4-fixture")
mk_v2_hctr2 = derive_master_key("tracium-fscrypt-v2-hctr2-fixture")

mount_fd = os.open(MNT, os.O_RDONLY)
try:
    add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR, mk_v1, b"\xAA" * 8)
    add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR, mk_v1_adiantum, b"\xBB" * 8)

    id_v2_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2)
    id_v2 = fscrypt_v2_identifier(mk_v2)
    if id_v2_kernel != id_v2:
        sys.exit(
            f"v2 identifier mismatch: kernel={id_v2_kernel.hex()} "
            f"python={id_v2.hex()}"
        )

    id_v2_cf_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2_cf)
    id_v2_cf = fscrypt_v2_identifier(mk_v2_cf)
    if id_v2_cf_kernel != id_v2_cf:
        sys.exit(
            f"v2-cf identifier mismatch: kernel={id_v2_cf_kernel.hex()} "
            f"python={id_v2_cf.hex()}"
        )

    id_v2_adi_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2_adiantum)
    id_v2_adi = fscrypt_v2_identifier(mk_v2_adiantum)
    if id_v2_adi_kernel != id_v2_adi:
        sys.exit(
            f"v2 Adiantum identifier mismatch: kernel={id_v2_adi_kernel.hex()} "
            f"python={id_v2_adi.hex()}"
        )

    id_v2_iv64_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2_iv64)
    id_v2_iv64 = fscrypt_v2_identifier(mk_v2_iv64)
    if id_v2_iv64_kernel != id_v2_iv64:
        sys.exit(
            f"v2 IV_INO_LBLK_64 identifier mismatch: kernel={id_v2_iv64_kernel.hex()} "
            f"python={id_v2_iv64.hex()}"
        )

    id_v2_iv32_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2_iv32)
    id_v2_iv32 = fscrypt_v2_identifier(mk_v2_iv32)
    if id_v2_iv32_kernel != id_v2_iv32:
        sys.exit(
            f"v2 IV_INO_LBLK_32 identifier mismatch: kernel={id_v2_iv32_kernel.hex()} "
            f"python={id_v2_iv32.hex()}"
        )

    id_v2_dus_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2_dus512)
    id_v2_dus = fscrypt_v2_identifier(mk_v2_dus512)
    if id_v2_dus_kernel != id_v2_dus:
        sys.exit(
            f"v2 DUS=512 identifier mismatch: kernel={id_v2_dus_kernel.hex()} "
            f"python={id_v2_dus.hex()}"
        )

    id_v2_direct_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2_direct_key)
    id_v2_direct = fscrypt_v2_identifier(mk_v2_direct_key)
    if id_v2_direct_kernel != id_v2_direct:
        sys.exit(
            f"v2 DIRECT_KEY identifier mismatch: kernel={id_v2_direct_kernel.hex()} "
            f"python={id_v2_direct.hex()}"
        )

    id_v2_aes128_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2_aes128)
    id_v2_aes128 = fscrypt_v2_identifier(mk_v2_aes128)
    if id_v2_aes128_kernel != id_v2_aes128:
        sys.exit(
            f"v2 AES-128 identifier mismatch: kernel={id_v2_aes128_kernel.hex()} "
            f"python={id_v2_aes128.hex()}"
        )

    # SM4 needs CONFIG_CRYPTO_SM4. Add the key unconditionally; the
    # per-directory policy ioctl below catches a missing SM4 module via
    # OSError(ENOPKG / EOPNOTSUPP) and skips the fixture dir without
    # failing the whole script.
    id_v2_sm4_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2_sm4)
    id_v2_sm4 = fscrypt_v2_identifier(mk_v2_sm4)
    if id_v2_sm4_kernel != id_v2_sm4:
        sys.exit(
            f"v2 SM4 identifier mismatch: kernel={id_v2_sm4_kernel.hex()} "
            f"python={id_v2_sm4.hex()}"
        )

    # HCTR2 requires kernel ≥ 6.0 + CONFIG_CRYPTO_HCTR2. Same skip-on-
    # missing-module pattern as SM4.
    id_v2_hctr2_kernel = add_key(mount_fd, FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER, mk_v2_hctr2)
    id_v2_hctr2 = fscrypt_v2_identifier(mk_v2_hctr2)
    if id_v2_hctr2_kernel != id_v2_hctr2:
        sys.exit(
            f"v2 HCTR2 identifier mismatch: kernel={id_v2_hctr2_kernel.hex()} "
            f"python={id_v2_hctr2.hex()}"
        )

    # v1 directory.
    v1_dir = os.path.join(MNT, "v1_dir")
    os.mkdir(v1_dir)
    fd = os.open(v1_dir, os.O_RDONLY | os.O_DIRECTORY)
    set_v1_policy(fd, b"\xAA" * 8)
    os.close(fd)
    with open(os.path.join(v1_dir, "hello.txt"), "wb") as f:
        f.write(b"v1 hello\n")
    os.mkdir(os.path.join(v1_dir, "subdir"))
    with open(os.path.join(v1_dir, "subdir", "nested.txt"), "wb") as f:
        f.write(b"v1 nested\n")

    # v1 + Adiantum directory (kernel `fscrypt_valid_enc_modes_v1`
    # accepts the (Adiantum, Adiantum) pair on v1 policies).
    v1_adiantum_dir = os.path.join(MNT, "v1_adiantum_dir")
    os.mkdir(v1_adiantum_dir)
    fd = os.open(v1_adiantum_dir, os.O_RDONLY | os.O_DIRECTORY)
    set_v1_adiantum_policy(fd, b"\xBB" * 8)
    os.close(fd)
    with open(os.path.join(v1_adiantum_dir, "hello.txt"), "wb") as f:
        f.write(b"v1 adiantum hello\n")
    os.symlink("hello.txt", os.path.join(v1_adiantum_dir, "slink"))

    # v2 directory.
    v2_dir = os.path.join(MNT, "v2_dir")
    os.mkdir(v2_dir)
    fd = os.open(v2_dir, os.O_RDONLY | os.O_DIRECTORY)
    set_v2_policy(fd, id_v2)
    os.close(fd)
    with open(os.path.join(v2_dir, "hello.txt"), "wb") as f:
        f.write(b"v2 hello\n")
    os.mkdir(os.path.join(v2_dir, "subdir"))
    with open(os.path.join(v2_dir, "subdir", "nested.txt"), "wb") as f:
        f.write(b"v2 nested\n")
    os.symlink("hello.txt", os.path.join(v2_dir, "slink"))
    # 200-byte plaintext name → 208-byte ciphertext (PAD_16 round-up). Exceeds
    # the 149-byte fscrypt_nokey_name inline slot, so the kernel populates the
    # SHA-256 tail field. fs-ext's no-key encoder mirrors that branch.
    long_nokey_name = b"long_nokey_sha256_test_" + b"X" * 173 + b".bin"
    assert len(long_nokey_name) == 200
    long_nokey_path = os.fsencode(v2_dir) + b"/" + long_nokey_name
    with open(long_nokey_path, "wb") as f:
        f.write(b"v2 long\n")

    # v2 + casefold directory.
    v2_cf_dir = os.path.join(MNT, "v2_cf_dir")
    os.mkdir(v2_cf_dir)
    # Set casefold attr via chattr +F equivalent: FS_IOC_SETFLAGS, EXT4_CASEFOLD_FL = 0x40000000.
    EXT4_CASEFOLD_FL = 0x40000000
    FS_IOC_GETFLAGS = 0x80086601
    FS_IOC_SETFLAGS = 0x40086602
    fd = os.open(v2_cf_dir, os.O_RDONLY | os.O_DIRECTORY)
    flags_buf = ctypes.c_uint(0)
    fcntl.ioctl(fd, FS_IOC_GETFLAGS, flags_buf)
    flags_buf.value |= EXT4_CASEFOLD_FL
    fcntl.ioctl(fd, FS_IOC_SETFLAGS, flags_buf)
    set_v2_policy(fd, id_v2_cf)
    os.close(fd)
    with open(os.path.join(v2_cf_dir, "Hello.TXT"), "wb") as f:
        f.write(b"v2cf hello\n")
    with open(os.path.join(v2_cf_dir, "READ.ME"), "wb") as f:
        f.write(b"v2cf readme\n")

    # v2 + Adiantum directory.
    v2_adiantum_dir = os.path.join(MNT, "v2_adiantum_dir")
    os.mkdir(v2_adiantum_dir)
    fd = os.open(v2_adiantum_dir, os.O_RDONLY | os.O_DIRECTORY)
    set_v2_adiantum_policy(fd, id_v2_adi)
    os.close(fd)
    with open(os.path.join(v2_adiantum_dir, "hello.txt"), "wb") as f:
        f.write(b"adiantum hello\n")
    os.symlink("hello.txt", os.path.join(v2_adiantum_dir, "slink"))

    # v2 + IV_INO_LBLK_64 directory (Android-style inline-crypto policy).
    v2_iv64_dir = os.path.join(MNT, "v2_iv64_dir")
    os.mkdir(v2_iv64_dir)
    fd = os.open(v2_iv64_dir, os.O_RDONLY | os.O_DIRECTORY)
    set_v2_iv_ino_lblk_policy(fd, id_v2_iv64, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64)
    os.close(fd)
    with open(os.path.join(v2_iv64_dir, "hello.txt"), "wb") as f:
        f.write(b"iv64 hello\n")
    os.mkdir(os.path.join(v2_iv64_dir, "subdir"))
    with open(os.path.join(v2_iv64_dir, "subdir", "nested.txt"), "wb") as f:
        f.write(b"iv64 nested\n")
    os.symlink("hello.txt", os.path.join(v2_iv64_dir, "slink"))

    # v2 + IV_INO_LBLK_32 directory (Android-style inline-crypto policy).
    v2_iv32_dir = os.path.join(MNT, "v2_iv32_dir")
    os.mkdir(v2_iv32_dir)
    fd = os.open(v2_iv32_dir, os.O_RDONLY | os.O_DIRECTORY)
    set_v2_iv_ino_lblk_policy(fd, id_v2_iv32, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32)
    os.close(fd)
    with open(os.path.join(v2_iv32_dir, "hello.txt"), "wb") as f:
        f.write(b"iv32 hello\n")
    os.mkdir(os.path.join(v2_iv32_dir, "subdir"))
    with open(os.path.join(v2_iv32_dir, "subdir", "nested.txt"), "wb") as f:
        f.write(b"iv32 nested\n")
    os.symlink("hello.txt", os.path.join(v2_iv32_dir, "slink"))

    # v2 + log2_data_unit_size = 9 (512 B sub-block units on a 4 KiB fs block).
    # Requires kernel ≥ 6.7 — the FS_IOC_SET_ENCRYPTION_POLICY ioctl
    # carries the new field directly, so no e2fsprogs awareness is needed.
    v2_dus512_dir = os.path.join(MNT, "v2_dus512_dir")
    os.mkdir(v2_dus512_dir)
    fd = os.open(v2_dus512_dir, os.O_RDONLY | os.O_DIRECTORY)
    set_v2_dus_policy(fd, id_v2_dus, 9)
    os.close(fd)
    # 4 KiB plaintext = 8 distinct 512 B data units; each must decrypt
    # under its own IV. Use a per-unit-distinct byte pattern so a
    # single-IV-per-fs-block bug would corrupt 7 of the 8 units.
    multi_unit_plaintext = b"".join(bytes([i] * 512) for i in range(8))
    assert len(multi_unit_plaintext) == 4096
    with open(os.path.join(v2_dus512_dir, "multi_unit.bin"), "wb") as f:
        f.write(multi_unit_plaintext)
    with open(os.path.join(v2_dus512_dir, "hello.txt"), "wb") as f:
        f.write(b"dus512 hello\n")

    # v2 + (Adiantum, Adiantum) + DIRECT_KEY directory (older Android
    # Adiantum-on-direct-key configuration). Per kernel
    # `fscrypt_setup_v2_file_key`, the per-file nonce enters via the IV
    # rather than the key derivation; the content/filename keys are the
    # per-mode HKDF derivation (context=DIRECT_KEY=3, info=[mode_num],
    # no FS UUID).
    v2_direct_key_dir = os.path.join(MNT, "v2_direct_key_dir")
    os.mkdir(v2_direct_key_dir)
    fd = os.open(v2_direct_key_dir, os.O_RDONLY | os.O_DIRECTORY)
    set_v2_direct_key_policy(fd, id_v2_direct)
    os.close(fd)
    with open(os.path.join(v2_direct_key_dir, "hello.txt"), "wb") as f:
        f.write(b"direct_key hello\n")
    os.mkdir(os.path.join(v2_direct_key_dir, "subdir"))
    with open(os.path.join(v2_direct_key_dir, "subdir", "nested.txt"), "wb") as f:
        f.write(b"direct_key nested\n")
    os.symlink("hello.txt", os.path.join(v2_direct_key_dir, "slink"))

    # v2 + (AES-128-CBC contents, AES-128-CTS filenames) directory.
    # Older Android (pre-AES-NI) and embedded ext4 still ship this combo.
    # Content cipher uses ESSIV — per-block CBC IV =
    # AES-256-ECB(SHA-256(content_key))(plain_iv).
    v2_aes128_dir = os.path.join(MNT, "v2_aes128_dir")
    os.mkdir(v2_aes128_dir)
    fd = os.open(v2_aes128_dir, os.O_RDONLY | os.O_DIRECTORY)
    set_v2_aes128_policy(fd, id_v2_aes128)
    os.close(fd)
    with open(os.path.join(v2_aes128_dir, "hello.txt"), "wb") as f:
        f.write(b"aes128 hello\n")
    os.mkdir(os.path.join(v2_aes128_dir, "subdir"))
    with open(os.path.join(v2_aes128_dir, "subdir", "nested.txt"), "wb") as f:
        f.write(b"aes128 nested\n")
    os.symlink("hello.txt", os.path.join(v2_aes128_dir, "slink"))

    # v2 + (SM4-XTS contents, SM4-CBC-CTS filenames). Chinese-market
    # devices (and some embedded ext4 deployments) use SM4 as the
    # national-cipher equivalent of AES. Skip gracefully if the kernel
    # lacks CONFIG_CRYPTO_SM4.
    v2_sm4_dir = os.path.join(MNT, "v2_sm4_dir")
    os.mkdir(v2_sm4_dir)
    fd = os.open(v2_sm4_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        set_v2_sm4_policy(fd, id_v2_sm4)
    except OSError as e:
        os.close(fd)
        os.rmdir(v2_sm4_dir)
        print(
            f"==> Skipping v2_sm4_dir: kernel rejected SM4 policy ({e}). "
            "Need CONFIG_CRYPTO_SM4 in the running kernel.",
            file=sys.stderr,
        )
    else:
        os.close(fd)
        with open(os.path.join(v2_sm4_dir, "hello.txt"), "wb") as f:
            f.write(b"sm4 hello\n")
        os.mkdir(os.path.join(v2_sm4_dir, "subdir"))
        with open(os.path.join(v2_sm4_dir, "subdir", "nested.txt"), "wb") as f:
            f.write(b"sm4 nested\n")
        os.symlink("hello.txt", os.path.join(v2_sm4_dir, "slink"))

    # v2 + (AES-256-XTS contents, AES-256-HCTR2 filenames) directory.
    # Android 14+ on inline-crypto SoCs ships this combo. HCTR2 is
    # wide-block, length-preserving, and deterministic for hash-table
    # lookup; XTS keeps the contents path identical to the (XTS, CTS)
    # mainline. Skip gracefully if the kernel lacks CONFIG_CRYPTO_HCTR2.
    v2_hctr2_dir = os.path.join(MNT, "v2_hctr2_dir")
    os.mkdir(v2_hctr2_dir)
    fd = os.open(v2_hctr2_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        set_v2_xts_hctr2_policy(fd, id_v2_hctr2)
    except OSError as e:
        os.close(fd)
        os.rmdir(v2_hctr2_dir)
        print(
            f"==> Skipping v2_hctr2_dir: kernel rejected HCTR2 policy ({e}). "
            "Need kernel >= 6.0 with CONFIG_CRYPTO_HCTR2 / CONFIG_CRYPTO_POLYVAL.",
            file=sys.stderr,
        )
    else:
        os.close(fd)
        with open(os.path.join(v2_hctr2_dir, "hello.txt"), "wb") as f:
            f.write(b"hctr2 hello\n")
        os.mkdir(os.path.join(v2_hctr2_dir, "subdir"))
        with open(os.path.join(v2_hctr2_dir, "subdir", "nested.txt"), "wb") as f:
            f.write(b"hctr2 nested\n")
        os.symlink("hello.txt", os.path.join(v2_hctr2_dir, "slink"))
finally:
    os.close(mount_fd)
PY

    $sudo_cmd umount "$mnt"
    $sudo_cmd losetup -d "$loop"
    rm -rf "$mnt"
    trap - RETURN

    e2fsck -fy "$img" >/dev/null 2>&1 || true
}

build_fscrypt_fixture

# --- summary ---
echo ""
echo "Fixtures generated:"
ls -lh ext2.img ext2-no-filetype.img ext3.img ext4.img ext4-meta-bg.img ext4-quota.img
if [ -f ext4-fscrypt.img ]; then
    ls -lh ext4-fscrypt.img
fi
echo ""
echo "Verifying magic numbers..."
for img in ext2.img ext2-no-filetype.img ext3.img ext4.img ext4-meta-bg.img ext4-quota.img; do
    magic=$(od -A n -t x2 -j 1080 -N 2 "$img" | tr -d ' ')
    echo "  $img magic: 0x$magic"
done
if [ -f ext4-fscrypt.img ]; then
    magic=$(od -A n -t x2 -j 1080 -N 2 ext4-fscrypt.img | tr -d ' ')
    echo "  ext4-fscrypt.img magic: 0x$magic"
fi
