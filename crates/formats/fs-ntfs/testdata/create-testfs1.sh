#!/bin/bash
set -eu

if [ "$(whoami)" != "root" ]; then
    echo "Needs to be run as root!"
    exit 1
fi

# Larger size to accommodate compressed files and edge cases
dd if=/dev/zero of=testfs1 bs=1k count=8192
mkntfs -c 512 -L mylabel -F testfs1

mkdir -p mnt
mount -t ntfs-3g -o loop,compression testfs1 mnt
cd mnt

# Create a file with a specific modification time that we can check.
touch -m -t 202101011337 empty-file
echo "Created: empty-file (with specific mtime)"

# Create a 5-bytes file with resident data.
echo -n 12345 > file-with-12345
echo "Created: file-with-12345 (5 bytes, resident)"

# Create a 1000-bytes file with non-resident data.
for i in {1..200}; do
    echo -n 12345 >> 1000-bytes-file
done
echo "Created: 1000-bytes-file (1000 bytes, non-resident)"

# Create a sparse file with data at the beginning and at the end.
echo -n 12345 > sparse-file
tr '\0' '1' < /dev/zero | dd of=sparse-file seek=500000 bs=1 count=5 2>/dev/null
echo "Created: sparse-file (sparse with data at start and end)"

# Create so many directories that the filesystem needs an INDEX_ROOT and INDEX_ALLOCATION.
mkdir many_subdirs
cd many_subdirs
for i in {1..512}; do
    mkdir "$i"
done
cd ..
echo "Created: many_subdirs/ (512 subdirectories)"

mkdir compressed
# Enable compression on the directory
setfattr -h -v 0x00000800 -n system.ntfs_attrib_be compressed 2>/dev/null || true
echo "Created: compressed/ (compressed directory)"

# Create a small compressed file
echo -n "Hello, compressed world!" > compressed/small-compressed.txt
setfattr -h -v 0x00000800 -n system.ntfs_attrib_be compressed/small-compressed.txt 2>/dev/null || true
echo "Created: compressed/small-compressed.txt"

# Create a larger compressed file with repetitive data (compresses well)
python3 -c "print('A' * 100000, end='')" > compressed/repetitive-compressed.txt 2>/dev/null || \
    perl -e "print 'A' x 100000" > compressed/repetitive-compressed.txt
setfattr -h -v 0x00000800 -n system.ntfs_attrib_be compressed/repetitive-compressed.txt 2>/dev/null || true
echo "Created: compressed/repetitive-compressed.txt (100KB repetitive)"

# Create a compressed file with mixed content (64KB - one compression unit)
dd if=/dev/urandom of=compressed/mixed-compressed.bin bs=1 count=65536 2>/dev/null
setfattr -h -v 0x00000800 -n system.ntfs_attrib_be compressed/mixed-compressed.bin 2>/dev/null || true
echo "Created: compressed/mixed-compressed.bin (64KB pattern)"

# Create a multi-unit compressed file (192KB - 3 compression units)
dd if=/dev/zero of=compressed/large-compressed.bin bs=1 count=196608 2>/dev/null
setfattr -h -v 0x00000800 -n system.ntfs_attrib_be compressed/large-compressed.bin 2>/dev/null || true
echo "Created: compressed/large-compressed.bin (192KB, 3 units)"

mkdir edge-cases

# File with very long name (close to 255 char limit)
LONG_NAME=$(printf 'a%.0s' {1..200}).txt
touch "edge-cases/$LONG_NAME"
echo "long filename test" > "edge-cases/$LONG_NAME"
echo "Created: edge-cases/$LONG_NAME"

# File with unicode characters in name
touch "edge-cases/unicode-名前-имя-🎉.txt"
echo "unicode filename test" > "edge-cases/unicode-名前-имя-🎉.txt"
echo "Created: edge-cases/unicode-名前-имя-🎉.txt"

# Empty directory
mkdir edge-cases/empty-directory
echo "Created: edge-cases/empty-directory/"

# Deeply nested directory structure
DEEP_PATH="edge-cases"
for i in {1..10}; do
    DEEP_PATH="$DEEP_PATH/level$i"
    mkdir -p "$DEEP_PATH"
done
echo "deeply nested file" > "$DEEP_PATH/deep-file.txt"
echo "Created: edge-cases/level1/.../level10/deep-file.txt"

# File with alternate data stream (ADS) - ntfs-3g supports this
echo "main stream content" > edge-cases/file-with-ads.txt
# ADS creation with ntfs-3g
setfattr -n user.hidden -v "alternate stream content" edge-cases/file-with-ads.txt 2>/dev/null || true
echo "Created: edge-cases/file-with-ads.txt (with ADS attempt)"

# Read-only file
echo "read only content" > edge-cases/readonly-file.txt
chmod 444 edge-cases/readonly-file.txt
echo "Created: edge-cases/readonly-file.txt"

# Hidden file (NTFS hidden attribute)
echo "hidden content" > edge-cases/hidden-file.txt
setfattr -h -v 0x00000002 -n system.ntfs_attrib_be edge-cases/hidden-file.txt 2>/dev/null || true
echo "Created: edge-cases/hidden-file.txt"

# System file (NTFS system attribute)
echo "system content" > edge-cases/system-file.txt
setfattr -h -v 0x00000004 -n system.ntfs_attrib_be edge-cases/system-file.txt 2>/dev/null || true
echo "Created: edge-cases/system-file.txt"

# File exactly at cluster boundary (512 bytes)
dd if=/dev/urandom of=edge-cases/cluster-boundary.bin bs=1 count=512 2>/dev/null
echo "Created: edge-cases/cluster-boundary.bin (512 bytes)"

# Zero-byte file
touch edge-cases/zero-bytes.bin
echo "Created: edge-cases/zero-bytes.bin (0 bytes)"

echo ""
echo "All test files created successfully!"

cd ..
umount mnt
rmdir mnt

echo ""
echo "Test filesystem created at: testfs1"
