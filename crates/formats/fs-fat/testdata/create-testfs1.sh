#!/bin/bash
set -euo pipefail

if [ "$(whoami)" != "root" ]; then
    echo "Needs to be run as root!"
    exit 1
fi

# Change to the directory containing this script
cd "$(dirname "$0")"

cleanup() {
    cd "$(dirname "$0")"
    umount mnt 2>/dev/null || true
    rmdir mnt 2>/dev/null || true
}
trap cleanup EXIT

# Create a 34MB FAT32 image with 512-byte clusters.
# FAT32 detection requires >= 65525 clusters. At 512 bytes/cluster
# this needs ~32MB. Using 34MB provides margin.
# The image is gitignored — regenerate with this script.
dd if=/dev/zero of=testfs1 bs=1M count=34
mkfs.fat -F 32 -s 1 -n TESTFAT32 testfs1

mkdir -p mnt
mount -o loop testfs1 mnt
cd mnt

# --- Simple files ---

# Small file with known content
echo -n "Hello, FAT32!" > hello.txt
echo "Created: hello.txt (13 bytes)"

# Empty file
touch empty-file
echo "Created: empty-file (0 bytes)"

# File with exactly 512 bytes (one sector)
dd if=/dev/urandom of=sector-size.bin bs=1 count=512 2>/dev/null
echo "Created: sector-size.bin (512 bytes)"

# File with known repeating pattern (1000 bytes)
for i in $(seq 1 200); do
    echo -n "12345" >> pattern-file.dat
done
echo "Created: pattern-file.dat (1000 bytes)"

# Larger file spanning multiple clusters
dd if=/dev/urandom of=multi-cluster.bin bs=1k count=64 2>/dev/null
echo "Created: multi-cluster.bin (64 KB)"

# --- Directory structure ---

# Simple subdirectory with a file
mkdir docs
echo "This is a readme." > docs/README.TXT
echo "Created: docs/README.TXT"

# Nested directories (3 levels)
mkdir -p projects/rust/src
echo "fn main() {}" > projects/rust/src/main.rs
echo "Created: projects/rust/src/main.rs"

# Empty directory
mkdir empty-dir
echo "Created: empty-dir/"

# --- Edge cases ---

mkdir edge-cases

# File with long filename (triggers LFN entries)
echo "long filename test" > "edge-cases/this-is-a-very-long-filename-that-requires-lfn-entries.txt"
echo "Created: edge-cases/this-is-a-very-long-filename-that-requires-lfn-entries.txt"

# File with spaces in name
echo "spaces content" > "edge-cases/file with spaces.txt"
echo "Created: edge-cases/file with spaces.txt"

# File with mixed case (FAT is case-insensitive for 8.3, LFN preserves case)
echo "mixed case" > "edge-cases/MiXeD-CaSe.TxT"
echo "Created: edge-cases/MiXeD-CaSe.TxT"

# File with lowercase extension (tests SFN case bits)
echo "lower ext" > "edge-cases/test.txt"
echo "Created: edge-cases/test.txt"

# Many files in one directory
mkdir many-files
for i in $(seq -w 1 50); do
    echo "file $i" > "many-files/file-$i.txt"
done
echo "Created: many-files/ (50 files)"

echo ""
echo "All test files created successfully!"

cd ..
umount mnt
rmdir mnt

echo ""
echo "Test filesystem created at: testfs1"
