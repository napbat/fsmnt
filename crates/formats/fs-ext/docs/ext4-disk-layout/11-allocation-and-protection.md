<!-- Allocation and Protection -->
<!-- MMP, encryption, verity, bigalloc, resize inode, and quota features. -->

# Allocation and Protection

This file documents ext4 features related to allocation strategies and data protection:
multiple mount protection (MMP), per-inode encryption, fs-verity, cluster-based allocation
(bigalloc), online resize support, and quota tracking.

## Multiple Mount Protection (MMP)

MMP prevents multiple nodes from mounting the same filesystem read-write simultaneously,
which would cause catastrophic corruption. Enabled by `INCOMPAT_MMP` in
**s_feature_incompat** (see [02-feature-flags.md](02-feature-flags.md)).

The MMP block is located at the block number stored in **s_mmp_block** (superblock offset
`0x178`). The block contains a 1024-byte `mmp_struct`:

### mmp_struct Field Layout

| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| `0x0` | 4 | `__le32` | **mmp_magic** | Magic number: `0x004D4D50` (ASCII "MMP\0") |
| `0x4` | 4 | `__le32` | **mmp_seq** | Sequence number, updated periodically by the mounting node |
| `0x8` | 8 | `__le64` | **mmp_time** | Time of last MMP update (seconds since epoch) |
| `0x10` | 64 | `char[64]` | **mmp_nodename** | Hostname of the node holding the mount (null-terminated) |
| `0x50` | 32 | `char[32]` | **mmp_bdevname** | Block device name (e.g., `/dev/sda1`, null-terminated) |
| `0x70` | 2 | `__le16` | **mmp_check_interval** | Recheck interval in seconds |
| `0x72` | 2 | `__le16` | **mmp_pad1** | Padding |
| `0x74` | 904 | `__le32[226]` | **mmp_pad2** | Padding (reserved for future use) |
| `0x3FC` | 4 | `__le32` | **mmp_checksum** | CRC32C checksum (see [09-checksumming.md](09-checksumming.md)) |

### MMP Sequence Protocol

The mounting node increments **mmp_seq** and writes the MMP block at regular intervals
(controlled by **mmp_check_interval**). A second node attempting to mount reads the MMP block,
waits for the check interval, then reads again. If **mmp_seq** changed, another node is
actively mounted and the second mount is refused.

### Special Sequence Values

| Name | Value | Description |
|------|-------|-------------|
| `EXT4_MMP_SEQ_CLEAN` | `0xFF4D4D50` | Filesystem was cleanly unmounted. Safe to mount. |
| `EXT4_MMP_SEQ_FSCK` | `0xE24D4D50` | fsck is running on the filesystem. Do not mount. |

Any other value in **mmp_seq** indicates an active mount. The kernel uses sequence numbers in
the range `1`..`0xFFFFFF00` during normal operation.

## Encryption

Per-inode filesystem encryption (fscrypt) protects file contents and filenames at rest.
Enabled by `INCOMPAT_ENCRYPT` in **s_feature_incompat**.

### Superblock Fields

| Superblock field | Offset | Size | Description |
|-----------------|--------|------|-------------|
| **s_encrypt_algos[4]** | `0x174` | 4 bytes | Encryption algorithm codes in use on this filesystem |
| **s_encrypt_pw_salt[16]** | `0x178` | 16 bytes | Salt for key derivation (string-to-key) |

### Encryption Algorithm Codes

Algorithm codes are defined in `include/uapi/linux/fscrypt.h`:

| Code | Name | Usage |
|------|------|-------|
| `1` | AES-256-XTS | File contents encryption |
| `2` | AES-256-CTS-CBC | Filename encryption |
| `3` | Adiantum | Contents and filenames (ARM devices without AES hardware) |
| `4` | AES-256-HCTR2 | Filename encryption (wide-block cipher) |
| `9` | SM4-XTS | File contents encryption (Chinese national standard) |
| `10` | SM4-CTS-CBC | Filename encryption (Chinese national standard) |

The **s_encrypt_algos** array records which algorithms are active on the filesystem. Each byte
holds one algorithm code. Unused slots are zero.

### Per-Inode Encryption

Encrypted inodes have `ENCRYPT_FL` (`0x800`) set in **i_flags** (see
[04-inodes.md](04-inodes.md)). The encryption policy — specifying algorithm, key descriptor,
flags, and key derivation parameters — is stored as an extended attribute under the name
`security.fscrypt` (see [07-extended-attributes.md](07-extended-attributes.md)).

Key derivation and per-file key wrapping are handled by the kernel's fscrypt subsystem. The
on-disk format stores only the encryption policy reference. A forensic parser cannot decrypt
file contents without the master key, but can identify encrypted inodes and read the policy
xattr to determine the algorithm and key identifier.

Encrypted directories store ciphertext filenames. Directory entries in encrypted directories
have padded name lengths (rounded up to the next multiple of 16 bytes for AES-based ciphers,
or 32 bytes for Adiantum). Encrypted symlinks store the ciphertext target in **i_block** (short
symlinks) or data blocks (long symlinks).

## Verity

fs-verity provides read-only integrity verification for individual files using Merkle hash
trees. Enabled by `RO_COMPAT_VERITY` (`0x8000`) in **s_feature_ro_compat** (Linux 5.4+).

### Inode Flag

Verity-enabled inodes have `VERITY_FL` (`0x100000`) set in **i_flags**. Once set, this flag
is immutable — the file becomes read-only.

### On-Disk Layout

After the file's regular data blocks, the filesystem appends:
1. The Merkle hash tree (hash blocks organized bottom-up, leaf level first)
2. An `fsverity_descriptor` structure containing the hash algorithm, data size, root hash,
   and signature

As a result, the inode's allocated block count exceeds what **i_size** alone would require.
A forensic parser must recognize `VERITY_FL` inodes to avoid interpreting Merkle tree blocks
as ordinary file data. The true file data size is **i_size**; blocks beyond that offset
contain integrity metadata.

## Bigalloc

Cluster-based allocation groups multiple contiguous blocks into a single allocation unit
(cluster), reducing metadata overhead for large filesystems. Enabled by `RO_COMPAT_BIGALLOC`
in **s_feature_ro_compat**.

### Cluster Size

```
cluster_size = 2^(10 + s_log_cluster_size) bytes
```

The superblock field **s_log_cluster_size** (offset `0x28`) determines the cluster size. When
bigalloc is not enabled, **s_log_cluster_size** must equal **s_log_block_size** (one block per
cluster).

### Allocation Implications

With bigalloc:
- **s_clusters_per_group** replaces **s_blocks_per_group** for allocation accounting. Each
  group's block bitmap tracks clusters rather than individual blocks.
- Block group sizes scale up. For example, with 4 KiB blocks and 64 KiB clusters (16
  blocks/cluster), each bitmap bit covers 64 KiB.
- Extent tree leaf entries (**ee_block**, **ee_len**) still use block-granularity logical
  offsets, but the allocator operates at cluster granularity.
- **i_blocks** counts may reflect cluster-aligned allocation.

See [03-block-groups.md](03-block-groups.md) for bitmap and group descriptor details and
[04-inodes.md](04-inodes.md) for **i_blocks** encoding.

## Resize Inode

Online filesystem resize is supported through reserved group descriptor table (GDT) space.

### Special Inode

Inode 7 is the "reserved group descriptors" inode. It holds indirect blocks that reserve space
in each block group for future group descriptor table growth. See
[04-inodes.md](04-inodes.md) for the special inode table.

### Superblock Field

| Superblock field | Offset | Description |
|-----------------|--------|-------------|
| **s_reserved_gdt_blocks** | `0xCE` | Number of blocks reserved per group for GDT expansion |

The reserved GDT blocks are allocated but contain no user data. They sit between the group
descriptor table and the block bitmap in each block group that has a superblock backup (see
[03-block-groups.md](03-block-groups.md) for block group layout). A parser encountering these
blocks should treat them as metadata, not free space or user data.

Online resize (`resize2fs`) grows the filesystem by populating reserved GDT blocks with new
group descriptors and updating the superblock's block/group counts.

## Quotas

Ext4 supports per-user, per-group, and per-project disk usage tracking through special quota
inodes.

### Quota Inodes

| Quota type | Inode | Source |
|-----------|-------|--------|
| User quota | inode 3 | Special inode (hardcoded) |
| Group quota | inode 4 | Special inode (hardcoded) |
| Project quota | **s_prj_quota_inum** | Superblock field (offset `0x26C`) |

### Feature Flags

| Flag | Value | Location | Description |
|------|-------|----------|-------------|
| `RO_COMPAT_QUOTA` | `0x100` | **s_feature_ro_compat** | Journaled quota tracking enabled |
| `RO_COMPAT_PROJECT` | `0x2000` | **s_feature_ro_compat** | Project quota tracking enabled |

### Scope

The quota inodes store VFS-level v2 quota file data. The internal format of quota files (quota
tree structure, dquot entries) is defined by the Linux VFS quota subsystem, not by ext4 itself.
Documenting the quota file internal format is out of scope for the ext4 disk layout reference.

A forensic parser can identify quota inodes and recognize that their data blocks contain quota
accounting records, but interpreting the records requires VFS quota format knowledge.
