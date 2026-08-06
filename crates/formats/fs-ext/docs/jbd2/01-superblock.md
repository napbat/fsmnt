<!-- jbd2: Superblock -->
<!-- journal_superblock_s field table, feature flags, v1 vs v2, checksum type codes -->

# jbd2: Superblock

The journal superblock occupies the first block of the journal (logical block 0). All fields are
**big-endian**. The block size equals the journal device block size, which typically matches the
filesystem block size (commonly 4096 bytes).

## journal_superblock_s

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | 12 | s_header | `journal_header_t`: **h_magic** (`0xC03B3998`), **h_blocktype** (3 = v1, 4 = v2), **h_sequence** (first transaction sequence number at creation time). Each sub-field is `__be32`. |
| 0xC | `__be32` | s_blocksize | Journal device block size in bytes. Must be a power of 2 between 1024 and 65536. |
| 0x10 | `__be32` | s_maxlen | Total number of blocks in the journal (including the superblock itself). |
| 0x14 | `__be32` | s_first | Block number of the first usable log block (first block after the superblock). |
| 0x18 | `__be32` | s_sequence | Expected sequence number of the first transaction to replay. Updated on checkpoint. |
| 0x1C | `__be32` | s_start | Block number of the start of the log (oldest uncheckpointed transaction). A zero value is used when the journal is marked empty, but it is not a reliable standalone proof that the journal is clean. |
| 0x20 | `__be32` | s_errno | Error number from the last failed journal operation. Non-zero indicates the journal needs recovery or repair. |
| 0x24 | `__be32` | s_feature_compat | Compatible feature flags. See [Compatible features](#compatible-features). |
| 0x28 | `__be32` | s_feature_incompat | Incompatible feature flags. See [Incompatible features](#incompatible-features). |
| 0x2C | `__be32` | s_feature_ro_compat | Read-only compatible feature flags. Currently no flags defined. |
| 0x30 | `__u8[16]` | s_uuid | 128-bit UUID identifying this journal. Used as input to checksum calculations and to match the journal to its filesystem. |
| 0x40 | `__be32` | s_nr_users | Number of filesystems sharing this journal. Typically 1. Values greater than 1 indicate a shared external journal. |
| 0x44 | `__be32` | s_dynsuper | Block number of the dynamic copy of the superblock. Zero if unused. |
| 0x48 | `__be32` | s_max_transaction | Maximum number of blocks allowed in a single transaction. Zero means no explicit limit (bounded by journal size). |
| 0x4C | `__be32` | s_max_trans_data | Maximum number of data blocks allowed per transaction. Zero means no explicit limit. |
| 0x50 | `__u8` | s_checksum_type | Checksum algorithm type. See [Checksum type](#checksum-type). |
| 0x51 | `__u8[3]` | s_padding2 | Reserved, must be zero. |
| 0x54 | `__be32` | s_num_fc_blocks | Number of blocks reserved for fast commits at the end of the journal. Zero if fast commits are not enabled. See [04-fast-commits.md](04-fast-commits.md). |
| 0x58 | `__be32` | s_head | Block number of the journal head (first unused block). Enables the kernel to resume writing without scanning the entire journal. V2 only. |
| 0x5C | `__u32[40]` | s_padding | Reserved padding (160 bytes), must be zero. |
| 0xFC | `__be32` | s_checksum | CRC32C checksum of the entire superblock with this field zeroed. Present in v2 superblocks when CSUM_V2 or CSUM_V3 is enabled. |
| 0x100 | `__u8[768]` | s_users | Array of 128-bit UUIDs identifying filesystems that share this journal. Each UUID is 16 bytes; the array holds up to 48 entries (768 / 16). Only the first **s_nr_users** entries are valid. |

The superblock occupies bytes `0x0` through `0x3FF` (1024 bytes of defined fields). The
remainder of the block (up to **s_blocksize**) is unused.

## Compatible features

| Flag | Value | Description |
|------|-------|-------------|
| JBD2_FEATURE_COMPAT_CHECKSUM | `0x1` | CRC32 checksums on data blocks. A single CRC32 of all data blocks in a transaction is stored in the commit block's **h_chksum[0]**. This is generation 1 checksumming. See [05-checksumming.md](05-checksumming.md). |

## Incompatible features

| Flag | Value | Description |
|------|-------|-------------|
| JBD2_FEATURE_INCOMPAT_REVOKE | `0x1` | Journal contains revocation records. Required for correct replay. See [03-revocation.md](03-revocation.md). |
| JBD2_FEATURE_INCOMPAT_64BIT | `0x2` | 64-bit block numbers. Block tags include **t_blocknr_high** for the upper 32 bits. Revocation blocks contain 8-byte block numbers instead of 4-byte. |
| JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT | `0x4` | Commit blocks are written without waiting for data block I/O to complete. Checksums are the sole integrity guarantee. Requires CSUM_V2 or CSUM_V3. |
| JBD2_FEATURE_INCOMPAT_CSUM_V2 | `0x8` | Per-block CRC32C checksums (generation 2). Uses `journal_block_tag_s` with 16-bit **t_checksum**. Adds descriptor block tails, revocation block tails, and commit block checksums. Mutually exclusive with CSUM_V3. See [05-checksumming.md](05-checksumming.md). |
| JBD2_FEATURE_INCOMPAT_CSUM_V3 | `0x10` | Per-block CRC32C checksums (generation 3). Uses `journal_block_tag3_s` with full 32-bit **t_checksum**. Otherwise identical to CSUM_V2. Mutually exclusive with CSUM_V2. Current default for new filesystems. See [05-checksumming.md](05-checksumming.md). |
| JBD2_FEATURE_INCOMPAT_FAST_COMMIT | `0x20` | Fast commit support. **s_num_fc_blocks** reserves space at the end of the journal for lightweight TLV-encoded operations. See [04-fast-commits.md](04-fast-commits.md). |

## Checksum type

The **s_checksum_type** field specifies the algorithm used for per-block checksums (CSUM_V2 and
CSUM_V3) and the superblock checksum:

| Value | Constant | Algorithm | Status |
|-------|----------|-----------|--------|
| 1 | `JBD2_CRC32_CHKSUM` | CRC32 | Used by the older COMPAT_CHECKSUM generation. |
| 2 | `JBD2_MD5_CHKSUM` | MD5 | Defined but **never implemented** in the kernel. |
| 3 | `JBD2_SHA1_CHKSUM` | SHA-1 | Defined but **never implemented** in the kernel. |
| 4 | `JBD2_CRC32C_CHKSUM` | CRC32C (Castagnoli) | Used by CSUM_V2 and CSUM_V3, and by modern ext4 journals in practice. |

The important parser distinction is between **CRC32** (used by COMPAT_CHECKSUM generation 1)
and **CRC32C** (used by CSUM_V2 and CSUM_V3). A parser must not treat checksum code `1`
and checksum code `4` as interchangeable.

## v1 vs v2

The journal superblock version is indicated by **h_blocktype** in the header:

| h_blocktype | Version | Fields present |
|-------------|---------|----------------|
| 3 | v1 | Only static geometry fields: **s_blocksize** through **s_errno** (offsets `0xC`–`0x20`). Feature flags, UUID, checksum, and sharing fields are absent or undefined. |
| 4 | v2 | All fields defined in the table above. Feature flags, UUID, checksum type, fast commit count, head pointer, and sharing array are valid. |

Modern ext4 always creates a **v2** journal superblock. A v1 superblock may be encountered on
legacy ext3 filesystems that predate feature flag support.

## Superblock checksum

When CSUM_V2 or CSUM_V3 is enabled, **s_checksum** at offset `0xFC` contains a CRC32C
checksum computed over the entire superblock with the **s_checksum** field itself set to zero during
calculation. The algorithm is determined by **s_checksum_type**, which must be `4`
(`JBD2_CRC32C_CHKSUM`) under CSUM_V2 or CSUM_V3. See the checksum type table above.
