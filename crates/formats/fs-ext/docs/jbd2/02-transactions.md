<!-- jbd2: Transactions -->
<!-- Transaction lifecycle, common header, descriptor/data/commit blocks, block tags, replay -->

# jbd2: Transactions

A transaction is the fundamental unit of journaling. On disk, a transaction consists of one or more
descriptor blocks, each followed by its data blocks, and terminated by a single commit block.
Revocation blocks (see [03-revocation.md](03-revocation.md)) may also appear within a
transaction. All structures in this file are **big-endian**.

## Common header: journal_header_s

Every journal metadata block (descriptor, commit, revocation, superblock) begins with a 12-byte
header:

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__be32` | h_magic | Journal magic number: `0xC03B3998`. Identifies the block as a journal metadata block. |
| 0x4 | `__be32` | h_blocktype | Block type. See [Block types](#block-types). |
| 0x8 | `__be32` | h_sequence | Transaction sequence number this block belongs to. |

## Block types

| Value | Type | Description |
|-------|------|-------------|
| 1 | Descriptor | Contains block tags mapping data blocks to filesystem destinations. |
| 2 | Commit | Marks the end of a transaction. |
| 3 | Superblock v1 | Journal superblock, legacy format. See [01-superblock.md](01-superblock.md). |
| 4 | Superblock v2 | Journal superblock, modern format. See [01-superblock.md](01-superblock.md). |
| 5 | Revocation | Lists filesystem blocks whose prior journal writes should not be replayed. See [03-revocation.md](03-revocation.md). |

## Transaction lifecycle

A single transaction on disk follows this structure:

```
[Descriptor block] [Data block 1] [Data block 2] ... [Data block N]
[Descriptor block] [Data block N+1] ...                              (optional)
[Revocation block]                                                    (optional)
[Commit block]
```

Multiple descriptor blocks may appear in one transaction if the number of tags exceeds what fits
in a single block. Revocation blocks may appear anywhere within the transaction before the commit
block. A transaction is only valid for replay if a commit block with the matching sequence number
is found and its checksums verify.

## Descriptor blocks

A descriptor block (block type 1) contains the 12-byte `journal_header_s` followed by an array
of **block tags**. Each tag describes one data block that follows the descriptor. Tags are packed
sequentially with no padding between them.

The tag format depends on the journal's feature flags:

- **CSUM_V3** enabled: tags use `journal_block_tag3_s` (32-bit checksum).
- **CSUM_V3 not enabled**: tags use `journal_block_tag_s` (16-bit checksum).

Tags are variable-length because the UUID field is conditional. The last tag in the descriptor has
the LAST_TAG flag set. The first tag in a descriptor must include the UUID (SAME_UUID not set);
subsequent tags may set SAME_UUID to omit it.

### Block tags v3: journal_block_tag3_s

Used when INCOMPAT_CSUM_V3 is enabled:

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__be32` | t_blocknr | Filesystem destination block number (lower 32 bits). |
| 0x4 | `__be32` | t_flags | Tag flags. See [Tag flags](#tag-flags). |
| 0x8 | `__be32` | t_blocknr_high | Upper 32 bits of the destination block number. Always present in the v3 tag layout; zero if INCOMPAT_64BIT is not enabled. |
| 0xC | `__be32` | t_checksum | CRC32C of the journal UUID + transaction sequence number + corresponding data block. Full 32-bit value. |
| 0x10 | `char[16]` | uuid | UUID of the target filesystem. Present only when the SAME_UUID flag is **not** set. Omitted (saving 16 bytes) when SAME_UUID is set. |

**Size calculation:** Base = 16 bytes. Add 16 bytes if SAME_UUID is **not** set. Unlike the
pre-v3 tag format, CSUM_V3 keeps the fixed 16-byte tag body even when 64-bit block numbers are
not in use.

### Block tags pre-v3: journal_block_tag_s

Used when CSUM_V3 is **not** enabled (including CSUM_V2 and legacy journals):

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__be32` | t_blocknr | Filesystem destination block number (lower 32 bits). |
| 0x4 | `__be16` | t_checksum | Checksum of the corresponding data block. Stores the lower 16 bits of CRC32C(journal UUID + transaction sequence number + data block). Valid only when CSUM_V2 is enabled; otherwise zero. |
| 0x6 | `__be16` | t_flags | Tag flags. See [Tag flags](#tag-flags). Note: 16-bit field (vs 32-bit in v3). |
| 0x8 | `__be32` | t_blocknr_high | Upper 32 bits of the destination block number. Present only when INCOMPAT_64BIT is enabled. |
| (end) | `char[16]` | uuid | UUID of the target filesystem. Present only when the SAME_UUID flag is **not** set. |

**Size calculation:** Base = 8 bytes. Add 4 bytes if 64BIT. Add 16 bytes if not SAME_UUID.

### Tag flags

| Value | Name | Description |
|-------|------|-------------|
| `0x1` | ESCAPE | The data block's first 4 bytes matched the journal magic (`0xC03B3998`). Those bytes have been replaced with zeros in the journal copy. On replay, the original magic bytes must be restored. |
| `0x2` | SAME_UUID | This tag uses the same UUID as the previous tag. The 16-byte UUID field is omitted. |
| `0x4` | DELETED | The filesystem block was freed by this transaction. The data block is still present in the journal for checksum validation, but a parser may note this flag for forensic analysis. |
| `0x8` | LAST_TAG | This is the last tag in the descriptor block. Parsing stops after this tag. |

## Data blocks

Data blocks immediately follow their descriptor block, one per tag, in the same order as the
tags. Each data block is a verbatim copy of a filesystem block at the time the transaction was
committed.

**Escaping:** If a filesystem block's first 4 bytes happen to equal `0xC03B3998` (the journal
magic), those bytes are replaced with zeros in the journal copy and the corresponding tag's
ESCAPE flag is set. On replay, a parser must check the ESCAPE flag and restore the magic bytes
before writing the block to its filesystem destination.

## Commit blocks

A commit block (block type 2) marks the successful completion of a transaction. Its structure
extends the common header:

### commit_header

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | 12 | header | `journal_header_s` (h_magic, h_blocktype=2, h_sequence). |
| 0xC | `__u8` | h_chksum_type | Checksum algorithm type used for the commit checksum. Mirrors **s_checksum_type** from the superblock. |
| 0xD | `__u8` | h_chksum_size | Size of each checksum in bytes. |
| 0xE | `__u8[2]` | h_padding | Reserved, must be zero. |
| 0x10 | `__be32[8]` | h_chksum | Checksum array (32 bytes total). Only **h_chksum[0]** is used. See [Commit checksum](#commit-checksum). |
| 0x30 | `__be64` | h_commit_sec | Commit timestamp: seconds since the Unix epoch (1970-01-01 00:00:00 UTC). |
| 0x38 | `__be32` | h_commit_nsec | Nanosecond component of the commit timestamp (0–999999999). |

### Commit checksum

The meaning of **h_chksum[0]** depends on the active checksum mode:

- **CSUM_V2 or CSUM_V3:** `h_chksum[0]` = CRC32C of the journal UUID concatenated with
  the entire commit block, with the **h_chksum** field zeroed during calculation.
- **COMPAT_CHECKSUM:** `h_chksum[0]` = CRC32 of all data blocks in the transaction,
  concatenated in order. This does not cover the commit block itself.
- **Neither:** The checksum field is unused.

## Descriptor block tail

When CSUM_V2 or CSUM_V3 is enabled, the last 4 bytes of each descriptor block contain a
`jbd2_journal_block_tail`:

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__be32` | t_checksum | CRC32C of the journal UUID concatenated with the entire descriptor block (with this field zeroed). |

The tail occupies the last 4 bytes of the block (offset = `s_blocksize - 4` within the
descriptor block). This reduces the space available for tags. A parser must account for these 4
bytes when calculating how many tags fit in a descriptor block.

## Transaction replay

Recovery walks the journal starting from **s_start** with sequence number **s_sequence** (both
from the journal superblock):

1. Read the block at the current position. Verify it starts with the journal magic and the
   expected sequence number.
2. If the block is a **descriptor**: parse tags, read the following data blocks (one per tag),
   and verify per-block checksums (CSUM_V2/V3).
3. If the block is a **revocation**: collect the listed block numbers into the revocation set
   for this transaction's sequence number. See [03-revocation.md](03-revocation.md).
4. If the block is a **commit**: verify the commit checksum. If valid, mark the transaction as
   committed and advance to the next sequence number.
5. **Stopping conditions:** Stop if (a) a block does not start with the journal magic, (b) the
   sequence number does not match expectations, (c) a commit block's checksum is invalid, or
   (d) the journal wraps past **s_maxlen** without finding a valid continuation.

After scanning, apply committed transactions in order: write each data block to the filesystem
destination identified by its tag, **except** for blocks that appear in the revocation set from a
later transaction's sequence number. Restore escaped magic bytes (ESCAPE flag) before writing.
