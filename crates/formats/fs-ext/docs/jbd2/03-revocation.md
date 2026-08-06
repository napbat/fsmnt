<!-- jbd2: Revocation -->
<!-- Revocation block format, block number sizing, replay role -->

# jbd2: Revocation

Revocation blocks cancel previously journaled writes to specific filesystem blocks. They prevent
stale data from being replayed over newer allocations during journal recovery. All fields are
**big-endian**.

## Overview

When a filesystem block is freed and reallocated during a later transaction, the journal must
ensure that an older transaction's copy of that block is not replayed. Revocation records solve
this: if block B was written in transaction T1 and revoked in transaction T2 (where T2 > T1), the
T1 write is skipped during replay.

A single transaction may contain zero or more revocation blocks. A single revocation block may
contain multiple revoked block numbers.

## jbd2_journal_revoke_header_s

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | 12 | r_header | `journal_header_s`: **h_magic** (`0xC03B3998`), **h_blocktype** (5), **h_sequence** (transaction sequence number). |
| 0xC | `__be32` | r_count | Total number of bytes used in this revocation block, including the 16-byte header itself. The remaining bytes up to **r_count** contain revoked block numbers. |
| 0x10 | varies | blocks[] | Array of revoked filesystem block numbers. Each entry is either 4 bytes (`__be32`) or 8 bytes (`__be64`), depending on the 64BIT feature. |

**Number of entries:** `(r_count - 16) / entry_size`, where **entry_size** is 4 (standard) or 8
(64BIT). When CSUM_V2 or CSUM_V3 is enabled, subtract an additional 4 bytes for the revocation
tail: `(r_count - 16 - 4) / entry_size`.

## Block number size

The size of each entry in the **blocks[]** array depends on the journal's INCOMPAT_64BIT flag:

| 64BIT flag | Entry size | Type | Range |
|------------|------------|------|-------|
| Not set | 4 bytes | `__be32` | 0 to 2^32 - 1 |
| Set | 8 bytes | `__be64` | 0 to 2^64 - 1 |

This is the same 64BIT feature flag that controls the presence of **t_blocknr_high** in descriptor
block tags.

## Revocation tail

When CSUM_V2 or CSUM_V3 is enabled, the last 4 bytes of the revocation block contain a
`jbd2_journal_revoke_tail`:

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x0 | `__be32` | r_checksum | CRC32C of the journal UUID concatenated with the entire revocation block (with this field zeroed during calculation). |

The tail is located at offset `s_blocksize - 4` within the revocation block. The **r_count**
field includes the data area up to (but not including) the tail; a parser should verify that
`r_count <= s_blocksize - 4` when checksumming is active.

## Replay role

During journal recovery, revocation processing follows a two-pass approach:

1. **Collection pass:** Scan all valid transactions in the journal. For each revocation block,
   record every revoked block number along with the transaction's sequence number. Build a map:
   filesystem block number to the highest sequence number that revoked it.

2. **Replay pass:** For each committed transaction's data blocks, check whether the destination
   block number appears in the revocation map with a sequence number **greater than** the current
   transaction's sequence. If so, skip the write. Otherwise, apply the data block to the
   filesystem.

This two-pass design ensures that revocations from later transactions take precedence even though
the journal is replayed in forward (sequential) order. Without revocation, a stale block from an
earlier transaction could overwrite a newer allocation that was freed and reused by a later
transaction.
