<!-- jbd2: Checksumming -->
<!-- Three checksum generations, algorithm codes, ASYNC_COMMIT, mutual exclusivity -->

# jbd2: Checksumming

The jbd2 journal has evolved through three generations of checksumming, each providing
increasingly granular integrity verification. All checksum fields in jbd2 structures are
**big-endian** (consistent with the rest of jbd2).

## Overview

| Generation | Feature flag | Algorithm | Granularity | Tag format |
|------------|-------------|-----------|-------------|------------|
| 1 | COMPAT_CHECKSUM (`0x1`) | CRC32 | Per-transaction | N/A (commit block only) |
| 2 | INCOMPAT_CSUM_V2 (`0x8`) | CRC32C | Per-block | `journal_block_tag_s` (16-bit checksum) |
| 3 | INCOMPAT_CSUM_V3 (`0x10`) | CRC32C | Per-block | `journal_block_tag3_s` (32-bit checksum) |

**CSUM_V2 and CSUM_V3 are mutually exclusive.** A journal must not have both flags set.
COMPAT_CHECKSUM may coexist in the flags with CSUM_V2 or CSUM_V3 for backward compatibility,
but the newer incompat flag takes precedence.

## Generation 1: COMPAT_CHECKSUM

**Flag:** `JBD2_FEATURE_COMPAT_CHECKSUM` (`0x1`), compatible feature.

A single CRC32 (polynomial `0x04C11DB7`) is computed over all data blocks in a transaction,
concatenated in order. The result is stored in the commit block's **h_chksum[0]** field.

**Coverage:** Data blocks only. Descriptor blocks, revocation blocks, and the commit block itself
are not covered.

**Limitations:** A single checksum over all data blocks cannot identify which specific block is
corrupted. It also does not protect metadata blocks (descriptors, revocations). This generation
was the original checksumming mechanism and is superseded by CSUM_V2/V3.

## Generation 2: CSUM_V2

**Flag:** `JBD2_FEATURE_INCOMPAT_CSUM_V2` (`0x8`), incompatible feature.

CRC32C (Castagnoli, polynomial `0x1EDC6F41`) is used for all CSUM_V2 checksums. The algorithm
type is recorded in the journal superblock's **s_checksum_type** field, which is `4`
(`JBD2_CRC32C_CHKSUM`) on modern ext4 journals using CSUM_V2 or CSUM_V3.

CSUM_V2 adds checksums to every journal metadata structure:

| Structure | Checksum field | Calculation |
|-----------|---------------|-------------|
| **Journal superblock** | `s_checksum` (offset `0xFC`) | CRC32C of the entire superblock with `s_checksum` zeroed. |
| **Descriptor block tail** | `t_checksum` in `jbd2_journal_block_tail` (last 4 bytes of block) | CRC32C of journal UUID + entire descriptor block with tail zeroed. |
| **Data block tag** | `t_checksum` in `journal_block_tag_s` (**16-bit**, offset `0x4`) | CRC32C of journal UUID + transaction sequence number + data block contents, truncated to lower 16 bits. |
| **Revocation block tail** | `r_checksum` in `jbd2_journal_revoke_tail` (last 4 bytes of block) | CRC32C of journal UUID + entire revocation block with tail zeroed. |
| **Commit block** | `h_chksum[0]` in `commit_header` (offset `0x10`) | CRC32C of journal UUID + entire commit block with `h_chksum` array zeroed. |

**Tag format:** CSUM_V2 uses `journal_block_tag_s`, which has a 16-bit **t_checksum** field.
This provides only 65536 distinct values per data block, which is sufficient for detecting random
corruption but weaker against targeted modification. This limitation motivated CSUM_V3.

See [02-transactions.md](02-transactions.md) for the `journal_block_tag_s` field layout and
[03-revocation.md](03-revocation.md) for the revocation tail.

## Generation 3: CSUM_V3

**Flag:** `JBD2_FEATURE_INCOMPAT_CSUM_V3` (`0x10`), incompatible feature.

Identical to CSUM_V2 in all respects except the block tag format:

| Structure | Checksum field | Difference from V2 |
|-----------|---------------|-------------------|
| **Data block tag** | `t_checksum` in `journal_block_tag3_s` (**32-bit**, offset `0xC`) | Full 32-bit CRC32C value instead of truncated 16-bit. |

All other checksums (superblock, descriptor tail, revocation tail, commit block) remain identical
to CSUM_V2.

**CSUM_V3 is the current default** for new ext4 filesystems created by `mke2fs`. It provides
full 32-bit checksum coverage for every block in the journal.

See [02-transactions.md](02-transactions.md) for the `journal_block_tag3_s` field layout.

## Checksum algorithm codes

The **s_checksum_type** field in the journal superblock specifies the algorithm for CSUM_V2 and
CSUM_V3:

| Value | Constant | Algorithm | Status |
|-------|----------|-----------|--------|
| 1 | `JBD2_CRC32_CHKSUM` | CRC32 | Used by the older COMPAT_CHECKSUM generation. |
| 2 | `JBD2_MD5_CHKSUM` | MD5 | Defined but never implemented in the kernel. |
| 3 | `JBD2_SHA1_CHKSUM` | SHA-1 | Defined but never implemented in the kernel. |
| 4 | `JBD2_CRC32C_CHKSUM` | CRC32C (Castagnoli) | Used by CSUM_V2 and CSUM_V3. |

A parser encountering **s_checksum_type** != 4 with CSUM_V2 or CSUM_V3 enabled should treat
the journal as unreadable (unknown checksum algorithm).

**Important distinction:** COMPAT_CHECKSUM (generation 1) uses **CRC32** (polynomial
`0x04C11DB7`). CSUM_V2 and CSUM_V3 use **CRC32C** (polynomial `0x1EDC6F41`). These are
different algorithms with different polynomials and different outputs. A parser must use the
correct algorithm for each generation.

## ASYNC_COMMIT

**Flag:** `JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT` (`0x4`).

When ASYNC_COMMIT is enabled, commit blocks are written to disk without waiting for the
preceding data blocks to complete their I/O. This improves write performance but means the commit
block may be durable on disk before all data blocks are. Checksums become the **sole integrity
guarantee**: during recovery, the commit block's checksum validates its own integrity, and each
data block's tag checksum validates individual block integrity. If any data block's checksum
fails, the entire transaction is discarded.

ASYNC_COMMIT requires CSUM_V2 or CSUM_V3. Without per-block checksums, there is no way to
verify that data blocks reached disk correctly when the commit was written asynchronously.

## Checksum calculation summary

For reference, CSUM_V2/V3 CRC32C calculations use two related patterns. The journal superblock
checksum covers the superblock alone. Descriptor, revocation, and commit checksums prepend the
journal UUID. Data block tag checksums prepend both the journal UUID and the transaction sequence
number. In every case, the checksum field itself is zeroed during calculation. The initial CRC
value is `~0` (all bits set). The final CRC is stored directly.

| What | Input to CRC32C | Where stored |
|------|-----------------|--------------|
| Superblock | Superblock (s_checksum zeroed) | `s_checksum` |
| Descriptor block | UUID + descriptor block (tail zeroed) | `jbd2_journal_block_tail.t_checksum` |
| Data block | UUID + sequence number + data block contents | Tag `t_checksum` (16-bit in V2, 32-bit in V3) |
| Revocation block | UUID + revocation block (tail zeroed) | `jbd2_journal_revoke_tail.r_checksum` |
| Commit block | UUID + commit block (h_chksum zeroed) | `commit_header.h_chksum[0]` |
