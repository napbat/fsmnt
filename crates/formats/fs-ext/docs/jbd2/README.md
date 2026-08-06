# jbd2 Journal Reference

On-disk format documentation for the jbd2 journaling layer used by ext3 and ext4. All jbd2 structures are **big-endian** — opposite of ext4. Exception: fast commit TLV entries are little-endian (see `04-fast-commits.md`).

For ext4-side journal linkage (feature flags, inode/device fields, orphan handling), see [ext4-disk-layout/10-journaling.md](../ext4-disk-layout/10-journaling.md).

## Files

| File | What to find here |
|------|-------------------|
| `00-introduction.md` | **Glossary** (transaction, descriptor/commit/revocation/data block, fast commit, checkpoint), endianness, write-ahead log overview, internal vs external journal |
| `01-superblock.md` | **`journal_superblock_s`** — all fields (magic 0xC03B3998), compatible features (CHECKSUM), incompatible features (REVOKE, 64BIT, ASYNC_COMMIT, CSUM_V2, CSUM_V3, FAST_COMMIT), checksum type codes (CRC32 / MD5 / SHA1 / CRC32C), v1 vs v2 |
| `02-transactions.md` | **Transaction lifecycle** — `journal_header_s`, block types (1–5), descriptor blocks, block tags (`journal_block_tag3_s` / `journal_block_tag_s`), tag flags (ESCAPE, SAME_UUID, DELETED, LAST_TAG), data block escaping, `commit_header` (with timestamps), descriptor tail, replay algorithm |
| `03-revocation.md` | **Revocation blocks** — `jbd2_journal_revoke_header_s`, block number arrays (32-bit vs 64-bit), revocation tail checksum, two-pass replay role |
| `04-fast-commits.md` | **Fast commits** — INCOMPAT_FAST_COMMIT, `ext4_fc_tl` TLV header (**little-endian**), all tag types (HEAD, ADD_RANGE, DEL_RANGE, CREAT, LINK, UNLINK, INODE, PAD, TAIL), replay idempotence |
| `05-checksumming.md` | **Checksum evolution** — COMPAT_CHECKSUM (CRC32), CSUM_V2 (CRC32C, 16-bit tags), CSUM_V3 (CRC32C, 32-bit tags), algorithm codes, ASYNC_COMMIT interaction, mutual exclusivity |

## Quick Lookup

| Question | File |
|----------|------|
| Journal magic number? | `01-superblock.md` (0xC03B3998) |
| Journal feature flags? | `01-superblock.md` |
| How does a transaction work? | `02-transactions.md` |
| Block tag format (v3 vs pre-v3)? | `02-transactions.md` |
| What is block escaping? | `02-transactions.md` |
| Commit block timestamp? | `02-transactions.md` |
| What are revocation records? | `03-revocation.md` |
| How does journal replay work? | `02-transactions.md` + `03-revocation.md` |
| Fast commit TLV format? | `04-fast-commits.md` |
| Why are fast commits little-endian? | `04-fast-commits.md` |
| CRC32 vs CRC32C in journal? | `05-checksumming.md` |
| CSUM_V2 vs CSUM_V3 difference? | `05-checksumming.md` |
| How does ASYNC_COMMIT affect integrity? | `05-checksumming.md` |
