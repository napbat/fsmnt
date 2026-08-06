<!-- jbd2: Introduction -->
<!-- Glossary, endianness, write-ahead log overview, internal vs external journal layout -->

# jbd2: Introduction

Glossary, endianness conventions, and overview of the jbd2 journaling layer used by ext3 and ext4.

## Glossary

**Transaction:** An atomic unit of work containing one or more filesystem metadata changes. A
transaction is represented on disk as a sequence of descriptor blocks, data blocks, and a commit
block. Transactions are numbered by monotonically increasing **sequence numbers** stored in each
block's `journal_header_s`.

**Descriptor block:** A journal block (block type 1) containing an array of **block tags** that map
subsequent data blocks to their filesystem destinations. Each tag identifies which filesystem block
the following data block should be written to during replay.

**Data block:** A journal block that contains a verbatim copy of a filesystem block. Data blocks
follow their descriptor block, one per tag, in tag order. If the block's first 4 bytes match the
journal magic (`0xC03B3998`), those bytes are zeroed in the journal copy and the tag's ESCAPE
flag is set.

**Commit block:** A journal block (block type 2) that marks the successful end of a transaction. A
transaction is only valid for replay if its commit block is present and its checksums verify. The
commit block contains a timestamp recording when the commit occurred.

**Revocation block:** A journal block (block type 5) containing a list of filesystem block numbers
whose previous journal writes should be ignored during replay. Revocations prevent stale data
from overwriting newer allocations. See [03-revocation.md](03-revocation.md).

**Fast commit:** A lightweight journaling mode (INCOMPAT_FAST_COMMIT) that records logical
operations (create, link, unlink, add extent, delete range) as tag-length-value (TLV) entries
instead of full block copies. Fast commit blocks occupy a reserved area after the main journal
circular buffer. See [04-fast-commits.md](04-fast-commits.md).

**Journal superblock:** The first block of the journal device or journal file. Contains journal
geometry (block size, total blocks, log start), feature flags, UUID, and checksum metadata. See
[01-superblock.md](01-superblock.md).

**Checkpoint:** The process of flushing committed journal data to its final filesystem location. Once
all data blocks from a transaction have been written to their destinations, the transaction's
journal space can be reclaimed. The journal operates as a circular buffer; checkpointing advances
the tail to free space for new transactions.

## Endianness

**All jbd2 on-disk structures are big-endian.** This is the opposite of ext4, which is entirely
little-endian. A parser must byte-swap every multi-byte field when running on a little-endian host.

**Exception:** Fast commit TLV entries (`ext4_fc_tl` and associated payload structures) use
**little-endian** encoding because they are defined by ext4, not jbd2. See
[04-fast-commits.md](04-fast-commits.md) for details.

## Write-Ahead Log Overview

jbd2 implements a write-ahead log (WAL) for crash consistency. The protocol is:

1. **Log:** Write modified filesystem blocks to the journal (descriptor + data blocks).
2. **Commit:** Write a commit block to mark the transaction as durable.
3. **Checkpoint:** Write the journaled blocks to their final filesystem locations.
4. **Reclaim:** Advance the journal tail past fully checkpointed transactions.

On crash recovery, the kernel replays all committed-but-not-checkpointed transactions from the
journal. Uncommitted transactions (missing or invalid commit block) are discarded. Revocation
records are collected first to prevent stale replays. See [02-transactions.md](02-transactions.md)
for the transaction replay algorithm.

The journal is a circular buffer. **s_start** in the journal superblock marks the first block of the
oldest uncheckpointed transaction. **s_sequence** is the sequence number of that transaction.
**s_head** (v2 superblock only) marks the first unused block. A zero **s_start** is used when the
journal is marked empty, but current kernel docs explicitly warn that `s_start == 0` alone does
not prove the journal is clean.

## Internal vs External Journal

### Internal journal

The journal is stored in a regular file on the same filesystem, typically **inode 8** (the reserved
journal inode). The journal inode's data blocks — located via the inode's block map or extent
tree — contain the journal superblock at logical block 0, followed by the circular log buffer.

The ext4 superblock field **s_journal_inum** (offset `0xE0`) identifies the journal inode. See
[ext4-disk-layout/10-journaling.md](../ext4-disk-layout/10-journaling.md) for ext4-side journal
linkage fields.

### External journal

The journal resides on a separate block device. The device layout is:

| Offset | Content |
|--------|---------|
| 0 | Boot block (1024 bytes, unused) |
| 1024 | ext4 superblock (identifies the device as an ext4 journal) |
| Block 1 | Journal superblock (`journal_superblock_s`) |
| Block 2+ | Circular log buffer |

The ext4 superblock at offset 1024 has **s_journal_dev** set to the device number and uses
feature flags to identify the device as a journal. The **s_journal_uuid** field (offset `0xD0`) in
the filesystem's own superblock is used to locate the matching external journal device.

## Relationship to ext4

jbd2 is a generic block-device journaling layer. ext4 is its primary (and effectively only)
consumer. The division of responsibility:

- **ext4** decides what to journal (metadata, optionally data), manages journal modes
  (data/ordered/writeback), and references the journal through superblock fields.
- **jbd2** owns the on-disk transaction format: superblock, descriptor blocks, data blocks, commit
  blocks, revocation blocks, and fast commits.

For ext4-side journal configuration (journal modes, orphan handling, recovery flag), see
[ext4-disk-layout/10-journaling.md](../ext4-disk-layout/10-journaling.md).
