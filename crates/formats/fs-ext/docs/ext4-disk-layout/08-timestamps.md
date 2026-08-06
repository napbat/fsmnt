<!-- ext4 Disk Layout: Timestamps -->
<!-- Base 32-bit and extended 34-bit+nanosecond inode timestamps, kernel decode rules, Y2038 handling, superblock timestamps. -->

## Timestamps

Each ext4 inode contains up to five timestamps. The base format is a 32-bit signed seconds
value inherited from ext2. Extended inodes add per-field `*_extra` fields that provide two
additional epoch bits and 30-bit nanosecond precision.

All timestamp fields are little-endian.

### Inode Timestamp Fields

| Offset | Size | Name | Extended Field | Extended Offset | Description |
|---|---|---|---|---|---|
| 0x08 | 4 | **i_atime** | **i_atime_extra** | 0x8C | Last access time. |
| 0x0C | 4 | **i_ctime** | **i_ctime_extra** | 0x84 | Last inode change time (metadata modification). |
| 0x10 | 4 | **i_mtime** | **i_mtime_extra** | 0x88 | Last data modification time. |
| 0x14 | 4 | **i_dtime** | (none) | — | Deletion time. Also used as the next pointer in the orphan inode linked list. See [10-journaling.md](10-journaling.md). |
| 0x90 | 4 | **i_crtime** | **i_crtime_extra** | 0x94 | File creation (birth) time. Only present in extended inodes. |

**i_atime**, **i_ctime**, **i_mtime**, and **i_dtime** exist in the base 128-byte inode
(offsets 0x08–0x17). All four are always present.

**i_crtime** and all `*_extra` fields exist only in extended inodes where `s_inode_size > 128`
and the field falls within the range covered by `i_extra_isize`. Specifically:
- `i_extra_isize >= 8`:  **i_ctime_extra** (0x84..0x88) is present.
- `i_extra_isize >= 12`: **i_mtime_extra** (0x88..0x8C) is present.
- `i_extra_isize >= 16`: **i_atime_extra** (0x8C..0x90) is present.
- `i_extra_isize >= 20`: **i_crtime** (0x90..0x94) is present.
- `i_extra_isize >= 24`: **i_crtime_extra** (0x94..0x98) is present.

### Base Timestamps (32-bit)

Each base timestamp field is a 32-bit **signed** integer representing seconds since the Unix
epoch (1970-01-01 00:00:00 UTC).

**Range:** 1901-12-13 20:45:52 UTC (`0x80000000` = -2147483648) to 2038-01-19 03:14:07 UTC
(`0x7FFFFFFF` = 2147483647).

These are the only timestamps available in 128-byte inodes (ext2/ext3 without extended inodes).
They are subject to the Y2038 problem.

### Extended Timestamps

Each `*_extra` field is a 32-bit value that extends the corresponding base timestamp.

| Bits | Width | Name | Description |
|---|---|---|---|
| 0–1 | 2 | Epoch bits | Extends the seconds range beyond 32 bits. |
| 2–31 | 30 | Nanoseconds | Sub-second precision: 0 to 999999999. |

**Extracting nanoseconds:**

```
nanoseconds = extra >> 2
```

### Encoding and Decoding

The combination of a signed 32-bit base with 2 epoch bits is **not** a simple unsigned
concatenation. The kernel uses sign-aware logic to produce a consistent timeline from
1901 through 2446.

**Kernel decode rules** (from `fs/ext4/ext4.h`, `ext4_decode_extra_time`):

```c
/* In-kernel decode (simplified from ext4.h): */
static inline void ext4_decode_extra_time(struct timespec64 *ts,
                                          __le32 base, __le32 extra)
{
    ts->tv_sec = (signed __s32)le32_to_cpu(base);
    if (sizeof(ts->tv_sec) > 4 && extra) {
        __u32 x = le32_to_cpu(extra);
        ts->tv_sec += (__s64)(x & 0x3) << 32;
    }
    ts->tv_nsec = extra ? (le32_to_cpu(extra) >> 2) : 0;
}
```

The key operation is: cast the base to a **signed** 32-bit value, then **add**
`(epoch_bits << 32)` as a signed 64-bit addition. This is not the same as
`(epoch_bits << 32) | (unsigned)base`.

**Decode table** showing the effective seconds for each combination of base sign and epoch
bits:

| Epoch Bits | Base Sign | Effective Seconds Range | Calendar Range |
|---|---|---|---|
| 0 (`0b00`) | `base >= 0` | 0 to 2^31 - 1 | 1970-01-01 to 2038-01-19 |
| 0 (`0b00`) | `base < 0` | -2^31 to -1 | 1901-12-13 to 1969-12-31 |
| 1 (`0b01`) | `base >= 0` | 2^32 to 2^32 + 2^31 - 1 | 2106-02-07 to 2174-02-25 |
| 1 (`0b01`) | `base < 0` | 2^32 - 2^31 to 2^32 - 1 | 2038-01-19 to 2106-02-07 |
| 2 (`0b10`) | `base >= 0` | 2^33 to 2^33 + 2^31 - 1 | 2242-03-16 to 2310-04-04 |
| 2 (`0b10`) | `base < 0` | 2^33 - 2^31 to 2^33 - 1 | 2174-02-25 to 2242-03-16 |
| 3 (`0b11`) | `base >= 0` | 3 * 2^32 to 3 * 2^32 + 2^31 - 1 | 2378-04-22 to 2446-05-10 |
| 3 (`0b11`) | `base < 0` | 3 * 2^32 - 2^31 to 3 * 2^32 - 1 | 2310-04-04 to 2378-04-22 |

**Effective range:** 1901-12-13 20:45:52 UTC to 2446-05-10 00:53:20 UTC, with nanosecond
precision for timestamps that have an `*_extra` field.

**Encoding** (writing a timestamp): the reverse process. Given a 64-bit seconds value `s` and
nanoseconds `ns`:

```
base  = (int32_t)(s & 0xFFFFFFFF)
extra = ((s >> 32) & 0x3) | (ns << 2)
```

The epoch bits are the lower 2 bits of `s >> 32`. Because the base is stored as a signed
value, the epoch bits and base together reconstruct the original `s` via signed addition.

### Creation Time

**i_crtime** (offset 0x90, 4 bytes): 32-bit signed seconds since epoch. Present in
extended inodes with `i_extra_isize >= 20`.

**i_crtime_extra** (offset 0x94, 4 bytes): Extended timestamp (epoch bits + nanoseconds).
Decoded using the same rules as other `*_extra` fields.

The creation time records when the inode was originally created. It is not updated by normal
file operations (`open`, `read`, `write`, `chmod`, `rename`), making it forensically valuable
for establishing when a file first appeared. The `statx()` system call exposes it as
`stx_btime`.

### Deletion Time

**i_dtime** (offset 0x14, 4 bytes): 32-bit signed seconds since epoch. Set when a file is
unlinked and its link count reaches zero.

**No extended field.** `i_dtime` has no corresponding `*_extra` field. It remains a 32-bit
signed value with no nanosecond precision and is subject to Y2038 overflow.

**Dual use:** When an inode is on the orphan list (pending deletion or truncation after a
crash), **i_dtime** is repurposed as the `__le32` inode number of the next inode in the orphan
linked list. The orphan list head is `s_last_orphan` in the superblock. See
[10-journaling.md](10-journaling.md) for orphan handling details.

**Forensic note:** An inode with `i_dtime != 0` and `i_links_count == 0` is a deleted file.
The deletion timestamp aids timeline reconstruction. An inode with `i_dtime != 0` but
`i_links_count > 0` may indicate an orphan list entry from an unclean shutdown.

### Superblock Timestamps

The superblock contains several timestamps, all 32-bit unsigned values with no extended fields
and no nanosecond precision. These are subject to Y2038 overflow.

| Offset | Size | Name | Description |
|---|---|---|---|
| 0x2C | 4 | **s_mtime** | Time of last mount operation. |
| 0x30 | 4 | **s_wtime** | Time of last write operation (any metadata update). |
| 0x40 | 4 | **s_lastcheck** | Time of last filesystem check (`fsck`). |
| 0x108 | 4 | **s_mkfs_time** | Time when the filesystem was created (`mkfs`). |
| 0x194 | 4 | **s_first_error_time** | Time of the first detected error. `0` if no errors recorded. |
| 0x1A4 | 4 | **s_last_error_time** | Time of the most recent detected error. `0` if no errors recorded. |

**s_mtime** and **s_wtime** are updated on every mount and write respectively. **s_lastcheck**
is updated by `e2fsck`. **s_mkfs_time** is set once at filesystem creation and never updated.
**s_first_error_time** is set when the first error is detected and preserved across subsequent
errors. **s_last_error_time** is updated on each new error.

These timestamps provide a coarse system activity timeline for forensic analysis. They record
mount/unmount cycles, maintenance events, and error history. See
[12-forensic-artifacts.md](12-forensic-artifacts.md) for timestamp analysis patterns.
