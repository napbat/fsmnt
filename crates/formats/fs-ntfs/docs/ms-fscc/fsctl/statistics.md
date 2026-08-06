<!-- MS-FSCC: Filesystem Statistics -->
<!-- FILESYSTEM_GET_STATISTICS request/reply. FILESYSTEM_STATISTICS, NTFS_STATISTICS (MftWrites, BitmapWrites, Allocate), FAT_STATISTICS, EXFAT_STATISTICS. -->

**2.3.11** **FSCTL_FILESYSTEM_GET_STATISTICS Request**

This message requests that the server return the statistical information of the file system such as
Type, Version, and so on, as specified in FSCTL_FILESYSTEM_GET_STATISTICS reply, for the file or
directory associated with the handle on which this **FSCTL** was invoked.<23>

This message does not contain any additional data elements.

**2.3.12** **FSCTL_FILESYSTEM_GET_STATISTICS Reply**

This message returns the result of the FSCTL_FILESYSTEM_GET_STATISTICS request message as a
pair of structures: a generic structure, FILESYSTEM_STATISTICS, optionally followed by a file system
type specific structure that can be either NTFS_STATISTICS, FAT_STATISTICS, or EXFAT_STATISTICS,
depending on the underlying file system type. There is one pair of these structures for each
processor.<24>

These statistics contain information about both user and metadata files. User files are available for the
user. Metadata files are system files that contain information that the file system uses for its internal
organization.

The statistics structures contain fields that can overflow during the server's lifetime. This is by design.
When an overflow occurs, the value just wraps. For example, 0XFFFFF000 + 0x2000 will result in
0x1000.

The structures within the output buffer MUST all start on 64-byte boundaries. The final output MUST
be padded to a 64-byte boundary. Any padding bytes MUST be filled with zeros.

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error
codes are listed in the following table.
|Error code|Meaning|
|---|---|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is too small to contain a FILESYSTEM_STATISTICS structure.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before all the statistics data could be returned.|

**2.3.12.1** **FILESYSTEM_STATISTICS**

The **FILESYSTEM_STATISTICS** data element is returned with a
FSCTL_FILESYSTEM_GET_STATISTICS reply message. It contains the generic information for the
message.

The **FILESYSTEM_STATISTICS** data element is as follows:

```
  FileSystemType (16 bits) | Version (16 bits)
  SizeOfCompleteStructure (32 bits)
  UserFileReads (32 bits)
  UserFileReadBytes (32 bits)
  UserDiskReads (32 bits)
  UserFileWrites (32 bits)
  UserFileWriteBytes (32 bits)
  UserDiskWrites (32 bits)
  MetaDataReads (32 bits)
  MetaDataReadBytes (32 bits)
  MetaDataDiskReads (32 bits)
  MetaDataWrites (32 bits)
  MetaDataWriteBytes (32 bits)
  MetaDataDiskWrites (32 bits)
```

**FileSystemType (2 bytes):** A 16-bit unsigned integer value containing the type of file system. This

field MUST contain one of the following values.
|Value|Meaning|
|---|---|
|FILESYSTEM_STATISTICS_TYPE_NTFS<br>0x0001|The file system is an**NTFS** file system. If this value is set, this<br>structure is followed by anNTFS_STATISTICS structure.|
|FILESYSTEM_STATISTICS_TYPE_FAT<br>0x0002|The file system is a**FAT file system**. If this value is set, this<br>structure is followed by aFAT_STATISTICS structure.|
|FILESYSTEM_STATISTICS_TYPE_EXFAT<br>0x0003|The file system is an exFAT file system. If this value is set, this<br>structure is followed by anEXFAT_STATISTICS structure.|
|FILESYSTEM_STATISTICS_TYPE_REFS<br>0x0004|The file system is an ReFS file system. If this value is set, this<br>structure is not followed by a structure specific to file system type.|

**Version (2 bytes):** A 16-bit unsigned integer value containing the version. This field MUST be set to

the value 0x0001.

**SizeOfCompleteStructure (4 bytes):** A 32-bit unsigned integer value that indicates the size, in

bytes, of this structure plus the size of the file system-specific structure that follows this structure,
each rounded up to a multiple of 64, then the sum is multiplied by the number of processors. For
example, if the size of **FILESYSTEM_STATISTICS** is 0x38, the size of **NTFS_STATISTICS** is
0XD4, and there are two processors, the size of the buffer allocated is 0x280. This is the sum of
the sizes of the **NTFS_STATISTICS** structure and the **FILESYSTEM_STATISTICS** structure,
both rounded up to a multiple of 64 (0x40 + 0x100 = 0x140) and multiplied by the number of
processors.

**UserFileReads (4 bytes):** A 32-bit unsigned integer value containing the number of read operations

on user files.

**UserFileReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes read

from user files.

**UserDiskReads (4 bytes):** A 32-bit unsigned integer value containing the number of read operations

on user files that went to the disk rather than the cache. This value includes **sub-read** operations.

**UserFileWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write operations

on user files.

**UserFileWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

written to user files.

**UserDiskWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations on user files that went to disk rather than the cache. This value includes sub-write
operations.

**MetaDataReads (4 bytes):** A 32-bit unsigned integer value containing the number of read

operations on metadata files.

**MetaDataReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

read from metadata files.

**MetaDataDiskReads (4 bytes):** A 32-bit unsigned integer value containing the number of read

operations on metadata files. This value includes sub-read operations.

**MetaDataWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations on metadata files.

**MetaDataWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

written to metadata files.
**MetaDataDiskWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations on metadata files. This value includes sub-write operations.

**2.3.12.2** **NTFS_STATISTICS**

The **NTFS_STATISTICS** data element is returned with a FSCTL_FILESYSTEM_GET_STATISTICS reply
message when NTFS file system statistics are requested.

The **NTFS_STATISTICS** data element is as follows:

```
  LogFileFullExceptions (32 bits)
  OtherExceptions (32 bits)
  MftReads (32 bits)
  MftReadBytes (32 bits)
  MftWrites (32 bits)
  MftWriteBytes (32 bits)
  MftWritesUserLevel (32 bits)
  MftWritesFlushForLogFileFull (16 bits) | MftWritesLazyWriter (16 bits)
  MftWritesUserRequest (16 bits) | Padding1 (16 bits)
  Mft2Writes (32 bits)
  Mft2WriteBytes (32 bits)
  Mft2WritesUserLevel (32 bits)
  Mft2WritesFlushForLogFileFull (16 bits) | Mft2WritesLazyWriter (16 bits)
  Mft2WritesUserRequest (16 bits) | Padding2 (16 bits)
  RootIndexReads (32 bits)
  RootIndexReadBytes (32 bits)
  RootIndexWrites (32 bits)
  ...
```
|RootIndexWriteBytes|Col2|
|---|---|
|BitmapReads|BitmapReads|
|BitmapReadBytes|BitmapReadBytes|
|BitmapWrites|BitmapWrites|
|BitmapWriteBytes|BitmapWriteBytes|
|BitmapWritesFlushForLogFileFull|BitmapWritesLazyWriter|
|BitmapWritesUserRequest|BitmapWritesUserLevel|
|...|...|
|MftBitmapReads|MftBitmapReads|
|MftBitmapReadBytes|MftBitmapReadBytes|
|MftBitmapWrites|MftBitmapWrites|
|MftBitmapWriteBytes|MftBitmapWriteBytes|
|MftBitmapWritesFlushForLogFileFull|MftBitmapWritesLazyWriter|
|MftBitmapWritesUserRequest|MftBitmapWritesUserLevel|
|...|...|
|...|Padding3|
|UserIndexReads|UserIndexReads|
|UserIndexReadBytes|UserIndexReadBytes|
|UserIndexWrites|UserIndexWrites|
|UserIndexWriteBytes|UserIndexWriteBytes|
|LogFileReads|LogFileReads|
|LogFileReadBytes|LogFileReadBytes|
|LogFileWrites|LogFileWrites|
|LogFileWriteBytes|LogFileWriteBytes|
|Allocate (40 bytes)|Allocate (40 bytes)|
**LogFileFullExceptions (4 bytes):** A 32-bit unsigned integer value containing the number of

exceptions generated due to the log file being full.

**OtherExceptions (4 bytes):** A 32-bit unsigned integer value containing the number of other

exceptions generated.

**MftReads (4 bytes):** A 32-bit unsigned integer value containing the number of read operations on

the **Master File Table (MFT)** .

**MftReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes read from

the MFT.

**MftWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write operations on

the MFT.

**MftWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes written to

the MFT.

**MftWritesUserLevel (8 bytes):** An MftWritesUserLevel structure containing statistics about writes

resulting from certain user-level operations.

**MftWritesFlushForLogFileFull (2 bytes):** A 16-bit unsigned integer containing the number of

flushes of the MFT performed because the log file was full.

**MftWritesLazyWriter (2 bytes):** A 16-bit unsigned integer containing the number of **MFT** write

operations performed by the lazy writer thread.

**MftWritesUserRequest (2 bytes):** A 16-bit unsigned integer that is the sum of the four fields in the

MftWritesUserLevel structure.

**Padding1 (2 bytes):** Unused. This field SHOULD be set to 0 and MUST be ignored.

**Mft2Writes (4 bytes):** A 32-bit unsigned integer value containing the number of write operations on

the **master file table mirror (MFT2)** .

**Mft2WriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes written

to the MFT2.

**Mft2WritesUserLevel (8 bytes):** An MftWritesUserLevel structure containing statistics about writes

resulting from certain user-level operations.

**Mft2WritesFlushForLogFileFull (2 bytes):** A 16-bit unsigned integer containing the number of

flushes of the MFT2 performed because the log file was full.

**Mft2WritesLazyWriter (2 bytes):** A 16-bit unsigned integer containing the number of **MFT2** write

operations performed by the lazy writer thread.

**Mft2WritesUserRequest (2 bytes):** A 16-bit unsigned integer that contains the sum of the four

fields in the Mft2WritesUserLevel structure.

**Padding2 (2 bytes):** Unused. This field SHOULD be set to 0 and MUST be ignored.

**RootIndexReads (4 bytes):** A 32-bit unsigned integer value containing the number of read

operations on the root index.
**RootIndexReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

read from the root index.

**RootIndexWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations on the root index.

**RootIndexWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

written to the root index.

**BitmapReads (4 bytes):** A 32-bit unsigned integer value containing the number of read operations

on the cluster allocation bitmap.

**BitmapReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes read

from the cluster allocation bitmap.

**BitmapWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write operations

on the cluster allocation bitmap. This is the sum of the **BitmapWritesFlushForLogFileFull**,
**BitmapWritesLazyWriter** and **BitmapWritesUserRequest** fields.

**BitmapWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

written to the cluster allocation bitmap.

**BitmapWritesFlushForLogFileFull (2 bytes):** A 16-bit unsigned integer containing the number of

flushes of the bitmap performed because the log file was full.

**BitmapWritesLazyWriter (2 bytes):** A 16-bit unsigned integer containing the number of bitmap

write operations performed by the lazy writer thread.

**BitmapWritesUserRequest (2 bytes):** A 16-bit unsigned integer that is the sum of the fields in the

BitmapWritesUserLevel structure.

**BitmapWritesUserLevel (6 bytes):** A BitmapWritesUserLevel structure containing statistics about

bitmap writes resulting from certain user-level operations.

**MftBitmapReads (4 bytes):** A 32-bit unsigned integer value containing the number of read

operations on the MFT bitmap.

**MftBitmapReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

read from the MFT bitmap.

**MftBitmapWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations on the MFT bitmap. This value is the sum of the
**MftBitmapWritesFlushForLogFileFull**, **MftBitmapWritesLazyWriter** and
**MftBitmapWritesUserRequest** fields.

**MftBitmapWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

written to the MFT bitmap.

**MftBitmapWritesFlushForLogFileFull (2 bytes):** A 16-bit unsigned integer containing the number

of flushes of the MFT bitmap performed because the log file was full.

**MftBitmapWritesLazyWriter (2 bytes):** A 16-bit unsigned integer value containing the number of

MFT bitmap write operations performed by the lazy writer thread.

**MftBitmapWritesUserRequest (2 bytes):** A 16-bit unsigned integer that is the sum of all the fields

in the MftBitmapWritesUserLevel structure.

**MftBitmapWritesUserLevel (8 bytes):** An MftBitmapWritesUserLevel structure containing statistics

about MFT bitmap writes resulting from certain user-level operations.

**Padding3 (2 bytes):** Unused. This field SHOULD be set to 0 and MUST be ignored.
**UserIndexReads (4 bytes):** A 32-bit unsigned integer value containing the number of read

operations on the user index.

**UserIndexReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

read from user indices.

**UserIndexWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations on user indices.

**UserIndexWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

written to user indices.

**LogFileReads (4 bytes):** A 32-bit unsigned integer value containing the number of read operations

on the log file.

**LogFileReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes read

from the log file.

**LogFileWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write operations

on the log file.

**LogFileWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

written to the log file.

**Allocate (40 bytes):** An Allocate structure describes cluster allocation patterns in NTFS.

**2.3.12.2.1** **MftWritesUserLevel**

The **MftWritesUserLevel** structure contains statistics about writes resulting from certain user-level
operations.

The **MftWritesUserLevel** structure is as follows.

```
  Write (16 bits) | Create (16 bits)
  SetInfo (16 bits) | Flush (16 bits)
```

**Write (2 bytes):** A 16-bit unsigned integer containing the number of **MFT** writes due to a write

operation.

**Create (2 bytes):** A 16-bit unsigned integer containing the number of **MFT** writes due to a create

operation.

**SetInfo (2 bytes):** A 16-bit unsigned integer containing the number of **MFT** writes due to a set file

information operation.

**Flush (2 bytes):** A 16-bit unsigned integer containing the number of **MFT** writes due to a flush

operation.

**2.3.12.2.2** **Mft2WritesUserLevel**

The **Mft2WritesUserLevel** structure contains statistics about writes resulting from certain user-level
operations.

The **Mft2WritesUserLevel** structure is as follows.
```
  Write (16 bits) | Create (16 bits)
  SetInfo (16 bits) | Flush (16 bits)
```

**Write (2 bytes):** A 16-bit unsigned integer containing the number of **MFT2** writes due to a write

operation.

**Create (2 bytes):** A 16-bit unsigned integer containing the number of **MFT2** writes due to a create

operation.

**SetInfo (2 bytes):** A16-bit unsigned integer containing the number of **MFT2** writes due to a set file

information operation.

**Flush (2 bytes):** A 16-bit unsigned integer containing the number of **MFT2** writes due to a flush

operation.

**2.3.12.2.3** **BitmapWritesUserLevel**

The **BitmapWritesUserLevel** structure contains statistics about bitmap writes resulting from certain
user-level operations.

The **BitmapWritesUserLevel** structure is as follows.

```
  Write (16 bits) | Create (16 bits)
```
|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|SetInfo|||||||||||||||||

**Write (2 bytes):** A 16-bit unsigned integer containing the number of bitmap writes due to a write

operation.

**Create (2 bytes):** A 16-bit unsigned integer containing the number of bitmap writes due to a create

operation.

**SetInfo (2 bytes):** A 16-bit unsigned integer containing the number of bitmap writes due to a set file

information operation.

**2.3.12.2.4** **MftBitmapWritesUserLevel**

The **MftBitmapWritesUserLevel** structure contains statistics about **MFT** bitmap write operations
resulting from certain user-level operations.

The **MftBitmapWritesUserLevel** structure is as follows.

```
  Write (16 bits) | Create (16 bits)
  SetInfo (16 bits) | Flush (16 bits)
```
**Write (2 bytes):** A 16-bit unsigned integer containing the number of **MFT** bitmap write operations

due to a write operation.

**Create (2 bytes):** A 16-bit unsigned integer containing the number of **MFT** bitmap write operations

due to a create operation.

**SetInfo (2 bytes):** A 16-bit unsigned integer containing the number of **MFT** bitmap write operations

due to a set file information operation.

**Flush (2 bytes):** A 16-bit unsigned integer containing the number of **MFT** bitmap write operations

due to a flush operation.

**2.3.12.2.5** **Allocate**

The **Allocate** structure describes cluster allocation patterns in NTFS. The cache refers to in-memory
structures that allow quick lookups of free cluster runs either by **logical cluster number (LCN)** or by
run length.

The **Allocate** structure is as follows.

```
  Calls (32 bits)
  Clusters (32 bits)
  Hints (32 bits)
  RunsReturned (32 bits)
  HintsHonored (32 bits)
  HintsClusters (32 bits)
  Cache (32 bits)
  CacheClusters (32 bits)
  CacheMiss (32 bits)
  CacheMissClusters (32 bits)
```

**Calls (4 bytes):** A 32-bit unsigned integer value containing the number of individual calls to allocate

clusters.

**Clusters (4 bytes):** A 32-bit unsigned integer value containing the number of clusters allocated.

**Hints (4 bytes):** A 32-bit unsigned integer value containing the number of times a hint was specified

when trying to determine which clusters to allocate.

**RunsReturned (4 bytes):** A 32-bit unsigned integer value containing the number of runs used to

satisfy all the requests.

**HintsHonored (4 bytes):** A 32-bit unsigned integer value containing the number of times the

starting LCN hint was used to determine which clusters to allocate.
**HintsClusters (4 bytes):** A 32-bit unsigned integer value containing the number of clusters allocated

via the starting LCN hint.

**Cache (4 bytes):** A 32-bit unsigned integer value containing the number of times the run length

cache was useful.

**CacheClusters (4 bytes):** A 32-bit unsigned integer value containing the number of clusters

allocated via the run length cache.

**CacheMiss (4 bytes):** A 32-bit unsigned integer value containing the number of times the cache was

not useful and the bitmapped had to be scanned for free clusters.

**CacheMissClusters (4 bytes):** A 32-bit unsigned integer value containing the number of clusters

allocated by scanning the bitmap.

**2.3.12.3** **FAT_STATISTICS**

The **FAT_STATISTICS** data element is returned with a FSCTL_FILESYSTEM_GET_STATISTICS reply
message when FAT file system statistics are requested.

The **FAT_STATISTICS** data element is as follows:

```
  CreateHits (32 bits)
  SuccessfulCreates (32 bits)
  FailedCreates (32 bits)
  NonCachedReads (32 bits)
  NonCachedReadBytes (32 bits)
  NonCachedWrites (32 bits)
  NonCachedWriteBytes (32 bits)
  NonCachedDiskReads (32 bits)
  NonCachedDiskWrites (32 bits)
```

**CreateHits (4 bytes):** A 32-bit unsigned integer value containing the number of create operations.

**SuccessfulCreates (4 bytes):** A 32-bit unsigned integer value containing the number of successful

create operations.

**FailedCreates (4 bytes):** A 32-bit unsigned integer value containing the number of failed create

operations.

**NonCachedReads (4 bytes):** A 32-bit unsigned integer value containing the number of read

operations that were not cached.

**NonCachedReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

read from a file that were not cached.
**NonCachedWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations that were not cached.

**NonCachedWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

written to a file that were not cached.

**NonCachedDiskReads (4 bytes):** A 32-bit unsigned integer value containing the number of read

operations that were not cached. This value includes **sub-read** operations.

**NonCachedDiskWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations that were not cached. This value includes sub-write operations.

**2.3.12.4** **EXFAT_STATISTICS**

The **EXFAT_STATISTICS** data element is returned with a FSCTL_FILESYSTEM_GET_STATISTICS
reply message when exFAT file system statistics are requested.

The **EXFAT_STATISTICS** data element is as follows:

```
  CreateHits (32 bits)
  SuccessfulCreates (32 bits)
  FailedCreates (32 bits)
  NonCachedReads (32 bits)
  NonCachedReadBytes (32 bits)
  NonCachedWrites (32 bits)
  NonCachedWriteBytes (32 bits)
  NonCachedDiskReads (32 bits)
  NonCachedDiskWrites (32 bits)
```

**CreateHits (4 bytes):** A 32-bit unsigned integer value containing the number of create operations.

**SuccessfulCreates (4 bytes):** A 32-bit unsigned integer value containing the number of successful

create operations.

**FailedCreates (4 bytes):** A 32-bit unsigned integer value containing the number of failed create

operations.

**NonCachedReads (4 bytes):** A 32-bit unsigned integer value containing the number of read

operations that were not cached.

**NonCachedReadBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

read from a file that were not cached.

**NonCachedWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations that were not cached.
**NonCachedWriteBytes (4 bytes):** A 32-bit unsigned integer value containing the number of bytes

written to a file that were not cached.

**NonCachedDiskReads (4 bytes):** A 32-bit unsigned integer value containing the number of read

operations that were not cached. This value includes **sub-read** operations.

**NonCachedDiskWrites (4 bytes):** A 32-bit unsigned integer value containing the number of write

operations that were not cached. This value includes sub-write operations.
