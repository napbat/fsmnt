<!-- MS-FSCC Reference: Common Data Types -->
<!-- Reparse points (tags, REPARSE_DATA_BUFFER, symlinks, mount points, NFS), FILE_OBJECTID_BUFFER, alternate data streams, pathnames, filenames, FILE_NAME_INFORMATION, 64/128-bit file IDs, STORAGE_OFFLOAD_TOKEN. -->

**2.1** **Common Data Types**

**2.1.1** **Time**

Unless otherwise noted, **Time** fields are 64-bit signed integers representing the number of 100nanosecond intervals that have elapsed since January 1, 1601, Coordinated Universal Time (UTC).

See FILETIME ([MS-DTYP] section 2.3.3) for related information.

For information regarding the semantics of the file timestamps of the **CreationTime**,
**LastAccessTime**, **LastWriteTime**, and **ChangeTime** fields, see [[FSBO]](https://go.microsoft.com/fwlink/?LinkId=140636) section 6.

**2.1.2** **Reparse Point Data Structures**

For conceptual information about reparse points, see [[REPARSE].](https://go.microsoft.com/fwlink/?LinkId=90259)

**2.1.2.1** **Reparse Tags**

Each **reparse point** has a **reparse tag** . The reparse tag uniquely identifies the owner of that reparse
point. The owner is the implementer of the file system **filter** driver associated with a reparse tag.

Reparse tags are stored as 32-bit unsigned integer values, as shown in the following diagram.

```
  M (1 bit) | R (1 bit) | N (1 bit) | D (1 bit) | Reserved (12 bits) | Value (16 bits)
```

**M (1 bit):** Microsoft bit. If this bit is set to 1, the tag is owned by Microsoft. All other tags MUST use

zero for this bit.

**R (1 bit):** Reserved bit. This bit MUST be set to zero for non-Microsoft tags. It was formerly known as

High-latency bit.

**N (1 bit):** Name Surrogate bit. If this bit is set to 1, the file or directory represents another named

entity in the system.

**D (1 bit):** Directory bit. Indicates that any directory with this reparse tag can have children. This bit

does not have special meaning when used on a non-directory file. This bit MUST NOT be set when
N (Name Surrogate) bit is set.
**Reserved (12 bits):** This field is reserved. This field SHOULD be set to 0 and MUST be ignored on

receipt.

**Value (2 bytes):** A 16-bit unsigned integer containing the reparse point tag that uniquely identifies

the owner of the reparse point.

Reparse tags are exposed to clients for third-party applications. Those applications can set, get, and
process reparse tags as needed. Third parties MUST request a reserved reparse tag value to ensure
[that conflicting tag values do not occur. [WHDC-RPTR]](https://go.microsoft.com/fwlink/?LinkId=90564) <1>

The following reparse tags, with the exception of IO_REPARSE_TAG_SYMLINK, are processed on the
server and are not processed by a client after transmission over the wire. Clients SHOULD treat
associated reparse data as opaque data.<2>

|Value|Meaning|
|---|---|
|IO_REPARSE_TAG_RESERVED_ZERO<br>0x00000000|Reserved reparse tag value.|
|IO_REPARSE_TAG_RESERVED_ONE<br>0x00000001|Reserved reparse tag value.|
|IO_REPARSE_TAG_RESERVED_TWO<br>0x00000002|Reserved reparse tag value.|
|IO_REPARSE_TAG_MOUNT_POINT<br>0xA0000003|Used for mount point support, specified in section2.1.2.5.|
|IO_REPARSE_TAG_HSM<br>0xC0000004|Obsolete. Used by legacy Hierarchical Storage Management<br>Product.|
|IO_REPARSE_TAG_DRIVE_EXTENDER<br>0x80000005|Home server drive extender.<3>|
|IO_REPARSE_TAG_HSM2<br>0x80000006|Obsolete. Used by legacy Hierarchical Storage Management<br>Product.|
|IO_REPARSE_TAG_SIS<br>0x80000007|Used by**single-instance storage (SIS)** filter driver. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_WIM<br>0x80000008|Used by the WIM Mount filter. Server-side interpretation only, not<br>meaningful over the wire.|
|IO_REPARSE_TAG_CSV<br>0x80000009|Obsolete. Used by Clustered Shared Volumes (CSV) version 1 in<br>Windows Server 2008 R2 operating system. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_DFS<br>0x8000000A|Used by the DFS filter. The DFS is described in the Distributed File<br>System (DFS): Referral Protocol Specification[MS-DFSC]. Server-<br>side interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_FILTER_MANAGER<br>0x8000000B|Used by**filter manager** test harness.<4>|
|IO_REPARSE_TAG_SYMLINK<br>0xA000000C|Used for**symbolic link** support. See section2.1.2.4.|
|IO_REPARSE_TAG_IIS_CACHE<br>0xA0000010|Used by Microsoft Internet Information Services (IIS) caching.<br>Server-side interpretation only, not meaningful over the wire.|
|Value|Meaning|
|---|---|
|IO_REPARSE_TAG_DFSR<br>0x80000012|Used by the DFS filter. The DFS is described in [MS-DFSC].<br>Server-side interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_DEDUP<br>0x80000013|Used by the Data Deduplication (Dedup) filter. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_APPXSTRM<br>0xC0000014|Not used.|
|IO_REPARSE_TAG_NFS<br>0x80000014|Used by the Network File System (NFS) component. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_FILE_PLACEHOLDER<br>0x80000015|Obsolete. Used by Windows Shell for legacy placeholder files in<br>Windows 8.1. Server-side interpretation only, not meaningful over<br>the wire.|
|IO_REPARSE_TAG_DFM<br>0x80000016|Used by the Dynamic File filter. Server-side interpretation only,<br>not meaningful over the wire.|
|IO_REPARSE_TAG_WOF<br>0x80000017|Used by the Windows Overlay filter, for either WIMBoot or single-<br>file compression. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_WCI<br>0x80000018|Used by the Windows Container Isolation filter. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_WCI_1<br>0x90001018|Used by the Windows Container Isolation filter. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_GLOBAL_REPARSE<br>0xA0000019|Used by NPFS to indicate a named pipe symbolic link from a<br>server silo into the host silo. Server-side interpretation only, not<br>meaningful over the wire.|
|IO_REPARSE_TAG_CLOUD<br>0x9000001A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as Microsoft OneDrive. Server-side interpretation only, not<br>meaningful over the wire.|
|IO_REPARSE_TAG_CLOUD_1<br>0x9000101A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_2<br>0x9000201A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_3<br>0x9000301A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_4<br>0x9000401A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_5<br>0x9000501A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_6<br>0x9000601A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|Value|Meaning|
|---|---|
|IO_REPARSE_TAG_CLOUD_7<br>0x9000701A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_8<br>0x9000801A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_9<br>0x9000901A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_A<br>0x9000A01A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_B<br>0x9000B01A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_C<br>0x9000C01A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_D<br>0x9000D01A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_E<br>0x9000E01A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_CLOUD_F<br>0x9000F01A|Used by the Cloud Files filter, for files managed by a sync engine<br>such as OneDrive. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_APPEXECLINK<br>0x8000001B|Used by Universal Windows Platform (UWP) packages to encode<br>information that allows the application to be launched by<br>CreateProcess. Server-side interpretation only, not meaningful<br>over the wire.|
|IO_REPARSE_TAG_PROJFS<br>0x9000001C|Used by the Windows Projected File System filter, for files<br>managed by a user mode provider such as VFS for Git. Server-<br>side interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_LX_SYMLINK<br>0xA000001D|Used by the Windows Subsystem for Linux (WSL) to represent a<br>UNIX symbolic link. See section2.1.2.7.|
|IO_REPARSE_TAG_STORAGE_SYNC<br>0x8000001E|Used by the Azure File Sync (AFS) filter. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_STORAGE_SYNC_FOLDER<br>0x90000027|Used by the Azure File Sync (AFS) filter for folder. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_WCI_TOMBSTONE<br>0xA000001F|Used by the Windows Container Isolation filter. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_UNHANDLED<br>0x80000020|Used by the Windows Container Isolation filter. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_ONEDRIVE|Not used.|
|Value|Meaning|
|---|---|
|0x80000021||
|IO_REPARSE_TAG_PROJFS_TOMBSTONE<br>0xA0000022|Used by the Windows Projected File System filter, for files<br>managed by a user mode provider such as VFS for Git. Server-<br>side interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_AF_UNIX<br>0x80000023|Used to represent a UNIX domain socket. Server-side<br>interpretation only, not meaningful over the wire. No defined<br>structure.|
|IO_REPARSE_TAG_LX_FIFO<br>0x80000024|Used by the Windows Subsystem for Linux (WSL) to represent a<br>UNIX FIFO (named pipe). Server-side interpretation only, not<br>meaningful over the wire. No defined structure.|
|IO_REPARSE_TAG_LX_CHR<br>0x80000025|Used by the Windows Subsystem for Linux (WSL) to represent a<br>UNIX character special file. Server-side interpretation only, not<br>meaningful over the wire. No defined structure.|
|IO_REPARSE_TAG_LX_BLK<br>0x80000026|Used by the Windows Subsystem for Linux (WSL) to represent a<br>UNIX block special file. Server-side interpretation only, not<br>meaningful over the wire. No defined structure.|
|IO_REPARSE_TAG_WCI_LINK<br>0xA0000027|Used by the Windows Container Isolation filter. Server-side<br>interpretation only, not meaningful over the wire.|
|IO_REPARSE_TAG_WCI_LINK_1<br>0xA0001027|Used by the Windows Container Isolation filter. Server-side<br>interpretation only, not meaningful over the wire.|

**2.1.2.2** **REPARSE_DATA_BUFFER**

The **REPARSE_DATA_BUFFER** data element stores data for a reparse point. This reparse data buffer
MUST be used only with reparse tag values whose high bit is set to 1.

This data element has the following subtypes:

- Symbolic Link Reparse Data Buffer

- Mount Point Reparse Data Buffer

- Network File System (NFS) Reparse Data Buffer

- LX SYMLINK REPARSE_DATA_BUFFER

```
  ReparseTag (32 bits)
  ReparseDataLength (16 bits) | Reserved (16 bits)
  DataBuffer (variable) (32 bits)
  ...
```
**ReparseTag (4 bytes):** A 32-bit unsigned integer value containing the reparse point tag that

uniquely identifies the owner of the **reparse point** .

**ReparseDataLength (2 bytes):** A 16-bit unsigned integer value containing the size, in bytes, of the

reparse data in the **DataBuffer** member.

**Reserved (2 bytes):** A 16-bit field. This field is reserved. This field SHOULD be set to 0, and MUST

be ignored.

**DataBuffer (variable):** A variable-length array of 8-bit unsigned integer values containing reparse
specific data for the reparse point. The format of this data is defined by the owner (that is, the
implementer of the **filter** driver associated with the specified ReparseTag) of the reparse point.

**2.1.2.3** **REPARSE_GUID_DATA_BUFFER**

The **REPARSE_GUID_DATA_BUFFER** data element stores data for a reparse point and associates a
GUID with the **reparse tag** . This reparse data buffer MUST be used only with reparse tag values
whose high bit is set to 0.

**Reparse point** **GUIDs** are assigned by the **independent software vendor (ISV)** . An ISV MUST link
one GUID to each assigned reparse point tag and MUST always use that GUID with that **tag** .

```
  ReparseTag (32 bits)
  ReparseDataLength (16 bits) | Reserved (16 bits)
  ReparseGuid (16 bytes) (32 bits)
  DataBuffer (variable) (32 bits)
  ...
```

**ReparseTag (4 bytes):** A 32-bit unsigned integer value containing the reparse point tag that

uniquely identifies the owner of the reparse point.

**ReparseDataLength (2 bytes):** A 16-bit unsigned integer value containing the size, in bytes, of the

reparse data in the **DataBuffer** member.

**Reserved (2 bytes):** A 16-bit field. This field SHOULD be set to 0 by the client, and MUST be ignored

by the server.

**ReparseGuid (16 bytes):** A 16-byte GUID that uniquely identifies the owner of the reparse point.

Reparse point GUIDs are not assigned by Microsoft. A reparse point implementer MUST select one
GUID to be used with their assigned reparse point tag to uniquely identify that reparse point. For
[more information, see [REPARSE].](https://go.microsoft.com/fwlink/?LinkId=90259)

**DataBuffer (variable):** The content of this buffer is opaque to the file system. On receipt, its content

MUST be preserved and properly returned to the caller.
**2.1.2.4** **Symbolic Link Reparse Data Buffer**

The **Symbolic Link Reparse Data Buffer** data element is a subtype of REPARSE_DATA_BUFFER,
which contains information on **symbolic link** **reparse points** . This reparse data buffer MUST be used
only with reparse tag values whose high bit is set to 1.

A symbolic link has a substitute name and a print name associated with it. The substitute name is a
pathname (section 2.1.5) identifying the target of the symbolic link. The print name SHOULD be an
informative pathname, suitable for display to a user, that also identifies the target of the symbolic
link. Either pathname can contain dot directory names as specified in section 2.1.5.1.

```
  ReparseTag (32 bits)
  ReparseDataLength (16 bits) | Reserved (16 bits)
  SubstituteNameOffset (16 bits) | SubstituteNameLength (16 bits)
  PrintNameOffset (16 bits) | PrintNameLength (16 bits)
  Flags (32 bits)
  PathBuffer (variable) (32 bits)
  ...
```

**ReparseTag (4 bytes):** A 32-bit unsigned integer value containing the **reparse point tag** that

uniquely identifies the owner (that is, the implementer of the **filter** driver associated with this
ReparseTag) of the reparse point. This value MUST be 0xA000000C.

**ReparseDataLength (2 bytes):** A 16-bit unsigned integer value containing the size, in bytes, of the

reparse data that follows the common portion of the REPARSE_DATA_BUFFER element. This value
is the length of the data starting at the **SubstituteNameOffset** field (or the size of the
**PathBuffer** field, in bytes, plus 12).

**Reserved (2 bytes):** A 16-bit field. This field is not used. It SHOULD be set to 0 and MUST be

ignored.

**SubstituteNameOffset (2 bytes):** A 16-bit unsigned integer that contains the offset, in bytes, of the

substitute name string in the **PathBuffer** array, computed as an offset from byte 0 of
**PathBuffer** . Note that this offset is divided by 2 to get the array index.

**SubstituteNameLength (2 bytes):** A 16-bit unsigned integer that contains the length, in bytes, of

the substitute name string. If this string is null-terminated, **SubstituteNameLength** does not
include the Unicode null character.

**PrintNameOffset (2 bytes):** A 16-bit unsigned integer that contains the offset, in bytes, of the print

name string in the **PathBuffer** array, computed as an offset from byte 0 of **PathBuffer** . Note that
this offset is divided by 2 to get the array index.

**PrintNameLength (2 bytes):** A 16-bit unsigned integer that contains the length, in bytes, of the

print name string. If this string is null-terminated, **PrintNameLength** does not include the
Unicode null character.
**Flags (4 bytes):** A 32-bit field that specifies whether the substitute name is a full path name or a

path name relative to the directory containing the symbolic link.

This field contains one of the values in the following table.

|Value|Meaning|
|---|---|
|0x00000000|The substitute name is a full path name.|
|SYMLINK_FLAG_RELATIVE<br>0x00000001|The substitute name is a path name relative to the directory containing the symbolic<br>link.|

**PathBuffer (variable): Unicode character** array that contains the substitute name string and print

name string. The substitute name and print name strings can appear in any order in the
**PathBuffer** . To locate the substitute name and print name strings in the **PathBuffer**, use the
**SubstituteNameOffset**, **SubstituteNameLength**, **PrintNameOffset**, and **PrintNameLength**
members.

**2.1.2.5** **Mount Point Reparse Data Buffer**

The **Mount Point Reparse Data Buffer** data element is a subtype of REPARSE_DATA_BUFFER, which
contains information about mount point **reparse points** . This reparse data buffer MUST be used only
with reparse tag values whose high bit is set to 1.

A mount point has a substitute name and a print name associated with it. The substitute name is a
pathname (section 2.1.5) identifying the target of the mount point. The print name SHOULD be an
informative pathname, suitable for display to a user, that also identifies the target of the mount point.
Neither of these pathnames can contain dot directory names.

```
  ReparseTag (32 bits)
  ReparseDataLength (16 bits) | Reserved (16 bits)
  SubstituteNameOffset (16 bits) | SubstituteNameLength (16 bits)
  PrintNameOffset (16 bits) | PrintNameLength (16 bits)
  PathBuffer (variable) (32 bits)
  ...
```

**ReparseTag (4 bytes):** A 32-bit unsigned integer value containing the **reparse point tag** that

uniquely identifies the owner (that is, the implementer of the **filter** driver associated with this
ReparseTag) of the reparse point. This value MUST be 0xA0000003.

**ReparseDataLength (2 bytes):** A 16-bit unsigned integer value containing the size, in bytes, of the

reparse data that follows the common portion of the REPARSE_DATA_BUFFER element. This value
is the length of the data starting at the **SubstituteNameOffset** field (or the size of the
**PathBuffer** field, in bytes, plus 8).

**Reserved (2 bytes):** A 16-bit field. This field is not used. It SHOULD be set to 0 and MUST be

ignored.
**SubstituteNameOffset (2 bytes):** A 16-bit unsigned integer that contains the offset, in bytes, of the

substitute name string in the **PathBuffer** array, computed as an offset from byte 0 of
**PathBuffer** . Note that this offset is divided by 2 to get the array index.

**SubstituteNameLength (2 bytes):** A 16-bit unsigned integer that contains the length, in bytes, of

the substitute name string. If this string is null-terminated, **SubstituteNameLength** does not
include the Unicode null character.

**PrintNameOffset (2 bytes):** A 16-bit unsigned integer that contains the offset, in bytes, of the print

name string in the **PathBuffer** array, computed as an offset from byte 0 of **PathBuffer** . Note that
this offset is divided by 2 to get the array index.

**PrintNameLength (2 bytes):** A 16-bit unsigned integer that contains the length, in bytes, of the

print name string. If this string is null-terminated, **PrintNameLength** does not include the
Unicode null character.

**PathBuffer (variable):** Unicode character array that contains the substitute name string and print

name string. The substitute name and print name strings can appear in any order in **PathBuffer** .
To locate the substitute name and print name strings in the **PathBuffer** field, use the
**SubstituteNameOffset**, **SubstituteNameLength**, **PrintNameOffset**, and **PrintNameLength**
members.

**2.1.2.6** **Network File System (NFS) Reparse Data Buffer**

The **Network File System Reparse Data Buffer** data element is a subtype of
REPARSE_DATA_BUFFER, which contains information about symbolic files and devices created by the
Network File System client.

```
  ReparseTag (32 bits)
  ReparseDataLength (16 bits) | Reserved (16 bits)
  GenericReparseBuffer (variable) (32 bits)
  ...
```

**ReparseTag (4 bytes):** A 32-bit unsigned integer value containing the reparse point tag that

uniquely identifies the owner (that is, the implementer of the filter driver associated with this
ReparseTag) of the reparse point. This value MUST be 0x80000014.

**ReparseDataLength (2 bytes):** A 16-bit unsigned integer value containing the size, in bytes, of the

reparse data that follows the common portion of the REPARSE_DATA_BUFFER element. This value
is the length of the data starting at the **GenericReparseBuffer** field.

**Reserved (2 bytes):** A 16-bit field. This field is not used. It SHOULD be set to 0 and MUST be

ignored.

**GenericReparseBuffer (variable):** The data in this variable buffer takes the following format.

```
  Type (32 bits)
```
**Type (8 bytes):** A 64-bit unsigned integer value describing the type and format of the data stored in

the **DataBuffer** field. The valid values for this field are:

|Value|Meaning|
|---|---|
|NFS_SPECFILE_LNK<br>0x00000000014B4E4C|Indicates that the**DataBuffer** field has a Unicode string containing the symbolic<br>link data.|
|NFS_SPECFILE_CHR<br>0x0000000000524843|Indicates that the**DataBuffer** field has two 32–bit integers that contain the major<br>and minor device numbers for the character special device created by the Network<br>File System client.|
|NFS_SPECFILE_BLK<br>0x00000000004B4C42|Indicates that the**DataBuffer** field has two 32–bit integers that contain the major<br>and minor device numbers for the block special device created by the Network File<br>System client.|
|NFS_SPECFILE_FIFO<br>0x000000004F464946|Indicates that the file containing the NFS reparse point is a named pipe device<br>created by the Network File System client. The**DataBuffer** field is empty.|
|NFS_SPECFILE_SOCK<br>0x000000004B434F53|Indicates that the file containing the NFS reparse point is a socket device created<br>by the Network File System client. The**DataBuffer** field is empty.|

**DataBuffer (variable):** A variable buffer that has the following formats depending upon the **Type**

field defined earlier.

- **NFS_SPECFILE_CHR** and **NFS_SPECFILE_BLK** : The **DataBuffer** field contains two 32-bit
integers that represent major and minor device numbers.

- **NFS_SPECFILE_LNK** : The **DataBuffer** field contains the symbolic link target path specified by
[the Network File System client in its NFSPROC_SYMLINK request, [RFC1813]](https://go.microsoft.com/fwlink/?LinkId=90294) section 3.3.10 and

[[RFC1094]](https://go.microsoft.com/fwlink/?LinkId=90267) section 2.2.14, represented in Unicode format and not NULL-terminated. The upper
limit on the size of the symbolic link data is 2050 bytes.

- **NFS_SPECFILE_FIFO** and **NFS_SPECFILE_SOCK** : The **DataBuffer** field is empty.

**2.1.2.7** **LX SYMLINK REPARSE_DATA_BUFFER**

The **LX SYMLINK** **Reparse Data Buffer** data element is a subtype of section
REPARSE_DATA_BUFFER, which contains information about symbolic files generated by WSL (Windows
Subsystem for Linux).

```
  ReparseTag (32 bits)
  ReparseDataLength (16 bits) | Reserved (16 bits)
  Version (32 bits)
```
**ReparseTag (4 bytes):** A 32-bit unsigned integer value containing the reparse point tag that

uniquely identifies the owner of the **reparse point** .

**ReparseDataLength (2 bytes):** A 16-bit unsigned integer value containing the size, in bytes, of the

reparse data that follows the common portion of the REPARSE_DATA_BUFFER element. This value
is the length of the data starting at the **Version** field.

**Reserved (2 bytes):** A 16-bit field. This field is reserved. This field SHOULD be set to 0, and MUST

be ignored.

**Version (4 bytes):** A 32-bit field. This field defines the layout of the **Target** field. This field MUST be
set to 2.

**Target (variable):** An array of 8-byte characters that contains the target path of the symlink.

**2.1.3** **FILE_OBJECTID_BUFFER Structure**

The **FILE_OBJECTID_BUFFER** structure contains extended metadata for a file system object,
including its object ID. This data element MUST be in one of the following two formats:

- FILE_OBJECTID_BUFFER Type 1

- FILE_OBJECTID_BUFFER Type 2

**2.1.3.1** **FILE_OBJECTID_BUFFER Type 1**

The first possible structure for the FILE_OBJECTID_BUFFER data element is as follows.

```
  ObjectId (16 bytes) (32 bits)
  BirthVolumeId (16 bytes) (32 bits)
  BirthObjectId (16 bytes) (32 bits)
  ...
```
**ObjectId (16 bytes):** A 16-byte **GUID** that uniquely identifies the file or directory within the **volume**

on which it resides. Specifically, the same object ID can be assigned to another file or directory on
a different volume, but it MUST NOT be assigned to another file or directory on the same volume.

**BirthVolumeId (16 bytes):** A 16-byte GUID that uniquely identifies the volume on which the object

resided when the **object identifier** was created, or zero if the volume had no object identifier at
that time. After copy operations, move operations, or other file operations, this value is potentially
different from the object identifier of the volume on which the object presently resides.

**BirthObjectId (16 bytes):** A 16-byte GUID value containing the object identifier of the object at the

time it was created. Copy operations, move operations, or other file operations MAY change the
value of the **ObjectId** member. Therefore, the **BirthObjectId** is potentially different from the
**ObjectId** member at present. Specifically, the same object ID MAY be assigned to another file or
directory on a different volume, but it MUST NOT be assigned to another file or directory on the
same volume. The object ID is assigned at file creation time.<5>

**DomainId (16 bytes):** A 16-byte GUID value containing the domain identifier. This value is unused;

it SHOULD be zero, and MUST be ignored.<6>

**2.1.3.2** **FILE_OBJECTID_BUFFER Type 2**

The second possible structure for the FILE_OBJECTID_BUFFER data element is as follows.

```
  ObjectId (16 bytes) (32 bits)
  ExtendedInfo (48 bytes) (32 bits)
  ...
```

**ObjectId (16 bytes):** A 16-byte **GUID** that uniquely identifies the file or directory within the **volume**

on which it resides. Specifically, the same object ID can be assigned to another file or directory on
a different volume, but it MUST NOT be assigned to another file or directory on the same volume.

**ExtendedInfo (48 bytes):** A 48-byte value containing extended data that was set with the

FSCTL_SET_OBJECT_ID_EXTENDED request. This field contains application-specific data.<7>
**2.1.4** **Alternate Data Streams**

A file system MAY<8> support alternate data streams within a file or a directory. For a general
description of **file streams**, section 1.1.

Every file has a default stream, which is the stream that is referenced when no stream name
component is specified as part of the pathname. A directory does not have a default data stream;
however, it can have named alternate data streams.

For more information on stream naming, see section 2.1.5; for more information on streams in
general, see section 5.

**2.1.5** **Pathname**

A pathname has the following characteristics:

- A pathname MUST be no more than 32,760 characters in length.

- A pathname is composed of one or more pathname components separated by the "\" backslash
character. All pathname components other than the last pathname component denote directories
or **reparse points** . The last pathname component denotes a directory, a file, a stream, or a
reparse point.

- A leading "\" backslash character is optional, and determines whether a pathname is absolute or
relative:

  - A pathname that begins with a leading "\" backslash character, for example, "\a\b\c", is an
absolute pathname. An absolute pathname SHOULD be evaluated relative to the root
directory.

  - A pathname that omits a leading "\" backslash character, for example, "a\b\c", is a relative
pathname. A relative pathname MAY be evaluated relative to any directory, such as an
application's current working directory.

- Each pathname component has one of the following forms:

  - A **dot directory name** as specified in section 2.1.5.1.

  - A filename as specified in section 2.1.5.2, optionally followed by a ":" colon character and a
streamname as specified in section 2.1.5.3, optionally followed by a ":" colon character and a
streamtype as specified in section 2.1.5.4. The streamname, if specified, MAY be zero-length
only if streamtype is also specified; otherwise, it MUST be at least one character. The
streamtype, if specified, MUST be at least one character.

**2.1.5.1** **Dot Directory Names**

The pathname components of "." (single period) and ".." (two periods) are reserved as dot directory
names.

Except where explicitly permitted, a pathname component that is a dot directory name MUST NOT be
sent over the wire.

When parsing pathname components, a dot directory name of "." refers to the current directory name
component and a dot directory name of ".." refers to the parent directory name of the current
directory name component.

Some examples to illustrate:

- In the pathname "dirA\.\dirB", the "." refers to dirA, so this expression is equivalent to "dirA\dirB".
- In the pathname "dirA\dirB\..\dirC", the ".." refers to dirA, so this expression is equivalent to
"dirA\dirC".

A dot directory name of ".." at the root of a share MUST be treated as equivalent to ".". For example:
\\ServerX\ShareY\..\dirA is equivalent to \\ServerX\ShareY\.\dirA (which is equivalent to
\\ServerX\ShareY\dirA).

**2.1.5.2** **Filename**

- All **Unicode characters** are legal in a filename except the following:

  - The characters

```
  " \ / : | < > * ?

```

  - Control characters, ranging from 0x00 through 0x1F.

- A filename MUST be at least one character but no more than 255 characters in length.

**2.1.5.2.1** **8.3 Filename**

An 8.3 filename (also referred to as a DOS name, a **short name**, or an 8.3-compliant filename) is a
filename that conforms to the following restrictions:

- An 8.3 filename MUST only contain characters that can be represented in ASCII, in the range
below 0x80.

- An 8.3 filename MUST NOT contain the " " space character.

- An 8.3 filename MUST NOT contain more than one "." period character.

- The general form of a valid 8.3 filename is a base filename, optionally followed by the "." period
character and a filename extension.

  - The base filename MUST be 1-8 characters in length and MUST NOT contain a "." period
character.

  - The filename extension, if present, MUST be 1-3 characters in length and MUST NOT contain a
"." period character.

**2.1.5.3** **Streamname**

- All **Unicode characters** are legal in a streamname component except the following:

  - The characters \ / :

  - Control character 0x00.

  - A streamname MUST be no more than 255 characters in length.

- A zero-length streamname denotes the default **stream** .

See section 5 for additional information on alternate streams in the **NTFS** file system.

**2.1.5.4** **Streamtype**

- All **Unicode characters** are legal in a streamtype component except the following:
  - The characters \ / :

  - Control character 0x00.

**2.1.6** **Share name**

A share name has the following characteristics:

- A share name MUST be no more than 80 characters in length.

- The following characters are illegal in a share name:

```
  " \ / [ ] : | < > + = ;, * ?

```

- Control characters in range 0x00 through 0x1F, inclusive, are illegal in a share name.

- All other Unicode characters are legal.

**2.1.7** **FILE_NAME_INFORMATION**

The **FILE_NAME_INFORMATION** data element is as follows.

```
  FileNameLength (32 bits)
  FileName (variable) (32 bits)
  ...
```

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** field.

**FileName (variable):** A sequence of Unicode characters containing a pathname (section 2.1.5). The

meaning of the pathname depends on the operation. The name string is not null-terminated.
There are scenarios where one or more padding characters can be at the end of the string due to
buffer alignment requirements, but their presence and their values MUST NOT be relied upon.
When working with this field, use **FileNameLength** to determine the length of the file name
rather than assuming the presence of a trailing null delimiter.

**2.1.8** **Boolean**

A **Boolean** data type is a primitive that has one of two possible values: TRUE and FALSE, which are
defined as follows:

**TRUE:** A sender MUST use any nonzero value to denote a TRUE. A receiver MUST interpret any

nonzero value as TRUE.<9>

**FALSE:** A sender MUST use a zero value to denote a FALSE. A receiver MUST interpret a zero value

as FALSE.
**2.1.9** **64-bit file ID**

A **64-bit file ID** value uniquely identifies a file within a given volume. This identifier is generated and
stored by the file system. The identifier SHOULD<10> be unique to the volume and stable until the
file is deleted.

For file systems that do not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored.

For files for which a unique 64-bit file ID cannot be established, this field MUST be set to
0xFFFFFFFFFFFFFFFF, and MUST be ignored.

**2.1.10** **128-bit file ID**

A **128-bit file ID** value uniquely identifies a file within a given volume. This identifier is generated
and stored by the file system. The identifier SHOULD<11> be unique to the volume and stable until
the file is deleted.

For file systems that do not support a **128-bit file ID**, this field MUST be set to 0, and MUST be
ignored.

For files for which a unique **128-bit file ID** cannot be established, this field MUST be set to
0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, and MUST be ignored.

**2.1.11** **STORAGE_OFFLOAD_TOKEN**

The **STORAGE_OFFLOAD_TOKEN** structure contains the **Token** to be used as a representation of
the data contained within the portion of the file specified in the FSCTL_OFFLOAD_READ_INPUT data
element at the time of the FSCTL_OFFLOAD_READ operation. This Token is used in
FSCTL_OFFLOAD_READ and FSCTL_OFFLOAD_WRITE operations. The format of the data within this
field is either vendor-specific or of a well-known type. The contents of this field MUST NOT be modified
during subsequent operations.<12>

The **TokenType** and **TokenIdLength** fields of **STORAGE_OFFLOAD_TOKEN** structure MUST be
sent in big-endian format. The **TokenId** field is a stream of bytes and has no endian property.

The **STORAGE_OFFLOAD_TOKEN** structure is as follows.

```
  TokenType (32 bits)
  Reserved (16 bits) | TokenIdLength (16 bits)
  TokenId (504 bytes) (32 bits)
  ...
```

**TokenType (4 bytes):** A 32-bit unsigned integer that defines the type of Token that is contained

within the **STORAGE_OFFLOAD_TOKEN** structure. This field MUST contain one of the following
values.
|Value|Meaning|
|---|---|
|STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA<br>0xFFFF0001|A well-known Token that indicates that the data logically<br>represented by the Token is logically equivalent to<br>zero.<13>|
|Reserved<br>0xFFFF0002 – 0xFFFFFFFF|Reserved for other well-known Tokens currently<br>undefined.|
|Any other value.<br>|A vendor-specific Token format is contained within the<br>**Token** field.|

**Reserved (2 bytes):** A 16-bit unsigned integer that is reserved. This field SHOULD be set to 0x0000

and MUST be ignored.

**TokenIdLength (2 bytes):** A 16-bit unsigned integer that defines the length of the **TokenId** field in

bytes.

**TokenId (504 bytes):** A 504-byte unsigned integer that contains opaque vendor-specific data.
