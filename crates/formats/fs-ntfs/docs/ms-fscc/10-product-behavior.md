<!-- MS-FSCC Reference: Product Behavior (Appendix B) -->
<!-- Windows version-specific behavior notes referenced throughout the spec. Maps <N> footnotes to specific Windows versions and behavioral differences. -->

**6** **Appendix B: Product Behavior**

The information in this specification is applicable to the following Microsoft products or supplemental
software. References to product versions include updates to those products.

The terms "earlier" and "later", when used with a product version, refer to either all preceding
versions or all subsequent versions, respectively. The term "through" refers to the inclusive range of
versions. Applicable Microsoft products are listed chronologically in this section.

- Windows NT 4.0 operating system

- Windows 98 operating system

- Windows 98 operating system Second Edition

- Windows 2000 operating system

- Windows XP operating system

- Windows Server 2003 operating system

- Windows Vista operating system

- Windows Server 2008 operating system

- Windows 7 operating system

- Windows Server 2008 R2 operating system

- Windows 8 operating system

- Windows Server 2012 operating system

- Windows 8.1 operating system

- Windows Server 2012 R2 operating system

- Windows 10 operating system

- Windows Server 2016 operating system

- Windows Server 2019 operating system

- Windows Server 2022 operating system

- Windows 11 operating system

- Windows Server 2025 operating system

Exceptions, if any, are noted in this section. If an update version, service pack or Knowledge Base
(KB) number appears with a product name, the behavior changed in that update. The new behavior
also applies to subsequent updates unless otherwise specified. If a product edition appears with the
product version, behavior is different in that product edition.

Unless otherwise specified, any statement of optional behavior in this specification that is prescribed
using the terms "SHOULD" or "SHOULD NOT" implies product behavior in accordance with the
SHOULD or SHOULD NOT prescription. Unless otherwise specified, the term "MAY" implies that the
product does not follow the prescription.

<1> Section 2.1.2.1: All reparse tags defined by Microsoft components MUST have the high bit set to
1. Non-Microsoft reparse tags MUST have the high bit set to 0.
<2> Section 2.1.2.1: These are Microsoft **reparse tags** . Except where explicitly allowed, clients MUST
NOT process the Microsoft reparse tag data buffers.

<3> Section 2.1.2.1: The Windows Home Server Drive Extender is part of the Windows Home Server
product.

<4> Section 2.1.2.1: The **filter manager** test harness is not shipped with Windows.

<5> Section 2.1.3.1: When a file is moved or copied from one **volume** to another, the **ObjectId**
member value changes to a random unique value to avoid the potential for **ObjectId** collisions
because the object ID is not guaranteed to be unique across volumes.

<6> Section 2.1.3.1: The **NTFS** file system places no constraints on the format of the 48 bytes of
information following the ObjectId in this structure. This format of the FILE_OBJECTID_BUFFER is used
on Windows by the Microsoft **Distributed Link Tracking** Service (see [MS-DLTW] section 3.1.6).

<7> Section 2.1.3.2: Windows places Distributed Link Tracking (DLT) information into the
ExtendedInfo field for use by the Distributed Link Tracking (DLT) protocols (see [MS-DLTW] section
3.1.6).

<8> Section 2.1.4: The following Windows file systems provide alternate data stream functionality:
NTFS, ReFS and **Universal Disk Format (UDF)** . ReFS supports alternate data streams of up to 128
KB in length in Windows 8.1 and later. ReFS does not support renaming of alternate data streams.

<9> Section 2.1.8: Windows defines a TRUE as "1"; however, it will interpret any nonzero value as
TRUE.

<10> Section 2.1.9: The following table lists the file systems that support the **64-bit file ID** :

|64 bit file ID|Generate|Stable|Unique|
|---|---|---|---|
|FAT|Yes|No|No|
|EXFAT|Yes|No|No|
|FAT32|Yes|No|No|
|Cdfs|No|n/a|n/a|
|UDFS|Yes|Yes|Yes|
|NTFS|Yes|Yes|Yes|
|ReFS|Yes|Yes|Yes|

NTFS computes the **64-bit file ID** as follows: the low 48 bits are the index of the file's primary record
in the master file table (MFT); the remaining 16 bits are a sequence number. Therefore, it is possible,
though rare, that a different file can have the same 64-bit file ID as a file on that volume had in the
past.

ReFS maps a subset of the possible **128-bit file ID** values to a 64-bit value using a reversible
algorithm; for values outside of this subset, ReFS sets the **64-bit file ID** to -1.

<11> Section 2.1.10: The following table lists the file systems that support the 128-bit file ID:

|128 bit file ID|Generate|Stable|Unique|
|---|---|---|---|
|FAT|No|n/a|n/a|
|EXFAT|No|n/a|n/a|
|FAT32|No|n/a|n/a|
|Cdfs|No|n/a|n/a|
|UDFS|No|n/a|n/a|
|NTFS|Yes|Yes|Yes|
|ReFS|Yes|Yes|Yes|

NTFS computes the **128-bit file ID** as follows: the low 48 bits are the index of the file's primary
record in the master file table (MFT), the next 16 bits are a sequence number, and the high 64 bits
MUST be zero. Therefore, it is possible, though rare, that a different file can have the same **128-bit**
**file ID** as a file on that volume had in the past.

ReFS computes the **128-bit file ID** as follows: the low 64 bits consists of an index uniquely
identifying the file's parent directory on the volume. The high 64-bits consists of an index uniquely
identifying the file within that directory.

<12> Section 2.1.11: The **Token** is defined in [[INCITS-T10/11-059].](https://go.microsoft.com/fwlink/?LinkId=239442)

<13> Section 2.1.11: When provided by a client to a server for an FSCTL_OFFLOAD_WRITE operation,
this Token value requests that the server logically write zeros.

<14> Section 2.2: NTFS supports **reparse points**, object IDs, and the **update sequence number**
**(USN)** change journal; ReFS supports reparse points and the USN change journal. The Microsoft **FAT**,
EXFAT, CDFS, and UDFS file systems do not support these attributes. Therefore, **FSCTLs** involving
these technologies will return STATUS_INVALID_DEVICE_REQUEST when the specified file or directory
is located on a volume formatted with the **FAT file system** . Windows also returns
STATUS_INVALID_DEVICE_REQUEST when a required file system **filter** is supported by the file
system but is not installed (see section 2.3.90).
<15> Section 2.2: The following table lists FSCTLs that are not supported remotely and that, if
received by the object store, will respond with a status code other than
STATUS_INVALID_DEVICE_REQUEST, as specified in section 2.2.

|FSCTL name|FSCTL function number|Status Code|
|---|---|---|
|FSCTL_GET_BOOT_AREA_INFO|0x90230|STATUS_INVALID_PARAMETER|
|FSCTL_GET_RETRIEVAL_POINTER_BASE|0x90234|STATUS_INVALID_PARAMETER|
|FSCTL_IS_VOLUME_DIRTY|0x90078|STATUS_INVALID_PARAMETER|
|FSCTL_ALLOW_EXTENDED_DASD_IO|0x90083|STATUS_ACCESS_DENIED|
|FSCTL_LOOKUP_STREAM_FROM_CLUSTER|0x901FC|STATUS_INVALID_PARAMETER|
|FSCTL_EXTEND_VOLUME|0x900F0|STATUS_INVALID_PARAMETER|
|FSCTL_SHRINK_VOLUME|0x901B0|STATUS_INVALID_PARAMETER|
|FSCTL_FILE_PREFETCH|0x90120|STATUS_INVALID_PARAMETER|
|FSCTL_SET_PERSISTENT_VOLUME_STATE|0x90238|STATUS_INVALID_PARAMETER|
|FSCTL_QUERY_PERSISTENT_VOLUME_STATE|0x9023C|STATUS_INVALID_PARAMETER|
|FSCTL_SD_GLOBAL_CHANGE|0x901F4|STATUS_INVALID_PARAMETER|

<16> Section 2.3: The NtFsControlFile function is used to invoke an FSCTL on a file handle. The
definition of this function, including its content and the function signature, is implementationdependent, and is not part of the protocol specification.

<17> Section 2.3.2: Windows will try 16 times to generate a unique ID, and will fail with this status if
16 attempts have been unsuccessful.

<18> Section 2.3.7: FSCTL_DUPLICATE_EXTENTS_TO_FILE is only supported by the ReFS file system
in Windows Server 2016 and later.

<19> Section 2.3.8: FSCTL_DUPLICATE_EXTENTS_TO_FILE is only supported by the ReFS file system
in Windows Server 2016 and later.

<20> Section 2.3.8: Applicable Windows Server releases return STATUS_INVALID_HANDLE if the
source file handle is closed, and STATUS_FILE_CLOSED if the target file handle is closed.

<21> Section 2.3.9: FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX request is only supported by the ReFS
file system in Windows 10 v1803 operating system and Windows Server v1803 operating system.

<22> Section 2.3.10: FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX reply is only supported by the ReFS
file system in Windows 10 v1803 and Windows Server v1803.

<23> Section 2.3.11: This FSCTL is implemented on ReFS, NTFS, FAT, and exFAT file systems. Other
file systems return STATUS_INVALID_DEVICE_REQUEST.

<24> Section 2.3.12: This FSCTL is implemented on ReFS, NTFS, FAT, and exFAT file systems. Other
file systems return STATUS_INVALID_DEVICE_REQUEST.

<25> Section 2.3.16: NTFS always returns at least 2 bytes and up to 8 bytes of trailing padding after
each entry in the reply, including the last entry.
<26> Section 2.3.18: The LZNT1 is the only compression algorithm implemented on Windows 2000,
Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7, and Windows
Server 2008 R2.

<27> Section 2.3.18: Windows 2000, Windows XP, Windows Server 2003, Windows Vista, Windows
Server 2008, Windows 7, and Windows Server 2008 R2 support file compression on volumes that are
formatted with the NTFS file system and have a **cluster** size less than or equal to 4 kilobytes.

<28> Section 2.3.19: The FSCTL_GET_INTEGRITY_INFORMATION_Request (section 2.3.19) message
is supported only by the ReFS file system.

<29> Section 2.3.28:

- Windows NT 4.0 returns STATUS_INVALID_DEVICE_REQUEST for a file on an NTFS, FAT, or CDFS
file system.

- Windows 2000 returns STATUS_INVALID_DEVICE_REQUEST for a file on a FAT or CDFS file
system.

- Windows XP returns STATUS_INVALID_DEVICE_REQUEST for a file on a FAT or CDFS file system.

- Windows Server 2003 returns STATUS_INVALID_DEVICE_REQUEST for a file on a FAT or CDFS file
system.

- Windows Vista returns STATUS_INVALID_DEVICE_REQUEST for a file on a FAT or CDFS file
system.

- Windows Server 2008 returns STATUS_INVALID_DEVICE_REQUEST for a file on a FAT or CDFS file
system.

- Windows 7 returns STATUS_INVALID_DEVICE_REQUEST for a file on a FAT or CDFS file system.

- Windows Server 2008 R2 returns STATUS_INVALID_DEVICE_REQUEST for a file on a FAT or CDFS
file system.

<30> Section 2.3.30: On an NTFS volume, very short data streams (typically several hundred bytes)
can be written to disk without having any clusters allocated. These short streams are sometimes
called resident because the data resides in the file's master file table (MFT) record. A resident data
stream has no retrieval pointers to return.

<31> Section 2.3.32: On an NTFS volume, very short data **streams** (typically several hundred bytes)
can be written to disk without having any clusters allocated. These short streams are sometimes
called resident because the data resides in the file's **master file table (MFT)** record. A resident data
stream has no retrieval pointers to return.

<32> Section 2.3.33: The FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT request is supported
only on ReFS and Windows 10 v1703 operating system and later and Windows Server 2019 and later.

<33> Section 2.3.34: On an ReFS volume, all alternate data streams are resident and all default data
streams are non-resident. A resident data stream has no retrieval pointers to return.

<34> Section 2.3.36: Windows NT operating system, Windows 2000, Windows XP, Windows Server
2003, Windows Vista, Windows Server 2008, Windows 7, and Windows Server 2008 R2 operating
system support the FSCTL_IS_PATHNAME_VALID Request (section 2.3.35) and return
STATUS_SUCCESS whenever this request is invoked.

<35> Section 2.3.39: This operation is supported only by the NTFS and ReFS file systems.

<36> Section 2.3.41: **Offload Read** operations are supported only by the NTFS file system running
on Windows 8 and later.
<37> Section 2.3.41: Clients and servers cannot depend on the **TokenTimeToLive** field as a true
timer, because vendors can choose to ignore the requested TTL value or can implement the TTL
counter in a vendor-specific manner. The **TokenTimeToLive** field can be interpreted as a hint.

<38> Section 2.3.41: The generated Token can represent less data than the requested amount; this
information is contained in the **TransferLength** field in the FSCTL_OFFLOAD_READ_OUTPUT data
element; for more information, see section 2.3.42.

<39> Section 2.3.42: In the following two cases, a well-known token,
STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA, is returned, even if the target volume does not
support Offload Read:

- If FSCTL_OFFLOAD_READ_INPUT.FileOffset is greater than or equal to the Valid Data Length
(VDL) of the file.

- Or, if FSCTL_OFFLOAD_READ_INPUT.CopyLength is 0.

<40> Section 2.3.42: File reads can start beyond the Valid Data Length (VDL), but not beyond EOF.

<41> Section 2.3.43: **Offload Write** operations are supported only by the NTFS file system running
on Windows 8 and later.

<42> Section 2.3.43: The FSCTL_OFFLOAD_READ and FSCTL_OFFLOAD_WRITE is used by Windows
to copy large files.

When copying files, Windows avoids using offload operations on volumes that do not support offload.
However, it is possible that the source volume and the destination volume both support offload, yet
offload cannot occur from the source volume to the destination volume because of SAN topology or
storage array compatibility issues. When this happens, Windows avoids repeated offload attempts
between these two volumes.

There is currently no reliable way to detect unreachable volume pairs because there is no unique
status code for this scenario. STATUS_INVALID_TOKEN can be returned for a variety of reasons
including unreachable volume pairs or a token expiration due to time-out.

In a best effort to detect unreachable volume pairs, Windows assumes a pair of volumes is not
reachable if all the following are true:

- This is the first token write on the file stream.

- The FSCTL_OFFLOAD_WRITE request returns with a status code of STATUS_INVALID_TOKEN.

- The Offload Write operation is made at offset 0 in the destination file.

Windows chunks data for Offload Write operations into segments of 256 MB, a size that is subject to
change.

<43> Section 2.3.44: While it is valid to issue a single Offload Write operation for the full contents of
a file, the Win32 CopyFileEx API does not perform this. Instead, CopyFileEx issues Offload Write
operations in 256-MB chunks so that components like Explorer can show proper progress of file copy
operations.

<44> Section 2.3.52: Each entry in the output array contains an offset and a length that indicates a
range in the file that can contain nonzero data. The actual nonzero data, if any, is somewhere within
this range, and the calling application scans further within the range to locate it and determines if it
really is valid data. Multiple instances of valid data can exist within the range.

<45> Section 2.3.52: **Sparse files** are supported by Windows 2000, Windows XP, Windows Server
2003, Windows Vista, Windows Server 2008, Windows 7, and Windows Server 2008 R2. The NTFS file
system rounds down the input file offset to a 65,536-byte (64-kilobyte) boundary, rounds up the
length to a convenient boundary, and then begins to walk through the file.
<46> Section 2.3.52: Windows does not track every piece of zero (0) or nonzero data. Because zero
(0) is often perfectly legal data, it would be misleading. Instead, the system tracks ranges in which
disk space is allocated. Where no disk space is allocated, all data bytes within that range for **Length**
bytes from **FileOffset** are assumed to be zero (0) (when data is read, NTFS returns a zero for every
byte in a sparse region). Allocated storage can contain zero (0) or nonzero data. So all that this
operation does is return information on parts of the file where nonzero data might be located. It is up
to the application to scan these parts of the file in accordance with the application's data conventions.

<47> Section 2.3.55: This region usage flag can only be specified for volumes using the NTFS file
system.

<48> Section 2.3.55: This region usage flag can only be specified for volumes using the ReFS file
system.

<49> Section 2.3.56.1: The NTFS file system is the only file system that returns this region usage
value.

<50> Section 2.3.56.1: The ReFS file system is the only file system that returns this region usage
value.

<51> Section 2.3.58: The following is the Windows UDF File System Support table. It lists the UDF
revisions and "builds" (VAT/Spared/Write) that are supported by each covered version of Windows.

|Windows|UDF<br>V1.02|UDF V1.5|UDF<br>V2.01|UDF V2.5|UDF 2.6|
|---|---|---|---|---|---|
|95 / 95OSR2|-|-|-|-|-|
|Windows 98|Read|-|-|-|-|
|Windows NT|-|-|-|-|-|
|Windows 2000|Read|Read|-|-|-|
|Windows XP|Read|Read|Read|-|-|
|Windows Server 2003|Read|Read|Read|-|-|
|Windows Vista|Read/Write|Read/Write|Read/Write|Read/Write|-|
|Windows 7 and later and Windows Server<br>2008 and later|Read/Write|Read/Write|Read/Write|Read/Write|Read/Write|

**Note** If Read of a given UDF version is supported, then reading of all UDF variants of that version are
supported (VAT, Sparing and Simple). If Read/Write of a given UDF version is supported, then
reading/writing of all UDF variants of that version are supported (VAT, Sparing and Simple).

<52> Section 2.3.58: The Windows UDF implementation pads the entire **CopyrightInfo** field with
NULLs.

<53> Section 2.3.58: The Windows UDF implementation pads the entire **AbstractInfo** field with
NULLs.

<54> Section 2.3.58: When the volume is formatted on Windows, this value is set to "*Microsoft
Windows" followed by Unicode NULLs.

<55> Section 2.3.58: When the volume is written to on a Windows system, this value is set to
"*Microsoft Windows" followed by Unicode NULLs.

<56> Section 2.3.61: This operation is supported by both the NTFS and ReFS file systems.
<57> Section 2.3.61: Currently supported values are 2 or 3. The **MinMajorVersion** is <=
**MaxMajorVersion** .

<58> Section 2.3.61: Currently supported values are 2 or 3. The **MinMajorVersion** is <=
**MaxMajorVersion** .

<59> Section 2.3.62.1: The major version number is 2 for file systems created on Windows 2000,
Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7, and Windows
Server 2008 R2.

<60> Section 2.3.62.1: The minor version number is 0 for file systems created on Windows 2000,
Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7, and Windows
Server 2008 R2.

<61> Section 2.3.62.2: The contents of a USN_RECORD_V2 or USN_RECORD_V3 element returned by
this FSCTL is a partially populated record compared to the fully populated records returned by a localonly FSCTL FSCTL_READ_USN_JOURNAL.

<62> Section 2.3.67: Equivalent to COMPRESSION_FORMAT_LZNT1.

<63> Section 2.3.67: The LZNT1 is the only compression algorithm implemented on Windows 2000,
Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7, and Windows
Server 2008 R2. Therefore, requests for COMPRESSION_FORMAT_DEFAULT and
COMPRESSION_FORMAT_LZNT1 are equivalent from the server's perspective.

<64> Section 2.3.71: This message is implemented only on NTFS, and it is only for private use by the
Encrypted File System (EFS). EFS issues this message locally on the machine that physically contains
the file, notifying NTFS of a change in the file/stream attributes and causing NTFS to invoke the EFS
callback that does the actual work of encrypting/decrypting streams.

This message is not used by any other component other than local EFS on Windows. It is not sent by
the SMB1 and SMB2 client redirectors, nor is it accepted by an SMB2 server. In order to manipulate
the encryption state of files and streams, clients use EFS and the EFSRPC protocol specified in [MSEFSR].

<65> Section 2.3.71: The SMB1 server does not currently fail the FSCTL_SET_ENCRYPTION
Request (section 2.3.71) if received. A QFE is planned to address this issue for the SMB1 server.

<66> Section 2.3.71: Windows sets the FILE_ATTRIBUTE_ENCRYPTED flag in the duplicate
information file attributes field, and invokes the EFS callback which then creates the $EFS attribute.

<67> Section 2.3.71: Windows takes the following actions to clear encryption:

- Clears the FILE_ATTRIBUTE_ENCRYPTED flag in the duplicate information file attributes field.

- Invokes the EFS callback, which removes the $EFS attribute.

<68> Section 2.3.71: Windows takes the following actions to set encryption on a stream:

- If the stream is a resident user data stream, converts it to non-resident.

- Sets ATTRIBUTE_FLAG_ENCRYPTED in the attribute header.

- Invokes the EFS callback to generate an encryption context for this stream.

Note that if this is called during the creation of a named data attribute on a file with an empty
unnamed data attribute, then the unnamed data attribute will be converted to non-resident and its
attribute header flag will be set to encrypted.

Also note that this will set the FILE_ATTRIBUTE_ENCRYPTED flag if it is the first stream on the file that
is encrypted.
<69> Section 2.3.71: Windows clears the ATTRIBUTE_FLAG_ENCRYPTED flag from the attribute
header and invokes the EFS callback to free the encryption context for the stream.

<70> Section 2.3.71: The **Private** field is a placeholder marking the beginning of the private portion
of the encryption buffer structure. This portion of the structure is meaningful only to EFS, because all
the information necessary to fill (making a well-formed request) is private to EFS. Windows uses the
EFSRPC protocol as specified in [MS-EFSR] to manipulate file encryption state.

<71> Section 2.3.72: An FSCTL_SET_ENCRYPTION operation never succeeds unless it is requested by
the Encrypted File System (EFS), because the information necessary to make a well-formed request is
visible only to EFS, as FSCTL_SET_ENCRYPTION is only for private use by EFS. Windows uses the
EFSRPC protocol as specified in [MS-EFSR] to manipulate file encryption state.

<72> Section 2.3.72: On Windows, encryption requires NTFS major version 2 or greater.

<73> Section 2.3.72: Windows returns this error code if the NTFS encryption driver is not loaded or
the FILE_CLEAR_ENCRYPTION operation was requested on a file containing a stream that is still
marked as encrypted.

<74> Section 2.3.72: Windows returns this error code if the $INDEX_ROOT attribute of the directory
that was trying to be encrypted, could not be found.

<75> Section 2.3.73: The FSCTL_SET_INTEGRITY_INFORMATION Request (section 2.3.73) message
is supported only by the ReFS file system.

<76> Section 2.3.75: The FSCTL_SET_INTEGRITY_INFORMATION_EX Request message is supported
only by Windows Server 2022 and later, and Windows 11, version 22H2 operating system and later.
FSCTL_SET_INTEGRITY_INFORMATION_EX is processed as described on systems updated with

[[MSKB-5014019], [MSKB-5014021],](https://go.microsoft.com/fwlink/?linkid=2194206) [[MSKB-5014022], [MSKB-5014023], or](https://go.microsoft.com/fwlink/?linkid=2194302) [[MSKB-5014702].](https://go.microsoft.com/fwlink/?linkid=2195314)

<77> Section 2.3.77: Windows expects that the file whose **object identifier** is set with this FSCTL
has been opened for write and that backup/restore operations were specified at file open. In Windows,
this is accomplished by specifying the flag, FILE_FLAG_BACKUP_SEMANTICS (whose value is
0x02000000), along with other attributes such as FILE_ATTRIBUTE_NORMAL when opening the file.

<78> Section 2.3.77: All Windows versions: This request is never sent to a remote server.

<79> Section 2.3.79: The Microsoft Distributed Link Tracking Service uses the last 48 bytes of the
ExtendedInfo BLOB to store information that helps it locate files that are moved to different volumes
or computers within a domain. For more information, see [MS-DLTW] section 3.1.6.

<80> Section 2.3.83: This operation is supported by both the NTFS and ReFS file systems. ReFS
supports this operation for conventional streams, but not for integrity streams, in Windows 8 and
Windows Server 2012. ReFS supports this operation for both conventional and integrity streams in
Windows 8.1 and later.

<81> Section 2.3.83: NTFS does not attempt to recover a failed unsparse operation by "resparsing".

<82> Section 2.3.83: Neither NFTS or ReFS deallocate existing clusters.

<83> Section 2.3.85: This operation is supported by both the NTFS and ReFS file systems.

Upon receipt of this message, NTFS might deallocate disk space in the file if the file is stored on an
NTFS volume and the file is sparse or compressed. It will free any allocated space in chunks of 64
kilobytes that begin at an offset that is a multiple of 64 kilobytes. Other bytes in the file (prior to the
first freed 64-kilobyte chunk and after the last freed 64-kilobyte chunk) will be zeroed but not
deallocated. This FSCTL sets the range of bytes to zero (0) without extending the file size.

ReFS supports FSCTL_SET_ ZERO_DATA for conventional file streams, but not for integrity file
streams, in Windows 8 and Windows Server 2012. ReFS supports FSCTL_SET_ ZERO_DATA for both
conventional and integrity file streams in Windows 8.1 and later and Windows Server 2012 R2
operating system and later.

Upon receipt of this message, ReFS might deallocate disk space in the file if the file is stored on a
ReFS volume and the file is sparse. It will free any allocated space in chunks of 64 kilobytes that begin
at an offset that is a multiple of 64 kilobytes. Other bytes in the file (prior to the first freed 64-kilobyte
chunk and after the last freed 64-kilobyte chunk) will be zeroed but not deallocated. This FSCTL sets
the range of bytes to zero (0) without extending the file size.

<84> Section 2.3.87: This message is implemented only by NTFS, which is supported on Windows NT,
Windows XP, Windows 2000, Windows Server 2003, Windows Vista, Windows Server 2008, Windows
7, and Windows Server 2008 R2.

<85> Section 2.3.89: Both the source and destination file names represent paths on the same
volume, and the file names are the full paths to the files, including the share or drive letter at which
each file is located.

<86> Section 2.3.91: All Windows Server versions return STATUS_NOT_IMPLEMENTED.

<87> Section 2.4: The FileHardLinkInformation, FileIdGlobalTxDirectoryInformation,
FileMailslotQueryInformation, FileMailslotSetInformation, FileNameInformation,
FileObjectIdInformation, FileReparsePointInformation, FileSfioReserveInformation,
FileStandardLinkInformation, and FileTrackingInformation file information classes are intended for
local use only; the server will fail them with STATUS_NOT_SUPPORTED.

<88> Section 2.4: Windows uses the NtQueryInformationFile function to process the specified query
for file information and NtSetInformationFile to process the specified request to set file information.
The definition of the function used to process any file information request, including its content and
the function signature, is implementation-dependent and is not part of the protocol specification.

<89> Section 2.4: FileDispositionInformationEx information class is supported in Windows 10 v1607
operating system and later and Windows Server 2016 and later.

<90> Section 2.4: FileId64ExtdBothDirectoryInformation information class is supported in the NTFS
and ReFS file systems in Windows 11, version 23H2 operating system and later and Windows Server
2022, 23H2 operating system and later.

<91> Section 2.4: FileId64ExtdDirectoryInformation information class is supported in the NTFS and
ReFS file systems in Windows 11, version 23H2 and later and Windows Server 2022, 23H2 and later.

<92> Section 2.4: FileIdAllExtdBothDirectoryInformation information class is supported in the NTFS
and ReFS file systems in Windows 11, version 23H2 and later and Windows Server 2022, 23H2 and
later.

<93> Section 2.4: FileIdAllExtdDirectoryInformation information class is supported in the NTFS and
ReFS file systems in Windows 11, version 23H2 and later and Windows Server 2022, 23H2 and later.

<94> Section 2.4: The FileIdInformation information class is supported in the NTFS and ReFS file
systems in Windows 8 and later and Windows Server 2012 and later.

<95> Section 2.4: This information class is not sent across the wire. In Windows, it is handled by the
**IOManager** on the client. If this operation is sent to an SMB server, both SMB and SMB2 send the
request to the **IOManager** on the server and perform normal processing of the operation.

<96> Section 2.4: Windows file systems do not implement this file information class; the server will
fail it with STATUS_NOT_SUPPORTED.

<97> Section 2.4: Windows 10 v1803 and later and Windows Server v1803 and later allow remote
FileNormalizedNameInformation query; other servers return STATUS_NOT_SUPPORTED.
<98> Section 2.4: The CIFS, SMB, and SMB2 protocols do not directly call this information class but
use the structures associated with it.

<99> Section 2.4: FileRenameInformationEx information class is supported in Windows 10 v1607 and
later and Windows Server 2016 and later.

<100> Section 2.4: Windows file systems do not implement this file information class; the server will
fail it with STATUS_NOT_SUPPORTED.

<101> Section 2.4.4: A file's allocation size and end-of-file position are independent of each other
with the following exception: The end-of-file position is always less than or equal to the allocation size.
If the allocation size is set to a value that is less than the end-of-file position, the end-of-file position
is automatically adjusted to match the allocation size. Because the end-of-file position can be less
than the file's allocation size, the last **sector** (or cluster) of a file can have unused bytes between the
last byte of the file and the last byte of the sector (or cluster).

<102> Section 2.4.4: NTFS rounds allocation size for resident files to a multiple of 8 bytes. When
shrinking a resident file's allocation size using the FileAllocationInformation info class, the file remains
resident with an allocation size rounded up to a multiple of 8 bytes. When extending a resident file's
allocation size using the FileAllocationInformation info class, the file is converted to nonresident with
an allocation size rounded up to a multiple of the cluster size.

<103> Section 2.4.5: NTFS assigns an **alternate name** to a file whose full name is not compliant
with restrictions for file names under MS-DOS and 16-bit Windows unless the system has been
configured through a registry entry to not generate these names to improve performance.

<104> Section 2.4.7: The file system updates the values of the **LastAccessTime**, **LastWriteTime**,
and **ChangeTime** members as appropriate after an I/O operation is performed on a file. However, a
driver or application can request that the file system not update one or more of these members for
I/O operations that are performed on the caller's file handle by setting the appropriate members to -1.
A driver or application can subsequently request that the file system resume updating one or more of
these members for I/O operations that are performed on the caller's file handle by setting the
appropriate members to -2. The caller can set one, all, or any other combination of these three
members to -1 and/or -2. Only the members that are set to -1 will be unaffected by I/O operations on
the file handle; the other members will be updated as appropriate. This behavior is consistent across
all file system types. Note that even though -1 and -2 can be used with the **CreationTime** field, they
have no effect because file creation time is never updated in response to file system calls such as read
and write.

|File system|Support value of -2|
|---|---|
|FAT|No|
|EXFAT|No|
|FAT32|No|
|Cdfs|No|
|UDFS|No|
|NTFS|Windows 8.1 and later, and Windows Server 2012 R2<br>and later|
|ReFS|Windows 10 v1507 operating system and later, and<br>Windows Server 2016 and later|

<105> Section 2.4.7: The file system updates the value of the **LastAccessTime** member as
appropriate after an I/O operation is performed on a file. However, a driver or application can request
that the file system not update one or more of these members for I/O operations that are performed
on the caller's file handle by setting the appropriate members to -1. A driver or application can
subsequently request that the file system resume updating one or more of these members for I/O
operations that are performed on the caller's file handle by setting the appropriate members to -2.
The caller can set one, all, or any other combination of these three members to -1 and/or -2. Only the
members that are set to -1 will be unaffected by I/O operations on the file handle; the other members
will be updated as appropriate. This behavior is consistent across all file system types. Note that even
though -1 and -2 can be used with the **CreationTime** field, they have no effect because file creation
time is never updated in response to file system calls such as read and write.

|File system|Support value of -2|
|---|---|
|FAT|No|
|EXFAT|No|
|FAT32|No|
|Cdfs|No|
|UDFS|No|
|NTFS|Windows 8.1 and later, and Windows Server 2012 R2<br>and later|
|ReFS|Windows 10 v1507 and later, and Windows Server<br>2016 and later|

<106> Section 2.4.7: The file system updates the value of the **LastWriteTime** member as
appropriate after an I/O operation is performed on a file. However, a driver or application can request
that the file system not update one or more of these members for I/O operations that are performed
on the caller's file handle by setting the appropriate members to -1. A driver or application can
subsequently request that the file system resume updating one or more of these members for I/O
operations that are performed on the caller's file handle by setting the appropriate members to -2.
The caller can set one, all, or any other combination of these three members to -1 and/or -2. Only the
members that are set to -1 will be unaffected by I/O operations on the file handle; the other members
will be updated as appropriate. This behavior is consistent across all file system types. Note that even
though -1 and -2 can be used with the **CreationTime** field, they have no effect because file creation
time is never updated in response to file system calls such as read and write.

|File system|Support value of -2|
|---|---|
|FAT|No|
|EXFAT|No|
|FAT32|No|
|Cdfs|No|
|UDFS|No|
|NTFS|Windows 8.1 and later, and Windows Server 2012 R2<br>and later|
|ReFS|Windows 10 v1507 and later, and Windows Server<br>2016 and later|
<107> Section 2.4.7: The file system updates the value of the **ChangeTime** member as appropriate
after an I/O operation is performed on a file. However, a driver or application can request that the file
system not update one or more of these members for I/O operations that are performed on the
caller's file handle by setting the appropriate members to -1. A driver or application can subsequently
request that the file system resume updating one or more of these members for I/O operations that
are performed on the caller's file handle by setting the appropriate members to -2. The caller can set
one, all, or any other combination of these three members to -1 and/or -2. Only the members that are
set to -1 will be unaffected by I/O operations on the file handle; the other members will be updated as
appropriate. This behavior is consistent across all file system types. Note that even though -1 and -2
can be used with the **CreationTime** field, they have no effect because file creation time is never
updated in response to file system calls such as read and write.

|File system|Support value of -2|
|---|---|
|FAT|No|
|EXFAT|No|
|FAT32|No|
|Cdfs|No|
|UDFS|No|
|NTFS|Windows 8.1 and later, and Windows Server 2012 R2<br>and later|
|ReFS|Windows 10 v1507 and later, and Windows Server<br>2016 and later|

<108> Section 2.4.8: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<109> Section 2.4.9: Windows 2000, Windows XP, Windows Server 2003, Windows Vista, Windows
Server 2008, Windows 7, and Windows Server 2008 R2 implement only one compression algorithm,
[LZNT1. For more information, see [UASDC].](https://go.microsoft.com/fwlink/?LinkId=90549)

<110> Section 2.4.9: NTFS uses a value of 16 calculated as (4 + **ClusterShift** ) for the
CompressionUnitShift by default. The ultimate size of data to be compressed depends on the cluster
size set for the file system at initialization. NTFS defaults to a 4-kilobyte cluster size, resulting in a
**ClusterShift** value of 12, but NTFS file systems can be initialized with a different cluster size, so the
value can vary. The default **compression unit** size based on this calculation is 64 kilobytes.

<111> Section 2.4.9: NTFS uses a value of 12 for the ChunkShift so that compression chunks are 4
kilobytes in size.

<112> Section 2.4.9: The value of this field depends on the cluster size set for the file system at
initialization. NTFS uses a value of 12 by default because the default NTFS cluster size is 4 kilobytes. If
an NTFS file system is initialized with a different cluster size, the value of **ClusterShift** would be log 2
of the cluster size for that file system.

<113> Section 2.4.10: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<114> Section 2.4.11: A file marked for deletion is not actually deleted until all open handles for the
file object have been closed, and the link count for the file is zero.
<115> Section 2.4.15: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<116> Section 2.4.17: In Windows, both the NTFS and UDFS file systems support hard links. UDFS
support of hard links was added in Windows Vista and Windows Server 2008.

<117> Section 2.4.18: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<118> Section 2.4.18: The NTFS, ReFS, FAT, and exFAT file systems return a **FileId** value of 0 for
the entry named ".." in directory query operations.

<119> Section 2.4.19: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<120> Section 2.4.19: The NTFS, ReFS, FAT, and exFAT file systems return a **FileId** value of 0 for
the entry named ".." in directory query operations.

<121> Section 2.4.20: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<122> Section 2.4.20: The NTFS, ReFS, FAT, and exFAT file systems return a **FileId** value of 0 for
the entry named ".." in directory query operations.

<123> Section 2.4.21: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<124> Section 2.4.21: The NTFS, ReFS, FAT, and exFAT file systems return a **FileId** value of 0 for
the entry named ".." in directory query operations.

<125> Section 2.4.22: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<126> Section 2.4.22: The NTFS, ReFS, FAT, and exFAT file systems return a **FileId** value of 0 for
the entry named ".." in directory query operations.

<127> Section 2.4.23: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<128> Section 2.4.24: Windows-based SMB Version 1 servers set the **NextEntryOffset** field to the
size of the current **FileIdFullDirectoryInformation** entry in bytes, if no other entries follow this one.

<129> Section 2.4.24: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<130> Section 2.4.24: The NTFS, ReFS, FAT, and exFAT file systems return a **FileId** value of 0 for
the entry named ".." in directory query operations.

<131> Section 2.4.25: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.
<132> Section 2.4.25: The NTFS, ReFS, FAT, and exFAT file systems return a **FileId** value of 0 for
the entry named ".." in directory query operations.

<133> Section 2.4.27: The NTFS, ReFS, FAT, and exFAT file systems return a **FileId** value of 0 for
the entry named ".." in directory query operations.

<134> Section 2.4.28: In Windows, both the NTFS and UDFS file systems support hard links. UDFS
support of hard links was added in Windows Vista and Windows Server 2008.

<135> Section 2.4.31: The **FileModeInformation** information class is not sent across the wire. In
Windows, it is handled by the **IOManager** on the client. If this operation is sent to an SMB server,
both SMB and SMB2 send the request to the **IOManager** on the server and perform normal
processing of the operation.

<136> Section 2.4.31: This flag is cleared by the respective server application while processing the
set operation in the following situations:

- SMB server on all supported versions of Windows if the file is not opened with a **DesiredAccess**
field value that has the FILE_WRITE_DATA or FILE_APPEND_DATA bit set (see [MS-CIFS] section
2.2.4.64.1).

- SMB2 server on Windows Vista and Windows Server 2008 always.

- SMB2 server on Windows 7 and Windows Server 2008 R2 if the file is opened with a
**CreateOptions** field value that has the FILE_NO_INTERMEDIATE_BUFFERING bit set (see [MSSMB2] section 2.2.13).

<137> Section 2.4.33: When using ReFS or NTFS, the position of a file within the parent directory is
not fixed and can be changed at any time. Windows sets this value to zero for files on ReFS and NTFS
file systems.

<138> Section 2.4.34: This operation works on both remote and local handles.

<139> Section 2.4.35: This information class is implemented on ReFS and NTFS file systems. Other
file systems return STATUS_INVALID_DEVICE_REQUEST.

<140> Section 2.4.36: The Microsoft ReFS, FAT, EXFAT, UDFS, and CDFS file systems do not support
the use of **ObjectId** s and return a status code of STATUS_INVALID_DEVICE_REQUEST.

<141> Section 2.4.36: The Microsoft Distributed Link Tracking protocols (see [MS-DLTW] section
3.1.6) use the first type of object ID structure for link tracking.

<142> Section 2.4.36.1: When a file is moved or copied from one volume to another, the **ObjectId**
member's value changes to a random unique value to avoid the potential for **ObjectId** collisions
because the object ID is not guaranteed to be unique across volumes.

<143> Section 2.4.40: Both the query and set FilePositionInformation operations are processed on
the local client; therefore, these operations are not transmitted across the wire. The fact that these
operations are processed on the client instead of the server is intended to be transparent to the
client's usage of these operations.

If a server receives a request to set FilePositionInformation, the specified file position will be set on
the remote handle, but its value will be ignored by future read/write operations. If a server receives a
request to query FilePositionInformation, an undetermined value will be returned. For more
information on how the **CurrentByteOffset** field is updated, see the [MS-FSA] sections for read and
write operations.

<144> Section 2.4.40: Each read and write operation via the Server Message Block (SMB) Protocol

[MS-SMB] and Server Message Block (SMB) Version 2 [MS-SMB2] protocols always provides an
explicit starting offset, and thus is unaffected by the file position. Windows does not update the file
position when read and write operations are performed via these protocols.
<145> Section 2.4.41: Query and set operations are supported only by the NTFS file system and are
valid only on handles opened to the NTFS metadata file "\$Extend\$Quota:$Q:$INDEX_ALLOCATION".

<146> Section 2.4.43: FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE is supported in Windows
10 v1709 operating system and later and Windows Server 2019 and later.

<147> Section 2.4.43: FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE is supported in
Windows 10 v1809 operating system and later and Windows Server 2019 and later.

<148> Section 2.4.43: FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE is supported in Windows 10
v1809 and later and Windows Server 2019 and later.

<149> Section 2.4.43: FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE is supported in Windows 10
v1809 and later and Windows Server 2019 and later.

<150> Section 2.4.43: FILE_RENAME_PRESERVE_AVAILABLE_SPACE is supported in Windows 10
v1809 and later and Windows Server 2019 and later.

<151> Section 2.4.43: FILE_RENAME_IGNORE_READONLY_ATTRIBUTE is supported in Windows 10
v1809 and later and Windows Server 2019 and later.

<152> Section 2.4.43: FILE_RENAME_FORCE_RESIZE_TARGET_SR is supported in Windows 10 v1903
operating system and later and Windows Server v1909 operating system and later.

<153> Section 2.4.43: FILE_RENAME_FORCE_RESIZE_SOURCE_SR is supported in Windows 10
v1903 and later and Windows Server v1909 and later.

<154> Section 2.4.43: FILE_RENAME_FORCE_RESIZE_SR is supported in Windows 10 v1903 and
later and Windows Server v1909 and later.

<155> Section 2.4.46: In Windows 7 and Windows Server 2008 R2, the existing **short name** is
deleted if the **FileNameLength** field in **FILE_NAME_INFORMATION** is zero. Previous Windows
implementations return STATUS_INVALID_PARAMETER when the **FileNameLength** field is zero.

<156> Section 2.4.48: This information class is supported on Windows 7 and later and Windows
Server 2008 R2 and later.

<157> Section 2.4.50: Windows supports the FileValidDataLengthInformation (section 2.4.50)
information class in the ReFS, NTFS, FAT, FAT32, and EXFAT file systems.

<158> Section 2.5: Windows uses the NtQueryVolumeInformationFile function to process the
specified query for file system information and the NtSetVolumeInformationFile function to set the
specified file system information. The definition of the function used to process any file system
information request, including its content and the function signature, is implementation-dependent
and is not part of the protocol specification.

<159> Section 2.5: This file system information class is intended for local use only; the server will fail
it with status STATUS_NOT_SUPPORTED.

<160> Section 2.5: This file system information class is intended for local use only; the server will fail
it with status STATUS_NOT_SUPPORTED. Furthermore, this file information class is not implemented
by any Windows file systems.

<161> Section 2.5: This file system information class is intended for local use only; the server will fail
a "query" with STATUS_ACCESS_NOT_SUPPORTED, and the server will fail a "set" with
STATUS_ACCESS_DENIED. Furthermore, this file information class is not implemented by any
Windows file systems.

<162> Section 2.5.1: The FILE_SUPPORTS_USN_JOURNAL, FILE_SUPPORTS_OPEN_BY_FILE_ID,
FILE_SUPPORTS_EXTENDED_ATTRIBUTES, and FILE_SUPPORTS_HARD_LINKS attributes are only
available on Windows 7 and Windows Server 2008 R2.
The FILE_READ_ONLY_VOLUME attribute is only available on Windows XP, Windows Server 2003,
Windows Vista, Windows Server 2008, Windows 7, and Windows Server 2008 R2.

The FILE_SUPPORT_INTEGRITY_STREAMS attribute is available only on ReFS/Windows 8.

<163> Section 2.5.1: Windows Vista, Windows Server 2008, Windows 7, and Windows Server 2008
R2 set this flag if the volume is formatted for NTFS 3.0 or higher.

<164> Section 2.5.1: Windows support for a volume formatted to NTFS version 3.0 or 3.1 is required
for EFS use. NTFS versions 3.0 and 3.1 are supported on Windows 2000 and later. Support for FAT
and EXFAT was added in Windows 10 v1607 and Windows Server 2016 and later.

<165> Section 2.5.1: NTFS file systems in Windows 10 v1607 and later and Windows Server 2016
and later support this flag.

<166> Section 2.5.1: NTFS file systems in Windows 10 v1607 and later and Windows Server 2016
and later support this flag.

<167> Section 2.5.1: Remote storage is provided by the Remote Storage service to create virtual disk
storage from a tape or other storage media.

<168> Section 2.5.1: For the Microsoft ReFS, NTFS, FAT, and EXFAT file systems, this value is 255.
For the Microsoft UDFS file system, this value is 254. For the Microsoft CDFS file system, this value is
110 for Joliet format and 221 otherwise.

<169> Section 2.5.1: Valid values for this field depend on the version of Windows that the server is
running.

|Windows version|FAT|FAT16|FAT32|exFAT|NTFS|CDFS|UDF|CSVFS|
|---|---|---|---|---|---|---|---|---|
|Windows 8 and later and Windows Server<br>2012 operating system and later|X|X|X|X|X|X|X|X|
|Windows 7, Windows Server 2008 R2|X|X|X|X|X|X|X||
|Windows Vista operating system with<br>Service Pack 1 (SP1), Windows Server<br>2008, Windows Server 2008 R2|X|X|X|X|X|X|X||
|Windows Vista RTM|X|X|X||X|X|X||
|Windows XP|X|X|X||X|X|||

<170> Section 2.5.2: Query and set operations are supported only by the NTFS file system, and the
quota index information is saved in the NTFS metadata file
"\$Extend\$Quota:$Q:$INDEX_ALLOCATION".

<171> Section 2.5.2: Logging makes an entry in the Windows application event log.

<172> Section 2.5.4: In Windows 2000, Windows XP, Windows Server 2003, Windows Vista, Windows
Server 2008, Windows 7, and Windows Server 2008 R2, if per-user quotas are in use, this value can
be less than the total number of allocation units on the disk. Non-Microsoft quota management
software might display the same behavior as these versions of Windows if that software was
implemented as a file system filter driver, and the driver implementer opted to set the
FileFsFullSizeInformation in the same manner as Windows 2000.

<173> Section 2.5.4: In Windows 2000, Windows XP, Windows Server 2003, Windows Vista, Windows
Server 2008, Windows 7, and Windows Server 2008 R2, if per-user quotas are in use, this value can
be less than the total number of free allocation units on the disk.
<174> Section 2.5.5: A maximum length of 32 characters is imposed for any Windows file system,
though some file systems can impose a stricter limit. The Microsoft FAT file system supports volume
labels that are 0 to 11 characters in length. ReFS and NTFS support volume labels that are 0 to 32
characters in length. All **Unicode characters** are permitted in a volume label with the exception of
the NULL character, which is reserved for use as a string terminator.

<175> Section 2.5.6: The Microsoft ReFS, FAT, EXFAT, UDFS, and CDFS file systems do not support
the use of object IDs and return a status code of STATUS_INVALID_PARAMETER.

<176> Section 2.5.6: Windows does not write information into the **ExtendedInfo** field for file
systems.

<177> Section 2.5.7: This information class is only available in the following:

- Windows 8 and later

- Microsoft-implemented file systems including NTFS, ReFS, FAT, ExFAT, UDFS, and CDFS

<178> Section 2.5.7: This is also the reported physical sector size of the device for atomicity. Note
that NTFS does basic sanitation to ensure this value does not cause unexpected application behavior.
NTFS performs the following basic sanitization:

- Ensures that the reported physical sector size is greater than or equal to the logical sector size. If
it is not, the value of this field is set to the logical sector size.

- Ensures that the reported physical sector size is a power of two. If it is not, the value of this field
is set to the logical sector size.

<179> Section 2.5.7: This is the reported physical sector size of the device for performance. Note that
NTFS does basic sanitation to ensure that this value does not cause unexpected application behavior.
NTFS performs the following basic sanitization:

- Ensures that the reported physical sector size is greater than or equal to the logical sector size. If
it is not, the value of this field is set to the logical sector size.

- Ensures that the reported physical sector size is a power of two. If it is not, the value of this field
is set to the logical sector size.

<180> Section 2.5.7: A client can interpret this field as the unit for which NTFS guarantees an atomic
operation. NTFS calculates the value of this field as follows:

- Retrieve the physical sector size the device reports for atomicity, and store in _x_ .

- Validate that the value _x_ is greater than or equal to the logical sector size. If it is not, set _x_ to the
logical sector size.

- Validate that the value _x_ is a power of two. If it is not, set _x_ to the logical sector size.

- Validate that the value _x_ is less than or equal to the system page size defined in [MS-FSA] section
2.1.1.1. If it is not, set _x_ to the system page size defined in [MS-FSA] section 2.1.1.1.

<181> Section 2.5.7: In this example, a storage device has a logical sector of 512 bytes, a physical
sector of 4 KB (with eight logical sectors in a physical sector), and an offset of three logical sectors.
The **ByteOffsetForSectorAlignment** field is therefore calculated as 3 * LogicalBytesPerSector =
1536 bytes.

|LBA|#|#|#|0|1|2|3|4|5|6|7|8|9|10|1|2|3|4|5|6|7|8|9|20|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Physical<br>Sector|0|0|0|0|0|0|0|0|1|1|1|1|1|1|1|1|2|2|2|2|2|2|2|2|
<182> Section 2.5.8: In Windows 2000, Windows XP, Windows Server 2003, Windows Vista, Windows
Server 2008, Windows 7, and Windows Server 2008 R2, if per-user quotas are in use, this value can
be less than the total number of allocation units on the disk. Non-Microsoft quota management
software might display the same behavior as Windows 2000 if that software was implemented as a file
system filter driver, and the driver implementer opted to set the FileFsSizeInformation in the same
manner as Windows 2000.

<183> Section 2.5.8: In Windows 2000, Windows XP, Windows Server 2003, Windows Vista, Windows
Server 2008, Windows 7, and Windows Server 2008 R2, if per-user quotas are in use, this value can
be less than the total number of free allocation units on the disk.

<184> Section 2.5.9: A maximum length of 32 characters is imposed for any Windows file system,
though some file systems can impose a stricter limit. The Microsoft FAT file system supports volume
labels that are 0 to 11 characters in length. NTFS supports volume labels that are 0 to 32 characters
in length. All Unicode characters are permitted in a volume label with the exception of the NULL
character, which is reserved for use as a string terminator.

<185> Section 2.5.9: This value is TRUE for NTFS and FALSE for other file systems implemented by
Windows.

<186> Section 2.5.10: A driver can skip the full check for appcontainers by setting this characteristic
on its device object.

<187> Section 2.6: The Windows file system does not persist the FILE_ATTRIBUTE_NORMAL flag.
When getting attributes via the FileAttributeTagInformation (section 2.4.6) information class, a client
will receive the FILE_ATTRIBUTE_NORMAL flag only if no other attributes were set. Some examples: If
a client sets the attributes as [FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL], the client will
see just [FILE_ATTRIBUTE_HIDDEN] when it gets the attributes. If the client sets the attributes as

[FILE_ATTRIBUTE_NORMAL], the client will see [FILE_ATTRIBUTE_NORMAL] when it gets the
attributes.

<188> Section 2.6: Only ReFS supports this attribute.

<189> Section 2.6: Only NTFS and ReFS support this attribute.

<190> Section 2.6: Only NTFS and ReFS support this attribute.

<191> Section 2.6: Only NTFS and ReFS support this attribute.

<192> Section 2.6: Only NTFS and ReFS support this attribute.

<193> Section 2.6: Only NTFS and ReFS support this attribute.

<194> Section 2.7.1: For FILE_ACTION_REMOVED_BY_DELETE, FILE_ACTION_ID_NOT_TUNNELLED,
and FILE_ACTION_TUNNELLED_ID_COLLISION only NTFS supports the special directory
"\$Extend\$ObjId:$O:$INDEX_ALLOCATION".
