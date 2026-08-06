<!-- MS-FSCC: Miscellaneous FSCTLs -->
<!-- FILE_LEVEL_TRIM, FIND_FILES_BY_SID, IS_PATHNAME_VALID, LMR_SET_LINK_TRACKING_INFORMATION, MARK_HANDLE, QUERY_FAT_BPB, QUERY_FILE_REGIONS, QUERY_ON_DISK_VOLUME_INFO, QUERY_SPARING_INFO, RECALL_FILE, REFS_STREAM_SNAPSHOT_MANAGEMENT, SET_DEFECT_MANAGEMENT, SIS_COPYFILE, VIRTUAL_STORAGE_QUERY_PROPERTY. -->

**2.3.13** **FSCTL_FILE_LEVEL_TRIM Request**

The FSCTL_FILE_LEVEL_TRIM operation informs the underlying storage medium that the contents of
the given range of the file no longer needs to be maintained. This message allows the storage medium
to manage its space more efficiently. This operation is required most commonly for Solid State
Devices (SSD), as well as for thinly provisioned storage environments.

The **FILE_LEVEL_TRIM** data element follows.

```
  Key (32 bits)
  NumRanges (32 bits)
  Ranges (variable) (32 bits)
  ...
```

**Key (4 bytes):** This field is used for byte range locks to uniquely identify different consumers of byte

range locks on the same thread. Typically, this field is used only by remote protocols such as SMB
or SMB2.

**NumRanges (4 bytes):** A count of how many **Offset**, **Length** pairs follow in the data item.

**Ranges (variable):** An array of zero or more FILE_LEVEL_TRIM_RANGE (section 2.3.13.1) data

elements. The **NumRanges** field contains the number of **FILE_LEVEL_TRIM_RANGE** data
elements in the array.

**2.3.13.1** **FILE_LEVEL_TRIM_RANGE**

The **FILE_LEVEL_TRIM_RANGE** data element follows.

```
  Offset (32 bits)
  Length (32 bits)
  ...
```
**Offset (8 bytes):** A 64-bit unsigned integer that contains a byte offset into the given file at which to

start the trim request.

**Length (8 bytes):** A 64-bit unsigned integer that contains the length, in bytes, of how much of the

file to trim, starting at **Offset** .

**2.3.14** **FSCTL_FILE_LEVEL_TRIM Reply**

This message returns the results of the FSCTL_FILE_LEVEL_TRIM Request (section 2.3.13).

The **FILE_LEVEL_TRIM_OUTPUT** data element follows.

```
  NumRangesProcessed (32 bits)
```

**NumRangesProcessed (4 bytes):** A 32-bit unsigned integer identifying the number of input ranges

that were processed.

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this FSCTL is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The given file is compressed or encrypted, or the size of the input buffer<br>is smaller than the size of the**FILE_LEVEL_TRIM** data element, or no<br>FILE_LEVEL_TRIM_RANGE (section 2.3.13.1) structures were given, or<br>the output buffer is smaller than the size of<br>**FILE_LEVEL_TRIM_OUTPUT**.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The file system does not support this operation.|
|STATUS_INTEGER_OVERFLOW<br>0xC0000095|An operation on a parameter in the FSCTL_FILE_LEVEL_TRIM input<br>structure overflowed 64 bits.|
|STATUS_NO_RANGES_PROCESSED<br>0xC0000460|The operation was successful, but no range was processed.|

**2.3.15** **FSCTL_FIND_FILES_BY_SID Request**

The FSCTL_FIND_FILES_BY_SID Request message requests that the server return a list of the files
and directories whose owner matches the specified **security identifier (SID)**, in no necessary order.
The search spans the file system subtree descending from the directory associated with the handle on
which this FSCTL was invoked. This message contains a FIND_BY_SID_DATA data element.

The FIND_BY_SID_DATA data element is as follows.

```
  Restart (32 bits)
```
**Restart (4 bytes):** A 32-bit unsigned integer value that indicates to restart the search. This value

MUST be 0x00000001 on the first call so that the search starts from the beginning of the directory
on which the operation is requested. For subsequent calls, this member SHOULD be zero so that
the search resumes at the point where it stopped.

**SID (variable):** A SID ([MS-DTYP] section 2.4.2.2) data element that specifies the owner.

**2.3.16** **FSCTL_FIND_FILES_BY_SID Reply**

The FSCTL_FIND_FILES_BY_SID Reply message returns the results of the FSCTL_FIND_FILES_BY_SID
Request (section 2.3.15) as an array of FILE_NAME_INFORMATION (section 2.1.7) data elements
containing relative pathnames (section 2.1.5), one for each matching file or directory that is found, in
no necessary order. All returned file names MUST be relative to the directory on which the
FSCTL_FIND_FILES_BY_SID Request was issued. This returns as many **FILE_NAME_INFORMATION**
data elements as will fit in the provided output buffer. The beginning of each
**FILE_NAME_INFORMATION** data element MUST be aligned to an 8-byte boundary, as measured
from the beginning of the buffer. The last **FILE_NAME_INFORMATION** structure returned MAY<25>
contain trailing padding.

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error
codes are listed in the following table.

|Status code|Meaning|
|---|---|
|STATUS_NO_QUOTAS_FOR_ACCOUNT<br>0x0000010D|Quota tracking is not enabled; therefore, the file system does not keep a<br>record of file owners. This is considered a success code. The reply MUST<br>NOT contain any data elements.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle specified is not the handle to a directory.|
|STATUS_ACCESS_DENIED<br>0xC0000022|Neither the SeManageVolumePrivilege nor the SeBackupPrivilege, as<br>specified in[MS-LSAD] section 3.1.1.2.1, privilege is held.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is not large enough to contain the<br>**FILE_NAME_INFORMATION** structure (including any trailing padding)<br>for the first matching file or directory.|
|STATUS_INVALID_USER_BUFFER<br>0xC00000E8|The input buffer is less than the size of a long integer (4 bytes) plus the<br>length of the SID provided, or the input or output buffer is not aligned to<br>the native word size of the platform, or the size of the output buffer is<br>less than the minimum size of a**FILE_NAME_INFORMATION** structure<br>(8 bytes), or the restart value is greater than 1.|

When the status code is STATUS_SUCCESS, the responder MUST retain an implementation-dependent
indication of where the directory processing ended, which is required to support a subsequent
FSCTL_FIND_FILES_BY_SID Request with the **Restart** field set to 0x00000000. For an example of
FSCTL_FIND_FILES_BY_SID restart handling, see [MS-FSA] section 2.1.5.10.8.
**2.3.35** **FSCTL_IS_PATHNAME_VALID Request**

The FSCTL_IS_PATHNAME_VALID request message requests that the server indicate whether the
specified pathname is well-formed (of acceptable length, with no invalid characters, and so on - see
section 2.1.5) with respect to the **volume** that contains the file or directory associated with the handle
on which this **FSCTL** was invoked.

The data element is as follows.

```
  PathNameLength (32 bits)
  PathName (variable) (32 bits)
  ...
```

**PathNameLength (4 bytes):** An unsigned 32-bit integer that specifies the length, in bytes, of the

**PathName** data element.
**PathName (variable):** A variable-length Unicode string that specifies the path name.

**2.3.36** **FSCTL_IS_PATHNAME_VALID Reply**

This message returns the results of the FSCTL_IS_PATHNAME_VALID Request (section 2.3.35).

A STATUS_SUCCESS from this call means that the pathname is valid. An error means that the
pathname is not valid.<34>

**2.3.37** **FSCTL_LMR_SET_LINK_TRACKING_INFORMATION Request**

The FSCTL_LMR_SET_LINK_TRACKING_INFORMATION request message sets **Distributed Link**
**Tracking (DLT)** information such as file system type, **volume** ID, object ID, and destination
computer's **NetBIOS name** for the file or directory associated with the handle on which this **FSCTL**
was invoked. For more information about Distributed Link Tracking (DLT), see [MS-DLTW] section
3.1.6.

There are two variations of this request, depending on whether it is embedded within [MS-SMB] or

[MS-SMB2]. The request definitions are as follows.

- FSCTL_LMR_SET_LINK_TRACKING_INFORMATION Request for SMB

- FSCTL_LMR_SET_LINK_TRACKING_INFORMATION Request for SMB2

**2.3.37.1** **FSCTL_LMR_SET_LINK_TRACKING_INFORMATION Request for SMB**

The message contains a REMOTE_LINK_TRACKING_INFORMATION32 data element. The SMB
REMOTE_LINK_TRACKING_INFORMATION32 data element is as follows.

```
  TargetFileObject (32 bits)
  TargetLinkTrackingInformationLength (32 bits)
  TargetLinkTrackingInformationBuffer (variable) (32 bits)
  ...
```

**TargetFileObject (4 bytes):** The **Fid** of the file from which to obtain link tracking information. For

Fid type, see [MS-SMB] section 2.2.7.2.1.

**TargetLinkTrackingInformationLength (4 bytes):** The length of the

**TargetLinkTrackingInformationBuffer** .

**TargetLinkTrackingInformationBuffer (variable):** This field is as specified in

TARGET_LINK_TRACKING_INFORMATION_Buffer.

**2.3.37.2** **FSCTL_LMR_SET_LINK_TRACKING_INFORMATION Request for SMB2**

The message contains an SMB2_REMOTE_LINK_TRACKING_INFORMATION data element. The
SMB2_REMOTE_LINK_TRACKING_INFORMATION data element is as follows.
```
  TargetFileObject (32 bits)
  TargetLinkTrackingInformationLength (32 bits)
  TargetLinkTrackingInformationBuffer (variable) (32 bits)
  ...
```

**TargetFileObject (8 bytes):** Nonzero values of **TargetFileObject** are never used in the Server

Message Block (SMB) Version 2 Protocol variant of the request. This field MUST be set to zero.

**TargetLinkTrackingInformationLength (4 bytes):** The length of the

**TargetLinkTrackingInformationBuffer** field.

**TargetLinkTrackingInformationBuffer (variable):** This field is as specified in

TARGET_LINK_TRACKING_INFORMATION_BUFFER.

**2.3.37.3** **TARGET_LINK_TRACKING_INFORMATION_Buffer**

The TARGET_LINK_TRACKING_INFORMATION_Buffer data element MUST take one of the following
forms:

- TARGET_LINK_TRACKING_INFORMATION_Buffer_1 if the
**TargetLinkTrackingInformationLength** value is less than 36.

- TARGET_LINK_TRACKING_INFORMATION_Buffer_2 if the
**TargetLinkTrackingInformationLength** value is greater than or equal to 36.

**2.3.37.3.1** **TARGET_LINK_TRACKING_INFORMATION_Buffer_1**

If the **TargetLinkTrackingInformationLength** value is less than 36, the
TARGET_LINK_TRACKING_INFORMATION_Buffer data element MUST be as follows.

```
  NetBIOSName (variable) (32 bits)
  ...
```

**NetBIOSName (variable):** A null-terminated ASCII string containing the **NetBIOS name** of the

destination computer, if known. For more information, see [MS-DLTW] section 3.1.6. If not
known, this field is zero length and contains nothing.

**2.3.37.3.2** **TARGET_LINK_TRACKING_INFORMATION_Buffer_2**

If the **TargetLinkTrackingInformationLength** value is greater than or equal to 36, the
TARGET_LINK_TRACKING_INFORMATION_Buffer data element MUST be as follows.
```
  Type (32 bits)
  VolumeId (16 bytes) (32 bits)
  ObjectId (16 bytes) (32 bits)
  NetBIOSName (variable) (32 bits)
  ...
```

**Type (4 bytes):** An unsigned 32-bit integer that indicates the type of file system on which the file is

hosted on the destination computer. MUST be one of the following.

|Value|Meaning|
|---|---|
|0x00000000|The destination file system is NTFS.|
|0x00000001|The destination file system is DFS. For more information, see[MSDFS].|

**VolumeId (16 bytes):** A 16-byte **GUID** that uniquely identifies the **volume** for the object, as

obtained from the **ObjectId** field of FileFsObjectIdInformation.

**ObjectId (16 bytes):** A 16-byte GUID that uniquely identifies the destination file or directory within

the volume on which it resides, as indicated by **VolumeId** .

**NetBIOSName (variable):** A null-terminated ASCII string containing the **NetBIOS name** of the

destination computer, if known. For more information, see [MS-DLTW] section 3.1.6. If not
known, this field is zero length and contains nothing.

**2.3.38** **FSCTL_LMR_SET_LINK_TRACKING_INFORMATION Reply**

This message returns the results of the FSCTL_LMR_SET_LINK_TRACKING_INFORMATION request.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The input buffer length is smaller than the length of the required input data<br>element.|
**2.3.39** **FSCTL_MARK_HANDLE Request**

The FSCTL_MARK_HANDLE request is used to set specific operational state on the given file handle.
This state is lost once the handle is closed.<35>

The **MARK_HANDLE_INFO** element is as follows:

```
  CopyNumber (32 bits)
  Unused (32 bits)
  VolumeHandle (32 bits)
  HandleInfo (32 bits)
  Reserved (32 bits)
  ...
```

**CopyNumber (4 bytes)** : A 32-bit unsigned integer that identifies, when reading from a file which

resides on redundant media, which copy to read.

**Unused (4 bytes):** Reserved for alignment. This field can contain any value and MUST be ignored.

**VolumeHandle (8 bytes):** A 64-bit HANDLE that is not used and MUST be set to zero.

**HandleInfo (4 bytes):** A 32-bit unsigned integer containing flags to identify the request. Only one of

the following values can be set:

|Value|Meaning|
|---|---|
|MARK_HANDLE_READ_COPY<br>0x00000080|When a file resides on redundant media (ex: mirrored or RAID) this tells<br>the file system that read operations on this handle should only come from<br>the specified copy of data.<br>When this state is not set a file system will return data from any copy<br>available as it sees fit.<br>This operation is typically used by scrubber applications that want to<br>validate the contents of all copies of data for a given file.|
|MARK_HANDLE_NOT_READ_COPY<br>0x00000100|When a file resides on redundant media (ex: mirrored or RAID) this tells<br>the file system that read operations on this handle may come from any<br>copy of the data as the file system sees fit. This turns off reading from a<br>specific copy.|

**Reserved (4 Bytes):** A 32-bit field. This field is reserved. This field SHOULD be set to 0, and MUST

be ignored.

**2.3.40** **FSCTL_MARK_HANDLE Reply**

This message returns the results of the FSCTL_MARK_HANDLE request.
The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this FSCTL is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|This status is returned if:<br> <br>HandleInfo contains any flag other than one and only one<br>of either MARK_HANDLE_READ_COPY or<br>MARK_HANDLE_NOT_READ_COPY<br> <br>The file was opened for cached IO<br> <br>The specified copy number is greater than the number of<br>available redundant copies|
|STATUS_DIRECTORY_NOT_SUPPORTED<br>0xC000047C|This operation is not supported on directory files.|
|STATUS_NOT_REDUNDANT_STORAGE<br>0xC0000479|This operation is only supported on redundant media.|
|STATUS_COMPRESSED_FILE_NOT_SUPPORTED<br>0xC000047B|This operation is not supported on compressed files.|

**2.3.53** **FSCTL_QUERY_FAT_BPB Request**

This message requests that the server return the first 0x24 bytes of sector 0 for the **volume** that
contains the file or directory associated with the handle on which this **FSCTL** was invoked. The first
0x24 bytes of sector 0 are known as the FAT BIOS Parameter Block (BPB), which contains hardwarespecific bootstrap information.

This message does not contain any additional data elements.

This FSCTL is valid only for a **FAT file system** . All other file systems treat this as an invalid FSCTL.

**2.3.54** **FSCTL_QUERY_FAT_BPB Reply**

The reply buffer contains the first 0x24 bytes of sector 0 for the **volume** associated with the handle
on which this FSCTL was invoked.

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error
codes are listed in the following table.

|Error Code|Meaning|
|---|---|
|STATUS_INVALID_DEVICE_REQUEST|The specified request is not a valid operation for the target device.|
|Error Code|Meaning|
|---|---|
|0xC0000010||
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The buffer is too small to contain the entry. No information has been<br>written to the buffer.|

**2.3.55** **FSCTL_QUERY_FILE_REGIONS Request**

The FSCTL_QUERY_FILE_REGIONS request message requests that the server return a list of file
regions, based on a specified usage parameter, for the file associated with the handle on which this
FSCTL was invoked. This message contains an optional FILE_REGION_INPUT data element. If no
FILE_REGION_INPUT parameter is specified, information for the entire size of the file is returned.

A FILE_REGION_INPUT data element is as follows.

```
  FileOffset (32 bits)
  Length (32 bits)
  DesiredUsage (32 bits)
  Reserved (32 bits)
  ...
```

**FileOffset (8 bytes):** A 64-bit signed integer that contains the file offset, in bytes, of the start of a

range of bytes in a file.

**Length (8 bytes):** A 64-bit signed integer that contains the size, in bytes, of the range.

**DesiredUsage (4 bytes):** A 32-bit unsigned integer that indicates usage parameters for this

operation. The following table provides the currently defined usage parameters.

|Value|Meaning|
|---|---|
|FILE_REGION_USAGE_VALID_CACHED_DATA<br>0x00000001|Information about the valid data length for the specified<br>file and file range in the cache will be returned.<47>|
|FILE_REGION_USAGE_VALID_NONCACHED_DATA<br>0x00000002|Information about the valid data length for the specified<br>file and file range on disk will be returned.<48>|
|All other values|If a FILE_REGION_INPUT object is specified in<br>FSCTL_QUERY_FILE_REGION, then any other value will<br>return STATUS_INVALID_PARAMETER.|

**Reserved (4 bytes):** A 32-bit unsigned integer that is reserved. This field SHOULD be 0x00000000

and MUST be ignored.
**2.3.56** **FSCTL_QUERY_FILE_REGIONS Reply**

The FSCTL_QUERY_FILE_REGIONS reply message returns the results of the
FSCTL_QUERY_FILE_REGIONS Request as a variably sized data element, FILE_REGION_OUTPUT,
which contains one or more FILE_REGION_INFO elements that contain the ranges computed as a
result of the desired usage.

A FILE_REGION_OUTPUT data element is as follows.

```
  Flags (32 bits)
  TotalRegionEntryCount (32 bits)
  RegionEntryCount (32 bits)
  Reserved (32 bits)
  Region (variable) (32 bits)
  ...
```

**Flags (4 bytes):** A 32-bit unsigned integer that indicates the flags for this operation. No flags are

currently defined, thus this field SHOULD be set to 0x00000000 and MUST be ignored.

**TotalRegionEntryCount (4 bytes):** A 32-bit unsigned integer that indicates the total number of

regions that could be returned.

**RegionEntryCount (4 bytes):** A 32-bit unsigned integer that indicates the number of regions that

were actually returned and which are contained in this structure.

**Reserved (4 bytes):** A 32-bit unsigned integer that is reserved. This field SHOULD be set to

0x00000000 and MUST be ignored.

**Region (variable):** One or more FILE_REGION_INFO structures, as specified in section 2.3.56.1, that

contain information on the desired ranges based on the desired usage indicated by the
**DesiredUsage** field.

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The input buffer is too small to contain a FILE_REGION_INPUT structure, or the<br>output buffer is too small to contain a FILE_REGION_OUTPUT structure.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before all the desired regions for this file were<br>returned.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|A specified file region is invalid, or the specified desired usage flag is invalid, or<br>the given handle is not for a file (but for a directory or volume instead).|
**2.3.56.1** **FILE_REGION_INFO**

The **FILE_REGION_INFO** structure contains a computed region of a file based on a desired usage.
This structure is used to store region information for the FSCTL_QUERY_FILE_REGIONS reply
message, with the FILE_REGION_OUTPUT structure containing one or more FILE_REGION_INFO
structures.

A FILE_REGION_INFO data element is as follows.

```
  FileOffset (32 bits)
  Length (32 bits)
  DesiredUsage (32 bits)
  Reserved (32 bits)
  ...
```

**FileOffset (8 bytes):** A 64-bit signed integer that contains the file offset, in bytes, of the region.

**Length (8 bytes):** A 64-bit signed integer that contains the size, in bytes, of the region.

**DesiredUsage (4 bytes):** A 32-bit unsigned integer that indicates the usage for the given region of

the file.

|Value|Meaning|
|---|---|
|0x00000000|The given range is invalid. It does not match the criteria<br>of the requested**DesiredUsage** as specified in section<br>2.3.55.|
|FILE _USAGE_VALID_CACHED_DATA<br>0x00000001|Defines those regions of the file that exists before VDL<br>as it exists in the cache manager.<49>|
|FILE _USAGE_VALID_NONCACHED_DATA<br>0x00000002|Defines those regions of the files that exist before VDL<br>on the storage device.<50>|

**Reserved (4 bytes):** A 32-bit unsigned integer field that is reserved. This field SHOULD be set to

0x00000000 and MUST be ignored.

**2.3.57** **FSCTL_QUERY_ON_DISK_VOLUME_INFO Request**

This message requests UDF-specific **volume** information for the volume that contains the file or
directory associated with the handle on which this **FSCTL** was invoked.

This message does not contain any additional data elements.
This FSCTL is only valid on UDF file systems. All other File Systems will treat this as an invalid FSCTL.
[For information regarding UDF, see [UDF].](https://go.microsoft.com/fwlink/?LinkId=184845)

**2.3.58** **FSCTL_QUERY_ON_DISK_VOLUME_INFO Reply**

This message returns the results of the FSCTL_QUERY_ON_DISK_VOLUME_INFO request (section
2.3.57) as a FSCTL_QUERY_ON_DISK_VOLUME_INFO_BUFFER structure.

```
  DirectoryCount (32 bits)
  FileCount (32 bits)
  FsFormatMajVersion (16 bits) | FsFormatMinVersion (16 bits)
  FsFormatName (24 bytes) (32 bits)
  FormatTime (32 bits)
  LastUpdateTime (32 bits)
  CopyrightInfo (68 bytes) (32 bits)
  AbstractInfo (68 bytes) (32 bits)
  FormattingImplementationInfo (68 bytes) (32 bits)
  ...
```
**DirectoryCount (8 bytes):** A 64-bit signed integer. The number of directories on the specified

**volume** . This member is -1 if the number is unknown.

For UDF file systems with a virtual allocation table, this information is available only if the UDF
revision of the volume is greater than 1.50.<51>

**FileCount (8 bytes):** A 64-bit signed integer. The number of files on the specified volume. Returns -1

if the number is unknown.

For UDF file systems with a virtual allocation table, this information is available only if the UDF
revision of the volume is greater than 1.50.

**FsFormatMajVersion (2 bytes):** A 16-bit signed integer. The major version number of the file

system. Returns -1 if the number is unknown or not applicable. For example on UDF 1.02 file
systems, 1 is returned.

**FsFormatMinVersion (2 bytes):** A 16-bit signed integer. The minor version number of the file

system. Returns -1 if the number is unknown or not applicable. For example: on UDF 1.02 file
systems, 2 is returned.

**FsFormatName (24 bytes):** Always returns "UDF" in Unicode characters followed by nine Unicode

NULL characters.

**FormatTime (8 bytes):** The time the volume was formatted; see section 2.1.1.

**LastUpdateTime (8 bytes):** The time the volume was last updated; see section 2.1.1.

**CopyrightInfo (68 bytes):** A Unicode string containing any copyright notifications associated with

the volume. This information is implementation-specific and will be padded with NULLs.<52>

**AbstractInfo (68 bytes):** A Unicode string containing any abstract information written on the

volume. This information is implementation-specific and will be padded with NULLs.<53>

**FormattingImplementationInfo (68 bytes):** A Unicode string containing the operating system

version that the volume was formatted by. This information is implementation-specific and will be
padded with NULLs.<54>

**LastModifyingImplementationInfo (68 bytes):** A Unicode string containing the operating system

version that the volume was last modified by. This information is implementation-specific and will
be padded with NULLs.<55>

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error Code|Meaning|
|---|---|
|STATUS_INVALID_USER_BUFFER<br>0xC00000E8|An access to a user buffer failed.|
|Error Code|Meaning|
|---|---|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The buffer is too small to contain the entry. No information has been written<br>to the buffer.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|An invalid parameter was passed to a service or function.|

**2.3.59** **FSCTL_QUERY_SPARING_INFO Request**

Retrieves the defect management properties of the **volume** that contains the file or directory
associated with the handle on which this **FSCTL** was invoked.

This message does not contain any additional data elements.

This FSCTL is only valid on UDF file systems. All other file systems will treat this as an invalid FSCTL.
[For information regarding UDF, see [UDF].](https://go.microsoft.com/fwlink/?LinkId=184845)

**2.3.60** **FSCTL_QUERY_SPARING_INFO Reply**

This message returns the results of the FSCTL_QUERY_SPARING_INFO request (section 2.3.59) as a
FSCTL_QUERY_SPARING_BUFFER structure.

```
  SparingUnitBytes (32 bits)
  SoftwareSparing (8 bits) | Reserved (24 bits)
  TotalSpareBlocks (32 bits)
  FreeSpareBlocks (32 bits)
```

**SparingUnitBytes (4 bytes):** A 32-bit unsigned integer that contains the size, in bytes, of a sparing

packet, which is the same as the underlying error check and correction (ECC) block size of the
media. For more information, see [[UDF].](https://go.microsoft.com/fwlink/?LinkId=184845)

**SoftwareSparing (1 byte):** A Boolean (section 2.1.8) value. If TRUE, indicates that sparing behavior

is software-based; if FALSE, it is hardware-based.

**Reserved (3 bytes):** A 24-bit reserved value. This field SHOULD be set to zero and MUST be ignored.

**TotalSpareBlocks (4 bytes):** A 32-bit unsigned integer that contains the total number of blocks

allocated for sparing.

**FreeSpareBlocks (4 bytes):** A 32-bit unsigned integer that contains the number of blocks available

for sparing.

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error codes are
listed in the following table.
|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|An invalid parameter was passed to a service or function, or the buffer is too<br>small to contain the entry.|

**2.3.63** **FSCTL_RECALL_FILE Request**

This message requests that the server recall the file (associated with the handle on which this **FSCTL**
was invoked) from storage media that Remote Storage manages. This FSCTL is not valid for
directories.

Typically, files stored on media that is managed by Remote Storage are recalled when an application
attempts to make the first access to data. An application that opens a file without immediately
accessing the data can speed up the first access by using FSCTL_RECALL_FILE immediately after
opening the file. For performance reasons, it is recommended that an application not recall a file
unnecessarily.

This message does not contain any additional data elements.

**2.3.64** **FSCTL_RECALL_FILE Reply**

This message returns the results of the FSCTL_RECALL_FILE request.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_ACCESS_DENIED<br>0xC0000022|The file is set to not allow recall.|
|ERROR_INVALID_FUNCTION<br>0x00000001|The Remote Storage option is not installed.|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The request is not supported.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The supplied handle is not that of a file.|

**2.3.65** **FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT Request**

The FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT request message requests that the server
perform a specific stream snapshot operation on a given data stream contained in a file. The operation
performed is dependent on the value defined in REFS_STREAM_SNAPSHOT_OPERATION. The request
message takes the form of a REFS_STREAM_SNAPSHOT_MANAGEMENT_INPUT_BUFFER structure.

The REFS_STREAM_SNAPSHOT_MANAGEMENT_INPUT_BUFFER is as follows.

```
  Operation (32 bits)
  SnapshotNameLength (16 bits) | OperationInputBufferLength (16 bits)
  Reserved (32 bits)
```
**Operation (4 bytes):** This field specifies the operation and MUST contain one of the following values:

|Value|Meaning|
|---|---|
|REFS_STREAM_SNAPSHOT_OPERATION_INVALID<br>0x00000000|All requests with this operational code MUST<br>be failed by the server.|
|REFS_STREAM_SNAPSHOT_OPERATION_CREATE<br>0x00000001|This request message requests the server<br>create a new snapshot of the UNICODE name<br>contained within**NameAndInputBuffer**, <br>saving a point-in-time view of the data<br>stream represented by the handle the<br>request is being sent on.|
|REFS_STREAM_SNAPSHOT_OPERATION_LIST<br>0x00000002|This request message requests the server<br>return a list of all snapshots of the set<br>containing the data stream represented by<br>the handle the request is being sent on, and<br>matching a given regular expression query<br>string contained in NameAndInputBuffer.|
|REFS_STREAM_SNAPSHOT_OPERATION_QUERY_DELTAS<br>0x00000003|This request message requests the server<br>return a list of all metadata extents that have<br>incurred modifying operations between the<br>data stream represented by the handle the<br>request is being sent on, and the data<br>stream represented by the UNICODE name<br>contained in NameAndInputBuffer. The data<br>stream represented by the handle must be of<br>a newer creation time than the data stream<br>represented by the UNICODE name.|
|REFS_STREAM_SNAPSHOT_OPERATION_REVERT<br>0x00000004|This request message requests the server<br>revert the data stream represented by the<br>handle the request is being sent on to a<br>point-in-time snapshot view represented by<br>the UNICODE name contained within<br>NameAndInputBuffer.|
|REFS_STREAM_SNAPSHOT_OPERATION_SET_SHADOW_BTREE<br>0x00000005|This request message requests the server<br>create a shadow data stream on the data<br>stream represented by the handle the<br>request is being sent on.|
|REFS_STREAM_SNAPSHOT_OPERATION_CLEAR_SHADOW_BTREE<br>0x00000006|This request message requests the server<br>remove a shadow data stream on the data<br>stream represented by the handle the<br>request is being sent on.|
|REFS_STREAM_SNAPSHOT_OPERATION_MAX|The maximum operational code supported by|
|Value|Meaning|
|---|---|
|0x00000006|the server. All operational codes larger than<br>this numerical value will be failed.|

**SnapshotNameLength (2 bytes):** An unsigned integer representing the length in bytes of the

unicode name contained within NameAndInputBuffer field. If no such name is present in the
message, then this value is set to zero.

**OperationInputBufferLength (2 bytes):** An unsigned integer representing the length in bytes of

the operational control structure present in the message and contained within
**NameAndInputBuffer** field. If no such control structure is present in the message, then this
value is set to zero.

**Reserved (16 bytes):** This field MUST be set to zero and MUST be ignored.

**NameAndInputBuffer (variable):** An array of bytes optionally containing a unicode name as well as

an operational control buffer. When a unicode name is present, it is located immediately within the
first byte of **NameAndInputBuffer** . When an operational control buffer is present, it is located at
the next quad aligned boundary past the end of the unicode name. If no such unicode name is
present, then the operational control buffer is located at the first byte of **NameAndInputBuffer** .

The following **Operation** codes require a unicode name to be present:

- REFS_STREAM_SNAPSHOT_OPERATION_CREATE

- REFS_STREAM_SNAPSHOT_OPERATION_LIST

- REFS_STREAM_SNAPSHOT_OPERATION_QUERY_DELTAS

- REFS_STREAM_SNAPSHOT_OPERATION_REVERT
The following **Operation** code requires a control structure of the following type:

- REFS_STREAM_SNAPSHOT_OPERATION_QUERY_DELTAS requires a
REFS_STREAM_SNAPSHOT_QUERY_DELTAS_INPUT_BUFFER to be present.

**2.3.65.1** **REFS_STREAM_SNAPSHOT_QUERY_DELTAS_INPUT_BUFFER**

The REFS_STREAM_SNAPSHOT_QUERY_DELTAS_INPUT_BUFFER is as follows:

```
  StartingVcn (32 bits)
  Flags (32 bits)
  Reserved (32 bits)
  ...
```

**StartingVcn (8 bytes):** A signed integer representing the starting VCN for which to perform the

request on.

**Flags (4 bytes):** An unsigned integer representing flags to modify the behavior of the request. This

field must be set to zero.

**Reserved (4 bytes):** This field MUST be set to zero and MUST be ignored.
**2.3.66** **FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT Reply**

This message returns the result of the FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT request.

The message returns either a status code, as specified in section 2.2, or depending on the operation,
an output data payload.

The most common error codes are listed in the following table.

|Value|Meaning|
|---|---|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The operation as requested is not supported, or the file<br>system does not support snapshot operations.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|One of the parameters to the request is incorrect.|
|STATUS_INSUFFICIENT_RESOURCES<br>0xC000009A|There were insufficient resources to complete the<br>operation.|
|STATUS_DISK_FULL<br>0xC000007F|The disk is full.|
|STATUS_MEDIA_WRITE_PROTECTED<br>0xC00000A2|The volume is read-only.|
|STATUS_SUCCESS<br>0x00000000|The operation was successful.|

**2.3.66.1** **REFS_STREAM_SNAPSHOT_LIST_OUTPUT_BUFFER**

The **REFS_STREAM_SNAPSHOT_LIST_OUTPUT_BUFFER** is as follows:

```
  EntryCount (32 bits)
  BufferSizeRequiredForQuery (32 bits)
  Reserved (32 bits)
  Entries (variable) (32 bits)
  ...
```

**EntryCount (4 bytes):** An unsigned integer representing the number of entries contained within the

Entries field.

**BufferSizeRequiredForQuery (4 bytes):** An unsigned integer representing the total number of

bytes to fully satisfy the request. This value is accurate upon returning STATUS_SUCCESS as well
as STATUS_BUFFER_OVERFLOW.
**Reserved (8 bytes):** This field MUST be set to zero and MUST be ignored.

**Entries (variable):** An array of **REFS_STREAM_SNAPSHOT_LIST_OUTPUT_BUFFER_ENTRY**

structs.

**2.3.66.1.1** **REFS_STREAM_SNAPSHOT_LIST_OUTPUT_BUFFER_ENTRY**

The **REFS_STREAM_SNAPSHOT_LIST_OUTPUT_BUFFER_ENTRY** is as follows:

```
  NextEntryOffset (32 bits)
  SnapshotNameLength (16 bits) | SnapshotCreationTime (16 bits)
  ... (16 bits) | StreamSize (16 bits)
  ... (16 bits) | StreamAllocationSize (16 bits)
  ... (16 bits) | Reserved (16 bits)
  ... (16 bits) | SnapshotName (variable) (16 bits)
  ...
```

**NextEntryOffset (4 bytes):** An unsigned integer representing the offset in bytes to the next

REFS_STREAM_SNAPSHOT_LIST_OUTPUT_BUFFER_ENTRY structure. When this value is zero
there are no more entries in the array.

**SnapshotNameLength (2 bytes):** A unsigned integer representing the length of the UNICODE name

contained in **SnapshotName** in bytes.

**SnapshotCreationTime (8 bytes):** An unsigned integer representing a FILETIME structure

containing the creation time of the snapshot.

**StreamSize (8 bytes):** An unsigned integer representing the End-Of-File marker of the data stream

represented by this entry.

**StreamAllocationSize (8 bytes):** An unsigned integer representing the size in bytes used by the

data owned by the data stream represented by this entry.

**Reserved (16 bytes):** This field MUST be set to zero and MUST be ignored.
**SnapshotName (variable):** An array of WCHARs, as specified in [MS-DTYP] section 2.2.60,

representing the UNICODE name for the snapshot representing this entry. The size of the array is
defined in the **SnapshotNameLength** field.

**2.3.66.2** **REFS_STREAM_SNAPSHOT_QUERY_DELTAS_OUTPUT_BUFFER**

The REFS_STREAM_SNAPSHOT_QUERY_DELTAS_OUTPUT_BUFFER is as follows:

```
  ExtentCount (32 bits)
  Reserved (32 bits)
  Extents (variable) (32 bits)
  ...
```

**ExtentCount (4 bytes):** An unsigned integer representing the number of REFS_STREAM_EXTENT

structs contained in the Extents field.

**Reserved (8 bytes):** This field MUST be set to zero and MUST be ignored.

**Extents (variable):** An array of REFS_STREAM_EXTENT structs.

**2.3.66.2.1** **REFS_STREAM_EXTENT**

The **REFS_STREAM_EXTENT** is as follows:

```
  Vcn (32 bits)
  Lcn (32 bits)
  Length (32 bits)
  Properties (32 bits)
  ...
```

**Vcn (8 bytes):** A signed integer representing a VCN within a data stream. This value will always be

greater than zero.

**Lcn (8 bytes):** A signed integer representing the LCN mapping to Vcn in a data stream. This value

will always be greater than zero.
**Length (8 bytes):** A signed integer representing the contiguous length in clusters for which the VCN

to LCN mapping holds. This value will always be greater than zero.

**Properties (4 bytes):** A value representing the properties for this VCN to LCN mapping. The value

MUST be one of the following:

|Value|Meaning|
|---|---|
|REFS_STREAM_EXTENT_PROPERTY_VALID<br>0x0010|The metadata extent is considered valid, where the<br>VCN to LCN mapping represents a written or zeroed<br>extent.|
|REFS_STREAM_EXTENT_PROPERTY_STREAM_RESERVED<br>0x0020|The metadata extent does not map to an LCN, but<br>instead contains a token representation an allocation<br>reservation.|
|REFS_STREAM_EXTENT_PROPERTY_CRC32<br>0x0080|The metadata extent references data that is<br>checksumed with the CRC32 algorithm.|
|REFS_STREAM_EXTENT_PROPERTY_CRC64<br>0x0100|The metadata extent references data that is<br>checksumed with the CRC64 algorithm.|
|REFS_STREAM_EXTENT_PROPERTY_GHOSTED<br>0x0200|The metadata extent contains a ghosted recall buffer.|
|REFS_STREAM_EXTENT_PROPERTY_READONLY<br>0x0400|The metadata extent is a cached copy of a different<br>metadata extent. This extent is immutable, and the<br>LCN it references is not writable via this extent.|
|REFS_STREAM_EXTENT_PROPERTY_SPARSE<br>0x0008|The metadata extent represents a sparse range within<br>the stream. The range represented by this extent is<br>analogous to a sparse hole in the stream table.|

**2.3.69** **FSCTL_SET_DEFECT_MANAGEMENT Request**

Sets the software defect management state for the specified file associated with the handle on which
this FSCTL was invoked. Used for UDF file systems.

This message contains a **FILE_SET_DEFECT_MGMT_BUFFER** structure.

**FILE_SET_DEFECT_MGMT_BUFFER** is defined as follows.

```
```
|Disable|Disable|Disable|Disable|Disable|Disable|Disable|Disable|||||||||||||||||||||||||

**Disable (1 byte):** A Boolean (section 2.1.8) value. If TRUE, indicates that defect management will be

disabled. If FALSE, indicates that defect management will be enabled.

This FSCTL is valid only on UDF file systems. All other file systems will treat this as an invalid
FSCTL. For information regarding UDF, see [[UDF].](https://go.microsoft.com/fwlink/?LinkId=184845)
**2.3.70** **FSCTL_SET_DEFECT_MANAGEMENT Reply**

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned directly by the function that processes this **FSCTL** is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|An invalid parameter was passed to a service or function or the handle on<br>which this FSCTL was invoked is that of a directory.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The specified request is not a valid operation for the target device.|
|STATUS_SHARING_VIOLATION<br>0xC0000043|A file cannot be opened because the share access flags are incompatible.|
|STATUS_VOLUME_DISMOUNTED<br>0xC000026E|An operation was attempted to a**volume** after it was dismounted.|
|STATUS_FILE_INVALID<br>0xC0000098|The volume for a file has been externally altered such that the opened file<br>is no longer valid.|
|STATUS_WRONG_VOLUME<br>0xC0000012|The wrong volume is in the drive.|
|STATUS_VERIFY_REQUIRED<br>0x80000016|The media has changed and a verify operation is in progress so no reads<br>or writes can be performed to the device, except those used in the verify<br>operation.|

There are no additional data elements in this reply.

**2.3.89** **FSCTL_SIS_COPYFILE Request**

The FSCTL_SIS_COPYFILE request message requests that the server use the **single-instance**
**storage (SIS)** **filter** to copy a file. The message contains an SI_COPYFILE data element.

If the SIS filter is installed on the server, it will attempt to copy the specified source file to the
specified destination file by creating an SIS link instead of actually copying the file data. If necessary
and allowed, the source file is placed under SIS control before the destination file is created.

This **FSCTL** can be issued against either a file or directory handle. The source and destination files
MUST reside on the **volume** associated with the given handle.

The SI_COPYFILE data element is as follows.

```
  SourceFileNameLength (32 bits)
  DestinationFileNameLength (32 bits)
  Flags (32 bits)
  SourceFileName (variable) (32 bits)
  DestinationFileName (variable) (32 bits)
  ...
```

**SourceFileNameLength (4 bytes):** A 32-bit unsigned integer that contains the size, in bytes, of the

**SourceFileName** element, including a terminating-Unicode null character.

**DestinationFileNameLength (4 bytes):** A 32-bit unsigned integer that contains the size, in bytes,

of the **DestinationFileName** element, including a terminating-Unicode null character.

**Flags (4 bytes):** A 32-bit unsigned integer that contains zero or more of the following flag values.

Flag values not specified in the following table SHOULD be set to 0 and MUST be ignored.

|Value|Meaning|
|---|---|
|COPYFILE_SIS_LINK<br>0x00000001|If this flag is set, only create the destination file if the source file is already under SIS<br>control. If the source file is not under SIS control, the FSCTL returns<br>STATUS_OBJECT_TYPE_MISMATCH.<br>If this flag is not specified, place the source file under SIS control (if it is not already<br>under SIS control), and create the destination file.|
|COPYFILE_SIS_REPLACE<br>0x00000002|If this flag is set, create the destination file if it does not exist; if it does exist,<br>overwrite it.<br>If this flag is not specified, create the destination file if it does not exist; if it does<br>exist, the FSCTL returns STATUS_OBJECT_NAME_COLLISION.|

**SourceFileName (variable):** A null-terminated Unicode string containing the source file name.

**DestinationFileName (variable):** A null-terminated Unicode string containing the destination file

name.<85>
**2.3.90** **FSCTL_SIS_COPYFILE Reply**

This message returns the results of the FSCTL_SIS_COPYFILE request.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The input buffer is NULL, or the input buffer length is less than the size of<br>the SI_COPYFILE structure, or the given**SourceFileNameLength** or<br>**DestinationFileNameLength** is less than 2 or greater than the buffer<br>length, or the given**SourceFileNameLength** plus<br>**DestinationFileNameLength** is greater than the length of the given<br>**SourceFileName** plus**DestinationFileName** in the input buffer, or the<br>given**SourceFileName** or**DestinationFileName** is NULL, or the given<br>**SourceFileName** or**DestinationFileName** is not null-terminated.|
|STATUS_OBJECT_NAME_NOT_FOUND<br>0xC0000034|The source file does not exist.|
|STATUS_OBJECT_NAME_COLLISION<br>0xC0000035|The COPYFILE_SIS_REPLACE flag was not specified, and the destination<br>file exists, or the source and destination file are the same.|
|STATUS_OBJECT_TYPE_MISMATCH<br>0xC0000024|The COPYFILE_SIS_LINK flag was specified, and the source file is not<br>under SIS control.|
|STATUS_NOT_SAME_DEVICE<br>0xC00000D4|The source and destination file names are not located on the same<br>**volume**, or the source and destination file names are located on the<br>same volume, but it is not the volume associated with the handle on<br>which the FSCTL was performed.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The**single-instance storage (SIS)** **filter** is not installed on the server.|
|STATUS_FILE_IS_A_DIRECTORY<br>0xC00000BA|The source or destination file is a directory.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The caller is not an administrator.|

**2.3.91** **FSCTL_VIRTUAL_STORAGE_QUERY_PROPERTY Request**

This request contains a message with the same structure as the IOCTL_STORAGE_QUERY_PROPERTY
request (section 2.8.1) with the following values:

**PropertyId** **(4 bytes)** : 0x00000004

**QueryType** **(4 bytes)** : 0x00000000

Remote servers SHOULD ignore this request.<86>
