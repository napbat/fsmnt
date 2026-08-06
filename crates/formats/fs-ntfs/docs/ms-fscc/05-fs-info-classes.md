<!-- MS-FSCC Reference: File System Information Classes -->
<!-- FileFsXxxInformation structures for querying volume/filesystem metadata. Includes: FileFsAttributeInformation, FileFsVolumeInformation, FileFsSizeInformation, FileFsFullSizeInformation, FileFsDeviceInformation, FileFsSectorSizeInformation, FileFsControlInformation, FileFsObjectIdInformation. -->

**2.5** **File System Information Classes**

File system information classes are numerical values (specified by the Level column in the following
table) that specify what information on a particular instance of a file system on a **volume** is to be
queried. File system information classes can retrieve information such as the file system type, volume
label, size of the file system, and name of the driver used to access the file system. The table
indicates which file system information classes are supported for query and set operations.<158>

|File system information class|Level|Uses|
|---|---|---|
|FileFsVolumeInformation|1|Query|
|FileFsLabelInformation|2|LOCAL<159>|
|FileFsSizeInformation|3|Query|
|FileFsDeviceInformation|4|Query|
|FileFsAttributeInformation|5|Query|
|FileFsControlInformation|6|Query, Set|
|FileFsFullSizeInformation|7|Query|
|FileFsObjectIdInformation|8|Query, Set|
|FileFsDriverPathInformation|9|LOCAL<160>|
|FileFsVolumeFlagsInformation|10|LOCAL<161>|
|FileFsSectorSizeInformation|11|Query|

If an Information Class is specified that does not match the usage in the above table,
STATUS_INVALID_INFO_CLASS MUST be returned. If a file system does not implement one of the
above defined uses of an Information Class, STATUS_INVALID_PARAMETER MUST be returned.

**2.5.1** **FileFsAttributeInformation**

This information class is used to query attribute information for a file system.

A **FILE_FS_ATTRIBUTE_INFORMATION** data element, defined as follows, is returned by the
server.
```
  FileSystemAttributes (32 bits)
  MaximumComponentNameLength (32 bits)
  FileSystemNameLength (32 bits)
  FileSystemName (variable) (32 bits)
  ...
```

**FileSystemAttributes (4 bytes):** A 32-bit unsigned integer that contains a bitmask of flags that

specify attributes of the specified file system as a combination of the following flags. The value of
this field MUST be a bitwise OR of zero or more of the following with the exception that
FILE_FILE_COMPRESSION and FILE_VOLUME_IS_COMPRESSED cannot both be set. Any flag
values not explicitly mentioned here can be set to any value, and MUST be ignored.<162>

|Value|Meaning|
|---|---|
|FILE_SUPPORTS_USN_JOURNAL<br>0x02000000|The file system implements a**USN** change journal.|
|FILE_SUPPORTS_OPEN_BY_FILE_ID<br>0x01000000|The file system supports opening a file by FileID or ObjectID.|
|FILE_SUPPORTS_EXTENDED_ATTRIBUTES<br>0x00800000|The file system persistently stores Extended Attribute<br>information per file.|
|FILE_SUPPORTS_HARD_LINKS<br>0x00400000|The file system supports hard linking files.|
|FILE_SUPPORTS_TRANSACTIONS<br>0x00200000|The**volume** supports transactions.<163>|
|FILE_SEQUENTIAL_WRITE_ONCE<br>0x00100000|The underlying volume is write once.|
|FILE_READ_ONLY_VOLUME<br>0x00080000|If set, the volume has been mounted in read-only mode.|
|FILE_NAMED_STREAMS<br>0x00040000|The file system supports**named streams**.|
|FILE_SUPPORTS_ENCRYPTION<br>0x00020000|The file system supports the Encrypted File System<br>(EFS).<164>|
|FILE_SUPPORTS_OBJECT_IDS<br>0x00010000|The file system supports**object identifiers**.|
|FILE_VOLUME_IS_COMPRESSED<br>0x00008000|The specified volume is a compressed volume. This flag is<br>incompatible with the FILE_FILE_COMPRESSION flag.|
|FILE_SUPPORTS_POSIX_UNLINK_RENAME<br>0x00000400|The file system supports POSIX-style delete and rename<br>operations.<165>|
|Value|Meaning|
|---|---|
|FILE_RETURNS_CLEANUP_RESULT_INFO<br>0x00000200|On a successful cleanup operation, the file system returns<br>information that describes additional actions taken during<br>cleanup, such as deleting the file. File system filters can<br>examine this information in their post-cleanup callback.<166>|
|FILE_SUPPORTS_REMOTE_STORAGE<br>0x00000100|The file system supports remote storage.<167>|
|FILE_SUPPORTS_REPARSE_POINTS<br>0x00000080|The file system supports**reparse points**.|
|FILE_SUPPORTS_SPARSE_FILES<br>0x00000040|The file system supports**sparse files**.|
|FILE_VOLUME_QUOTAS<br>0x00000020|The file system supports per-user quotas.|
|FILE_FILE_COMPRESSION<br>0x00000010|The file volume supports file-based compression. This flag is<br>incompatible with the FILE_VOLUME_IS_COMPRESSED flag.|
|FILE_PERSISTENT_ACLS<br>0x00000008|The file system preserves and enforces access control lists<br>(ACLs).|
|FILE_UNICODE_ON_DISK<br>0x00000004|The file system supports Unicode in file and directory names.<br>This flag applies only to file and directory names; the file<br>system neither restricts nor interprets the bytes of data within a<br>file.|
|FILE_CASE_PRESERVED_NAMES<br>0x00000002|The file system preserves the case of file names when it places<br>a name on disk.|
|FILE_CASE_SENSITIVE_SEARCH<br>0x00000001|The file system supports case-sensitive file names when looking<br>up (searching for) file names in a directory.|
|FILE_SUPPORT_INTEGRITY_STREAMS<br>0x04000000|The file system supports integrity streams.|
|FILE_SUPPORTS_BLOCK_REFCOUNTING<br>0x08000000|The file system supports sharing logical clusters between files<br>on the same volume. The file system reallocates on writes to<br>shared clusters. Indicates that<br>FSCTL_DUPLICATE_EXTENTS_TO_FILE is a supported<br>operation.|
|FILE_SUPPORTS_SPARSE_VDL<br>0x10000000|The file system tracks whether each cluster of a file contains<br>valid data (either from explicit file writes or automatic zeros) or<br>invalid data (has not yet been written to or zeroed).<br>File systems that use Sparse VDL do not store a valid data<br>length (section 2.4.50) and do not require that valid data be<br>contiguous within a file.|

**MaximumComponentNameLength (4 bytes):** A 32-bit signed integer that contains the maximum

**file name component** length, in characters, supported by the specified file system. The value of
this field MUST be greater than zero and MUST be no more than 255.<168>

**FileSystemNameLength (4 bytes):** A 32-bit unsigned integer that contains the length, in bytes, of

the file system name in the **FileSystemName** field. The value of this field MUST be greater than
0.
**FileSystemName (variable):** A variable-length Unicode field containing the name of the file system.

This field is not null-terminated and MUST be handled as a sequence of **FileSystemNameLength**
bytes. This field is intended to be informative only. A client SHOULD NOT infer file system type
specific behavior from this field.<169>

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before all of the file system information could<br>be returned; only a portion of the FileSystemName field is returned.|

**2.5.2** **FileFsControlInformation**

This information class is used to query or set quota and content indexing control information for a file
system **volume** .

Setting quota information requires the caller to have permission to open a volume handle or a handle
to the quota index file<170> for write access.

A **FILE_FS_CONTROL_INFORMATION** data element, defined as follows, is returned by the server
or provided by the client.

```
  FreeSpaceStartFiltering (32 bits)
  FreeSpaceThreshold (32 bits)
  FreeSpaceStopFiltering (32 bits)
  DefaultQuotaThreshold (32 bits)
  DefaultQuotaLimit (32 bits)
  FileSystemControlFlags (32 bits)
  ...
```
Padding

**FreeSpaceStartFiltering (8 bytes):** A 64-bit signed integer that contains the minimum amount of

free disk space, in bytes, that is required for the operating system's **content indexing service** to
begin document filtering. This value SHOULD be set to 0 and MUST be ignored.

**FreeSpaceThreshold (8 bytes):** A 64-bit signed integer that contains the minimum amount of free

disk space, in bytes, that is required for the indexing service to continue to filter documents and
merge word lists. This value SHOULD be set to 0 and MUST be ignored.

**FreeSpaceStopFiltering (8 bytes):** A 64-bit signed integer that contains the minimum amount of

free disk space, in bytes, that is required for the content indexing service to continue filtering. This
value SHOULD be set to 0, and MUST be ignored.

**DefaultQuotaThreshold (8 bytes):** A 64-bit unsigned integer that contains the default per-user

**disk quota** warning threshold, in bytes, for the volume. A value of 0xFFFFFFFFFFFFFFFF specifies
that no default quota warning threshold per user is set.

**DefaultQuotaLimit (8 bytes):** A 64-bit unsigned integer that contains the default per-user disk

quota limit, in bytes, for the volume. A value of 0xFFFFFFFFFFFFFFFF specifies that no default
quota limit per user is set.

**FileSystemControlFlags (4 bytes):** A 32-bit unsigned integer that contains a bitmask of flags that

control quota enforcement and logging of user-related quota events on the volume. The following
bit flags are valid in any combination. Bits not defined in the following table SHOULD be set to 0,
and MUST be ignored.<171>

|Value|Meaning|
|---|---|
|FILE_VC_CONTENT_INDEX_DISABLED<br>0x00000008|Content indexing is disabled.|
|FILE_VC_LOG_QUOTA_LIMIT<br>0x00000020|An event log entry will be created when the user exceeds the<br>assigned disk quota limit.|
|FILE_VC_LOG_QUOTA_THRESHOLD<br>0x00000010|An event log entry will be created when the user exceeds his or her<br>assigned quota warning threshold.|
|FILE_VC_LOG_VOLUME_LIMIT<br>0x00000080|An event log entry will be created when the volume's free space limit<br>is exceeded.|
|FILE_VC_LOG_VOLUME_THRESHOLD<br>0x00000040|An event log entry will be created when the volume's free space<br>threshold is exceeded.|
|FILE_VC_QUOTA_ENFORCE<br>0x00000002|Quotas are tracked and enforced on the volume.<br>Note: FILE_VC_QUOTA_TRACK takes precedence over this flag. In<br>other words, if both FILE_VC_QUOTA_TRACK and<br>FILE_VC_QUOTA_ENFORCE are set, the FILE_VC_QUOTA_ENFORCE<br>flag is ignored. This flag will be ignored if a client attempts to set it.|
|FILE_VC_QUOTA_TRACK<br>0x00000001|Quotas are tracked on the volume, but they are not enforced.<br>Tracked quotas enable reporting on the file system space used by<br>system users. If both this flag and FILE_VC_QUOTA_ENFORCE are<br>specified, FILE_VC_QUOTA_ENFORCE is ignored.<br>Note: This flag takes precedence over FILE_VC_QUOTA_ENFORCE. In<br>other words, if both FILE_VC_QUOTA_TRACK and<br>FILE_VC_QUOTA_ENFORCE are set, the FILE_VC_QUOTA_ENFORCE<br>flag is ignored. This flag will be ignored if a client attempts to set it.|
|Value|Meaning|
|---|---|
|FILE_VC_QUOTAS_INCOMPLETE<br>0x00000100|The quota information for the volume is incomplete because it is<br>corrupt, or the system is in the process of rebuilding the quota<br>information.<br>Note: This does not necessarily imply that<br>FILE_VC_QUOTAS_REBUILDING is set. This flag will be ignored if a<br>client attempts to set it.|
|FILE_VC_QUOTAS_REBUILDING<br>0x00000200|The file system is rebuilding the quota information for the volume.<br>Note: This does not necessarily imply that<br>FILE_VC_QUOTAS_INCOMPLETE is set. This flag will be ignored if a<br>client attempts to set it.|

**Padding (4 bytes):** This field SHOULD be set to 0x00000000 and MUST be ignored.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_VOLUME_NOT_UPGRADED<br>0xC000029C|The file system on the volume does not support quotas.|

**2.5.3** **FileFsDriverPathInformation**

This information class is used locally to query if a given driver is in the I/O path for a file system
**volume** .

A **FILE_FS_DRIVER_PATH_INFORMATION** data element, defined as follows, is returned to the
caller.

```
  DriverInPath (8 bits) | Reserved (24 bits)
  DriverNameLength (32 bits)
  DriverName (variable) (32 bits)
  ...
```

**DriverInPath (1 byte):** A Boolean (section 2.1.8) value. Set to TRUE if the driver is in the I/O path

for the file system volume; set to FALSE otherwise.

**Reserved (3 bytes):** Reserved for alignment. This field can contain any value and MUST be ignored.

**DriverNameLength (4 bytes):** A 32-bit unsigned integer that contains the length of the

**DriverName** string.
**DriverName (variable):** A variable-length Unicode field containing the name of the driver for which

to query. This sequence of Unicode characters MUST NOT be null-terminated.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.5.4** **FileFsFullSizeInformation**

This information class is used to query **sector** size information for a file system **volume** .

A **FILE_FS_FULL_SIZE_INFORMATION** data element, defined as follows, is returned by the server.

```
  TotalAllocationUnits (32 bits)
  CallerAvailableAllocationUnits (32 bits)
  ActualAvailableAllocationUnits (32 bits)
  SectorsPerAllocationUnit (32 bits)
  BytesPerSector (32 bits)
  ...
```

**TotalAllocationUnits (8 bytes):** A 64-bit signed integer that contains the total number of allocation

units on the volume that are available to the user associated with the calling thread. The value of
this field MUST be greater than or equal to 0.<172>

**CallerAvailableAllocationUnits (8 bytes):** A 64-bit signed integer that contains the total number

of free allocation units on the volume that are available to the user associated with the calling
thread. The value of this field MUST be greater than or equal to 0.<173>

**ActualAvailableAllocationUnits (8 bytes):** A 64-bit signed integer that contains the total number

of free allocation units on the volume. The value of this field MUST be greater than or equal to 0.

**SectorsPerAllocationUnit (4 bytes):** A 32-bit unsigned integer that contains the number of sectors

in each allocation unit.

**BytesPerSector (4 bytes):** A 32-bit unsigned integer that contains the number of bytes in each

sector.
This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.5.5** **FileFsLabelInformation**

This information class is used locally to set the label for a file system **volume** .

A **FILE_FS_LABEL_INFORMATION** data element, defined as follows, is provided by the caller.

```
  VolumeLabelLength (32 bits)
  VolumeLabel (variable) (32 bits)
  ...
```

**VolumeLabelLength (4 bytes):** A 32-bit unsigned integer that contains the length, in bytes,

including the trailing null, if present, of the name for the volume.<174>

**VolumeLabel (variable):** A variable-length Unicode field containing the name of the volume. The

content of this field can be a null-terminated string, or it can be a string padded with the space
character to be **VolumeLabelLength** bytes long.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.5.6** **FileFsObjectIdInformation**

This information class is used to query or set the object ID for a file system data element. The
operation MUST fail if the file system does not support object IDs.<175>

A **FILE_FS_OBJECTID_INFORMATION** data element, defined as follows, is returned by the server
or provided by the client.
```
  ObjectId (16 bytes) (32 bits)
  ExtendedInfo (48 bytes) (32 bits)
  ...
```

**ObjectId (16 bytes):** A 16-byte **GUID** that identifies the file system **volume** on the disk. This value

is not required to be unique on the system.

**ExtendedInfo (48 bytes):** A 48-byte value containing extended information on the file system

volume. If no extended information has been written for this file system volume, the server MUST
return 48 bytes of 0x00 in this field.<176>

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_VOLUME_NOT_UPGRADED<br>0xC000029C|The file system on the volume does not support object IDs.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The file system does not implement object IDs.|

**2.5.7** **FileFsSectorSizeInformation**

This information class is used to query for the extended sector size and alignment information for a
volume. The message contains a **FILE_FS_SECTOR_SIZE_INFORMATION** data element.<177>

A **FILE_FS_SECTOR_SIZE_INFORMATION** data element, defined as follows, is returned to the
caller.

```
  LogicalBytesPerSector (32 bits)
  PhysicalBytesPerSectorForAtomicity (32 bits)
```
**LogicalBytesPerSector (4 bytes):** A 32-bit unsigned integer that contains the number of bytes in a

logical sector for the device backing the volume. This field is the unit of logical addressing for the
device and is not the unit of atomic write. Applications SHOULD NOT utilize this value for
operations requiring physical sector alignment.

**PhysicalBytesPerSectorForAtomicity (4 bytes):** A 32-bit unsigned integer that contains the

number of bytes in a physical sector for the device backing the volume. Note that this is the
reported physical sector size of the device and is the unit of atomic write. Applications
SHOULD<178> utilize this value for operations requiring sector alignment.

**PhysicalBytesPerSectorForPerformance (4 bytes):** A 32-bit unsigned integer that contains the

number of bytes in a physical sector for the device backing the volume. This is the reported
physical sector size of the device and is the unit of performance. Applications SHOULD<179>
utilize this value for operations requiring sector alignment.

**FileSystemEffectivePhysicalBytesPerSectorForAtomicity (4 bytes):** A 32-bit unsigned integer

containing the unit, in bytes, that the file system on the volume will use for internal operations
that require alignment and atomicity.<180>

**Flags (4 bytes):** A 32-bit unsigned integer that indicates the flags for this operation. Currently

defined flags are:

|Value|Meaning|
|---|---|
|SSINFO_FLAGS_ALIGNED_DEVICE<br>0x00000001|When set, this flag indicates that the first physical<br>sector of the device is aligned with the first logical<br>sector. When not set, the first physical sector of the<br>device is misaligned with the first logical sector.|
|SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE<br>0x00000002|When set, this flag indicates that the partition is<br>aligned to physical sector boundaries on the storage<br>device.|
|SSINFO_FLAGS_NO_SEEK_PENALTY<br>0x00000004|When set, the device reports that it does not incur a<br>seek penalty (this typically indicates that the device<br>does not have rotating media, such as flash-based<br>disks).|
|SSINFO_FLAGS_TRIM_ENABLED<br>0x00000008|When set, the device supports TRIM operations, either<br>T13 (ATA) TRIM or T10 (SCSI/SAS) UNMAP.|

**ByteOffsetForSectorAlignment (4 bytes):** A 32-bit unsigned integer that contains the logical

sector offset within the first physical sector where the first logical sector is placed, in bytes. If this
value is set to SSINFO_OFFSET_UNKNOWN (0XFFFFFFFF), there was insufficient information to
compute this field.<181>

**ByteOffsetForPartitionAlignment (4 bytes):** A 32-bit unsigned integer that contains the byte

offset from the first physical sector where the first partition is placed. If this value is set to
SSINFO_OFFSET_UNKNOWN (0XFFFFFFFF), there was either insufficient information or an error
was encountered in computing this field.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error Code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.5.8** **FileFsSizeInformation**

This information class is used to query **sector** size information for a file system **volume** .

A **FILE_FS_SIZE_INFORMATION** data element, defined as follows, is returned by the server.

```
  TotalAllocationUnits (32 bits)
  AvailableAllocationUnits (32 bits)
  SectorsPerAllocationUnit (32 bits)
  BytesPerSector (32 bits)
  ...
```

**TotalAllocationUnits (8 bytes):** A 64-bit signed integer that contains the total number of allocation

units on the volume that are available to the user associated with the calling thread. This value
MUST be greater than or equal to 0.<182>

**AvailableAllocationUnits (8 bytes):** A 64-bit signed integer that contains the total number of free

allocation units on the volume that are available to the user associated with the calling thread.
This value MUST be greater than or equal to 0.<183>

**SectorsPerAllocationUnit (4 bytes):** A 32-bit unsigned integer that contains the number of sectors

in each allocation unit.

**BytesPerSector (4 bytes):** A 32-bit unsigned integer that contains the number of bytes in each

sector.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH|The specified information record length does not match the length that is|
|Error code|Meaning|
|---|---|
|0xC0000004|required for the specified information class.|

**2.5.9** **FileFsVolumeInformation**

This information class is used to query information on a **volume** on which a file system is mounted.

A **FILE_FS_VOLUME_INFORMATION** data element, defined as follows, is returned by the server.

```
  VolumeCreationTime (32 bits)
  VolumeSerialNumber (32 bits)
  VolumeLabelLength (32 bits)
  SupportsObjects (8 bits) | Reserved (8 bits) | VolumeLabel (variable) (16 bits)
  ...
```

**VolumeCreationTime (8 bytes):** The time when the volume was created; see section 2.1.1. The

value of this field MUST be greater than or equal to 0.

**VolumeSerialNumber (4 bytes):** A 32-bit unsigned integer that contains the serial number of the

volume. The serial number is an opaque value generated by the file system at format time, and is
not necessarily related to any hardware serial number for the device on which the file system is
located. No specific format or content of this field is required for protocol interoperation. This value
is not required to be unique.

**VolumeLabelLength (4 bytes):** A 32-bit unsigned integer that contains the length, in bytes,

including the trailing null, if present, of the name of the volume.<184>

**SupportsObjects (1 byte):** A Boolean (section 2.1.8) value. Set to TRUE if the file system supports

**object-oriented file system** objects; set to FALSE otherwise.<185>

**Reserved (1 byte):** An 8-bit field. This field is reserved. This field MUST be set to zero and MUST be

ignored.

**VolumeLabel (variable):** A variable-length Unicode field containing the name of the volume. The

content of this field can be a null-terminated string or can be a string padded with the space
character to be **VolumeLabelLength** bytes long.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

If the volume label is greater than 32 characters, return the first 32 characters of the label and
STATUS_SUCCESS.
|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before all of the volume information could be<br>returned; only a portion of the**VolumeLabel** field is returned.|

**2.5.10** **FileFsDeviceInformation**

This information class is used to query device information associated with a file system **volume** .

A **FILE_FS_DEVICE_INFORMATION** data element, defined as follows, is returned by the server.

```
  DeviceType (32 bits)
  Characteristics (32 bits)
```

**DeviceType (4 bytes):** This identifies the type of given volume. It MUST be one of the following.

|Value|Meaning|
|---|---|
|FILE_DEVICE_CD_ROM<br>0x00000002|Volume resides on a CD ROM.|
|FILE_DEVICE_DISK<br>0x00000007|Volume resides on a disk.|

**Characteristics (4 bytes):** A bit field which identifies various characteristics about a given volume.

The following are valid bit values.

|Value|Meaning|
|---|---|
|FILE_REMOVABLE_MEDIA<br>0x00000001|Indicates that the storage device supports removable<br>media. Notice that this characteristic indicates<br>removable media, not a removable device. For<br>example, drivers for JAZ drive devices specify this<br>characteristic, but drivers for PCMCIA flash disks do<br>not.|
|FILE_READ_ONLY_DEVICE<br>0x00000002|Indicates that the device cannot be written to.|
|FILE_FLOPPY_DISKETTE<br>0x00000004|Indicates that the device is a floppy disk device.|
|FILE_WRITE_ONCE_MEDIA<br>0x00000008|Indicates that the device supports write-once media.|
|FILE_REMOTE_DEVICE<br>0x00000010|Indicates that the volume is for a remote file system<br>like SMB or CIFS.|
|Value|Meaning|
|---|---|
|FILE_DEVICE_IS_MOUNTED<br>0x00000020|Indicates that a file system is mounted on the device.|
|FILE_VIRTUAL_VOLUME<br>0x00000040|Indicates that the volume does not directly reside on<br>storage media but resides on some other type of<br>media (memory for example).|
|FILE_DEVICE_SECURE_OPEN<br>0x00000100|By default, volumes do not check the ACL associated<br>with the volume, but instead use the ACLs associated<br>with individual files on the volume. When this flag is<br>set the volume ACL is also checked.|
|FILE_CHARACTERISTIC_TS_DEVICE<br>0x00001000|Indicates that the device object is part of a Terminal<br>Services device stack. See[MS-RDPBCGR] for more<br>information.|
|FILE_CHARACTERISTIC_WEBDAV_DEVICE<br>0x00002000|Indicates that a web-based Distributed Authoring and<br>Versioning (WebDAV) file system is mounted on the<br>device. See[MS-WDVME] for more information.|
|FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL<br>0x00020000|The IO Manager normally performs a full security<br>check for traverse access on every file open when the<br>client is an appcontainer.  Setting of this flag<br>bypasses this enforced traverse access check if the<br>client token already has traverse privileges.<186>|
|FILE_PORTABLE_DEVICE<br>0x0004000|Indicates that the given device resides on a portable<br>bus like USB or Firewire and that the entire device<br>(not just the media) can be removed from the<br>system.|

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file system information class is STATUS_SUCCESS. The
most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
