<!-- MS-FSCC: Basic File Metadata -->
<!-- FileAccessInformation, FileAllInformation, FileAlignmentInformation, FileAllocationInformation, FileBasicInformation (timestamps + attributes), FileEndOfFileInformation, FileModeInformation, FilePositionInformation, FileStandardInformation, FileStandardLinkInformation, FileValidDataLengthInformation. -->

**2.4.1** **FileAccessInformation**

This information class is used to query the access rights of a file that were granted when the file was
opened.

A **FILE_ACCESS_INFORMATION** data element, defined as follows, is returned by the server.

```
  AccessFlags (32 bits)
```

**AccessFlags (4 bytes):** A 32-bit unsigned integer that MUST contain values specified in [MS-SMB2]

section 2.2.13.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.2** **FileAllInformation**

This information class is used to query a collection of file information structures.

A **FILE_ALL_INFORMATION** data element, defined as follows, is returned by the server.
```
  BasicInformation (40 bytes) (32 bits)
  StandardInformation (24 bytes) (32 bits)
  InternalInformation (32 bits)
  EaInformation (32 bits)
  AccessInformation (32 bits)
  PositionInformation (32 bits)
  ModeInformation (32 bits)
  AlignmentInformation (32 bits)
  NameInformation (variable) (32 bits)
  ...
```

**BasicInformation (40 bytes):** A FILE_BASIC_INFORMATION structure specified in section 2.4.7.

**StandardInformation (24 bytes):** A FILE_STANDARD_INFORMATION structure specified in section

2.4.47.

**InternalInformation (8 bytes):** A FILE_INTERNAL_INFORMATION structure specified in section

2.4.27.

**EaInformation (4 bytes):** A FILE_EA_INFORMATION structure specified in section 2.4.13.

**AccessInformation (4 bytes):** A FILE_ACCESS_INFORMATION structure specified in section 2.4.1.

**PositionInformation (8 bytes):** A FILE_POSITION_INFORMATION structure specified in section

2.4.40.

**ModeInformation (4 bytes):** A FILE_MODE_INFORMATION structure specified in section 2.4.31.

**AlignmentInformation (4 bytes):** A FILE_ALIGNMENT_INFORMATION structure specified in section

2.4.3.
**NameInformation (variable):** A FILE_NAME_INFORMATION structure specified in section 2.4.32.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.3** **FileAlignmentInformation**

This information class is used to query the buffer alignment required by the underlying device.

A **FILE_ALIGNMENT_INFORMATION** data element, defined as follows, is returned by the server.

```
  AlignmentRequirement (32 bits)
```

**AlignmentRequirement (4 bytes):** A 32-bit unsigned integer that MUST contain one of the

following values.

|Value|Meaning|
|---|---|
|FILE_BYTE_ALIGNMENT<br>0x00000000|Specifies that there are no alignment requirements for the device.|
|FILE_WORD_ALIGNMENT<br>0x00000001|Specifies that data MUST be aligned on a 2-byte boundary.|
|FILE_LONG_ALIGNMENT<br>0x00000003|Specifies that data MUST be aligned on a 4-byte boundary.|
|FILE_QUAD_ALIGNMENT<br>0x00000007|Specifies that data MUST be aligned on an 8-byte boundary.|
|FILE_OCTA_ALIGNMENT<br>0X0000000F|Specifies that data MUST be aligned on a 16-byte boundary.|
|FILE_32_BYTE_ALIGNMENT<br>0X0000001F|Specifies that data MUST be aligned on a 32-byte boundary.|
|FILE_64_BYTE_ALIGNMENT<br>0X0000003F|Specifies that data MUST be aligned on a 64-byte boundary.|
|FILE_128_BYTE_ALIGNMENT<br>0X0000007F|Specifies that data MUST be aligned on a 128-byte boundary.|
|FILE_256_BYTE_ALIGNMENT<br>0X000000FF|Specifies that data MUST be aligned on a 256-byte boundary.|
|FILE_512_BYTE_ALIGNMENT|Specifies that data MUST be aligned on a 512-byte boundary.|
|Value|Meaning|
|---|---|
|0X000001FF||

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.4** **FileAllocationInformation**

This information class is used to set but not to query the allocation size for a file. The file system is
passed a 64-bit signed integer containing the file allocation size, in bytes. The file system rounds the
requested allocation size up to an integer multiple of the cluster size for nonresident files, or an
implementation-defined multiple for resident files.<101><102> All unused allocation (beyond EOF) is
freed on the last handle close.

A FILE_ALLOCATION_INFORMATION data element, defined as follows, is provided by the client.

```
  AllocationSize (32 bits)
  ...
```

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the desired allocation to be used by

the given file.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle is for a directory and not a file, or the allocation is greater than<br>the maximum file size allowed.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened to write file data or file attributes.|
|STATUS_DISK_FULL<br>0xC000007F|The disk is full.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
**2.4.7** **FileBasicInformation**

This information class is used to query or set file information.

A **FILE_BASIC_INFORMATION** data element, defined as follows, is returned by the server or
provided by the client.

```
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  LastWriteTime (32 bits)
  ChangeTime (32 bits)
  FileAttributes (32 bits)
  Reserved (32 bits)
  ...
```

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. A valid time for this

field is an integer greater than or equal to 0. When setting file attributes, a value of 0 indicates to
the server that it MUST NOT change this attribute. When setting file attributes, a value of -1
indicates to the server that it MUST NOT change this attribute for all subsequent operations on the
same file handle. When setting file attributes, a value of -2 indicates to the server that it MUST
change this attribute for all subsequent operations on the same file handle. This field MUST NOT
be set to a value less than -2.<104>

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. A valid time for

this field is an integer greater than or equal to 0. When setting file attributes, a value of 0
indicates to the server that it MUST NOT change this attribute. When setting file attributes, a value
of -1 indicates to the server that it MUST NOT change this attribute for all subsequent operations
on the same file handle. When setting file attributes, a value of -2 indicates to the server that it
MUST change this attribute for all subsequent operations on the same file handle. This field MUST
NOT be set to a value less than -2.<105>
**LastWriteTime (8 bytes):** The last time information was written to the file; see section 2.1.1. A

valid time for this field is an integer greater than or equal to 0. When setting file attributes, a
value of 0 indicates to the server that it MUST NOT change this attribute. When setting file
attributes, a value of -1 indicates to the server that it MUST NOT change this attribute for all
subsequent operations on the same file handle. When setting file attributes, a value of -2 indicates
to the server that it MUST change this attribute for all subsequent operations on the same file
handle. This field MUST NOT be set to a value less than -2.<106>

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. A valid time for this

field is an integer greater than or equal to 0. When setting file attributes, a value of 0 indicates to
the server that it MUST NOT change this attribute. When setting file attributes, a value of -1
indicates to the server that it MUST NOT change this attribute for all subsequent operations on the
same file handle. When setting file attributes, a value of -2 indicates to the server that it MUST
change this attribute for all subsequent operations on the same file handle. This field MUST NOT
be set to a value less than -2.<107>

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid file

attributes are specified in section 2.6.

**Reserved (4 bytes):** A 32-bit field. This field is reserved. This field can be set to any value, and

MUST be ignored.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened to read file data or file attributes.|

**2.4.14** **FileEndOfFileInformation**

This information class is used to set end-of-file information for a file.

A **FILE_END_OF_FILE_INFORMATION** data element, defined as follows, is provided by the client.

```
  EndOfFile (32 bits)
  ...
```

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end of file position as a

byte offset from the start of the file. EndOfFile specifies the offset from the beginning of the file of
the byte following the last byte in the file. That is, it is the offset from the beginning of the file at
which new bytes appended to the file will be written. The value of this field MUST be greater than
or equal to 0.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.
|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle was for a directory and not a file, or the allocation is greater<br>than the maximum file size allowed.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened to read file data or file attributes.|
|STATUS_DISK_FULL<br>0xC000007F|The disk is full.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.31** **FileModeInformation**

The **FileModeInformation** information class is used to query or set the mode of the file. The mode
returned by a query corresponds to the **CreateOptions** used in the initial create operation, modified
by any set FileModeInformation operations performed since the create operation.<135>
A **FILE_MODE_INFORMATION** data element, defined as follows, is returned by the server or
provided by the client.

```
  Mode (32 bits)
```

**Mode (4 bytes):** A 32-bit unsigned integer that specifies how the file will subsequently be accessed.

|Value|Meaning|
|---|---|
|FILE_WRITE_THROUGH<br>0x00000002|When set, any system services, file system drivers (FSDs), and<br>drivers that write data to the file are required to actually transfer<br>the data into the file before any requested write operation is<br>considered complete.|
|FILE_SEQUENTIAL_ONLY<br>0x00000004|This is a hint that informs the cache that it SHOULD<136> <br>optimize for sequential access. Non-sequential access of the file<br>can result in performance degradation.|
|FILE_NO_INTERMEDIATE_BUFFERING<br>0x00000008|When set, the file cannot be cached or buffered in a driver's<br>internal buffers.|
|FILE_SYNCHRONOUS_IO_ALERT<br>0x00000010|When set, all operations on the file are performed synchronously.<br>Any wait on behalf of the caller is subject to premature termination<br>from alerts. This flag also causes the I/O system to maintain the<br>file position context.|
|FILE_SYNCHRONOUS_IO_NONALERT<br>0x00000020|When set, all operations on the file are performed synchronously.<br>Wait requests in the system to synchronize I/O queuing and<br>completion are not subject to alerts. This flag also causes the I/O<br>system to maintain the file position context.|
|FILE_DELETE_ON_CLOSE<br>0x00001000|This flag is not implemented and is always returned as not set.|

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_INVALID_PARAMETER|An attempt to set the file mode returns STATUS_INVALID_PARAMETER in<br>any of the following cases:<br> <br>The**Mode** field contains any flag other than FILE_WRITE_THROUGH,<br>FILE_SEQUENTIAL_ONLY, FILE_SYNCHRONOUS_IO_ALERT, or<br>FILE_SYNCHRONOUS_IO_NONALERT.<br> <br>FILE_SYNCHRONOUS_IO_ALERT or<br>FILE_SYNCHRONOUS_IO_NONALERT is set and the file was not<br>opened for synchronous I/O.<br> <br>Neither FILE_SYNCHRONOUS_IO_ALERT nor<br>FILE_SYNCHRONOUS_IO_NONALERT are set and the file was opened<br>for synchronous I/O.|
|Error code|Meaning|
|---|---|
|| <br>FILE_SYNCHRONOUS_IO_ALERT and<br>FILE_SYNCHRONOUS_IO_NONALERT are both set.<br>|

**2.4.40** **FilePositionInformation**

This information class is used to query or set the position of the file pointer within a file.<143>

A **FILE_POSITION_INFORMATION** data element, defined as follows, is returned by the server or
provided by the client.
```
  CurrentByteOffset (32 bits)
  ...
```

**CurrentByteOffset (8 bytes):** A 64-bit signed integer that MUST contain the offset, in bytes, of the

file pointer from the beginning of the file. A unique offset value is maintained for each open of a
file. When setting the position, only values greater than or equal to zero are valid. If the given file
was opened using the FILE_NO_INTERMEDIATE_BUFFERING flag, the offset that is being set
SHOULD be aligned to a sector boundary. This value SHOULD<144> be updated by read and write
operations if the given file was opened using the FILE_SYNCHRONOUS_IO_ALERT or
FILE_SYNCHRONOUS_IO_NONALERT flags.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|Returned when setting the offset if the**CurrentByteOffset** is negative or<br>the file was opened using the FILE_NO_INTERMEDIATE_BUFFERING flag<br>and**CurrentByteOffset** is not aligned to a sector boundary.|

**2.4.47** **FileStandardInformation**

This information class is used to query file information.

A **FILE_STANDARD_INFORMATION** data element, defined as follows, is returned by the server.

```
  AllocationSize (32 bits)
  EndOfFile (32 bits)
  NumberOfLinks (32 bits)
  DeletePending (8 bits) | Directory (8 bits) | Reserved (16 bits)
  ...
```
**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the **cluster** size.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute end-of-file position as a byte

offset from the start of the file. **EndOfFile** specifies the offset to the byte immediately following
the last valid byte in the file. Because this value is zero-based, it actually refers to the first free
byte in the file. That is, it is the offset from the beginning of the file at which new bytes appended
to the file will be written. The value of this field MUST be greater than or equal to 0.

**NumberOfLinks (4 bytes):** A 32-bit unsigned integer that contains the number of non-deleted links

to this file.

**DeletePending (1 byte):** A Boolean (section 2.1.8) value. Set to TRUE to indicate that a file deletion

has been requested; set to FALSE otherwise.

**Directory (1 byte):** A Boolean (section 2.1.8) value. Set to TRUE to indicate that the file is a

directory; set to FALSE otherwise.

**Reserved (2 bytes):** A 16-bit field. This field is reserved. This field can be set to any value, and

MUST be ignored.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.48** **FileStandardLinkInformation**

This information class is used locally to query file link information.<156>

A **FILE_STANDARD_LINK_INFORMATION** data element, defined as follows, is returned to the
caller.

```
  NumberOfAccessibleLinks (32 bits)
  TotalNumberOfLinks (32 bits)
  DeletePending (8 bits) | Directory (8 bits) | Reserved (16 bits)
```

**NumberOfAccessibleLinks (4 bytes):** A 32-bit unsigned integer that contains the number of non
deleted links to this file.

**TotalNumberOfLinks (4 bytes):** A 32-bit unsigned integer that contains the total number of links to

this file, including links marked for delete.

**DeletePending (1 byte):** A Boolean (section 2.1.8) value that MUST be set to TRUE to indicate that

a file deletion has been requested; otherwise, FALSE.
**Directory (1 byte):** An 8-bit field that MUST be set to 1 to indicate that the file is a directory;

otherwise, 0.

**Reserved (2 bytes):** A 16-bit field. This field is reserved. This field can be set to any value and MUST

be ignored.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_STATUS_NOT_SUPPORTED<br>0xC00000BB|The request is not supported.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.50** **FileValidDataLengthInformation**

This information class is used to set the valid data length information for a file. A file's valid data
length is the length, in bytes, of the data that has been written to the file. This valid data extends
from the beginning of the file to the last byte in the file that has not been zeroed or left
uninitialized.<157>

A **FILE_VALID_DATA_LENGTH_INFORMATION** data element, defined as follows, is provided by
the client.

```
  ValidDataLength (32 bits)
  ...
```

**ValidDataLength (8 bytes):** A 64-bit signed integer that contains the new valid data length for the

file. This parameter MUST be a positive value that is greater than the current valid data length,
but less than or equal to the current file size.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_MEDIA_WRITE_PROTECTED|The target cannot be written to because it is write-protected.|
|Error code|Meaning|
|---|---|
|0xC00000A2||
|STATUS_INVALID_PARAMETER<br>0xC000000D|The_ValidDataLength_ specified is not a valid parameter or the given<br>handle is to a sparse or compressed file.|
|STATUS_PRIVILEGE_NOT_HELD<br>0xC0000061|The manage volume privilege is not held.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
