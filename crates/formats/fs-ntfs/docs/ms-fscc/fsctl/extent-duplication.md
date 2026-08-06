<!-- MS-FSCC: Extent Duplication (Block Cloning) -->
<!-- DUPLICATE_EXTENTS_TO_FILE, DUPLICATE_EXTENTS_TO_FILE_EX. DUPLICATE_EXTENTS_DATA, SMB2_DUPLICATE_EXTENTS_DATA. -->

**2.3.7** **FSCTL_DUPLICATE_EXTENTS_TO_FILE Request**

The FSCTL_DUPLICATE_EXTENTS_TO_FILE<18> request message requests that the server copy the
specified portion of one file (that is the source file) into a specified portion of another file (target file)
on the same volume. The logical sizes of the portions have to be the same. The two files involved in
this operation can refer to the same file, but in that case, the logical portions have to refer to disjoint
regions on the file. The FSCTL is sent on a handle opened to the target file.

When used locally, the request message takes the form of DUPLICATE_EXTENTS_DATA as specified in
section 2.3.7.1. When used remotely with [MS-SMB2], the request message takes the form of
SMB2_DUPLICATE_EXTENTS_DATA as specified in section 2.3.7.2.
**2.3.7.1** **DUPLICATE_EXTENTS_DATA**

A **DUPLICATE_EXTENTS_DATA** data element is defined as follows:

```
  FileHandle (32 bits)
  SourceFileOffset (32 bits)
  TargetFileOffset (32 bits)
  ByteCount (32 bits)
  ...
```

**FileHandle (8 bytes):** A HANDLE ([MS-DTYP] section 2.2.16) data type that is an identifier of the

open to the source file.

**SourceFileOffset (8 bytes)** : A 64-bit signed integer that contains the file offset, in bytes, of the

start of a range of bytes in a source file from which the data is to be copied. The value of this field
MUST be greater than or equal to 0x0000000000000000 and MUST be aligned to a logical cluster
boundary.

**TargetFileOffset (8 bytes)** : A 64-bit signed integer that contains the file offset, in bytes, of the start

of a range of bytes in a target file to which the data is to be copied. The value of this field MUST
be greater than or equal to 0x0000000000000000 and MUST be aligned to a logical cluster
boundary.

**ByteCount (8 bytes)** : A 64-bit signed integer that contains the number of bytes to copy from source

to target. The value of this field MUST be greater than or equal to 0x0000000000000000 and
MUST be aligned to a logical cluster boundary.

**2.3.7.2** **SMB2_DUPLICATE_EXTENTS_DATA**

A **SMB2_DUPLICATE_EXTENTS_DATA** data element is defined as follows:

```
  SourceFileID (32 bits)
  ...
```
**SourceFileID (16 bytes):** An SMB2_FILEID structure, as specified in [MS-SMB2] section 2.2.14.1,

that is an identifier of the open to the source file.

**SourceFileOffset (8 bytes):** A 64-bit signed integer that contains the file offset, in bytes, of the

start of a range of bytes in a source file from which the data is to be copied. The value of this field
MUST be greater than or equal to 0x0000000000000000 and MUST be aligned to a logical cluster
boundary.

**TargetFileOffset (8 bytes):** A 64-bit signed integer that contains the file offset, in bytes, of the start

of a range of bytes in a target file to which the data is to be copied. The value of this field MUST
be greater than or equal to 0x0000000000000000 and MUST be aligned to a logical cluster
boundary.

**ByteCount (8 bytes):** A 64-bit signed integer that contains the number of bytes to copy from source

to target. The value of this field MUST be greater than or equal to 0x0000000000000000 and
MUST be aligned to a logical cluster boundary.

**2.3.8** **FSCTL_DUPLICATE_EXTENTS_TO_FILE Reply**

This message returns the result of the FSCTL_DUPLICATE_EXTENTS_TO_FILE<19> request.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this FSCTL SHOULD<20> be
STATUS_SUCCESS. The most common error codes are listed in the following table.

|Error Code|Meaning|
|---|---|
|STATUS_NOT_SUPPORTED<br>0xC00000BB| <br>The source and target destination ranges overlap on the same file.<br> <br>Source file is sparse, while target is a non-sparse file.<br> <br>The source range is beyond the source file's allocation size.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The FileHandle parameter is either invalid or does not represent a handle<br>to an opened file on the same volume.|
|STATUS_INSUFFICIENT_RESOURCES<br>0xC000009A|There were insufficient resources to complete the operation.|
|STATUS_DISK_FULL<br>0xC000007F|The disk is full.|
|STATUS_MEDIA_WRITE_PROTECTED|The volume is read-only.|
|Error Code|Meaning|
|---|---|
|0xC00000A2||
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The file system does not support duplicating extents.|

**2.3.9** **FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX Request**

The FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX<21> request message requests that the server copy
the specified portion of the source file into a specified portion of the target file on the same volume.
The logical sizes of the portions MUST be the same. The two files involved in this operation can refer
to the same file but the logical portions have to refer to disjoint regions on the file. The FSCTL is sent
on a handle opened to the target file. When the DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC
flag isn’t set, the behavior is identical to FSCTL_DUPLICATE_EXTENTS_TO_FILE. When the flag is set,
duplication is atomic from the source's point of view. It means duplication fully succeeds or fails
without side effect (when only part of source file region is duplicated).

When used locally, the request message takes the form of DUPLICATE_EXTENTS_DATA_EX as
specified in section 2.3.9.1. When used remotely with [MS-SMB2], the request message takes the
form of SMB2_DUPLICATE_EXTENTS_DATA_EX as specified in section 2.3.9.2.

**2.3.9.1** **DUPLICATE_EXTENTS_DATA_EX**

A **DUPLICATE_EXTENTS_DATA_EX** data element is defined as follows:

```
  StructureSize (32 bits)
  … (32 bits)
  FileHandle (32 bits)
  SourceFileOffset (32 bits)
  TargetFileOffset (32 bits)
  ByteCount (32 bits)
  Flags (32 bits)
  ...
```
**StructureSize (8 bytes):** A SIZE_T [MS-DTYP] section 2.2.43) data type that specifies the size of

the structure, in bytes.

**FileHandle (8 bytes):** A HANDLE ([MS-DTYP] section 2.2.16) data type that is an identifier of the

open to the source file.

**SourceFileOffset (8 bytes):** A 64-bit signed integer that contains the file offset, in bytes, of the

start of a range of bytes in a source file from which the data is to be copied. The value of this field
MUST be greater than or equal to 0x0000000000000000 and MUST be aligned to a logical cluster
boundary.

**TargetFileOffset (8 bytes):** A 64-bit signed integer that contains the file offset, in bytes, of the start

of a range of bytes in a target file to which the data is to be copied. The value of this field MUST
be greater than or equal to 0x0000000000000000 and MUST be aligned to a logical cluster
boundary.

**ByteCount (8 bytes):** A 64-bit signed integer that contains the number of bytes to copy from source

to target. The value of this field MUST be greater than or equal to 0x0000000000000000 and
MUST be aligned to a logical cluster boundary.

**Flags (4 bytes):** A 32-bit unsigned integer that contains zero or more of the following flag values.

Flag values not specified in the following table SHOULD be set to 0 and MUST be ignored.

|Value|Meaning|
|---|---|
|DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC<br>0x00000001|Indicates that duplication is atomic from source<br>point of view.|

**2.3.9.2** **SMB2_DUPLICATE_EXTENTS_DATA_EX**

A **SMB2_DUPLICATE_EXTENTS_DATA_EX** data element is defined as follows:

```
  StructureSize (32 bits)
  … (32 bits)
  SourceFileID (32 bits)
  SourceFileOffset (32 bits)
  ...
```
**StructureSize (8 bytes):** A 64-bit unsigned integer value that specifies the size of the structure, in

bytes. This field MUST be set to 0x30.

**SourceFileID (16 bytes):** An SMB2_FILEID structure, as specified in [MS-SMB2] section 2.2.14.1,

that is an identifier of the open to the source file.

**SourceFileOffset (8 bytes):** A 64-bit signed integer that contains the file offset, in bytes, of the

start of a range of bytes in a source file from which the data is to be copied. The value of this field
MUST be greater than or equal to 0x0000000000000000 and MUST be aligned to a logical cluster
boundary.

**TargetFileOffset (8 bytes):** A 64-bit signed integer that contains the file offset, in bytes, of the start

of a range of bytes in a target file to which the data is to be copied. The value of this field MUST
be greater than or equal to 0x0000000000000000 and MUST be aligned to a logical cluster
boundary.

**ByteCount (8 bytes):** A 64-bit signed integer that contains the number of bytes to copy from source

to target. The value of this field MUST be greater than or equal to 0x0000000000000000 and
MUST be aligned to a logical cluster boundary.

**Flags (4 bytes):** A 32-bit unsigned integer that contains zero or more of the following flag values.

Flag values not specified in the following table SHOULD be set to 0 and MUST be ignored.

|Value|Meaning|
|---|---|
|DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC<br>0x00000001|Indicates that duplication is atomic from source<br>point of view.|

**Reserved (4 bytes):** This field SHOULD be set to zero and MUST be ignored.

**2.3.10** **FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX Reply**

This message returns the result of the FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX request<22>.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this FSCTL SHOULD be STATUS_SUCCESS.
The most common error codes are listed in the following table.

|Error Code|Meaning|
|---|---|
|STATUS_NOT_SUPPORTED<br>0xC00000BB| <br>The source and target destination ranges overlap<br>on the same file.|
|Error Code|Meaning|
|---|---|
|| <br>Source file is sparse, while target is a non-sparse<br>file.<br> <br>The source range is beyond the source file's<br>allocation size.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The FileHandle parameter is either invalid or does not<br>represent a handle to an opened file on the same<br>volume.|
|STATUS_INSUFFICIENT_RESOURCES<br>0xC000009A|There were insufficient resources to complete the<br>operation.|
|STATUS_DISK_FULL<br>0xC000007F|The disk is full.|
|STATUS_MEDIA_WRITE_PROTECTED<br>0xC00000A2|The volume is read-only.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The file system does not support duplicating extents.|
