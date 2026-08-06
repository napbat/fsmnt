<!-- MS-FSCC: Offload Read/Write -->
<!-- OFFLOAD_READ, OFFLOAD_WRITE with STORAGE_OFFLOAD_TOKEN. -->

**2.3.41** **FSCTL_OFFLOAD_READ Request**

The FSCTL_OFFLOAD_READ Request message requests that the server perform an **Offload Read**
operation to a specified portion of a file on a target volume. On the client side, this request is
received, processed, and sent down to an intelligent storage subsystem that generates and returns a
**Token** in an FSCTL_OFFLOAD_READ Reply (section 2.3.42) message. This Token logically represents
the data to be read and can be used with an FSCTL_OFFLOAD_WRITE Request (section 2.3.43) and an
FSCTL_OFFLOAD_WRITE Reply (section 2.3.44) pair to complete the data movement.<36>

The request message contains an **FSCTL_OFFLOAD_READ_INPUT** data element, as follows.

```
  Size (32 bits)
  Flags (32 bits)
  TokenTimeToLive (32 bits)
  Reserved (32 bits)
  FileOffset (32 bits)
  CopyLength (32 bits)
  ...
```
...

**Size (4 bytes):** A 32-bit unsigned integer that indicates the size, in bytes, of this data element.

**Flags (4 bytes):** A 32-bit unsigned integer that indicates the flags to be set for this operation.

Currently, no flags are defined. This field SHOULD be set to 0x00000000 and MUST be ignored.

**TokenTimeToLive (4 bytes):** A 32-bit unsigned integer that contains the requested Time to Live

(TTL) value in milliseconds for the generated Token. This value MUST be greater than or equal to
0x00000000. A value of 0x00000000 represents a default TTL interval.<37>

**Reserved (4 bytes):** A 32-bit unsigned integer field that is reserved. This field SHOULD be set to

0x00000000 and MUST be ignored.

**FileOffset (8 bytes):** A 64-bit unsigned integer that contains the file offset, in bytes, of the start of a

range of bytes in a file from which to generate the Token. The value of this field MUST be greater
than or equal to 0x0000000000000000 and MUST be aligned to a logical sector boundary on the
volume.

**CopyLength (8 bytes):** A 64-bit unsigned integer that contains the size, in bytes, of the requested

range of the file from which to generate the Token. The value of this field MUST be greater than or
equal to 0x0000000000000000 and MUST be aligned to a logical sector boundary on the
volume.<38>

**2.3.42** **FSCTL_OFFLOAD_READ Reply**

The FSCTL_OFFLOAD_READ Reply message returns the results of the FSCTL_OFFLOAD_READ
Request (section 2.3.41).

The **FSCTL_OFFLOAD_READ_OUTPUT** data element is as follows.

```
  Size (32 bits)
  Flags (32 bits)
  TransferLength (32 bits)
  Token (512 bytes) (32 bits)
  ...
```

**Size (4 bytes):** A 32-bit unsigned integer that indicates the size, in bytes, of the returned data

element.

**Flags (4 bytes):** A 32-bit unsigned integer that indicates which flags were returned for this

operation. Possible values for the flags follow. All unused bits are reserved for future use, SHOULD
be set to 0, and MUST be ignored.
|Value|Meaning|
|---|---|
|OFFLOAD_READ_FLAG_ALL_ZERO_BEYOND_CURRENT_RANGE<br>0x00000001|The data beyond the current range is<br>logically equivalent to zero.|

**TransferLength (8 bytes):** A 64-bit unsigned integer that contains the amount, in bytes, of data

that the **Token** logically represents. This value indicates a contiguous region of the file from the
beginning of the requested offset in the **FileOffset** field in the FSCTL_OFFLOAD_READ_INPUT
data element (section 2.3.41). This value can be smaller than the **CopyLength** field specified in
the FSCTL_OFFLOAD_READ_INPUT data element, which indicates that less data was logically
represented (logically read) with the Token than was requested. The value of this field MUST be
greater than 0x0000000000000000 and MUST be aligned to a logical sector boundary on the
**volume** .

**Token (512 bytes):** A STORAGE_OFFLOAD_TOKEN (section 2.1.11) structure that contains the

generated Token to be used as a representation of the data contained within the portion of the file
specified in the FSCTL_OFFLOAD_READ_INPUT data element at the time of the
FSCTL_OFFLOAD_READ operation. The contents of this field MUST NOT be modified during
subsequent operations.<39>

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The file system does not support offload operations.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|At least one of the following assertions is true:<br> <br>The target file is smaller than the logical sector size.<br> <br>The**FileOffset** field is not a multiple of the logical sector<br>size of the volume.<br> <br>The**CopyLength** field is not a multiple of the logical<br>sector size of the volume.<br> <br>The**Size** field is not equivalent to the size of an<br>FSCTL_OFFLOAD_READ_INPUT data element.<br> <br>Adding the**FileOffset** and**CopyLength** fields results in<br>the overflow of a 64-bit value.<br>|
|STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED<br>0xC000A2A3|Offload operations cannot be performed on:<br> <br>Compressed Files<br> <br>Sparse Files<br> <br>Encrypted Files<br> <br>File System Metadata Files<br>|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The file system indicates that the volume does not support<br>the**Offload Read** operation.|
|Error code|Meaning|
|---|---|
|STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED<br>0xC000A2A1|A file system filter on the server has not opted in for Offload<br>Read support.|
|STATUS_FILE_DELETED<br>0xC0000123|The specified data**stream** is not valid.|
|STATUS_FILE_CLOSED<br>0xC0000128|The specified file handle is closed.|
|STATUS_END_OF_FILE<br>0xC0000011|The file read starts beyond the End Of the File (EOF).<40>|
|STATUS_INSUFFICIENT_RESOURCES<br>0xC000009A|There were insufficient resources to complete the operation.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The input buffer is too small to contain an<br>FSCTL_OFFLOAD_READ_INPUT data element.<br>or<br>The output buffer is too small to contain an<br>FSCTL_OFFLOAD_READ_OUTPUT data element.|
|STATUS_DEVICE_FEATURE_NOT_SUPPORTED<br>0xC0000463|The storage device does not support offload read.|

**2.3.43** **FSCTL_OFFLOAD_WRITE Request**

The FSCTL_OFFLOAD_WRITE Request message requests that the server perform an **Offload Write**
operation to a specified portion of a file on a target **volume**, providing a **Token** to the server that
indicates what data is to be logically written. On the server side, this request is received, processed,
and sent to an intelligent storage subsystem that processes the Token and determines whether it can
perform the data movement to the requested portion of the file. The Token is generated by an
intelligent storage subsystem through an FSCTL_OFFLOAD_READ Request (section 2.3.41) or is
constructed as a well-known Token type such as STORAGE_OFFLOAD_TOKEN in section
2.1.11.<41><42>

The request message contains an **FSCTL_OFFLOAD_WRITE_INPUT** data element, as follows:

```
  Size (32 bits)
  Flags (32 bits)
  FileOffset (32 bits)
  CopyLength (32 bits)
  ...
```
**Size (4 bytes):** A 32-bit unsigned integer that indicates the size, in bytes, of this data element.

**Flags (4 bytes):** A 32-bit unsigned integer that indicates the flags to be set for this operation.

Currently, no flags are defined. This field SHOULD be set to 0x00000000 and MUST be ignored.

**FileOffset (8 bytes):** A 64-bit unsigned integer that contains the file offset, in bytes, of the start of a

range of bytes in a file at which to begin writing the data logically represented by the Token. The
value of this field MUST be greater than or equal to 0x0000000000000000 and MUST be aligned to
a logical sector boundary on the volume.

**CopyLength (8 bytes):** A 64-bit unsigned integer that contains the size, in bytes, of the requested

range of the file to write the data logically represented by the Token. The value of this field MUST
be greater than or equal to 0x0000000000000000 and MUST be aligned to a logical sector
boundary on the volume. This value can be smaller than the size of the data logically represented
by the Token.

**TransferOffset (8 bytes):** A 64-bit unsigned integer that contains the file offset, in bytes, relative to

the front of a region of data logically represented by the Token at which to start writing. The value
of this field MUST be greater than or equal to 0x0000000000000000 and MUST be aligned to a
logical sector boundary on the volume.

**Token (512 bytes):** A STORAGE_OFFLOAD_TOKEN (section 2.1.11) structure that contains the

generated (or constructed) Token to be used as a representation of the data to be logically
written. The contents of this field MUST NOT be modified during subsequent operations.

**2.3.44** **FSCTL_OFFLOAD_WRITE Reply**

The FSCTL_OFFLOAD_WRITE Reply message returns the results of the FSCTL_OFFLOAD_WRITE
Request (section 2.3.43).

The **FSCTL_OFFLOAD_WRITE_OUTPUT** data element is as follows.

```
  Size (32 bits)
  Flags (32 bits)
  LengthWritten (32 bits)
  ...
```

**Size (4 bytes):** A 32-bit unsigned integer that indicates the size, in bytes, of the returned data

element.
**Flags (4 bytes):** A 32-bit unsigned integer that indicates which flags were returned for this

operation. Currently, no flags are defined. This field SHOULD be set to 0x00000000 and MUST be
ignored.

**LengthWritten (8 bytes):** A 64-bit unsigned integer that contains the amount, in bytes, of data that

was written. The value of this field MUST be greater than or equal to zero and MUST be aligned to
a logical sector boundary on the volume. This value can be smaller than the **CopyLength** field
specified in the FSCTL_OFFLOAD_WRITE_INPUT data element. A smaller value indicates that less
data was logically written with the specified Token than was requested. This field MUST NOT be
greater than the **CopyLength** field specified in the FSCTL_OFFLOAD_WRITE_INPUT data element,
meaning it is incorrect to copy more than what was requested<43>.

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The file system does not support offload operations.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|At least one of the following assertions is true:<br> <br>The target file is smaller than the logical sector size.<br> <br>The**FileOffset** field is not a multiple of the logical<br>sector size of the**volume**. <br> <br>The**CopyLength** field is not a multiple of the logical<br>sector size of the volume.<br> <br>The**TransferOffset** field is not a multiple of the logical<br>sector size of the volume.<br> <br>The**FileOffset** field is greater than the Valid Data<br>Length (VDL) for the file.<br> <br>The**Size** field is not equivalent to the size of an<br>FSCTL_OFFLOAD_WRITE_INPUT data element.<br> <br>Adding the**FileOffset** and**CopyLength** fields results<br>in the overflow of a 64-bit value.<br>|
|STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED<br>0xC000A2A4|Offload operations cannot be performed on:<br> <br>Compressed Files<br> <br>Sparse Files<br> <br>Encrypted Files<br> <br>File System Metadata Files<br>|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The file system indicates that the volume does not support<br>the**Offload Write** operation.|
|STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED<br>0xC000A2A2|A file system filter on the server has not opted in for Offload<br>Write support.|
|Error code|Meaning|
|---|---|
|STATUS_FILE_DELETED<br>0xC0000123|The specified data**stream** was not valid.|
|STATUS_FILE_CLOSED<br>0xC0000128|The specified file handle is closed.|
|STATUS_END_OF_FILE<br>0xC0000011|The file offset for the write is beyond the End Of the File<br>(EOF).|
|STATUS_MEDIA_WRITE_PROTECTED<br>0xC00000A2|The volume is read only.|
|STATUS_INSUFFICIENT_RESOURCES<br>0xC000009A|There were insufficient resources to complete the operation.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The input buffer is too small to contain an<br>FSCTL_OFFLOAD_WRITE_INPUT data element.<br>or<br>The output buffer is too small to contain an<br>FSCTL_OFFLOAD_WRITE_OUTPUT data element.|
|STATUS_DEVICE_FEATURE_NOT_SUPPORTED<br>0xC0000463|The storage device does not support Offload Write.|
|STATUS_DEVICE_UNREACHABLE<br>0xC0000464|Data cannot be moved by Offload Write because the source<br>device cannot communicate with the destination device.|
|STATUS_INVALID_TOKEN<br>0xC0000465L|The token representing the data is invalid or expired.|
