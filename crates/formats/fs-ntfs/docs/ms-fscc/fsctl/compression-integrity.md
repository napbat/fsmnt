<!-- MS-FSCC: Compression and Integrity -->
<!-- GET/SET_COMPRESSION (NONE, DEFAULT, LZNT1). GET/SET_INTEGRITY_INFORMATION, SET_INTEGRITY_INFORMATION_EX. -->

**2.3.17** **FSCTL_GET_COMPRESSION Request**

This message requests that the server return the current compression state of the file or directory
associated with the handle on which this **FSCTL** was invoked.

This message does not contain any additional data elements.

**2.3.18** **FSCTL_GET_COMPRESSION Reply**

The FSCTL_GET_COMPRESSION reply message returns the results of the FSCTL_GET_COMPRESSION
request as a 16-bit unsigned integer value that indicates the current compression state of the file or
directory.

The **CompressionState** element is as follows.

```
```
|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|||||||||||||||||

**CompressionState (2 bytes):** One of the following standard values MUST be returned.

|Value|Meaning|
|---|---|
|COMPRESSION_FORMAT_NONE<br>0x0000|The file or directory is not compressed.|
|COMPRESSION_FORMAT_LZNT1<br>0x0002|The file or directory is compressed by using the LZNT1 compression algorithm.<br>For more information, see[UASDC].|
|All other values|Reserved for future use and MUST NOT be used.|

The actual file or directory compression format is implementation-dependent.<26>

If the file system of the **volume** that contains the specified file or directory does not support per-file
or per-directory compression, the request MUST NOT succeed. The error code that is returned in this
situation MUST be as specified in section 2.2.

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error
codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The output buffer length is less than 2, or the handle is not to a file or<br>directory.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The volume does not support compression.<27>|

**2.3.67** **FSCTL_SET_COMPRESSION Request**

The FSCTL_SET_COMPRESSION request message requests that the server set the compression state
of the file or directory associated with the handle on which this **FSCTL** was invoked. The message
contains a 16-bit unsigned integer.

The CompressionState element is as follows.

```
```
|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|CompressionState|||||||||||||||||

**CompressionState (2 bytes):** MUST be one of the following standard values.

|Value|Meaning|
|---|---|
|COMPRESSION_FORMAT_NONE<br>0x0000|The file or directory is not compressed.|
|COMPRESSION_FORMAT_DEFAULT<br>0x0001|The file or directory is compressed by using the default compression<br>algorithm.<62>|
|COMPRESSION_FORMAT_LZNT1|The file or directory is compressed by using the LZNT1 compression|
|Value|Meaning|
|---|---|
|0x0002|algorithm. For more information, see[UASDC].|
|All other values|Reserved for future use and MUST NOT be used.|

The actual file or directory compression performed when a server receives a request for
COMPRESSION_FORMAT_DEFAULT and COMPRESSION_FORMAT_LZNT1 is implementationdependent.<63>

If the file system of the **volume** containing the specified file or directory does not support per-file
or per-directory compression, the request MUST NOT succeed. The error code returned in this
situation is specified in section 2.2.

**2.3.68** **FSCTL_SET_COMPRESSION Reply**

This message returns the results of the FSCTL_SET_COMPRESSION request.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The input buffer length is less than 2, or the handle is not to a file or<br>directory, or the requested CompressionState is not one of the values<br>listed in the table for**CompressionState** in FSCTL_SET_COMPRESSION<br>Request (section 2.3.67).|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The**volume** does not allow compression.|
|STATUS_DISK_FULL<br>0xC00007F|The disk is full.|

**2.3.19** **FSCTL_GET_INTEGRITY_INFORMATION Request**

The FSCTL_GET_INTEGRITY_INFORMATION Request message requests that the server return the
current integrity state of the file or directory associated with the handle on which this **FSCTL** is
invoked.<28>
If the file system of the **volume** containing the specified file or directory does not support the use of
integrity, the request will not succeed. The error code returned in this situation varies, depending on
the file system.

This message does not contain additional data elements.

**2.3.20** **FSCTL_GET_INTEGRITY_INFORMATION Reply**

The FSCTL_GET_INTEGRITY_INFORMATION Reply message returns the results of the
FSCTL_GET_INTEGRITY_INFORMATION Request (section 2.3.19) and indicates the current integrity
state of the file or directory.

The **FSCTL_GET_INTEGRITY_INFORMATION_BUFFER** data element is as follows.

```
  ChecksumAlgorithm (16 bits) | Reserved (16 bits)
  Flags (32 bits)
  ChecksumChunkSizeInBytes (32 bits)
  ClusterSizeInBytes (32 bits)
```

**ChecksumAlgorithm (2 bytes):** For **ReFS v1**, the field MUST be set to one of the following standard

values.

|Value|Meaning|
|---|---|
|CHECKSUM_TYPE_NONE<br>0x0000|The file or directory is not configured to use integrity.|
|CHECKSUM_TYPE_CRC64<br>0x0002|The file or directory is configured to use a CRC64 checksum to provide integrity.|
|All other values|Reserved for future use and MUST NOT be used.|

For **ReFS v2**, the field MUST be set to one of the following standard values.

|Value|Meaning|
|---|---|
|CHECKSUM_TYPE_NONE<br>0x0000|The file or directory is not configured to use integrity.|
|CHECKSUM_TYPE_CRC32<br>0x0001|The file or directory is configured to use a CRC32 checksum to provide integrity.|
|CHECKSUM_TYPE_CRC64<br>0x0002|The file or directory is configured to use a CRC64 checksum to provide integrity.|
|All other values|Reserved for future use and MUST NOT be used.|

**Reserved (2 bytes):** A 16-bit reserved value. This field MUST be set to 0x0000 and MUST be

ignored.
**Flags (4 bytes):** A 32-bit unsigned integer that contains zero or more of the following flag values.

Flag values not specified in the following table SHOULD be set to 0 and MUST be ignored.

|Value|Meaning|
|---|---|
|FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF<br>0x00000001|Indicates that checksum enforcement is not<br>currently enabled on the target file.|
|All other values|Reserved for future use and MUST NOT be<br>used.|

**ChecksumChunkSizeInBytes (4 bytes):** A 32-bit unsigned integer specifying the size in bytes of

each chunk in a **stream** that is configured with integrity.

**ClusterSizeInBytes (4 bytes):** A 32-bit unsigned integer specifying the size of a **cluster** for this

volume in bytes.

This message also returns a status code, as specified in section 2.2. Upon success, the status code
returned by the function that processes this **FSCTL** MUST be STATUS_SUCCESS or one of the
following.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The output buffer length is less than the size of the<br>FSCTL_GET_INTEGRITY_INFORMATION_BUFFER data element, or the<br>handle is not to a file or directory.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The volume does not support integrity.|

**2.3.73** **FSCTL_SET_INTEGRITY_INFORMATION Request**

The FSCTL_SET_INTEGRITY_INFORMATION Request message requests that the server set the
integrity state of the file or directory associated with the handle on which this FSCTL was
invoked.<75>

If the file system of the volume containing the specified file or directory does not support integrity, the
request MUST NOT succeed. The error code returned in this situation is specified in section 2.2.

The FSCTL_SET_INTEGRITY_INFORMATION_BUFFER element is as follows.

```
  ChecksumAlgorithm (16 bits) | Reserved (16 bits)
  Flags (32 bits)
```

**ChecksumAlgorithm (2 bytes):** For **ReFS v1**, the field MUST be set to one of the following standard

values.

|Value|Meaning|
|---|---|
|CHECKSUM_TYPE_NONE<br>0x0000|The file or directory is set to not use integrity.|
|CHECKSUM_TYPE_CRC64<br>0x0002|The file or directory is set to provide integrity using a CRC64 checksum.|
|CHECKSUM_TYPE_UNCHANGED<br>0xFFFF|The integrity status of the file or directory is unchanged.|
|All other values<br>0x0003 — 0xFFFE|Reserved for future use and MUST NOT be used.|

For **ReFS v2**, the field MUST be set to one of the following standard values.

|Value|Meaning|
|---|---|
|CHECKSUM_TYPE_NONE<br>0x0000|The file or directory is set to not use integrity.|
|CHECKSUM_TYPE_CRC32|The file or directory is set to provide integrity using a CRC32 or CRC64|
|Value|Meaning|
|---|---|
|0x0001|checksum. If the ReFS cluster size is 4KB, the checksum used is CRC32;<br>otherwise, if the cluster size is 64K, the CRC64 checksum is used.|
|CHECKSUM_TYPE_CRC64<br>0x0002|The file or directory is set to provide integrity using a CRC32 or CRC64<br>checksum. If the ReFS cluster size is 4KB, the checksum used is CRC32;<br>otherwise, if the cluster size is 64K, the CRC64 checksum is used.|
|CHECKSUM_TYPE_UNCHANGED<br>0xFFFF|The integrity status of the file or directory is unchanged.|
|All other values<br>0x0003 — 0xFFFE|Reserved for future use and MUST NOT be used.|

Note that for **ReFS v2** any value except CHECKSUM_TYPE_NONE or
CHECKSUM_TYPE_UNCHANGED will set the integrity value to a file-system-selected integrity
mechanism and is not guaranteed to use the user specified checksum value.

**Reserved (2 bytes):** A 16-bit reserved value. This field MUST be set to zero and MUST be ignored.

**Flags (4 bytes):** A 32-bit unsigned integer that contains zero or more of the following flag values.

Flag values that are unspecified in the following table SHOULD be set to 0 and MUST be ignored.

|Value|Meaning|
|---|---|
|FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF<br>0x00000001|When set, if a checksum does not match, the<br>associated I/O operation will not be failed.|

**2.3.74** **FSCTL_SET_INTEGRITY_INFORMATION Reply**

This message returns the results of the FSCTL_SET_INTEGRITY_INFORMATION
Request (section 2.3.73).

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The input buffer length is less than the size, in bytes, of the<br>FSCTL_SET_INTEGRITY_INFORMATION_BUFFER element; the handle is<br>not to a file or directory; or the requested**ChecksumAlgorithm** field is<br>not one of the values listed in the table for the**ChecksumAlgorithm** <br>field in the FSCTL_SET_INTEGRITY_INFORMATION Request.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The volume does not support integrity.|
|STATUS_DISK_FULL<br>0xC000007F|The disk is full.|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The file has been ghosted (allocation blocks are being shared).|
**2.3.75** **FSCTL_SET_INTEGRITY_INFORMATION_EX Request**

The FSCTL_SET_INTEGRITY_INFORMATION_EX Request message requests that the server set the
integrity state of the file or directory associated with the handle on which this FSCTL was
invoked.<76>

If the file system of the volume containing the specified file or directory does not support integrity, the
request MUST NOT succeed. The error code returned in this situation is specified in section 2.2.

The **FSCTL_SET_INTEGRITY_INFORMATION_BUFFER_EX** element is as follows.

```
  EnableIntegrity (8 bits) | A (8 bits) | Reserved1 (16 bits)
  Flags (32 bits)
  Version (8 bits) | Reserved2 (24 bits)
  … (32 bits)
```

**EnableIntegrity (1 byte):** This field MUST be one of the following values:

|Value|Meaning|
|---|---|
|0x00|The file or directory is set to not use integrity.|
|0x01|The file or directory is set to provide integrity using<br>CRC32 or CRC64 checksum.|

**A - KeepIntegrityStateUnchanged (1 byte):** This field MUST be one of the following values:

|Value|Meaning|
|---|---|
|0x00|The file or directory integrity state should change<br>based on the EnableIntegrity parameter.|
|0x01|The file or directory integrity state must not change.|

**Reserved1 (2 bytes):** A 16-bit reserved value. This field MUST be set to zero and MUST be ignored.

**Flags (4 bytes):** A 32-bit unsigned integer that contains zero or more of the following flag values.

Flag values that are unspecified in the following table SHOULD be set to 0 and MUST be ignored.

|Value|Meaning|
|---|---|
|FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF<br>0x00000001|When set, if a checksum does not match, the<br>associated I/O operation will not be failed.|

**Version (1 byte):** An 8-bit value. This field MUST be set to 1.

**Reserved2 (7 bytes):** A 56-bit reserved value. This field MUST be set to zero and MUST be ignored.
**2.3.76** **FSCTL_SET_INTEGRITY_INFORMATION_EX Reply**

This message returns the results of the FSCTL_SET_INTEGRITY_INFORMATION_EX Request (section
2.3.75).

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The input buffer length is less than the size, in bytes, of<br>the FSCTL_SET_INTEGRITY_INFORMATION_BUFFER_EX<br>element; the handle is not to a file or directory; or<br>Version is not equal to 1.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The volume does not support integrity.|
|STATUS_DISK_FULL<br>0xC000007F|The disk is full.|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The file has been ghosted (allocation blocks are being<br>shared).|
