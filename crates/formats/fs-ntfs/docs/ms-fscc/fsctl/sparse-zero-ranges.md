<!-- MS-FSCC: Sparse Files, Zero Data, Allocated Ranges -->
<!-- SET_SPARSE, SET_ZERO_DATA, SET_ZERO_ON_DEALLOCATION, QUERY_ALLOCATED_RANGES. -->

**2.3.51** **FSCTL_QUERY_ALLOCATED_RANGES Request**

The FSCTL_QUERY_ALLOCATED_RANGES request message requests that the server scan a file or
alternate **stream** looking for byte ranges that can contain nonzero data, and then return information
on those ranges. Only **sparse files** can have zeroed ranges known to the operating system. For other
files, the server will return only a single range that contains the starting point and the length
requested. The request message contains a FILE_ALLOCATED_RANGE_BUFFER data element.

The FILE_ALLOCATED_RANGE_BUFFER data element is as follows.

```
  FileOffset (32 bits)
  Length (32 bits)
  ...
```

**FileOffset (8 bytes):** A 64-bit signed integer that contains the file offset, in bytes, of the start of a

range of bytes in a file. The value of this field MUST be greater than or equal to 0.

**Length (8 bytes):** A 64-bit signed integer that contains the size, in bytes, of the range. In a request

message, the value of this field MUST be greater than or equal to 0. In a reply message, it MUST
be greater than 0.

**2.3.52** **FSCTL_QUERY_ALLOCATED_RANGES Reply**

The FSCTL_QUERY_ALLOCATED_RANGES Reply message returns the results of the
FSCTL_QUERY_ALLOCATED_RANGES Request (section 2.3.51).

This message MUST return an array of zero or more FILE_ALLOCATED_RANGE_BUFFER data elements.
The number of FILE_ALLOCATED_RANGE_BUFFER elements returned is computed by dividing the size
of the returned output buffer (from either SMB or SMB2, the lower-layer protocol that carries the
**FSCTL** ) by the size of the FILE_ALLOCATED_RANGE_BUFFER element. Ranges returned MUST
intersect the range specified in the FSCTL_QUERY_ALLOCATED_RANGES Request. Zero
FILE_ALLOCATED_RANGE_BUFFER data elements MUST be returned when the file has no allocated
ranges.<44>

The FILE_ALLOCATED_RANGE_BUFFER data element is as follows.

```
  FileOffset (32 bits)
  Length (32 bits)
  ...
```
**FileOffset (8 bytes):** A 64-bit signed integer that contains the file offset in bytes from the start of

the file; the start of a range of bytes to which storage is allocated. If the file is a **sparse file**, it
can contain ranges of bytes for which storage is not allocated; these ranges will be excluded from
the list of allocated ranges returned by this FSCTL.<45> Because an application using a sparse file
can choose whether or not to allocate disk space for each sequence of 0x00-valued bytes, the
allocated ranges can contain 0x00-valued bytes. This value MUST be greater than or equal to
0.<46>

**Length (8 bytes):** A 64-bit signed integer that contains the size, in bytes, of the range. In a request

message, the value of this field MUST be greater than or equal to 0. In a reply message, it MUST
be greater than 0.

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this FSCTL is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle is not to a file, or the size of the input buffer is less than the size<br>of a FILE_ALLOCATED_RANGE_BUFFER structure, or the given**FileOffset** <br>field value is less than zero, or the given**Length** field value is less than zero,<br>or the given**FileOffset** field value plus the given**Length** field value is larger<br>than 0x7FFFFFFFFFFFFFFF.|
|STATUS_INVALID_USER_BUFFER<br>0xC00000E8|The input buffer or output buffer is not aligned to a 4-byte boundary.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is too small to contain a FILE_ALLOCATED_RANGE_BUFFER<br>structure.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer is too small to contain the required number of<br>FILE_ALLOCATED_RANGE_BUFFER structures.|

**2.3.83** **FSCTL_SET_SPARSE Request**

This message requests that the server mark the file that is associated with the handle on which this
**FSCTL** was invoked as sparse. In a **sparse file**, large ranges of zeros (0) might not require disk
allocation. Space for nonzero data is allocated as the file is written. The message either has no data
elements at all or it contains a FILE_SET_SPARSE_BUFFER element. If there is no data element, the
sparse flag for the file is set, exactly as if the FILE_SET_SPARSE_BUFFER element was supplied and
had a **SetSparse** value of TRUE.<80>

The **FILE_SET_SPARSE_BUFFER** element is as follows:
```
```
|SetSparse|SetSparse|SetSparse|SetSparse|SetSparse|SetSparse|SetSparse|SetSparse|||||||||||||||||||||||||

**SetSparse (1 byte):** A Boolean (section 2.1.8) value.

A FALSE value will cause the file system to attempt to "unsparse" the file by allocating clusters for
any regions of the file that are currently sparsed. If the entire file is successfully unsparsed, the
sparse flag is cleared for the file. If an error is encountered during unsparsing, any regions of the
file that were unsparsed MAY<81> remain unsparsed.

A TRUE value will cause the sparse flag for the file to set. Currently allocated clusters SHOULD
NOT<82> be deallocated.

**2.3.84** **FSCTL_SET_SPARSE Reply**

This message returns the results of the FSCTL_SET_SPARSE request.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle is not to a file, or the input buffer length is nonzero and is less than<br>the size of a FILE_SET_SPARSE_BUFFER structure.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle is not open with write data or write attribute access.|

**2.3.85** **FSCTL_SET_ZERO_DATA Request**

The FSCTL_SET_ZERO_DATA request message requests that the server fill the specified range of the
file (associated with the handle on which this **FSCTL** was invoked) with zeros. The message contains a
FILE_ZERO_DATA_INFORMATION element.

The FILE_ZERO_DATA_INFORMATION element is as follows.

```
  FileOffset (32 bits)
  BeyondFinalZero (32 bits)
  ...
```

**FileOffset (8 bytes):** A 64-bit signed integer that contains the file offset of the start of the range to

set to zeros, in bytes. The value of this field MUST be greater than or equal to 0.
**BeyondFinalZero (8 bytes):** A 64-bit signed integer that contains the byte offset of the first byte

beyond the last zeroed byte. The value of this field MUST be greater than or equal to 0.

How an implementation zeros data within a file is implementation-dependent. A file system MAY
choose to deallocate regions of disk space that have been zeroed.<83>

**2.3.86** **FSCTL_SET_ZERO_DATA Reply**

This message returns the results of the FSCTL_SET_ZERO_DATA request.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle is not to a file, or input buffer length is not equal to the size of a<br>FILE_ZERO_DATA_INFORMATION structure, or the given**FileOffset** is less than<br>zero, or the given**BeyondFinalZero** is less than zero, or the given**FileOffset** <br>is greater than the given BeyondFinalZero.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle is not open with write data or write attribute access.|

**2.3.87** **FSCTL_SET_ZERO_ON_DEALLOCATION Request**

This message requests that the server fill the clusters of the target file with zeros when they are
deallocated.<84> This is used to set a file to secure delete mode, which ensures that data will be
zeroed upon file truncation or deletion.

There are several side effects associated with this operation.

- If the file is resident, it is converted to non-resident and the resident portion is zeroed.

- When reallocating ranges of a compressed file, the clusters are both zeroed and then replaced
with a cluster representing compressed zeros before being reallocated.

This message does not contain any additional data elements.

**2.3.88** **FSCTL_SET_ZERO_ON_DEALLOCATION Reply**

This message returns the results of the FSCTL_SET_ZERO_ON_DEALLOCATION request. The only data
item this message returns is a status code, as specified in section 2.2. Upon success, the status code
returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error
codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_ACCESS_DENIED<br>0xC0000022|Zero on deallocation can only be set on a user file opened for write access and<br>cannot be set on a directory.<br>|
