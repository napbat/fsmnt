<!-- MS-FSCC: Reparse Point Operations -->
<!-- DELETE, GET, SET reparse point request/reply pairs. -->

**2.3.5** **FSCTL_DELETE_REPARSE_POINT Request**

This message requests that the server delete the **reparse point** from the file or directory associated
with the handle on which this **FSCTL** was invoked. The underlying file or directory MUST NOT be
deleted.

The message MUST contain a REPARSE_GUID_DATA_BUFFER or a REPARSE_DATA_BUFFER data
element (including subtypes). Both the REPARSE_GUID_DATA_BUFFER and the
REPARSE_DATA_BUFFER structures begin with a **ReparseTag** field. The **ReparseTag** value uniquely
identifies the **filter** driver that creates/uses the reparse point, and the application's filter driver
processes the reparse point data as either a REPARSE_GUID_DATA_BUFFER or a
REPARSE_DATA_BUFFER, depending on the structure implemented by the filter driver for that type of
reparse point.

This message MUST only be sent for a file or directory handle.

**2.3.6** **FSCTL_DELETE_REPARSE_POINT Reply**

This message returns the result of the FSCTL_DELETE_REPARSE_POINT request.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|A nonzero value was passed for the output buffer's length, or the<br>handle is not to a file or directory.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened to write file data or file attributes.|
|STATUS_IO_REPARSE_DATA_INVALID<br>0xC0000278|The input buffer's length is neither the size of a<br>REPARSE_DATA_BUFFER nor aREPARSE_GUID_DATA_BUFFER; or<br>the reparse data length is nonzero; or the reparse tag is a third<br>party reparse tag, and the length is other than the size of<br>REPARSE_GUID_DATA_BUFFER.|
|STATUS_IO_REPARSE_TAG_INVALID<br>0xC0000276|The specified reparse tag with a value of 0 or 1 is reserved for use<br>by the system and cannot be deleted.|
|STATUS_NOT_A_REPARSE_POINT<br>0xC0000275|The file or directory does not have a**reparse point**.|
|STATUS_IO_REPARSE_TAG_MISMATCH<br>0xC0000277|The file or directory has a reparse point but not one with the reparse<br>tag that was specified in this call.|
|STATUS_REPARSE_ATTRIBUTE_CONFLICT<br>0xC00002B2|The file or directory has a third party tag, and the Reparse GUID<br>provided does not match the one in the reparse point for this file or<br>directory.|

**2.3.27** **FSCTL_GET_REPARSE_POINT Request**

This message requests that the server return the **reparse point** data for the file or directory
associated with the handle on which this **FSCTL** was invoked.

This message MUST only be sent for a file or directory handle.

This message does not contain any additional data elements.

**2.3.28** **FSCTL_GET_REPARSE_POINT Reply**

This message returns the results of the FSCTL_GET_REPARSE_POINT request. The message contains a
REPARSE_GUID_DATA_BUFFER (including subtypes) or a REPARSE_DATA_BUFFER data element.

Both the REPARSE_GUID_DATA_BUFFER and the REPARSE_DATA_BUFFER structures begin with a
**ReparseTag** field. The ReparseTag value uniquely identifies the **filter** driver that creates/uses the
**reparse point**, and the application's filter driver processes the reparse point data as either a
REPARSE_GUID_DATA_BUFFER or a REPARSE_DATA_BUFFER, depending on the structure
implemented by the filter driver for that type of reparse point. A particular filter driver is implemented
with specific support for the type of reparse point data structure it accepts.
If the file system of the **volume** containing the specified file or directory does not support the use of
reparse points, the request will not succeed. The error code returned in this situation MAY vary,
depending on the file system.<29>

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error
codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is too small to contain a<br>REPARSE_GUID_DATA_BUFFER.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle is not to a file or directory.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer filled before all the reparse point data was returned.|
|STATUS_NOT_A_REPARSE_POINT<br>0xC0000275|The file or directory is not a reparse point.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The file system does not support the use of reparse points.|

**2.3.81** **FSCTL_SET_REPARSE_POINT Request**

This message requests that the server set a **reparse point** on the file or directory associated with the
handle on which this **FSCTL** was invoked.

The message contains a REPARSE_GUID_DATA_BUFFER or a REPARSE_DATA_BUFFER (including
subtypes) data element. Both the REPARSE_GUID_DATA_BUFFER and REPARSE_DATA_BUFFER
structures begin with a **ReparseTag** field. The ReparseTag value uniquely identifies the **filter** driver
that creates/uses the reparse point, and the filter driver processes the reparse point data as either a
REPARSE_GUID_DATA_BUFFER or a REPARSE_DATA_BUFFER, depending on the structure
implemented by the filter driver for that type of reparse point.

This message is applicable only to a file or directory handle, not to a **volume** handle.

**2.3.82** **FSCTL_SET_REPARSE_POINT Reply**

This message returns the results of the FSCTL_SET_REPARSE_POINT request.

If the file system of the **volume** containing the specified file or directory does not support **reparse**
**points**, the request will not succeed. The error code returned in this situation varies, depending on
the file system.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle is not to a file or directory, or the output buffer's length is<br>greater than 0.|
|STATUS_IO_REPARSE_DATA_INVALID<br>0xC0000278|The input buffer length is less than the size of a<br>REPARSE_DATA_BUFFER structure, or the input buffer length is greater<br>than 16,384, or a REPARSE_DATA_BUFFER structure has been specified<br>for a third party reparse tag, or the GUID specified for a third party<br>reparse tag does not match the GUID known by the operating system<br>for this reparse point, or the reparse tag is 0 or 1.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The file system does not support reparse points.|
