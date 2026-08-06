<!-- MS-FSCC: Pipes, Mailslots, Quota -->
<!-- FileMailslotQuery/SetInformation, FilePipeInformation, FilePipeLocalInformation, FilePipeRemoteInformation, FileQuotaInformation (FILE_GET_QUOTA_INFORMATION), FileSfioReserveInformation. -->

**2.4.29** **FileMailslotQueryInformation**

This information class is used locally to query information on a **mailslot** .

A **FILE_MAILSLOT_QUERY_INFORMATION** data element, defined as follows, is returned to the
caller.

```
  MaximumMessageSize (32 bits)
  MailslotQuota (32 bits)
  NextMessageSize (32 bits)
  MessagesAvailable (32 bits)
  ReadTimeout (32 bits)
  ...
```

**MaximumMessageSize (4 bytes):** A 32-bit unsigned integer that contains the maximum size of a

single message that can be written to the mailslot, in bytes. To specify that the message can be of
any size, set this value to zero.

**MailslotQuota (4 bytes):** A 32-bit unsigned integer that contains the quota, in bytes, for the

mailslot. The mailslot quota specifies the in-memory pool quota that is reserved for writes to this
mailslot.

**NextMessageSize (4 bytes):** A 32-bit unsigned integer that contains the next message size, in

bytes.

**MessagesAvailable (4 bytes):** A 32-bit unsigned integer that contains the total number of

messages waiting to be read from the mailslot.

**ReadTimeout (8 bytes):** A 64-bit signed integer that contains the time a read operation can wait

for a message to be written to the mailslot before a time-out occurs in milliseconds. The value of
this field MUST be (-1) or greater than or equal to 0. A value of (-1) requests that the read wait
forever for a message, without timing out. A value of 0 requests that the read not wait and return
immediately whether a pending message is available to be read or not.
This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.30** **FileMailslotSetInformation**

This information class is used locally to set information on a **mailslot** .

A **FILE_MAILSLOT_SET_INFORMATION** data element, defined as follows, is provided by the caller.

```
  ReadTimeout (32 bits)
  ...
```

**ReadTimeout (8 bytes):** A 64-bit signed integer that contains the time that a read operation can

wait for a message to be written to the mailslot before a time-out occurs as follows:

- A positive value specifies the operation time-out as an absolute system time on the server,
represented as a count of 100-nanosecond intervals since January 1, 1601.

- A negative value specifies the number of 100-nanosecond intervals for the operation to time out
relative to the current server time.

- A value of -1 (0xFFFFFFFFFFFFFFFF) requests that the read wait forever for a message without
timing out.

- A value of zero sends a request that the read not wait and return immediately, whether a pending
message is available to be read or not.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.37** **FilePipeInformation**

This information class is used to query or set information on a named pipe that is not specific to one
end of the pipe or another.

A **FILE_PIPE_INFORMATION** data element, defined as follows, is returned by the server or
provided by the client.
```
  ReadMode (32 bits)
  CompletionMode (32 bits)
```

**ReadMode (4 bytes):** A 32-bit unsigned integer that MUST contain one of the following values.

|Value|Meaning|
|---|---|
|FILE_PIPE_BYTE_STREAM_MODE<br>0x00000000|If this value is specified, data MUST be read from the pipe as a stream of<br>bytes.|
|FILE_PIPE_MESSAGE_MODE<br>0x00000001|If this value is specified, data MUST be read from the pipe as a stream of<br>messages.|

If this field is set to FILE_PIPE_BYTE_STREAM_MODE, any attempt to subsequently change it MUST
fail with a STATUS_INVALID_PARAMETER error code.

**CompletionMode (4 bytes):** A 32-bit unsigned integer that MUST contain one of the following

values.

|Value|Meaning|
|---|---|
|FILE_PIPE_QUEUE_OPERATION<br>0x00000000|If this value is specified, blocking mode MUST be enabled. When the<br>pipe is being connected, read to, or written from, the operation is not<br>completed until there is data to read, all data is written, or a client is<br>connected. Use of this mode can result in the server waiting indefinitely<br>for a client process to perform an action.|
|FILE_PIPE_COMPLETE_OPERATION<br>0x00000001|If this value is specified, non-blocking mode MUST be enabled. When<br>the pipe is being connected, read to, or written from, the operation<br>completes immediately.|

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|An invalid parameter was passed to a service or function. When setting the<br>FilePipeInformation information level, STATUS_INVALID_PARAMETER will<br>be returned:<br> <br>If the**ReadMode** field is set to FILE_PIPE_BYTE_STREAM_MODE and a<br>subsequent set operation attempts to set the**ReadMode** field to any<br>value other than FILE_PIPE_BYTE_STREAM_MODE.<br> <br>If the value of the**ReadMode** field is not equal to<br>FILE_PIPE_MESSAGE_MODE or FILE_PIPE_BYTE_STREAM_MODE.<br> <br>If the value of the**CompletionMode** field is not equal to<br>FILE_PIPE_QUEUE_OPERATION or FILE_PIPE_COMPLETE_OPERATION.<br>|
[For more information on named pipes, please see [PIPE].](https://go.microsoft.com/fwlink/?LinkId=90247)

**2.4.38** **FilePipeLocalInformation**

This information class is used to query information on a named pipe that is associated with the end of
the pipe that is being queried.

A **FILE_PIPE_LOCAL_INFORMATION** data element, defined as follows, is returned by the server.

```
  NamedPipeType (32 bits)
  NamedPipeConfiguration (32 bits)
  MaximumInstances (32 bits)
  CurrentInstances (32 bits)
  InboundQuota (32 bits)
  ReadDataAvailable (32 bits)
  OutboundQuota (32 bits)
  WriteQuotaAvailable (32 bits)
  NamedPipeState (32 bits)
  NamedPipeEnd (32 bits)
```

**NamedPipeType (4 bytes):** A 32-bit unsigned integer that contains the named pipe type. MUST be

one of the following.

|Value|Meaning|
|---|---|
|FILE_PIPE_BYTE_STREAM_TYPE<br>0x00000000|If this value is specified, data MUST be read from the pipe as a**stream** of<br>bytes.|
|FILE_PIPE_MESSAGE_TYPE<br>0x00000001|If this flag is specified, data MUST be read from the pipe as a stream of<br>messages.|

**NamedPipeConfiguration (4 bytes):** A 32-bit unsigned integer that contains the named pipe

configuration. MUST be one of the following.

|Value|Meaning|
|---|---|
|FILE_PIPE_INBOUND<br>0x00000000|If this value is specified, the flow of data in the pipe goes from client to server<br>only.|
|FILE_PIPE_OUTBOUND<br>0x00000001|If this value is specified, the flow of data in the pipe goes from server to client<br>only.|
|Value|Meaning|
|---|---|
|FILE_PIPE_FULL_DUPLEX<br>0x00000002|If this value is specified, the pipe is bi-directional; both server and client<br>processes can read from and write to the pipe.|

**MaximumInstances (4 bytes):** A 32-bit unsigned integer that contains the maximum number of

instances that can be created for this pipe.

**CurrentInstances (4 bytes):** A 32-bit unsigned integer that contains the number of current named

pipe instances.

**InboundQuota (4 bytes):** A 32-bit unsigned integer that contains the inbound quota, in bytes, for

the named pipe. The inbound quota is the size of the buffer reserved for inbound transfer of data
on the pipe.

**ReadDataAvailable (4 bytes):** A 32-bit unsigned integer that contains the bytes of data available

to be read from the named pipe.

**OutboundQuota (4 bytes):** A 32-bit unsigned integer that contains the outbound quota, in bytes,

for the named pipe. The outbound quota is the size of the buffer reserved for outbound transfer of
data on the pipe.

**WriteQuotaAvailable (4 bytes):** A 32-bit unsigned integer that contains the write quota, in bytes,

for the named pipe. If the **NamedPipeEnd** field is set to FILE_PIPE_CLIENT_END, the
**WriteQuotaAvailable** field is the remaining **InboundQuota** field available. If the
**NamedPipeEnd** field is set to FILE_PIPE_SERVER_END, the **WriteQuotaAvailable** field is the
remaining **OutboundQuota** field available.

**NamedPipeState (4 bytes):** A 32-bit unsigned integer that contains the named pipe state that

specifies the connection status for the named pipe. MUST be one of the following.

|Value|Meaning|
|---|---|
|FILE_PIPE_DISCONNECTED_STATE<br>0x00000001|Named pipe is disconnected.|
|FILE_PIPE_LISTENING_STATE<br>0x00000002|Named pipe is waiting to establish a connection.|
|FILE_PIPE_CONNECTED_STATE<br>0x00000003|Named pipe is connected.|
|FILE_PIPE_CLOSING_STATE<br>0x00000004|Named pipe is in the process of being closed.|

**NamedPipeEnd (4 bytes):** A 32-bit unsigned integer that contains the type of the named pipe end,

which specifies whether this is the client or the server side of a named pipe. MUST be one of the
following.

|Value|Meaning|
|---|---|
|FILE_PIPE_CLIENT_END<br>0x00000000|This is the client end of a named pipe.|
|FILE_PIPE_SERVER_END<br>0x00000001|This is the server end of a named pipe.|
This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

[For more information on named pipes, please see [PIPE].](https://go.microsoft.com/fwlink/?LinkId=90247)

**2.4.39** **FilePipeRemoteInformation**

This information class is used to query information on a named pipe that is associated with the client
end of the pipe that is being queried. Remote information is not available for local pipes or for the
server end of a remote pipe. Therefore, this information class is usable only by the client to retrieve
information associated with its end of the pipe.

A **FILE_PIPE_REMOTE_INFORMATION** data element, defined as follows, is returned by the server.

```
  CollectDataTime (32 bits)
  MaximumCollectionCount (32 bits)
  ...
```

**CollectDataTime (8 bytes):** A 64-bit signed integer that MUST contain the maximum amount of

time counted in 100-nanosecond intervals that will elapse before transmission of data from the
client machine to the server.

**MaximumCollectionCount (4 bytes):** A 32-bit unsigned integer that MUST contain the maximum

size, in bytes, of data that will be collected on the client machine before transmission to the
server.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

[For more information on named pipes, please see [PIPE].](https://go.microsoft.com/fwlink/?LinkId=90247)

**2.4.41** **FileQuotaInformation**

This information class is used to query or to set file quota information for a **volume** . For queries, an
optional buffer of FILE_GET_QUOTA_INFORMATION (section 2.4.41.1) data elements is provided by
the client to specify the **SID** s for which quota information is requested. If the
**FILE_GET_QUOTA_INFORMATION** buffer is not specified, information for all quotas is returned. A
buffer of **FILE_QUOTA_INFORMATION** data elements is returned by the server. For sets,
**FILE_QUOTA_INFORMATION** data elements are populated and sent by the client, as specified in

[MS-SMB] section 2.2.7.6.1 and [MS-SMB2] section 3.2.4.15.<145>

When multiple **FILE_QUOTA_INFORMATION** data elements are present in the buffer, each MUST be
aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to zero, and the
receiver MUST ignore them. No padding is required following the last data element.

A **FILE_QUOTA_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  SidLength (32 bits)
  ChangeTime (32 bits)
```
**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_QUOTA_INFORMATION entry is located, if multiple
entries are present in a buffer. This member MUST be zero if no other entries follow this one. An
implementation MUST use this value to determine the location of the next entry (if multiple entries
are present in a buffer).

**SidLength (4 bytes):** A 32-bit unsigned integer that contains the length, in bytes, of the **Sid** data

element.

**ChangeTime (8 bytes):** The last time that the quota was changed; see section 2.1.1. This value

MUST be greater than or equal to 0x0000000000000000. When setting quota information, the
server MUST ignore the value of this field.

**QuotaUsed (8 bytes):** A 64-bit signed integer that contains the amount of quota used by this user,

in bytes. This value MUST be greater than or equal to 0x0000000000000000. When setting quota
information, the server MUST ignore the value of this field.

**QuotaThreshold (8 bytes):** A 64-bit signed integer that contains the **disk quota** warning

threshold, in bytes, on this volume for this user. This field MUST be set to a 64-bit integer value
greater than or equal to 0 to set a quota warning threshold for this user on this volume. If this
field is set to -1 there is no quota warning threshold for this user.

**QuotaLimit (8 bytes):** A 64-bit signed integer that contains the disk quota limit, in bytes, on this

volume for this user. This field MUST be set to a 64-bit integer value greater than or equal to zero
to set a disk quota limit for this user on this volume, to -1 to specify that no quota limit is set for
this user, or to -2 to delete the quota entry for the user.

**Sid (variable):** Security identifier (SID) for this user.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The target file system does not implement this functionality.|
|Error code|Meaning|
|---|---|
|STATUS_INVALID_INFO_CLASS<br>0xC0000003|The specified information class is not a valid information class for the<br>specified object.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The SID or SID Length specified is not a valid parameter.|
|STATUS_NO_SUCH_FILE<br>0xC000000F|For query operations, indicates that no**FILE_QUOTA_INFORMATION** <br>data elements were returned that matched the input criteria.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The buffer is too small to contain the entry. No information has been<br>written to the buffer.|

**2.4.41.1** **FILE_GET_QUOTA_INFORMATION**

This structure is used to provide the list of **SIDs** for which quota query information is requested.

When multiple **FILE_GET_QUOTA_INFORMATION** data elements are present in the buffer, each
MUST be aligned on a 4-byte boundary. Any bytes inserted for alignment SHOULD be set to zero, and
the receiver MUST ignore them. No padding is required following the last data element.

A **FILE_GET_QUOTA_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  SidLength (32 bits)
  Sid (variable) (32 bits)
  ...
```

**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_GET_QUOTA_INFORMATION entry is located, if
multiple entries are present in a buffer. This member MUST be zero if no other entries follow this
one. An implementation MUST use this value to determine the location of the next entry (if
multiple entries are present in a buffer).

**SidLength (4 bytes):** A 32-bit unsigned integer that contains the length, in bytes, of the **Sid** data

element.

**Sid (variable):** SID for this user. SIDs are sent in little-endian format and require no padding. The

format of a SID is as specified in [MS-DTYP] section 2.4.2.2.
**2.4.45** **FileSfioReserveInformation**

This information class is used locally to query or set reserved bandwidth for a file handle. Conceptually
reserving bandwidth is effectively specifying the bytes per second to allocate to file IO.
A **FILE_SFIO_RESERVE_INFORMATION** data element, defined as follows, is returned to the caller.

```
  RequestsPerPeriod (32 bits)
  Period (32 bits)
  RetryFailures (8 bits) | Discardable (8 bits) | Reserved (16 bits)
  RequestSize (32 bits)
  NumOutstandingRequests (32 bits)
```

**RequestsPerPeriod (4 bytes):** A 32-bit unsigned integer indicating the number of I/O requests that

complete per period of time, as specified in the **Period** field. When setting bandwidth reservation,
a value of 0 indicates to the file system that it MUST free any existing reserved bandwidth.

**Period (4 bytes):** A 32-bit unsigned integer that contains the period for reservation, which is the

time from which I/O is issued to the kernel until the time the I/O is completed, specified in
milliseconds.

**RetryFailures (1 byte):** A Boolean (section 2.1.8) value.

**Discardable (1 byte):** A Boolean (section 2.1.8) value.

**Reserved (2 bytes):** Reserved for alignment. This field can contain any value and MUST be ignored.

**RequestSize (4 bytes):** A 32-bit unsigned integer that indicates the minimum size of any individual

I/O request that can be issued by an application using bandwidth reservation. When setting
reservations, this field MUST be ignored by servers and SHOULD be set to 0 by clients.

**NumOutstandingRequests (4 bytes):** A 32-bit unsigned integer that indicates the number of

RequestSize I/O requests allowed to be outstanding at any time. When setting reservations, this
field MUST be ignored by servers and SHOULD be set to 0 by clients.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The request is not supported.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
