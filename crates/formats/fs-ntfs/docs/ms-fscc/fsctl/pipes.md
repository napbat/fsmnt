<!-- MS-FSCC: Named Pipe Operations -->
<!-- PIPE_PEEK, PIPE_TRANSCEIVE, PIPE_WAIT request/reply pairs. -->

**2.3.45** **FSCTL_PIPE_PEEK Request**

The FSCTL_PIPE_PEEK request requests that the server copy a named pipe's data into a buffer for
preview without removing it. The FSCTL_PIPE_PEEK request message is issued to invoke a reply, and
does not have an associated data structure.

**2.3.46** **FSCTL_PIPE_PEEK Reply**

The **FSCTL_PIPE_PEEK** response returns data from the pipe server's output buffer in the FSCTL
output buffer. The structure of that data is as follows.

```
  NamedPipeState (32 bits)
  ReadDataAvailable (32 bits)
  NumberOfMessages (32 bits)
  MessageLength (32 bits)
```
**NamedPipeState (4 bytes):** A 32-bit unsigned integer referring to the current state of the pipe. The

allowed values are shown in the following table.

|Pipe State|Meaning|
|---|---|
|FILE_PIPE_CONNECTED_STATE<br>0x00000003|The specified named pipe is in the connected state.|
|FILE_PIPE_CLOSING_STATE<br>0x00000004|The server end of the specified named pipe has been closed, but data is<br>still available for the client to read.|

**ReadDataAvailable (4 bytes):** A 32-bit unsigned integer that specifies the size, in bytes, of the data

available to read from the pipe.

**NumberOfMessages (4 bytes):** A 32-bit unsigned integer that specifies the number of messages

available in the pipe if the pipe has been created as a message-type pipe. Otherwise, this field is
0.

**MessageLength (4 bytes):** A 32-bit unsigned integer that specifies the length of the first message

available in the pipe if the pipe has been created as a message-type pipe. Otherwise, this field is
0.

**Data (variable):** A byte buffer of data from the pipe.

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_PIPE_DISCONNECTED<br>0xC00000B0|The specified named pipe is in the disconnected state.|
|STATUS_INVALID_PIPE_STATE<br>0xC00000AD|The data cannot be read in the current state of the specified pipe.|
|STATUS_PIPE_BROKEN<br>0xC000014B|The pipe operation has failed because the other end of the pipe has been<br>closed.|
|STATUS_INVALID_USER_BUFFER<br>0xC00000E8|An exception was raised while accessing a user buffer.|
|STATUS_INSUFFICIENT_RESOURCES<br>0xC000009A|There were insufficient resources to complete the operation.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The type of the handle is not a pipe.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The data was too large for the specified buffer. This is a warning, not an<br>error. Response contains information including available data length and<br>data that fits into the buffer.|

[For more information on named pipes, see [PIPE].](https://go.microsoft.com/fwlink/?LinkId=90247)
**2.3.47** **FSCTL_PIPE_TRANSCEIVE Request**

The FSCTL_PIPE_TRANSCEIVE request is used to send and receive data from an open pipe. Any bytes
in the FSCTL input buffer are written as a **binary large object (BLOB)** to the input buffer of the pipe
server.

The FSCTL input buffer does not have an associated structure. The buffer is a BLOB of bytes that are
written into the associated pipe.

**2.3.48** **FSCTL_PIPE_TRANSCEIVE Reply**

The FSCTL_PIPE_TRANSCEIVE response returns data from the pipe server's output buffer in the FSCTL
output buffer.

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_PIPE_DISCONNECTED<br>0xC00000B0|The specified named pipe is in the disconnected state.|
|STATUS_INVALID_PIPE_STATE<br>0xC00000AD|The named pipe is not in the connected state or not in the full-duplex<br>message mode.|
|STATUS_PIPE_BUSY<br>0xC00000AE|The named pipe contains unread data.|
|STATUS_INVALID_USER_BUFFER<br>0xC00000E8|An exception was raised while accessing a user buffer.|
|STATUS_INSUFFICIENT_RESOURCES<br>0xC000009A|There were insufficient resources to complete the operation.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The type of the handle is not a pipe.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The data was too large to fit into the specified buffer.|

[For more information on named pipes, see [PIPE].](https://go.microsoft.com/fwlink/?LinkId=90247)

**2.3.49** **FSCTL_PIPE_WAIT Request**

The FSCTL_PIPE_WAIT Request requests that the server wait until either a time-out interval elapses,
or an instance of the specified named pipe is available for connection.

```
  Timeout (32 bits)
  NameLength (32 bits)
  ...
```
|TimeoutSpecified|Padding|Name (variable)|
|---|---|---|
|...|...|...|

**Timeout (8 bytes):** A 64-bit signed integer that specifies the maximum amount of time, in units of

100 milliseconds, that the function can wait for an instance of the named pipe to be available.

**NameLength (4 bytes):** A 32-bit unsigned integer that specifies the size, in bytes, of the named

pipe **Name** field.

**TimeoutSpecified (1 byte):** A Boolean (section 2.1.8) value that specifies whether or not the

**Timeout** parameter will be ignored.

|Value|Meaning|
|---|---|
|FALSE|Indicates that the server MUST wait forever (no timeout) for the named pipe. Any value in**Timeout** <br>MUST be ignored.|
|TRUE|Indicates that the server MUST use the value in the**Timeout** parameter.|

**Padding (1 byte):** The client SHOULD set this field to 0x00, and the server MUST ignore it.

**Name (variable):** A Unicode string that contains the name of the named pipe. **Name** MUST not

include the "\pipe\", so if the operation was on \\server\pipe\pipename, the name would be
"pipename".

[For more information on named pipes, see [PIPE].](https://go.microsoft.com/fwlink/?LinkId=90247)

**2.3.50** **FSCTL_PIPE_WAIT Reply**

This message returns the results of the FSCTL_PIPE_WAIT request.

The only data item this message returns is a status code, as specified in section 2.2. Upon success,
the status code returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_SUCCESS<br>0x00000000|The specified named pipe is available for connection.|
|STATUS_OBJECT_NAME_NOT_FOUND<br>0xC0000034|The specified named pipe does not exist.<br>This error code is also returned when the pipe is closed during wait.|
|STATUS_IO_TIMEOUT<br>0xC00000B5|Timeout specified in the FSCTL_PIPE_WAIT request expired.|
|STATUS_INSUFFICIENT_RESOURCES<br>0xC000009A|There were insufficient resources to complete the operation.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The type of the handle is not a pipe.|
