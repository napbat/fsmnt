<!-- MS-FSCC: Encryption -->
<!-- SET_ENCRYPTION request/reply. ENCRYPTION_BUFFER, DECRYPTION_STATUS_BUFFER. -->

**2.3.71** **FSCTL_SET_ENCRYPTION Request**

The FSCTL_SET_ENCRYPTION request sets the encryption for the file or directory associated with the
given handle.<64><65>

The message contains an ENCRYPTION_BUFFER structure that indicates whether to encrypt/decrypt a
file or an individual stream.

**ENCRYPTION_BUFFER** is defined as follows.

```
  EncryptionOperation (32 bits)
  Private (8 bits) | Padding (24 bits)
```

**EncryptionOperation (4 bytes):** A 32-bit unsigned integer value that indicates the operation to be

performed. The valid values are as follows.

|Value|Meaning|
|---|---|
|FILE_SET_ENCRYPTION<br>0x00000001|This operation requests encryption of the specified file or directory.<66>|
|Value|Meaning|
|---|---|
|FILE_CLEAR_ENCRYPTION<br>0x00000002|This operation requests removal of encryption from the specified file or<br>directory. It MUST fail if any streams for the file are marked<br>encrypted.<67>|
|STREAM_SET_ENCRYPTION<br>0x00000003|This operation requests encryption of the specified stream.<68>|
|STREAM_CLEAR_ENCRYPTION<br>0x00000004|This operation requests the removal of encryption from the specified<br>stream.<69>|

**Private (1 byte):** An 8-bit unsigned char value.<70>

**Padding (3 bytes):** These bytes MUST be ignored.

**2.3.72** **FSCTL_SET_ENCRYPTION Reply**

This message returns the results of the FSCTL_SET_ENCRYPTION request. If the file system of the
**volume** containing the specified file or directory does not support encryption, the request MUST NOT
succeed. The error code returned in this situation varies, depending on the file system.

This message returns a status code, as specified in section 2.2, as well as a
DECRYPTION_STATUS_BUFFER (section 2.3.72.1) if an output buffer is passed in.

Upon success, the status code returned by the function that processes this **FSCTL** is
STATUS_SUCCESS<71>. The most common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_MEDIA_WRITE_PROTECTED<br>0xC00000A2|The disk cannot be written to because it is write-protected.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The**EncryptionOperation** field value is invalid, the open request is not<br>for a file or directory or stream encryption has been requested on a<br>stream that is compressed.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The size of the input buffer is less than the size of the encryption buffer<br>structure defined in section2.3.71, or an output buffer is present and is<br>smaller than a DECRYPTION_STATUS_BUFFER structure.|
|STATUS_VOLUME_NOT_UPGRADED<br>0xC000029C|The version of the file system on the volume does not support<br>encryption.<72>|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The request was invalid for a system-specific reason.<73>|
|STATUS_FILE_CORRUPT_ERROR<br>0xC0000102|A required attribute is missing from a directory for which encryption was<br>requested.<74>|
|STATUS_VOLUME_DISMOUNTED<br>0xC000026E|The volume is not mounted.|
|STATUS_INVALID_USER_BUFFER<br>0xC00000E8|An exception was raised while accessing a user buffer.|
**2.3.72.1** **DECRYPTION_STATUS_BUFFER**

The **DECRYPTION_STATUS_BUFFER** is defined as follows.

```
```
|NoEncryptedStreams|NoEncryptedStreams|NoEncryptedStreams|NoEncryptedStreams|NoEncryptedStreams|NoEncryptedStreams|NoEncryptedStreams|NoEncryptedStreams|||||||||||||||||||||||||

**NoEncryptedStreams (1 byte):** A Boolean (section 2.1.8) value. A TRUE value means that the last

encrypted stream of the specified file was just decrypted by an FSCTL_SET_ENCRYPTION
operation; otherwise, a FALSE value is returned.
