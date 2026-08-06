<!-- MS-FSCC: Streams, Extended Attributes, Reparse, Object IDs, File IDs -->
<!-- FileAttributeTagInformation, FileCompressionInformation, FileEaInformation, FileFullEaInformation (FILE_GET_EA_INFORMATION), FileObjectIdInformation (Type 1/2), FileReparsePointInformation, FileStreamInformation, FileIdInformation, FileInternalInformation. -->

**2.4.6** **FileAttributeTagInformation**

This information class is used to query for attribute and reparse **tag** information for a file.

A **FILE_ATTRIBUTE_TAG_INFORMATION** data element, defined as follows, is returned by the
server.

```
  FileAttributes (32 bits)
  ReparseTag (32 bits)
```

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid file

attributes are as specified in section 2.6.

**ReparseTag (4 bytes):** A 32-bit unsigned integer that specifies the **reparse point tag** . If the

**FileAttributes** member includes the FILE_ATTRIBUTE_REPARSE_POINT attribute flag, this
member specifies the reparse tag. Otherwise, this member SHOULD be set to 0, and MUST be
ignored. Section 2.1.2.1 contains more details on reparse tags.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|Error code|Meaning|
|---|---|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened to read file data or file attributes.|

**2.4.9** **FileCompressionInformation**

This information class is used to query compression information for a file.

A FILE_COMPRESSION_INFORMATION data element, defined as follows, is returned by the server.

```
  CompressedFileSize (32 bits)
  CompressionFormat (16 bits) | CompressionUnitShift (8 bits) | ChunkShift (8 bits)
  ClusterShift (8 bits) | Reserved (24 bits)
  ...
```

**CompressedFileSize (8 bytes):** A 64-bit signed integer that contains the size, in bytes, of the

compressed file. This value MUST be greater than or equal to 0.

**CompressionFormat (2 bytes):** A 16-bit unsigned integer that contains the compression format.

The actual compression operation associated with each of these compression format values is
implementation-dependent. An implementation can link any local compression algorithm with the
values described in the following table because the compressed data does not travel across the
wire in the context of **FSCTL**, FileInformation class, or FileSystemInformation class requests or
replies.<109>

|Value|Meaning|
|---|---|
|COMPRESSION_FORMAT_NONE<br>0x0000|The file or directory is not compressed.|
|COMPRESSION_FORMAT_LZNT1<br>0x0002|The file or directory is compressed by using the LZNT1 compression<br>algorithm.|
|All other values|Reserved for future use.|

**CompressionUnitShift (1 byte):** An 8-bit unsigned integer that contains the **compression unit**

**shift**, which is the number of bits by which to left-shift a 1 bit to arrive at the **compression unit**
size. The compression unit size is the number of bytes in a compression unit, that is, the number
of bytes to be compressed. This value is implementation-defined.<110>

**ChunkShift (1 byte):** An 8-bit unsigned integer that contains the compression **chunk** size shift,

which is the number of bits by which to left-shift a 1 bit to arrive at the compression chunk size.
The chunk size is the number of bytes that the operating system's implementation of the LempelZiv compression algorithm tries to compress at one time. This value is implementationdefined.<111>

**ClusterShift (1 byte):** An 8-bit unsigned integer that contains the **cluster** size shift, which is the

number of bits by which to left-shift a 1 bit to arrive at the cluster size. The cluster size specifies
the amount of space that is saved by compression to successfully compress a compression unit. If
a cluster size amount of space is not saved by compression, the data in that compression unit is
stored uncompressed. Each successfully compressed compression unit MUST occupy at least one
cluster less than the uncompressed compression unit. This value is implementation-defined.<112>

**Reserved (3 bytes):** A 24-bit reserved value. This field SHOULD be set to 0, and MUST be ignored.
This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The data was too large to fit into the specified buffer. No data is returned.|

**2.4.13** **FileEaInformation**

This information class is used to query for the size of the extended attributes (EA) for a file. An
extended attribute is a piece of application-specific metadata that an application can link with a file
that is not part of the file's data. For more information about extended attributes, see [MS-CIFS]
section 2.2.1.2.

A **FILE_EA_INFORMATION** data element, defined as follows, is returned by the server.

```
  EaSize (32 bits)
```

**EaSize (4 bytes):** A 32-bit unsigned integer that contains the combined length, in bytes, of the

extended attributes (EA) for the file.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.16** **FileFullEaInformation**

This information class is used to query or set extended attribute (EA) information for a file. For
queries, the client provides a list of FILE_GET_EA_INFORMATION (section 2.4.16.1) structures, and a
list of **FILE_FULL_EA_INFORMATION** structures is returned by the server. For setting EA
information, the client provides a list of **FILE_FULL_EA_INFORMATION** structures, and a status
code is returned by the server, as specified in section 2.2.

When multiple **FILE_FULL_EA_INFORMATION** data elements are present in the buffer, each MUST
be aligned on a 4-byte boundary. Any bytes inserted for alignment SHOULD be set to zero, and the
receiver MUST ignore them. No padding is required following the last data element.

A **FILE_FULL_EA_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  Flags (8 bits) | EaNameLength (8 bits) | EaValueLength (16 bits)
  EaName (variable) (32 bits)
  EaValue (variable) (32 bits)
  ...
```

**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_FULL_EA_INFORMATION entry is located, if
multiple entries are present in the buffer. This member MUST be zero if no other entries follow this
one. An implementation MUST use this value to determine the location of the next entry (if
multiple entries are present in a buffer).

**Flags (1 byte):** An 8-bit unsigned integer that MUST contain one of the following flag values.
|Value|Meaning|
|---|---|
|0x00000000|If no flags are set, this EA does not prevent the file to which the EA belongs from being<br>interpreted by applications that do not understand EAs.|
|FILE_NEED_EA<br>0x00000080|If this flag is set, the file to which the EA belongs cannot be interpreted by applications that<br>do not understand EAs.|

**EaNameLength (1 byte):** An 8-bit unsigned integer that contains the length, in bytes, of the

extended attribute name in the **EaName** field. This value MUST NOT include the terminating null
character to **EaName** .

**EaValueLength (2 bytes):** A 16-bit unsigned integer that contains the length, in bytes, of the

extended attribute value in the **EaValue** field. When setting EA information, if this field is zero,
then the given EaName and its current value are deleted from the given file.

**EaName (variable):** An array of 8-bit ASCII characters that contains the extended attribute name

followed by a single terminating null character byte. The **EaName** MUST be less than 255
characters and MUST NOT contain any of the following characters:

ASCII values 0x00 - 0x1F, \ / : * ? " < > |, + = [ ] ;

**EaValue (variable):** An array of bytes that contains the extended attribute value. The length of this

array is specified by the **EaValueLength** field.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The target file system does not implement this functionality.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened to read file data or file attributes.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The buffer is too small to contain the entry. No information has been<br>written to the buffer.|
|STATUS_NO_EAS_ON_FILE<br>0xC0000052|The file for which EAs were requested has no EAs.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before all of the EA data could be returned.<br>Only complete FILE_FULL_EA_INFORMATION structures are returned.|
|STATUS_INVALID_EA_NAME<br>0x80000013|The**Flags** field contains a value other than zero or FILE_NEED_EA, or the<br>**EaName** field is longer than 255 characters, or it contains any of the<br>following characters:<br>ASCII values 0x00 - 0x1F,  \ / : * ? " < > |, + = [ ] ;|

**2.4.16.1** **FILE_GET_EA_INFORMATION**

This data structure can be used to specify an explicit list of attributes to query via the
FileFullEaInformation (section 2.4.16) information class. If no FILE_GET_EA_INFORMATION elements
are specified, all extended attributes for the given file are returned.
When multiple FILE_GET_EA_INFORMATION data elements are present in the buffer, each MUST be
aligned on a 4-byte boundary. Any bytes inserted for alignment SHOULD be set to zero, and the
receiver MUST ignore them. No padding is required following the last data element.

```
  NextEntryOffset (32 bits)
  EaNameLength (8 bits) | EaName (variable) (24 bits)
  ...
```

**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next **FILE_GET_EA_INFORMATION** entry is located, if
multiple entries are present in a buffer. This member MUST be zero if no other entries follow this
one. An implementation MUST use this value to determine the location of the next entry (if
multiple entries are present in a buffer).

**EaNameLength (1 byte):** An 8-bit unsigned integer that contains the length, in bytes, of the

**EaName** field. This value MUST NOT include the terminating null character to **EaName** .

**EaName (variable):** An array of 8-bit ASCII characters that contains the extended attribute name

followed by a single terminating null character byte.

**2.4.36** **FileObjectIdInformation**

This information class is used locally to query object ID information for the files in a directory on a
**volume** . The query MUST fail if the file system does not support object IDs.<140>

The data returned to the caller will take one of two forms. The choice of which data structure to use,
and the interpretation of the data within it, is application-specific. An application implementer chooses
one of the following two data elements as the structure for its object ID information data.<141>

- FILE_OBJECTID_INFORMATION_TYPE_1 (section 2.4.36.1).

- FILE_OBJECTID_INFORMATION_TYPE_2 (section 2.4.36.2).

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The target file system does not implement this functionality.|
|STATUS_INVALID_INFO_CLASS<br>0xC0000003|The specified information class is not a valid information class for the<br>specified object.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The file specified is not a valid parameter.|
|STATUS_NO_SUCH_FILE<br>0xC000000F|The file does not exist.|
|STATUS_NO_MORE_FILES<br>0x80000006|No more files were found which match the file specification.|
|Error code|Meaning|
|---|---|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before all of the**ObjectID** information could<br>be returned. Only complete**FILE_OBJECTID_INFORMATION** structures<br>are returned.|

**2.4.36.1** **FILE_OBJECTID_INFORMATION_TYPE_1**

A **FILE_OBJECTID_INFORMATION_TYPE_1** data element is as follows.

```
  FileReferenceNumber (32 bits)
  ObjectId (16 bytes) (32 bits)
  BirthVolumeId (16 bytes) (32 bits)
  BirthObjectId (16 bytes) (32 bits)
  DomainId (16 bytes) (32 bits)
  ...
```

**FileReferenceNumber (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file. For file

systems that do not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored.

**ObjectId (16 bytes):** A 16-byte **GUID** that uniquely identifies the file or directory within the

**volume** on which it resides. Specifically, the same object ID can be assigned to another file or
directory on a different volume, but it MUST NOT be assigned to another file or directory on the
same volume.

**BirthVolumeId (16 bytes):** A 16-byte GUID that uniquely identifies the volume on which the object

resided when the object identifier was created, or zero if the volume had no object identifier at
that time. After copy operations, move operations, or other file operations, this might not be the
same as the object identifier of the volume on which the object presently resides.

**BirthObjectId (16 bytes):** A 16-byte GUID value containing the object identifier of the object at the

time it was created. After copy operations, move operations, or other file operations, this value
might not be the same as the **ObjectId** member at present.<142>

**DomainId (16 bytes):** A 16-byte GUID value containing the domain identifier. This value is unused;

it SHOULD be zero and MUST be ignored.

**2.4.36.2** **FILE_OBJECTID_INFORMATION_TYPE_2**

A **FILE_OBJECTID_INFORMATION_TYPE_2** data element is as follows.

```
  FileReferenceNumber (32 bits)
  ObjectId (16 bytes) (32 bits)
  ExtendedInfo (48 bytes) (32 bits)
  ...
```

**FileReferenceNumber (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file. For file

systems that do not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored.

**ObjectId (16 bytes):** A 16-byte **GUID** that uniquely identifies the file or directory within the

**volume** on which it resides. Specifically, the same object ID can be assigned to another file or
directory on a different volume, but it MUST NOT be assigned to another file or directory on the
same volume.

**ExtendedInfo (48 bytes):** A 48-byte BLOB that contains application-specific extended information

on the file object. If no extended information has been written for this file, the server MUST return
48 bytes of 0x00 in this field.

**2.4.44** **FileReparsePointInformation**

This information class is used locally to query for information on a **reparse point** .

A **FILE_REPARSE_POINT_INFORMATION** data element, defined as follows, is returned to the
caller.

```
  FileReferenceNumber (32 bits)
  Tag (32 bits)
  ...
```

**FileReferenceNumber (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file.

**Tag (4 bytes):** A 32-bit unsigned integer value containing the **reparse point tag** that uniquely

identifies the owner of the reparse point. Section 2.1.2.1 contains more details on reparse tags.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The target file system does not implement this functionality.|
|STATUS_INVALID_INFO_CLASS<br>0xC0000003|The specified information class is not a valid information class for the<br>specified object.|
|STATUS_NO_SUCH_FILE<br>0xC000000F|No reparse points exist for the given file.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before all of the<br>FILE_REPARSE_POINT_INFORMATION structures could be returned; a<br>partial structure might be returned.|

**2.4.49** **FileStreamInformation**

This information class is used to enumerate the data **streams** of a file or a directory. A buffer of
**FILE_STREAM_INFORMATION** data elements is returned by the server.

When multiple **FILE_STREAM_INFORMATION** data elements are present in the buffer, each MUST
be aligned on an 8-byte boundary; any bytes inserted for alignment SHOULD be set to zero and the
receiver MUST ignore them. No padding is required following the last data element.

A **FILE_STREAM_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  StreamNameLength (32 bits)
  StreamSize (32 bits)
  StreamAllocationSize (32 bits)
  StreamName (variable) (32 bits)
  ...
```

**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next **FILE_STREAM_INFORMATION** entry is located, if
multiple entries are present in a buffer. This member is zero if no other entries follow this one. An
implementation MUST use this value to determine the location of the next entry (if multiple entries
are present in a buffer).
**StreamNameLength (4 bytes):** A 32-bit unsigned integer that contains the length, in bytes, of the

stream name string.

**StreamSize (8 bytes):** A 64-bit signed integer that contains the size, in bytes, of the stream. The

value of this field MUST be greater than or equal to 0x0000000000000000.

**StreamAllocationSize (8 bytes):** A 64-bit signed integer that contains the file stream allocation

size, in bytes. The value of this field MUST be an integer multiple of the **cluster** size.

**StreamName (variable):** A sequence of Unicode characters containing the name of the stream using

the form ":streamname:$DATA", or "::$DATA" for the default data stream, as specified in section
2.1.4. This field is not null-terminated and MUST be handled as a sequence of
**StreamNameLength** bytes.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before all of the stream information could be<br>returned. Only complete FILE_STREAM_INFORMATION structures are<br>returned.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.26** **FileIdInformation**

This information class is used to query the volume serial number and fileid information for a file.

A **FILE_ID_INFORMATION** data element, defined as follows, is provided by the server.

```
  VolumeSerialNumber (32 bits)
  FileId (32 bits)
  ...
```
**VolumeSerialNumber (8 bytes):** A 64-bit unsigned integer that contains the serial number of the

volume where the file is located.

**FileId (16 bytes):** The 128-bit file ID, as specified in section 2.1.10, of the file. For file systems that

do not support a 128-bit file ID, this field MUST be set to 0, and MUST be ignored.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error Code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not<br>match the length that is required for the specified<br>information class.|

**2.4.27** **FileInternalInformation**

This information class is used to query for the file system's 64-bit file ID, as specified in section 2.1.9.

A **FILE_INTERNAL_INFORMATION** data element, defined as follows, is returned by the server.

```
  IndexNumber (32 bits)
  ...
```

**IndexNumber (8 bytes):** The 64-bit file ID for the file. For file systems that do not support a 64-bit

file ID, this field MUST be set to 0, and MUST be ignored. <133>

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
