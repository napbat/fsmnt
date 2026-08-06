<!-- MS-FSCC: USN Journal -->
<!-- READ_FILE_USN_DATA request/reply with USN_RECORD_COMMON_HEADER, USN_RECORD_V2, USN_RECORD_V3 (reason codes, source info, timestamps). WRITE_USN_CLOSE_RECORD request/reply. -->

**2.3.61** **FSCTL_READ_FILE_USN_DATA Request**

This message requests that the server return the most recent change journal **USN** for the file or
directory associated with the handle on which this **FSCTL** was invoked. This message contains an
optional READ_FILE_USN_DATA data element.<56>

The READ_FILE_USN_DATA data element is as follows.

```
  MinMajorVersion (16 bits) | MaxMajorVersion (16 bits)
```

**MinMajorVersion (2 bytes):** A 16-bit unsigned integer that contains the minimum major version of

records returned in the results of this request.<57>

**MaxMajorVersion (2 bytes):** A 16-bit unsigned integer that contains the maximum major version of

records returned in the results of this request.<58>

**2.3.62** **FSCTL_READ_FILE_USN_DATA Reply**

The FSCTL_READ_FILE_USN_DATA reply message returns the results of the
FSCTL_READ_FILE_USN_DATA request as a USN_RECORD_V2 or a USN_RECORD_V3. Both forms of
reply message begin with a USN_RECORD_COMMON_HEADER, which can be used to determine the
form of the full reply message.

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle is not to a file, directory or if invalid**MinMajorVersion** and<br>**MaxMajorVersion** values are specified. .|
|STATUS_INVALID_USER_BUFFER<br>0xC00000E8|The output buffer is not aligned to a 4-byte boundary.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is too small to contain a USN_RECORD structure.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The file system does not support the use of a USN change journal.|

**2.3.62.1** **USN_RECORD_COMMON_HEADER**

The USN_RECORD_COMMON_HEADER element is as follows.
```
  RecordLength (32 bits)
  MajorVersion (16 bits) | MinorVersion (16 bits)
```

**RecordLength (4 bytes):** A 32-bit unsigned integer that contains the total length of the **update**

**sequence number (USN)** record, in bytes.

**MajorVersion (2 bytes):** A 16-bit unsigned integer that contains the major version of the change

journal software for this record. For example, if the change journal software is version 2.0, the
major version number is 2.<59>

**MinorVersion (2 bytes):** A 16-bit unsigned integer that contains the minor version of the change

journal software for this record. For example, if the change journal software is version 2.0, the
minor version number is 0 (zero).<60>

**2.3.62.2** **USN_RECORD_V2**

The **USN_RECORD_V2** element is as follows.

```
  RecordLength (32 bits)
  MajorVersion (16 bits) | MinorVersion (16 bits)
  FileReferenceNumber (32 bits)
  ParentFileReferenceNumber (32 bits)
  Usn (32 bits)
  TimeStamp (32 bits)
  Reason (32 bits)
  SourceInfo (32 bits)
  SecurityId (32 bits)
  FileAttributes (32 bits)
  ...
```
|FileNameLength|FileNameOffset|
|---|---|
|FileName (variable)|FileName (variable)|
|...|...|

**RecordLength (4 bytes):** A 32-bit unsigned integer that contains the total length of the **update**

**sequence number (USN)** record, in bytes.

**MajorVersion (2 bytes):** A 16-bit unsigned integer that contains the major version of the change

journal software for this record. For a USN_RECORD_V2, the major version number is 2.

**MinorVersion (2 bytes):** A 16-bit unsigned integer that contains the minor version of the change

journal software for this record. For a USN_RECORD_V2, the minor version number is 0 (zero).

**FileReferenceNumber (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, of the file or

directory for which this record notes changes.

**ParentFileReferenceNumber (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, of the

directory on which the file or directory that is associated with this record is located.

**Usn (8 bytes):** A 64-bit signed integer, opaque to the client, containing the USN of the record. This

value is unique within the **volume** on which the file is stored. This value MUST be greater than or
equal to 0. This value MUST be 0 if no USN change journal records have been logged for the file or
directory associated with this record. For more information, see [[MSDN-CJ].](https://go.microsoft.com/fwlink/?LinkId=89970)

**TimeStamp (8 bytes):** The absolute system time that this change journal event was logged; see

section 2.1.1.

**Reason (4 bytes):** A 32-bit unsigned integer that contains flags that indicate reasons for changes

that have accumulated in this file or directory journal record since the file or directory was
opened. When a file or directory is closed, a final USN record is generated with the
USN_REASON_CLOSE flag set in this field. The next change, occurring after the next open
operation or deletion, starts a new record with a new set of reason flags. A rename or move
operation generates two USN records: one that records the old parent directory for the item and
one that records the new parent in the **ParentFileReferenceNumber** member. Possible values
for the reason code are as follows (all unused bits are reserved for future use and MUST NOT be
used).

|Value|Meaning|
|---|---|
|USN_REASON_BASIC_INFO_CHANGE<br>0x00008000|A user has either changed one or more files or directory<br>attributes (such as read-only, hidden, archive, or sparse) or<br>one or more time stamps.|
|USN_REASON_CLOSE<br>0x80000000|The file or directory is closed.|
|USN_REASON_COMPRESSION_CHANGE<br>0x00020000|The compression state of the file or directory is changed from<br>(or to) compressed.|
|USN_REASON_DATA_EXTEND<br>0x00000002|The file or directory is extended (added to).|
|USN_REASON_DATA_OVERWRITE<br>0x00000001|The data in the file or directory is overwritten.|
|USN_REASON_DATA_TRUNCATION|The file or directory is truncated.|
|Value|Meaning|
|---|---|
|0x00000004||
|USN_REASON_EA_CHANGE<br>0x00000400|The user made a change to the extended attributes of a file or<br>directory. These NTFS file system attributes are not accessible<br>to nonnative applications. This USN reason does not appear<br>under normal system usage but can appear if an application or<br>utility bypasses the Win32 API and uses the native API to<br>create or modify extended attributes of a file or directory.|
|USN_REASON_ENCRYPTION_CHANGE<br>0x00040000|The file or directory is encrypted or decrypted.|
|USN_REASON_FILE_CREATE<br>0x00000100|The file or directory is created for the first time.|
|USN_REASON_FILE_DELETE<br>0x00000200|The file or directory is deleted.|
|USN_REASON_HARD_LINK_CHANGE<br>0x00010000|A hard link is added to (or removed from) the file or directory.|
|USN_REASON_INDEXABLE_CHANGE<br>0x00004000|A user changes the FILE_ATTRIBUTE_NOT_CONTEXT_INDEXED<br>attribute. That is, the user changes the file or directory from<br>one in which content can be indexed to one in which content<br>cannot be indexed, or vice versa.|
|USN_REASON_NAMED_DATA_EXTEND<br>0x00000020|The one (or more) named data stream for a file is extended<br>(added to).|
|USN_REASON_NAMED_DATA_OVERWRITE<br>0x00000010|The data in one (or more) named data stream for a file is<br>overwritten.|
|USN_REASON_NAMED_DATA_TRUNCATION<br>0x00000040|One (or more) named data stream for a file is truncated.|
|USN_REASON_OBJECT_ID_CHANGE<br>0x00080000|The object identifier of a file or directory is changed.|
|USN_REASON_RENAME_NEW_NAME<br>0x00002000|A file or directory is renamed, and the file name in the<br>USN_RECORD structure is the new name.|
|USN_REASON_RENAME_OLD_NAME<br>0x00001000|The file or directory is renamed, and the file name in the<br>USN_RECORD structure is the previous name.|
|USN_REASON_REPARSE_POINT_CHANGE<br>0x00100000|The**reparse point** that is contained in a file or directory is<br>changed, or a reparse point is added to (or deleted from) a file<br>or directory.|
|USN_REASON_SECURITY_CHANGE<br>0x00000800|A change is made in the access rights to a file or directory.|
|USN_REASON_STREAM_CHANGE<br>0x00200000|A **named stream** is added to (or removed from) a file, or a<br>named stream is renamed.|
|USN_REASON_INTEGRITY_CHANGE<br>0x00800000|A change is made in the integrity status of a file or directory.|

**SourceInfo (4 bytes):** A 32-bit unsigned integer that provides additional information about the

source of the change. When a thread writes a new USN record, the source information flags in the
prior record continue to be present only if the thread also sets those flags. Therefore, the source
information structure allows applications to **filter** out USN records that are set only by a known
source, for example, an antivirus filter. This flag MUST contain one of the following values.

|Value|Meaning|
|---|---|
|USN_SOURCE_DATA_MANAGEMENT<br>0x00000001|The operation provides information about a change to the file<br>or directory that was made by the operating system. For<br>example, a change journal record with this SourceInfo value is<br>generated when the Remote Storage system moves data from<br>external to local storage. This SourceInfo value indicates that<br>the modifications did not change the application data in the<br>file.|
|USN_SOURCE_AUXILIARY_DATA<br>0x00000002|The operation adds a private data stream to a file or directory.<br>For example, a virus detector might add checksum information.<br>As the virus detector modifies the item, the system generates<br>USN records. This SourceInfo value indicates that the<br>modifications did not change the application data in the file.|
|USN_SOURCE_REPLICATION_MANAGEMENT<br>0x00000004|The operation modified the file to match the content of the<br>same file that exists in another member of the**replica set** for<br>the File Replication Service (FRS).|

**SecurityId (4 bytes):** A 32-bit unsigned integer that contains an index of a unique security identifier

assigned to the file or directory associated with this record. This index is internal to the underlying
object store and MUST be ignored.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains attributes for the file or directory

associated with this record. Attributes of **streams** associated with the file or directory are
excluded. Valid file attributes are specified in section 2.6.

**FileNameLength (2 bytes):** A 16-bit unsigned integer that contains the length of the file or directory

name associated with this record, in bytes. The **FileName** member contains this name. Use this
member to determine file name length rather than depending on a trailing null to delimit the file
name in **FileName** .

**FileNameOffset (2 bytes):** A 16-bit unsigned integer that contains the offset, in bytes, of the

**FileName** member from the beginning of the structure.

**FileName (variable):** A variable-length field of **Unicode characters** containing the name of the file

or directory associated with this record in Unicode format. When working with this field, do not
assume that the file name will contain a trailing Unicode null character.

The fields **Reason**, **TimeStamp**, **SourceInfo**, and **SecurityId** for a USN RECORD element returned
by this **FSCTL** MUST all be set to 0.<61>

**2.3.62.3** **USN_RECORD_V3**

The **USN_RECORD_V3** element is as follows.

```
  RecordLength (32 bits)
  MajorVersion (16 bits) | MinorVersion (16 bits)
  FileReferenceNumber (16 bytes) (32 bits)
```
|...|Col2|
|---|---|
|...|...|
|ParentFileReferenceNumber (16 bytes)|ParentFileReferenceNumber (16 bytes)|
|...|...|
|...|...|
|Usn|Usn|
|...|...|
|TimeStamp|TimeStamp|
|...|...|
|Reason|Reason|
|SourceInfo|SourceInfo|
|SecurityId|SecurityId|
|FileAttributes|FileAttributes|
|FileNameLength|FileNameOffset|
|FileName (variable)|FileName (variable)|
|...|...|

**RecordLength (4 bytes):** A 32-bit unsigned integer that contains the total length of the **update**

**sequence number (USN)** record, in bytes.

**MajorVersion (2 bytes):** A 16-bit unsigned integer that contains the major version of the change

journal software for this record. For a USN_RECORD_V3, the major version number is 3.

**MinorVersion (2 bytes):** A 16-bit unsigned integer that contains the minor version of the change

journal software for this record. For a USN_RECORD_V3, the minor version number is 0 (zero).

**FileReferenceNumber (16 bytes):** The 128-bit file ID, as specified in section 2.1.10, of the file or

directory for which this record notes changes.

**ParentFileReferenceNumber (16 bytes):** The 128-bit file ID, as specified in section 2.1.10, of the

directory on which the file or directory that is associated with this record is located.

The fields **Usn**, **TimeStamp**, **Reason**, **SourceInfo**, **SecurityId**, **FileAttributes**, **FileNameLength**,
**FileNameOffset**, and **FileName** for a USN RECORD_V3 element are as described for a
USN_RECORD_V2 element; see section 2.3.62.2.
**2.3.92** **FSCTL_WRITE_USN_CLOSE_RECORD Request**

This message requests that the server generate a record in the server's file system change journal
**stream** for the file or directory associated with the handle on which this **FSCTL** was invoked,
indicating that the file or directory was closed. This FSCTL can be called independently of the actual
file close operation to write a **USN** record and cause a post of any pending USN updates for the
indicated file.

No data structure is associated with this request.

**2.3.93** **FSCTL_WRITE_USN_CLOSE_RECORD Reply**

This message returns the results of the FSCTL_WRITE_USN_CLOSE_RECORD request as a single field,
**Usn**, which is a 64-bit signed integer that contains the server file system's **USN** for the file or
directory. This value MUST be greater than or equal to 0.

This message returns a status code as specified in section 2.2. Upon success, the status code returned
by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error codes are
listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle is not to a file or directory, or the length of the output buffer<br>is less than the size of a 64-bit integer, or the output buffer does not<br>begin on a 4-byte boundary.|
|STATUS_INVALID_DEVICE_REQUEST<br>0xC0000010|The file system does not support the use of a USN change journal.|
