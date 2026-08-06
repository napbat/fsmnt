<!-- MS-FSCC: Directory Enumeration Classes -->
<!-- FileBothDirectoryInformation, FileDirectoryInformation, FileFullDirectoryInformation, FileIdBothDirectoryInformation, FileIdFullDirectoryInformation, FileIdGlobalTxDirectoryInformation, FileId64Extd*, FileIdAllExtd*, FileIdExtd*, FileNamesInformation, FileNetworkOpenInformation. -->

**2.4.8** **FileBothDirectoryInformation**

This information class is used in directory enumeration to return detailed information about the
contents of a directory.

This information class returns a list that contains a **FILE_BOTH_DIR_INFORMATION** data element
for each file or directory within the target directory.

This information class differs from FileDirectoryInformation (section 2.4.10) in that it includes short
names in the returns list.

When multiple **FILE_BOTH_DIR_INFORMATION** data elements are present in the buffer, each
MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to zero,
and the receiver MUST ignore them. No padding is required following the last data element.

A **FILE_BOTH_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
```
|FileIndex|Col2|Col3|
|---|---|---|
|CreationTime|CreationTime|CreationTime|
|...|...|...|
|LastAccessTime|LastAccessTime|LastAccessTime|
|...|...|...|
|LastWriteTime|LastWriteTime|LastWriteTime|
|...|...|...|
|ChangeTime|ChangeTime|ChangeTime|
|...|...|...|
|EndOfFile|EndOfFile|EndOfFile|
|...|...|...|
|AllocationSize|AllocationSize|AllocationSize|
|...|...|...|
|FileAttributes|FileAttributes|FileAttributes|
|FileNameLength|FileNameLength|FileNameLength|
|EaSize|EaSize|EaSize|
|ShortNameLength|Reserved|ShortName (24 bytes)|
|...|...|...|
|...|...|...|
|...|...|FileName (variable)|
|...|...|...|

**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_BOTH_DIR_INFORMATION entry is located, if
multiple entries are present in a buffer. This member is zero if no other entries follow this one. An
implementation MUST use this value to determine the location of the next entry (if multiple entries
are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<108>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. This value MUST be

greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. This value MUST

be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written to the file; see section 2.1.1. This

value MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. This value MUST be

greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. EndOfFile specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the **cluster** size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid file

attributes are specified in section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**EaSize (4 bytes):** If **FILE_ATTRIBUTE_REPARSE_POINT** is set in the **FileAttributes** field, this

field MUST contain a reparse tag as specified in section 2.1.2.1. Otherwise, this field is a 32-bit
unsigned integer that contains the combined length, in bytes, of the extended attributes (EA) for
the file.

**ShortNameLength (1 byte):** An 8-bit signed integer that specifies the length, in bytes, of the file

name contained in the **ShortName** member. This value MUST be greater than or equal to 0.

**Reserved (1 byte):** Reserved for alignment. This field can contain any value and MUST be ignored.

**ShortName (24 bytes):** A sequence of Unicode characters containing the short (8.3) file name.

When working with this field, use **ShortNameLength** to determine the length of the file name
rather than assuming the presence of a trailing null delimiter.

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. **Dot directory names** are valid for this field. For more
details, see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
**2.4.10** **FileDirectoryInformation**

This information class is used in directory enumeration to return detailed information about the
contents of a directory.

This information class returns a list that contains a **FILE_DIRECTORY_INFORMATION** data element
for each file or directory within the target directory.

When multiple **FILE_DIRECTORY_INFORMATION** data elements are present in the buffer, each
MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to zero,
and the receiver MUST ignore them. No padding is required following the last data element.

A **FILE_DIRECTORY_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  LastWriteTime (32 bits)
  ChangeTime (32 bits)
  EndOfFile (32 bits)
  ...
```
**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_DIRECTORY_INFORMATION entry is located, if
multiple entries are present in a buffer. This member MUST be zero if no other entries follow this
one. An implementation MUST use this value to determine the location of the next entry (if
multiple entries are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<113>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. This value MUST be

greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. This value MUST

be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written to the file; see section 2.1.1. This

value MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. This value MUST be

greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. EndOfFile specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the **cluster** size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. **Dot directory names** are valid for this field. For more
details, see section 2.1.5.1.
This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.15** **FileFullDirectoryInformation**

This information class is used in directory enumeration to return detailed information about the
contents of a directory.

This information class returns a list that contains a **FILE_FULL_DIR_INFORMATION** data element
for each file or directory within the target directory.

When multiple **FILE_FULL_DIR_INFORMATION** data elements are present in the buffer, each MUST
be aligned on an 8-byte boundary; any bytes inserted for alignment SHOULD be set to zero, and the
receiver MUST ignore them. No padding is required following the last data element.

A **FILE_FULL_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  LastWriteTime (32 bits)
  ChangeTime (32 bits)
  EndOfFile (32 bits)
  ...
```
**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_FULL_DIR_INFORMATION entry is located, if
multiple entries are present in a buffer. This member is zero if no other entries follow this one. An
implementation MUST use this value to determine the location of the next entry (if multiple entries
are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<115>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. This value MUST be

greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. This value MUST

be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written to the file; see section 2.1.1. This

value MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. This value MUST be

greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. EndOfFile specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the **cluster** size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. For a list of valid

file attributes, see section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**EaSize (4 bytes):** If **FILE_ATTRIBUTE_REPARSE_POINT** is set in the **FileAttributes** field, this

field MUST contain a reparse tag as specified in section 2.1.2.1. Otherwise, this field is a 32-bit
unsigned integer that contains the combined length, in bytes, of the extended attributes (EA) for
the file.

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. **Dot directory names** are valid for this field. For more
details, see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.18** **FileId64ExtdBothDirectoryInformation**

This information class is used in directory enumeration to return extended information about the
contents of a directory.

This information class returns a list that contains a
**FILE_ID_64_EXTD_BOTH_DIR_INFORMATION** data element for each file or directory within the
target directory.

When multiple **FILE_ID_64_EXTD_BOTH_DIR_INFORMATION** data elements are present in the
buffer, each MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be
set to zero, and the receiver MUST ignore them. No padding is required following the last data
element.

A **FILE_ID_64_EXTD_BOTH_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  LastWriteTime (32 bits)
  ChangeTime (32 bits)
  EndOfFile (32 bits)
  AllocationSize (32 bits)
  FileAttributes (32 bits)
  FileNameLength (32 bits)
  EaSize (32 bits)
  ...
```
|ReparsePointTag|Col2|Col3|
|---|---|---|
|FileId|FileId|FileId|
|...|...|...|
|ShortNameLength|Reserved1|ShortName (24 bytes)|
|...|...|...|
|...|...|...|
|FileName (variable)|FileName (variable)|FileName (variable)|
|...|...|...|

**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_ID_64_EXTD_BOTH_DIR_INFORMATION entry is
located, if multiple entries are present in the buffer. This member MUST be zero if no other entries
follow this one. An implementation MUST use this value to determine the location of the next entry
(if multiple entries are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<117>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. The value of this field

MUST be greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. **EndOfFile** specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the cluster size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**EaSize (4 bytes):** A 32-bit unsigned integer that contains the combined length, in bytes, of the

extended attributes (EA) for the file.
**ReparsePointTag (4 bytes):** If **FILE_ATTRIBUTE_REPARSE_POINT** is set in the **FileAttributes**

field, this field MUST contain a 32-bit unsigned integer value containing the reparse point tag that
uniquely identifies the owner of the reparse point. Section 2.1.2.1 contains more details on
reparse tags.

**FileId (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file. For file systems that do

not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored. For file systems
which do not explicitly store directory entries named ".." (synonymous with the parent directory),
an implementation MAY set this field to 0 for the entry named "..", and this value MUST be
ignored.<118>

**ShortNameLength (1 byte):** An 8-bit signed integer that specifies the length, in bytes, of the file

name contained within the **ShortName** member.

**Reserved1 (1 byte):** An 8-bit field. This field is reserved. This field MUST be set to zero, and MUST

be ignored.

**ShortName (24 bytes):** A sequence of Unicode characters containing the short (8.3) file name.

When working with this field, use **ShortNameLength** to determine the length of the file name
rather than assuming the presence of a trailing null delimiter.

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. Dot directory names are valid for this field. For more details,
see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.19** **FileId64ExtdDirectoryInformation**

This information class is used in directory enumeration to return extended information about the
contents of a directory.

This information class returns a list that contains a **FILE_ID_64_EXTD_DIR_INFORMATION** data
element for each file or directory within the target directory.

When multiple **FILE_ID_64_EXTD_DIR_INFORMATION** data elements are present in the buffer,
each MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to
zero, and the receiver MUST ignore them. No padding is required following the last data element.

A **FILE_ID_64_EXTD_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
```
**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_ID_64_EXTD_DIR_INFORMATION entry is located,
if multiple entries are present in the buffer. This member MUST be zero if no other entries follow
this one. An implementation MUST use this value to determine the location of the next entry (if
multiple entries are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<119>
**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. The value of this field

MUST be greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. **EndOfFile** specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the cluster size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**EaSize (4 bytes):** A 32-bit unsigned integer that contains the combined length, in bytes, of the

extended attributes (EA) for the file.

**ReparsePointTag (4 bytes):** If **FILE_ATTRIBUTE_REPARSE_POINT** is set in the **FileAttributes**

field, this field MUST contain a 32-bit unsigned integer value containing the reparse point tag that
uniquely identifies the owner of the reparse point. section 2.1.2.1 contains more details on reparse
tags.

**FileId (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file. For file systems that do

not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored. For file systems
which do not explicitly store directory entries named ".." (synonymous with the parent directory),
an implementation MAY set this field to 0 for the entry named "..", and this value MUST be
ignored.<120>

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. Dot directory names are valid for this field. For more details,
see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
**2.4.20** **FileIdAllExtdBothDirectoryInformation**

This information class is used in directory enumeration to return extended information about the
contents of a directory.

This information class returns a list that contains a
**FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION** data element for each file or directory within the
target directory.

When multiple **FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION** data elements are present in the
buffer, each MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be
set to zero, and the receiver MUST ignore them. No padding is required following the last data
element.

A **FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  LastWriteTime (32 bits)
  ChangeTime (32 bits)
  EndOfFile (32 bits)
  AllocationSize (32 bits)
  FileAttributes (32 bits)
  FileNameLength (32 bits)
  EaSize (32 bits)
  ...
```
|ReparsePointTag|Col2|Col3|
|---|---|---|
|FileId|FileId|FileId|
|...|...|...|
|FileId128|FileId128|FileId128|
|…|…|…|
|…|…|…|
|…|…|…|
|ShortNameLength|Reserved1|ShortName (24 bytes)|
|...|...|...|
|...|...|...|
|FileName (variable)|FileName (variable)|FileName (variable)|
|...|...|...|

**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next **FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION**
entry is located, if multiple entries are present in the buffer. This member MUST be zero if no
other entries follow this one. An implementation MUST use this value to determine the location of
the next entry (if multiple entries are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<121>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. The value of this field

MUST be greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. **EndOfFile** specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.
**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the cluster size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**EaSize (4 bytes):** A 32-bit unsigned integer that contains the combined length, in bytes, of the

extended attributes (EA) for the file.

**ReparsePointTag (4 bytes):** If **FILE_ATTRIBUTE_REPARSE_POINT** is set in the **FileAttributes**

field, this field MUST contain a 32-bit unsigned integer value containing the reparse point tag that
uniquely identifies the owner of the reparse point. section 2.1.2.1 contains more details on reparse
tags.

**FileId (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file. For file systems that do

not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored. For file systems
which do not explicitly store directory entries named ".." (synonymous with the parent directory),
an implementation MAY set this field to 0 for the entry named "..", and this value MUST be
ignored.<122>

**FileId128 (16 bytes):** The 128-bit file ID, as specified in section 2.1.10, of the file. For file systems

that do not support a 128-bit file ID, this field MUST be set to 0, and MUST be ignored.

**ShortNameLength (1 byte):** An 8-bit signed integer that specifies the length, in bytes, of the file

name contained within the **ShortName** member.

**Reserved1 (1 byte):** An 8-bit field. This field is reserved. This field MUST be set to zero, and MUST

be ignored.

**ShortName (24 bytes):** A sequence of Unicode characters containing the short (8.3) file name.

When working with this field, use **ShortNameLength** to determine the length of the file name
rather than assuming the presence of a trailing null delimiter.

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. Dot directory names are valid for this field. For more details,
see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.21** **FileIdAllExtdDirectoryInformation**

This information class is used in directory enumeration to return extended information about the
contents of a directory.

This information class returns a list that contains a **FILE_ID_ALL_EXTD_DIR_INFORMATION** data
element for each file or directory within the target directory.
When multiple **FILE_ID_ALL_EXTD_DIR_INFORMATION** data elements are present in the buffer,
each MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to
zero, and the receiver MUST ignore them. No padding is required following the last data element.

A **FILE_ID_ALL_EXTD_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  LastWriteTime (32 bits)
  ChangeTime (32 bits)
  EndOfFile (32 bits)
  AllocationSize (32 bits)
  FileAttributes (32 bits)
  FileNameLength (32 bits)
  EaSize (32 bits)
  ReparsePointTag (32 bits)
  FileId (32 bits)
  … (32 bits)
  ...
```
**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next **FILE_ID_ALL_EXTD_DIR_INFORMATION** entry is
located, if multiple entries are present in the buffer. This member MUST be zero if no other entries
follow this one. An implementation MUST use this value to determine the location of the next entry
(if multiple entries are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<123>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. The value of this field

MUST be greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. **EndOfFile** specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the cluster size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**EaSize (4 bytes):** A 32-bit unsigned integer that contains the combined length, in bytes, of the

extended attributes (EA) for the file.

**ReparsePointTag (4 bytes):** If **FILE_ATTRIBUTE_REPARSE_POINT** is set in the **FileAttributes**

field, this field MUST contain a 32-bit unsigned integer value containing the reparse point tag that
uniquely identifies the owner of the reparse point. section 2.1.2.1 contains more details on reparse
tags.

**FileId (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file. For file systems that do

not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored. For file systems
which do not explicitly store directory entries named ".." (synonymous with the parent directory),
an implementation MAY set this field to 0 for the entry named "..", and this value MUST be
ignored.<124>

**FileId128 (16 bytes):** The 128-bit file ID, as specified in section 2.1.10, of the file. For file systems

that do not support a 128-bit file ID, this field MUST be set to 0, and MUST be ignored.

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. Dot directory names are valid for this field. For more details,
see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.22** **FileIdBothDirectoryInformation**

This information class is used in directory enumeration to return detailed information about the
contents of a directory.

This information class returns a list that contains a **FILE_ID_BOTH_DIR_INFORMATION** data
element for each file or directory within the target directory.

When multiple **FILE_ID_BOTH_DIR_INFORMATION** data elements are present in the buffer, each
MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to zero,
and the receiver MUST ignore them. No padding is required following the last data element.

A **FILE_ID_BOTH_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  ...
```
|LastWriteTime|Col2|Col3|
|---|---|---|
|...|...|...|
|ChangeTime|ChangeTime|ChangeTime|
|...|...|...|
|EndOfFile|EndOfFile|EndOfFile|
|...|...|...|
|AllocationSize|AllocationSize|AllocationSize|
|...|...|...|
|FileAttributes|FileAttributes|FileAttributes|
|FileNameLength|FileNameLength|FileNameLength|
|EaSize|EaSize|EaSize|
|ShortNameLength|Reserved1|ShortName (24 bytes)|
|...|...|...|
|...|...|...|
|...|...|Reserved2|
|FileId|FileId|FileId|
|...|...|...|
|FileName (variable)|FileName (variable)|FileName (variable)|
|...|...|...|

**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_ID_BOTH_DIR_INFORMATION entry is located, if
multiple entries are present in the buffer. This member MUST be zero if no other entries follow this
one. An implementation MUST use this value to determine the location of the next entry (if
multiple entries are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<125>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.
**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. The value of this field

MUST be greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. EndOfFile specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the **cluster** size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**EaSize (4 bytes):** If **FILE_ATTRIBUTE_REPARSE_POINT** is set in the **FileAttributes** field, this

field MUST contain a reparse tag as specified in section 2.1.2.1. Otherwise, this field is a 32-bit
unsigned integer that contains the combined length, in bytes, of the extended attributes (EA) for
the file.

**ShortNameLength (1 byte):** An 8-bit signed integer that specifies the length, in bytes, of the file

name contained within the **ShortName** member.

**Reserved1 (1 byte):** An 8-bit field. This field is reserved. This field MUST be set to zero, and MUST

be ignored.

**ShortName (24 bytes):** A sequence of Unicode characters containing the short (8.3) file name.

When working with this field, use **ShortNameLength** to determine the length of the file name
rather than assuming the presence of a trailing null delimiter.

**Reserved2 (2 bytes):** A 16-bit field. This field is reserved. This field MUST be set to zero, and MUST

be ignored.

**FileId (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file. For file systems that do

not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored. For file systems
which do not explicitly store directory entries named ".." (synonymous with the parent directory),
an implementation MAY set this field to 0 for the entry named "..", and this value MUST be
ignored.<126>

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. **Dot directory names** are valid for this field. For more
details, see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH|The specified information record length does not match the length that is|
|Error code|Meaning|
|---|---|
|0xC0000004|required for the specified information class.|

**2.4.23** **FileIdExtdDirectoryInformation**

This information class is used in directory enumeration to return extended information about the
contents of a directory.

This information class returns a list that contains a **FILE_ID_EXTD_DIR_INFORMATION** data
element for each file or directory within the target directory.

When multiple **FILE_ID_EXTD_DIR_INFORMATION** data elements are present in the buffer, each
MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to zero,
and the receiver MUST ignore them. No padding is required following the last data element.

A **FILE_ID_EXTD_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  LastWriteTime (32 bits)
  ChangeTime (32 bits)
  EndOfFile (32 bits)
  AllocationSize (32 bits)
  ...
```
**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_ID_EXTD_DIR_INFORMATION entry is located, if
multiple entries are present in the buffer. This member MUST be zero if no other entries follow this
one. An implementation MUST use this value to determine the location of the next entry (if
multiple entries are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<127>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. The value of this field

MUST be greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. **EndOfFile** specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the **cluster** size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.
**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**EaSize (4 bytes):** A 32-bit unsigned integer that contains the combined length, in bytes, of the

extended attributes (EA) for the file.

**ReparsePointTag (4 bytes):** If **FILE_ATTRIBUTE_REPARSE_POINT** is set in the **FileAttributes**

field, this field MUST contain a 32-bit unsigned integer value containing the reparse point tag that
uniquely identifies the owner of the reparse point. section 2.1.2.1 contains more details on reparse
tags.

**FileId (16 bytes):** The 128-bit file ID, as specified in section 2.1.10, of the file. For file systems that

do not support a 128-bit file ID, this field MUST be set to 0, and MUST be ignored.

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. **Dot directory name** are valid for this field. For more details,
see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.24** **FileIdFullDirectoryInformation**

This information class is used in directory enumeration to return detailed information about the
contents of a directory.

This information class returns a list that contains a **FILE_ID_FULL_DIR_INFORMATION** data
element for each file or directory within the target directory.

When multiple **FILE_ID_FULL_DIR_INFORMATION** data elements are present in the buffer, each
MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to zero,
and the receiver MUST ignore them. No padding is required following the last data element.

A **FILE_ID_FULL_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  ...
```
**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_ID_FULL_DIR_INFORMATION entry is located, if
multiple entries are present in a buffer. This field SHOULD<128> be zero if no other entries follow
this one. An implementation MUST use this value to determine the location of the next entry (if
multiple entries are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<129>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.
**LastWriteTime (8 bytes):** The last time information was written; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. The value of this field

MUST be greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. EndOfFile specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the **cluster** size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**EaSize (4 bytes):** If **FILE_ATTRIBUTE_REPARSE_POINT** is set in the **FileAttributes** field, this

field MUST contain a reparse tag as specified in section 2.1.2.1. Otherwise, this field is a 32-bit
unsigned integer that contains the combined length, in bytes, of the extended attributes (EA) for
the file.

**Reserved (4 bytes):** Reserved for alignment. This field can contain any value and MUST be ignored.

**FileId (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file. For file systems that do

not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored. For file systems
which do not explicitly store directory entries named ".." (synonymous with the parent directory),
an implementation MAY set this field to 0 for the entry named "..", and this value MUST be
ignored.<130>

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. **Dot directory names** are valid for this field. For more
details, see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.25** **FileIdGlobalTxDirectoryInformation**

This information class is used locally to query transactional visibility information for the files in a
directory. This information class MAY be implemented for file systems that return the
FILE_SUPPORTS_TRANSACTIONS flag in response to **FileFsAttributeInformation** specified in section
2.5.1. This information class MUST NOT be implemented for file systems that do not return that flag.

This information class returns a list that contains a **FILE_ID_GLOBAL_TX_DIR_INFORMATION**
data element for each file or directory within the target directory. This list MUST reflect the presence
of a subdirectory named "." (synonymous with the target directory itself) within the target directory
and one named ".." (synonymous with the parent directory of the target directory), unless the target
directory is the root of the volume. For more details, see section 2.1.5.1.

When multiple **FILE_ID_GLOBAL_TX_DIR_INFORMATION** data elements are present in the buffer,
each MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to
zero, and the receiver MUST ignore them. No padding is required following the last data element.

A **FILE_ID_GLOBAL_TX_DIR_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  LastWriteTime (32 bits)
  ChangeTime (32 bits)
  EndOfFile (32 bits)
  AllocationSize (32 bits)
  FileAttributes (32 bits)
  FileNameLength (32 bits)
  FileId (32 bits)
  LockingTransactionId (16 bytes) (32 bits)
  ...
```
**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_ID_GLOBAL_TX_DIR_INFORMATION entry is
located, if multiple entries are present in a buffer. This member MUST be zero if no other entries
follow this one. An implementation MUST use this value to determine the location of the next entry
(if multiple entries are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<131>

**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written to the file; see section 2.1.1. The

value of this field MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. The value of this field

MUST be greater than or equal to 0.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. **EndOfFile** specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the **cluster** size.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**FileId (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, for the file. For file systems that do

not support a 64-bit file ID, this field MUST be set to 0, and MUST be ignored. For file systems
which do not explicitly store directory entries named ".." (synonymous with the parent directory),
an implementation MAY set this field to 0 for the entry named "..", and this value MUST be
ignored.<132>

**LockingTransactionId (16 bytes):** A **GUID** value that is the ID of the transaction that has this file

locked for modification. This number is generated and assigned by the file system. If the
FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_WRITELOCKED flag is not set in the **TxInfoFlags** field,
this field MUST be ignored.
**TxInfoFlags (4 bytes):** A 32-bit unsigned integer that contains a bitmask of flags that indicate the

transactional visibility of the file. The value of this field MUST be a bitwise OR of zero or more of
the following values. Any flag values not explicitly mentioned here can be set to any value and
MUST be ignored. If the FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_WRITELOCKED flag is not set, the
other flags MUST NOT be set. If flags other than
FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_WRITELOCKED are set,
FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_WRITELOCKED MUST be set.

|Value|Meaning|
|---|---|
|FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_WRITELOCKED<br>0x00000001|The file is locked for modification by a<br>transaction. The transaction's ID MUST be<br>contained in the**LockingTransactionId** <br>field if this flag is set.|
|FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_VISIBLE_TO_TX<br>0x00000002|The file is visible to transacted enumerators<br>of the directory whose transaction ID is in<br>the**LockingTransactionId** field.|
|FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_VISIBLE_OUTSIDE_TX<br>0x00000004|The file is visible to transacted enumerators<br>of the directory other than the one whose<br>transaction ID is in the<br>**LockingTransactionId** field, and it is visible<br>to non-transacted enumerators of the<br>directory.|

**FileName (variable):** A sequence of Unicode characters containing the file name. When working with

this field, use **FileNameLength** to determine the length of the file name rather than assuming the
presence of a trailing null delimiter. Dot directory names are valid for this field. For more details,
see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The request is not supported.|

**2.4.33** **FileNamesInformation**

This information class is used in directory enumeration to return detailed information about the
contents of a directory.

This information class returns a list that contains a **FILE_NAMES_INFORMATION** data element for
each file or directory within the target directory.

When multiple **FILE_NAMES_INFORMATION** data elements are present in the buffer, each MUST be
aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to zero, and the
receiver MUST ignore them. No padding is required following the last data element.

A **FILE_NAMES_INFORMATION** data element is as follows.

```
  NextEntryOffset (32 bits)
  FileIndex (32 bits)
  FileNameLength (32 bits)
  FileName (variable) (32 bits)
  ...
```
**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that contains the byte offset from the

beginning of this entry, at which the next FILE_NAMES_INFORMATION entry is located, if multiple
entries are present in a buffer. This member MUST be zero if no other entries follow this one. An
implementation MUST use this value to determine the location of the next entry (if multiple entries
are present in a buffer).

**FileIndex (4 bytes):** A 32-bit unsigned integer that contains the byte offset of the file within the

parent directory. For file systems in which the position of a file within the parent directory is not
fixed and can be changed at any time to maintain sort order, this field SHOULD be set to 0 and
MUST be ignored.<137>

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** member.

**FileName (variable):** A sequence of Unicode characters containing the file name. When working

with this field, use **FileNameLength** to determine the length of the file name rather than
assuming the presence of a trailing null delimiter. Dot directory names are valid for this field. For
more details, see section 2.1.5.1.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.34** **FileNetworkOpenInformation**

This information class is used to query for information that is commonly needed when a file is opened
across a network.<138>

A **FILE_NETWORK_OPEN_INFORMATION** data element, defined as follows, is returned by the
server.

```
  CreationTime (32 bits)
  LastAccessTime (32 bits)
  LastWriteTime (32 bits)
  ChangeTime (32 bits)
  ...
```
**CreationTime (8 bytes):** The time when the file was created; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastAccessTime (8 bytes):** The last time the file was accessed; see section 2.1.1. The value of this

field MUST be greater than or equal to 0.

**LastWriteTime (8 bytes):** The last time information was written to the file; see section 2.1.1. The

value of this field MUST be greater than or equal to 0.

**ChangeTime (8 bytes):** The last time the file was changed; see section 2.1.1. The value of this field

MUST be greater than or equal to 0.

**AllocationSize (8 bytes):** A 64-bit signed integer that contains the file allocation size, in bytes. The

value of this field MUST be an integer multiple of the **cluster** size.

**EndOfFile (8 bytes):** A 64-bit signed integer that contains the absolute new end-of-file position as a

byte offset from the start of the file. EndOfFile specifies the offset to the byte immediately
following the last valid byte in the file. Because this value is zero-based, it actually refers to the
first free byte in the file. That is, it is the offset from the beginning of the file at which new bytes
appended to the file will be written. The value of this field MUST be greater than or equal to 0.

**FileAttributes (4 bytes):** A 32-bit unsigned integer that contains the file attributes. Valid attributes

are as specified in section 2.6.

**Reserved (4 bytes):** A 32-bit field. This field is reserved. This field can be set to any value and MUST

be ignored.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened to read file data or file attributes.|
