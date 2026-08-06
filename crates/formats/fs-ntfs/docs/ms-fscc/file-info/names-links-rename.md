<!-- MS-FSCC: Names, Links, Rename, Disposition -->
<!-- FileAlternateNameInformation, FileNameInformation, FileNormalizedNameInformation, FileShortNameInformation, FileDispositionInformation/Ex, FileHardLinkInformation, FileLinkInformation (SMB/SMB2), FileRenameInformation/Ex (SMB/SMB2). -->

**2.4.5** **FileAlternateNameInformation**

This information class is used to query **alternate name** information for a file. The alternate name for
a file is its **8.3** format name (eight characters that appear before the "." and three characters that
appear after). A file MAY have an alternate name to achieve compatibility with the 8.3 naming
requirements of legacy applications.<103>

A FILE_NAME_INFORMATION (section 2.1.7) data element containing an 8.3 file name (section
2.1.5.2.1) is returned by the server.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_OBJECT_NAME_NOT_FOUND<br>0xC0000034|The object name is not found or is empty.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before the complete name could be returned.|

**2.4.32** **FileNameInformation**

This information class is used locally to query the name of a file. This information class returns a
**FILE_NAME_INFORMATION** data element containing an absolute pathname (section 2.1.5).

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The resource is not supported.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before the complete name could be returned.|

**2.4.35** **FileNormalizedNameInformation**

This information class is used to query the normalized name of a file. A normalized name is an
absolute pathname where each short name component has been replaced with the corresponding long
name component, and each name component uses the exact letter casing stored on disk. This
information class returns a FILE_NAME_INFORMATION data element containing an absolute
pathname, as specified in section 2.1.7. <139>

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error Code|Meaning|
|---|---|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The resource is not supported.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before the complete name<br>could be returned.|

**2.4.46** **FileShortNameInformation**

This information class is used to change a file's **short name** . If the supplied name is of zero length,
the file's existing short name, if any, SHOULD<155> be deleted. Otherwise, the supplied name MUST
be a valid short name as specified in section 2.1.5.2.1 and be unique among all file names and short
names in the same directory as the file being operated on. A caller changing the file's short name
MUST have SeRestorePrivilege, as specified in [MS-LSAD] section 3.1.1.2.1.

A FILE_NAME_INFORMATION (section 2.1.7) data element containing an 8.3 file name (section
2.1.5.2.1) is provided by the client.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_MEDIA_WRITE_PROTECTED<br>0xC00000A2|The target cannot be written to because it is write-<br>protected.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The file name is not a valid parameter.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened to write file data or file<br>attributes, or the file has been deleted.|
|STATUS_PRIVILEGE_NOT_HELD<br>0xC0000061|The SeRestorePrivilege privilege is not held.|
|STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME<br>0xC000019F|Short names are not enabled on this volume.|
|STATUS_OBJECT_NAME_COLLISION<br>0xC0000035|The specified name already exists.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match<br>the length that is required for the specified information<br>class.|

**2.4.11** **FileDispositionInformation**

This information class is used to mark a file for deletion.

A **FILE_DISPOSITION_INFORMATION** data element, defined as follows, is provided by the client.

```
```
|DeletePending|DeletePending|DeletePending|DeletePending|DeletePending|DeletePending|DeletePending|DeletePending|||||||||||||||||||||||||

**DeletePending (1 byte):** An 8-bit field that is set to 1 to indicate that a file SHOULD be deleted

when it is closed; otherwise, 0 which means the file SHOULD NOT be deleted.<114>

[For a discussion of file deletion semantics, see [FSBO].](https://go.microsoft.com/fwlink/?LinkId=140636)

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened with delete access.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_DIRECTORY_NOT_EMPTY<br>0xC0000101|Indicates that the directory trying to be deleted is not empty.|

**2.4.12** **FileDispositionInformationEx**

This information class is used to mark a file for deletion.

A **FILE_DISPOSITION_INFORMATION_EX** data element, defined as follows, is provided by the
client.

```
  Flags (32 bits)
```
**Flags (4 bytes):** A 32-bit field that specifies options on how the file is deleted.

This field contains one or more of the values in the following table.

|Value|Meaning|
|---|---|
|FILE_DISPOSITION_DO_NOT_DELETE_FILE<br>0x00000000|If no flag is set, the file MUST NOT be deleted.|
|FILE_DISPOSITION_DELETE<br>0x00000001|If set, indicates the file SHOULD be deleted.|
|FILE_DISPOSITION_POSIX_SEMANTICS<br>0x00000002|If set and FILE_DISPOSITION_DELETE is set,<br>indicates the file SHOULD be deleted using POSIX-<br>style semantics. This means the link is removed from<br>the visible namespace as soon as the POSIX delete<br>handle is closed, but the file's data streams remain<br>accessible by other existing handles.|
|FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK<br>0x00000004|If set, indicates the system SHOULD fail deleting the<br>file if an image section exists. If not set and the<br>FILE_DISPOSITION_POSIX_SEMANTICS flag is set;<br>indicates the file can be deleted even if it has an<br>image section. This flag was added to support<br>backward compatibility with the existing behavior of<br>the FileDispositionInformation (see section2.4.11) <br>operation.|
|FILE_DISPOSITION_ON_CLOSE<br>0x00000008|If set and the<br>FILE_DISPOSITION_POSIX_SEMANTICS flag is set;<br>the file FILE_DELETE_ON_CLOSE state is updated to<br>specify POSIX-style delete semantics.<br>If set and the<br>FILE_DISPOSITION_POSIX_SEMANTICS flag is**not** <br>set; the file FILE_DELETE_ON_CLOSE state is<br>updated to**not** specify POSIX-style delete semantics.<br>If set and the file is not opened with<br>FILE_DELETE_ON_CLOSE, STATUS_NOT_SUPPORTED<br>MUST be returned.|
|FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE<br>0x00000010|If set, allows files with the READ_ONLY attribute to<br>be deleted anyway.  Without this flag, deleting a<br>read-only file MUST return<br>STATUS_CANNOT_DELETE.|

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened with delete access.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_DIRECTORY_NOT_EMPTY<br>0xC0000101|Indicates that the directory trying to be deleted is not empty.|
|STATUS_CANNOT_DELETE|An attempt has been made to remove a file or directory that cannot be|
|Error code|Meaning|
|---|---|
|0xC0000121|deleted.|

**2.4.17** **FileHardLinkInformation**

This information class is used locally to query hard links to an existing file.<116> At least one name
MUST be returned.

A **FILE_LINKS_INFORMATION** data element, defined as follows, is returned to the caller.

```
  BytesNeeded (32 bits)
  EntriesReturned (32 bits)
  Entries (variable) (32 bits)
  ...
```

**BytesNeeded (4 bytes):** A 32-bit unsigned integer that MUST contain the number of bytes needed

to hold all available names. This field MUST NOT be 0.

**EntriesReturned (4 bytes):** A 32-bit unsigned integer that MUST contain the number of

FILE_LINK_ENTRY_INFORMATION structures that have been returned in the **Entries** field.

The query MUST return as many entries as will fit in the supplied output buffer. A value of
0x00000000 for this field indicates that there is insufficient room to return any entry. The error
STATUS_BUFFER_OVERFLOW (0x80000005) indicates that not all available entries were returned.

**Entries (variable):** A buffer that MUST contain the returned FILE_LINK_ENTRY_INFORMATION

structures. It MUST be **BytesNeeded** bytes in size to return all of the available entries.
This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The request is not supported.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer was filled before all of the link information could be<br>returned. Only complete FILE_LINK_ENTRY_INFORMATION structures are<br>returned.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.17.1** **FILE_LINK_ENTRY_INFORMATION**

The **FILE_LINK_ENTRY_INFORMATION** packet is used to describe a single hard link to an existing
file.

When multiple **FILE_LINK_ENTRY_INFORMATION** data elements are present in the buffer, each
MUST be aligned on an 8-byte boundary. Any bytes inserted for alignment SHOULD be set to zero,
and the receiver MUST ignore them. No padding is required following the last data element.

```
  NextEntryOffset (32 bits)
  ParentFileId (32 bits)
  FileNameLength (32 bits)
  FileName (variable) (32 bits)
  ...
```

**NextEntryOffset (4 bytes):** A 32-bit unsigned integer that MUST specify the offset, in bytes, from

the current **FILE_LINK_ENTRY_INFORMATION** structure to the next
**FILE_LINK_ENTRY_INFORMATION** structure. A value of 0 indicates this is the last entry
structure.

**ParentFileId (8 bytes):** The 64-bit file ID, as specified in section 2.1.9, of the parent directory of the

given link. For file systems which do not support a 64-bit file ID, this field MUST be set to 0, and
MUST be ignored.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that MUST specify the length, in characters,

of the **FileName** for the given link.

**FileName (variable):** A sequence of **FileNameLength** **Unicode characters** that MUST contain the

Unicode string name of the given link.
**2.4.28** **FileLinkInformation**

This information class is used to create a hard link to an existing file.<134> The Server Message Block
(SMB) Protocol [MS-SMB] and the Server Message Block (SMB) Version 2 Protocol [MS-SMB2]
implement unique structure variants:

- **FILE_LINK_INFORMATION_TYPE_1**, as specified in section 2.4.28.1.

- **FILE_LINK_INFORMATION_TYPE_2**, as specified in section 2.4.28.2.

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|An invalid parameter was specified for the**RootDirectory** field.|
|STATUS_FILE_IS_A_DIRECTORY<br>0xC00000BA|The file that was specified is a directory.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The object has been deleted.|
|STATUS_OBJECT_NAME_INVALID<br>0xC0000033|The object name is invalid for the target file system.|
|STATUS_TOO_MANY_LINKS<br>0xC0000265|An attempt was made to create more links on a file than the file system<br>supports.|
|STATUS_OBJECT_NAME_COLLISION<br>0xC0000035|The specified name already exists and**ReplaceIfExists** is zero.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|
|STATUS_NOT_SUPPORTED<br>0xC00000BB|The request is not supported.|

**2.4.28.1** **FileLinkInformation for the SMB Protocol**

This information class is used to create a hard link to an existing file via the SMB Protocol as specified
in [MS-SMB].

A **FILE_LINK_INFORMATION_TYPE_1** data element, defined as follows, is provided by the client.

```
  ReplaceIfExists (8 bits) | Reserved (24 bits)
  RootDirectory (32 bits)
  FileNameLength (32 bits)
```
**ReplaceIfExists (1 byte):** A Boolean (section 2.1.8) value. Set to TRUE to indicate that if the link

already exists, it SHOULD be replaced with the new link. Set to FALSE to indicate that the link
creation operation MUST fail if the link already exists.

**Reserved (3 bytes):** This field SHOULD be set to zero by the client and MUST be ignored by the

server.

**RootDirectory (4 bytes):** A 32-bit unsigned integer that contains the file handle for the directory

where the link is to be created. For network operations, this value MUST always be zero.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that contains the length in bytes of the

**FileName** field.

**FileName (variable):** A sequence of **Unicode characters** that contains the name to be assigned to

the newly created link. When working with the **FileName** field, the **FileNameLength** field is used
to determine the length of the file name rather than assuming the presence of a trailing null
delimiter. If the **RootDirectory** field is zero, this field MUST specify a full pathname to the link to
be created. For network operations, this pathname is relative to the root of the share. If the
**RootDirectory** field is not zero, this field MUST specify a pathname, relative to **RootDirectory**,
for the link name.

**2.4.28.2** **FileLinkInformation for the SMB2 Protocol**

This information class is used to create a hard link to an existing file via the SMB Version 2 Protocol,
as specified in [MS-SMB2].

A **FILE_LINK_INFORMATION_TYPE_2** data element, defined as follows, is provided by the client.

```
  ReplaceIfExists (8 bits) | Reserved (24 bits)
  RootDirectory (32 bits)
  FileNameLength (32 bits)
  FileName (variable) (32 bits)
  ...
```

**ReplaceIfExists (1 byte):** A Boolean (section 2.1.8) value. Set to TRUE to indicate that if the link

already exists, it SHOULD be replaced with the new link. Set to FALSE to indicate that the link
creation operation MUST fail if the link already exists.

**Reserved (7 bytes):** Reserved for alignment. This field can contain any value and MUST be ignored.
**RootDirectory (8 bytes):** A 64-bit unsigned integer that contains the file handle for the directory

where the link is to be created. For network operations, this value MUST be zero.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length in bytes of the file

name contained within the **FileName** field.

**FileName (variable):** A sequence of **Unicode characters** containing the name to be assigned to the

newly created link. When working with this field, the **FileNameLength** field is used to determine
the length of the file name rather than assuming the presence of a trailing null delimiter. If the
**RootDirectory** field is zero, this field MUST specify a full pathname to the link to be created. For
network operations, this pathname is relative to the root of the share. If the **RootDirectory** field
is not zero, this field MUST specify a pathname, relative to **RootDirectory**, for the link name.

**2.4.42** **FileRenameInformation**

This information class is used to rename a file. The data element provided by the client takes one of
two forms, depending on whether it is embedded within SMB or SMB2. The structure definitions are as
follows:

- FILE_RENAME_INFORMATION_TYPE_1 for the SMB protocol (section 2.4.42.1).

- FILE_RENAME_INFORMATION_TYPE_2 for the SMB2 protocol (section 2.4.42.2).

This operation returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this file information class is STATUS_SUCCESS. The most
common error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|An invalid parameter was passed for**FileName** or**FileNameLength**, or<br>the**RootDirectory** field value was nonzero for a network operation.|
|STATUS_ACCESS_DENIED<br>0xC0000022|The handle was not opened with delete access, or the target file was open<br>and**ReplaceIfExists** is nonzero.|
|STATUS_NOT_SAME_DEVICE<br>0xC00000D4|The destination file of a rename request is located on a different device<br>than the source of the rename request.|
|STATUS_OBJECT_NAME_INVALID<br>0xC0000033|The object name is invalid for the target file system.|
|STATUS_OBJECT_NAME_COLLISION<br>0xC0000035|The specified name already exists and**ReplaceIfExists** is zero.|
|STATUS_INFO_LENGTH_MISMATCH<br>0xC0000004|The specified information record length does not match the length that is<br>required for the specified information class.|

**2.4.42.1** **FileRenameInformation for SMB**

This information class is used to rename a file from within the SMB Protocol, as specified in [MS-SMB].

A **FILE_RENAME_INFORMATION_TYPE_1** data element, defined as follows, is provided by the
client.

```
  ReplaceIfExists (8 bits) | Reserved (24 bits)
  RootDirectory (32 bits)
  FileNameLength (32 bits)
  FileName (variable) (32 bits)
  ...
```
**ReplaceIfExists (1 byte):** A Boolean (section 2.1.8) value. Set to TRUE to indicate that if a file with

the given name already exists, it SHOULD be replaced with the given file. Set to FALSE to indicate
that the rename operation MUST fail if a file with the given name already exists.

**Reserved (3 bytes):** Reserved area for alignment. This field can contain any value and MUST be

ignored.

**RootDirectory (4 bytes):** A 32-bit unsigned integer that contains the file handle for the directory to

which the new name of the file is relative. For network operations, this value MUST be zero.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** field.

**FileName (variable):** A sequence of **Unicode characters** containing the new file name of type

**Filename** (section 2.1.5.2). When working with this field, use **FileNameLength** to determine the
length of the file name rather than assuming the presence of a trailing null delimiter.

**2.4.42.2** **FileRenameInformation for SMB2**

This information class is used to rename a file from within the SMB2 Protocol [MS-SMB2].

A **FILE_RENAME_INFORMATION_TYPE_2** data element, defined as follows, is provided by the
client.

```
  ReplaceIfExists (8 bits) | Reserved (24 bits)
  RootDirectory (32 bits)
  FileNameLength (32 bits)
  FileName (variable) (32 bits)
  Padding (variable) (32 bits)
  ...
```

**ReplaceIfExists (1 byte):** A Boolean (section 2.1.8) value. Set to TRUE to indicate that if a file with

the given name already exists, it SHOULD be replaced with the given file. Set to FALSE to indicate
that the rename operation MUST fail if a file with the given name already exists.

**Reserved (7 bytes):** Reserved area for alignment. This field can contain any value and MUST be

ignored.

**RootDirectory (8 bytes):** A 64-bit unsigned integer that contains the file handle for the directory to

which the new name of the file is relative. For network operations, this value MUST always be
zero.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** field.
**FileName (variable):** A sequence of **Unicode characters** containing the new name of the file. When

working with this field, use **FileNameLength** to determine the length of the file name rather than
assuming the presence of a trailing null delimiter.

**Padding (variable):** Length of this field MUST be the number of bytes required to make the size of

this structure at least 24. This field MAY be set to 0 and MUST be ignored on receipt.

**2.4.43** **FileRenameInformationEx**

This information class is used to rename a file.

A **FILE_RENAME_INFORMATION_EX** data element, defined as follows, is provided by the client.

```
  Flags (32 bits)
  Reserved (32 bits)
  RootDirectory (32 bits)
  FileNameLength (32 bits)
  FileName (variable) (32 bits)
  Padding (variable) (32 bits)
  ...
```

**Flags (4 bytes):** A 32-bit field that specifies options on how the file is renamed.

This field contains one or more of the values in the following table.

|Value|Meaning|
|---|---|
|FILE_RENAME_REPLACE_IF_EXISTS<br>0x00000001|If set, indicates that if a file with the given name<br>already exists, it SHOULD be replaced with the given<br>file. If not set, indicates that the rename operation<br>MUST fail if a file with the given name already exists.|
|FILE_RENAME_POSIX_SEMANTICS<br>0x00000002|If set and FILE_RENAME_REPLACE_IF_EXISTS is set,<br>indicates that if a file with the given name already<br>exists the file SHOULD be deleted using POSIX-style<br>semantics. Existing handles to the replaced file<br>continue to be valid. Any subsequent opens of the<br>target name will open the renamed file, not the<br>replaced file.|
|FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE<br>0x00000004|If set, when renaming a file to a new directory,<br>suppress any inheritance rules related to the<br>FILE_ATTRIBUTE_PINNED and|
|Value|Meaning|
|---|---|
||FILE_ATTRIBUTE_UNPINNED attributes.<146>|
|FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERI<br>TANCE<br>0x00000008|If set, when renaming a file to a new directory, it<br>suppresses any inheritance rules related to the storage<br>reserve ID property of the file.<147>|
|FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE<br>0x00000010|If set and<br>FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERI<br>TANCE is not set; when renaming a file to a new<br>directory, automatically resize affected storage reserve<br>areas as needed to prevent the user visible free space<br>on the volume from increasing. Requires manage<br>volume access.<148>|
|FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE<br>0x00000020|if set and<br>FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERI<br>TANCE is not set; when renaming a file to a new<br>directory, automatically resize affected storage reserve<br>areas as needed to prevent the user visible free space<br>on the volume from decreasing. Requires manage<br>volume access.<149>|
|FILE_RENAME_PRESERVE_AVAILABLE_SPACE<br>0x00000030|Equivalent to specifying both<br>FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE and<br>FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE.<15<br>0>|
|FILE_RENAME_IGNORE_READONLY_ATTRIBUTE<br>0x00000040|If set and FILE_RENAME_REPLACE_IF_EXISTS is set;<br>allow replacing a file even if the read-only attribute is<br>set on the file.<151>|
|FILE_RENAME_FORCE_RESIZE_TARGET_SR<br>0x00000080|If set and<br>FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERI<br>TANCE is not set; when renaming a file to a new<br>directory that is part of a different storage reserve<br>area, always grow the target directory's storage<br>reserve area by the full size of the file being renamed.<br>Requires manage volume access.<152>|
|FILE_RENAME_FORCE_RESIZE_SOURCE_SR<br>0x00000100|If set and<br>FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERI<br>TANCE is not set; when renaming a file to a new<br>directory that is part of a different storage reserve<br>area, always shrink the source directory's storage<br>reserve area by the full size of the file being renamed.<br>Requires manage volume access.<153>|
|FILE_RENAME_FORCE_RESIZE_SR<br>0x00000180|Equivalent to specifying both<br>FILE_RENAME_FORCE_RESIZE_TARGET_SR and<br>FILE_RENAME_FORCE_RESIZE_SOURCE_SR.<154>|

**Reserved (4 bytes):** Reserved area for alignment. This field can contain any value and MUST be

ignored.

**RootDirectory (8 bytes):** A 64-bit unsigned integer that contains the file handle for the directory to

which the new name of the file is relative. For network operations, this value MUST always be
zero.

**FileNameLength (4 bytes):** A 32-bit unsigned integer that specifies the length, in bytes, of the file

name contained within the **FileName** field.
**FileName (variable):** A sequence of **Unicode characters** containing the new name of the file. When

working with this field, use **FileNameLength** to determine the length of the file name rather than
assuming the presence of a trailing null delimiter.

**Padding (variable):** Length of this field MUST be the number of bytes required to make the size of

this structure at least 24. This field MAY be set to 0 and MUST be ignored on receipt.
