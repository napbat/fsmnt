<!-- MS-FSCC Reference: File Attributes -->
<!-- FILE_ATTRIBUTE_* flag definitions and values. READONLY, HIDDEN, SYSTEM, DIRECTORY, ARCHIVE, NORMAL, TEMPORARY, SPARSE_FILE, REPARSE_POINT, COMPRESSED, OFFLINE, NOT_CONTENT_INDEXED, ENCRYPTED, INTEGRITY_STREAM, NO_SCRUB_DATA, RECALL_ON_OPEN, PINNED, UNPINNED, RECALL_ON_DATA_ACCESS. -->

**2.6** **File Attributes**

The following attributes are defined for files and directories. They can be used in any combination
unless noted in the description of the attribute's meaning. There is no file attribute with the value
0x00000000 because a value of 0x00000000 in the **FileAttributes** field means that the file attributes
for this file MUST NOT be changed when setting basic information for the file.

**Note** : File systems silently ignore any attribute that is not supported by that file system.
Unsupported attributes MUST NOT be persisted on the media. It is recommended that unsupported
attributes be masked off when encountered.

|Value|Meaning|
|---|---|
|FILE_ATTRIBUTE_READONLY<br>0x00000001|A file or directory that is read-only. For a file, applications can<br>read the file but cannot write to it or delete it. For a directory,<br>applications cannot delete it, but applications can create and|
|Value|Meaning|
|---|---|
||delete files from that directory.|
|FILE_ATTRIBUTE_HIDDEN<br>0x00000002|A file or directory that is hidden. Files and directories marked<br>with this attribute do not appear in an ordinary directory listing.|
|FILE_ATTRIBUTE_SYSTEM<br>0x00000004|A file or directory that the operating system uses a part of or<br>uses exclusively.|
|FILE_ATTRIBUTE_DIRECTORY<br>0x00000010|This item is a directory.|
|FILE_ATTRIBUTE_ARCHIVE<br>0x00000020|A file or directory that requires to be archived. Applications use<br>this attribute to mark files for backup or removal.|
|FILE_ATTRIBUTE_NORMAL<br>0x00000080|A file that does not have other attributes set. This flag is used to<br>clear all other flags by specifying it with no other flags set.<br>This flag MUST be ignored if other flags are set.<187>|
|FILE_ATTRIBUTE_TEMPORARY<br>0x00000100|A file that is being used for temporary storage. The operating<br>system can choose to store this file's data in memory rather than<br>on mass storage, writing the data to mass storage only if data<br>remains in the file when the file is closed.|
|FILE_ATTRIBUTE_SPARSE_FILE<br>0x00000200|A file that is a**sparse file**.|
|FILE_ATTRIBUTE_REPARSE_POINT<br>0x00000400|A file or directory that has an associated**reparse point**.|
|FILE_ATTRIBUTE_COMPRESSED<br>0x00000800|A file or directory that is compressed. For a file, all of the data in<br>the file is compressed. For a directory, compression is the default<br>for newly created files and subdirectories.|
|FILE_ATTRIBUTE_OFFLINE<br>0x00001000|The data in this file is not available immediately. This attribute<br>indicates that the file data is physically moved to offline storage.<br>This attribute is used by Remote Storage, which is hierarchical<br>storage management software.|
|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED<br>0x00002000|A file or directory that is not indexed by the**content indexing**<br>**service**.|
|FILE_ATTRIBUTE_ENCRYPTED<br>0x00004000|A file or directory that is encrypted. For a file, all data streams in<br>the file are encrypted. For a directory, encryption is the default<br>for newly created files and subdirectories.|
|FILE_ATTRIBUTE_INTEGRITY_STREAM<br>0x00008000|A file or directory that is configured with integrity support. For a<br>file, all data streams in the file have integrity support. For a<br>directory, integrity support is the default for newly created files<br>and subdirectories, unless the caller specifies otherwise.<188>|
|FILE_ATTRIBUTE_NO_SCRUB_DATA<br>0x00020000|A file or directory that is configured to be excluded from the data<br>integrity scan. For a directory configured with<br>FILE_ATTRIBUTE_NO_SCRUB_DATA, the default for newly<br>created files and subdirectories is to inherit the<br>**FILE_ATTRIBUTE_NO_SCRUB_DATA** attribute.<189>|
|FILE_ATTRIBUTE_RECALL_ON_OPEN<br>0x00040000|This attribute appears only in directory enumeration classes<br>(FILE_DIRECTORY_INFORMATION,<br>FILE_BOTH_DIR_INFORMATION, etc.). When this attribute is set,<br>it means that the file or directory has no physical representation<br>on the local system; the item is virtual. Opening the item will be|
|Value|Meaning|
|---|---|
||more expensive than usual because it will cause at least some of<br>the file or directory content to be fetched from a remote store.<br>This attribute can only be set by kernel-mode components. This<br>attribute is for use with hierarchical storage management<br>software.<190>|
|FILE_ATTRIBUTE_PINNED<br>0x00080000|This attribute indicates user intent that the file or directory<br>should be kept fully present locally even when not being actively<br>accessed. This attribute is for use with hierarchical storage<br>management software.<191>|
|FILE_ATTRIBUTE_UNPINNED<br>0x00100000|This attribute indicates that the file or directory should not be<br>kept fully present locally except when being actively accessed.<br>This attribute is for use with hierarchical storage management<br>software.<192>|
|FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS<br>0x00400000|When this attribute is set, it means that the file or directory is<br>not fully present locally. For a file this means that not all of its<br>data is on local storage (for example, it may be sparse with<br>some data still in remote storage). For a directory it means that<br>some of the directory contents are being virtualized from another<br>location. Reading the file or enumerating the directory will be<br>more expensive than usual because it will cause at least some of<br>the file or directory content to be fetched from a remote store.<br>Only kernel-mode callers can set this attribute. This attribute is<br>for use with hierarchical storage management software.<193>|
