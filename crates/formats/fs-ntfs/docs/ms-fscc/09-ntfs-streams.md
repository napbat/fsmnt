<!-- MS-FSCC Reference: NTFS Alternate Streams (Appendix A) -->
<!-- NTFS stream types, attribute types ($STANDARD_INFORMATION, $FILE_NAME, $DATA, $INDEX_ROOT, $INDEX_ALLOCATION, $BITMAP, $REPARSE_POINT, $EA, $EA_INFORMATION, $LOGGED_UTILITY_STREAM, $ATTRIBUTE_LIST), reserved filenames ($MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, $Bitmap, $Boot, $BadClus, $Secure, $UpCase, $Extend), stream naming rules, and known alternate stream names. -->

**5** **Appendix A: NTFS Alternate Streams**

**5.1** **NTFS Streams**

All files on an NTFS volume consist of at least one stream - the main stream – this is the normal,
viewable file in which data is stored. The full name of a stream is of the form below.

<filename>:<stream name>:<stream type>

The default data stream has no name. That is, the fully qualified name for the default stream for a file
called "sample.txt" is "sample.txt::$DATA" since "sample.txt" is the name of the file and "$DATA" is
the stream type.

A user can create a named stream in a file and "$DATA" as a legal name. That means that for this
stream, the full name is sample.txt:$DATA:$DATA. If the user had created a named stream of name
"bar", its full name would be sample.txt:bar:$DATA. Any legal characters for a file name are legal for
the stream name (including spaces). For more information about the naming format for streams, see

[MS-FSCC]. For more information about the attributes of a stream, see [MS-FSA].

In the case of directories, there is no default data stream, but there is a default directory stream.
Directories are the stream type $INDEX_ALLOCATION. The default stream name for the type
$INDEX_ALLOCATION (a directory stream) is $I30. (This contrasts with the default stream name for a
$DATA stream, which has an empty stream name.) The following are equivalent:

Dir C:\Users

Dir C:\Users:$I30:$INDEX_ALLOCATION

Dir C:\Users::$INDEX_ALLOCATION

Although directories do not have a default data stream, they can have named data streams. These
alternate data streams are not normally visible, but can be observed from a command line using the
/R option of the DIR command.

**5.2** **NTFS Attribute Types**

On a NTFS volume, each unit of information associated with a file including its name, its owner, its
timestamp, its contents, and so on, is implemented as a file attribute. A file's data is an attribute; the
"Data Attribute" known as $DATA. A number of attributes exist on a NTFS volume. The attribute
names used by NTFS are listed in the table below.

|Attribute Name|Description|
|---|---|
|$ATTRIBUTE_LIST|Lists the location of all attribute records that do not fit in the MFT record|
|$BITMAP|Attribute for Bitmaps|
|$DATA|Contains the default file data|
|$EA|Extended the attribute index|
|$EA_INFORMATION|Extended attribute information|
|$FILE_NAME|File name|
|$INDEX_ALLOCATION|The type name for a Directory Stream. A string for the attribute code for index<br>allocation|
|$INDEX_ROOT|Used to support folders and other indexes|
|Attribute Name|Description|
|---|---|
|$LOGGED_UTILITY_STREAM|Use by the encrypting file system|
|$OBJECT_ID|Unique**GUID** for every MFT record|
|$PROPERTY_SET|Obsolete|
|$REPARSE_POINT|Used for volume mount points|
|$SECURITY_DESCRIPTOR|Security descriptor stores**ACL** and**SIDs**|
|$STANDARD_INFORMATION|Standard information, such as file times and quota data|
|$SYMBOLIC_LINK|Obsolete|
|$TXF_DATA|Transactional NTFS data|
|$VOLUME_INFORMATION|Version and state of the volume|
|$VOLUME_NAME|Name of the volume|
|$VOLUME_VERSION|Obsolete. Volume version|

A comprehensive discussion and explanation about attributes is available in [WININTERNALS]
Chapter 12 and [[MSFT-NTFSWorks].](https://go.microsoft.com/fwlink/?LinkId=168880)

**5.3** **NTFS Reserved File Names**

NTFS uses a number of names as part of the file system internals. The names used by NTFS within the
root directory are listed in the following table:

|Filename|Description|
|---|---|
|\$Mft|Master File Table (MFT) - an index of every file|
|\$MftMirr|A backup copy of the first 4 records of the MFT|
|\$LogFile|Transactional logging file|
|\$Volume|Serial number, creation time, dirty flag|
|\$AttrDef|Attribute definitions|
|\$Bitmap|Contains the volume's cluster map (in-use vs. free)|
|\$Boot|Boot record of the volume|
|\$BadClus|Lists bad clusters on the volume|
|\$Secure|Security descriptors used by the volume|
|\$UpCase|Table of uppercase characters used for collating|
|\$Extend|A directory|

An additional set of names are found in the system directory as follows:

|Filename|Description|
|---|---|
|\$Extend\$Config|Use for NTFS repair activity|
|Filename|Description|
|---|---|
|\$Extend\$Delete|Delete file name|
|\$Extend\$ObjId|Unique Ids given to every file|
|\$Extend\$Quota|Quota information|
|\$Extend\$Repair|Repair name|
|\$Extend\$Repair.log|Repair log name|
|\$Extend\$Reparse|Reparse point information|
|\$Extend\$RmMetadata|Transactional NTFS resource manager metadata name|
|\$Extend\$Tops|Transactional NTFS Old Page Stream, used to store data that has been overwritten<br>inside a currently active transaction|
|\$Extend\$Txf|Transactional NTFS|
|\$Extend\$TxfLog|Transactional NTFS log|

**5.4** **NTFS Stream Names**

NTFS by convention uses names starting with '$' for internal metadata files and streams on those
internal metadata files. There is no mechanism to stop applications from using names of this form;
therefore, it is recommended that names of this form not be used internally by an object store for a
server environment except when emulating NTFS metadata streams such as
"\$Extend\$Quota:$Q:$INDEX_ALLOCATION" or "\$Extend\$Reparse:$R:$INDEX_ALLOCATION".

Stream Names currently used by NTFS are as follows:

|NTFS Internal Stream Names|Example|
|---|---|
|$I30|Default name for directory streams C:\Users:$I30:$INDEX_ALLOCATION|
|$O|\$Extend\$ObjId:$O:$INDEX_ALLOCATION|
|$Q|\$Extend\$Quota:$Q:$INDEX_ALLOCATION|
|$R|\$Extend\$Reparse:$R:$INDEX_ALLOCATION|
|$J|\$Extend\$UsnJrnl:$J:$DATA|
|$MAX|\$Extend\$UsnJrnl:$MAX:$DATA|
|$SDH|\$Secure:$SDH:$INDEX_ALLOCATION|
|$SII|\$Secure:$SII:$INDEX_ALLOCATION|

**5.5** **NTFS Stream Types**

Names currently used are as follows:
**5.6** **Known Alternate Stream Names**

Selection of an alternate stream name, is in principle, identical to selection of a filename. An
application might need to check whether a name is in use prior to attempting to use a name. When an
application has successfully avoided a file name conflict, it has complete control over any stream
names that it might wish to use. It is advisable to use textual **GUID** ( **GUIDString** ) as stream names
in order to avoid conflicts. Injection of streams into files that an application does not completely own
has the potential to cause unpredictable behavior and can be flagged by virus scanning software.

**5.6.1** **Zone.Identifier Stream Name**

Windows Internet Explorer uses the stream name Zone.Identifier for storage of **URL** security zones.

The fully qualified form is sample.txt: Zone.Identifier:$DATA

The stream is a simple text stream of the form:

[ZoneTransfer]

ZoneId=3

[[MSDN-SECZONES]](https://go.microsoft.com/fwlink/?LinkId=90660) gives an explanation of security zones.

**5.6.2** **Outlook Express Properties Stream Name**

Outlook Express uses the stream name OECustomProperty for storage of custom properties related to
email files.

The fully qualified form is sample.eml:OECustomProperty:$DATA

**5.6.3** **Document Properties Stream Name**

Property sets, when applied to files, use a number of different stream names. The initial character is
Unicode U+2663, known as (BLACK CLUB).

The names "♣ BnhqlkugBim0elg1M1pt2tjdZe", "♣ SummaryInformation" and the **GUID** {4c8cc1556c1e-11d1-8e41-00c04fb9386d} are used.

The fully qualified names would be as follows:

sample.doc:♣ BnhqlkugBim0elg1M1pt2tjdZe:$DATA

sample.doc:♣ SummaryInformation:$DATA

sample.gif:{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}:$DATA
**5.6.4** **Encryptable Thumbnails Stream Name**

Windows Shell uses the stream name "encryptable" to store attributes relating to thumbnails in the
thumbnails database.

The fully qualified name would be as follows:

Thumbs.db:encryptable:$DATA

**5.6.5** **Internet Explorer Favicon Stream Name**

Internet Explorer uses the stream name "favicon" for storing favorite ICONs for web pages.

The fully qualified name would be as follows:

Pages.url:favicon:$DATA

**5.6.6** **Macintosh Supported Stream Names**

Two stream names exist for compatibility with Macintosh operating system property lists. These
names are "AFP_AfpInfo" and "AFP_Resource".

The fully qualified name would be as follows:

Sample.txt:AFP_AfpInfo:$DATA

Sample.txt:AFP_Resource:$DATA

**5.6.7** **XPRESS Stream Name**

The stream name "{59828bbb-3f72-4c1b-a420-b51ad66eb5d3}.XPRESS" is used during remote
differential compression.

The fully qualified name would be as follows:

Sample.bin: {59828bbb-3f72-4c1b-a420-b51ad66eb5d3}.XPRESS:$DATA
