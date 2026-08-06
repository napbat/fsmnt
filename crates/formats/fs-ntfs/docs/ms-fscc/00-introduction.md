<!-- MS-FSCC Reference: Introduction, Glossary, References -->
<!-- Terminology definitions, normative/informative references, spec overview. Read this first to understand terms used throughout the spec. -->

**1** **Introduction**

This specification defines the network format of native Windows structures that can be used within
other protocols. It also describes the structure of common Windows native file system control codes,
file information levels, and file system information levels that are issued in client/server and
server/server communications. These structures do not result in a protocol, but their structure is
common across multiple protocols. As such, they are placed in this document as a reference that can
be used by other protocols to ensure consistency and accuracy.

Sections 1.7 and 2 of this specification are normative. All other sections and examples in this
specification are informative.

**1.1** **Glossary**

This document uses the following terms:

**8.3 name** : A file name string restricted in length to 12 characters that includes a base name of up

to eight characters, one character for a period, and up to three characters for a file name
extension. For more information on 8.3 file names, see [MS-CIFS] section 2.2.1.1.1.

**access control list (ACL)** : A list of access control entries (ACEs) that collectively describe the

security rules for authorizing access to some resource; for example, an object or set of objects.

**alternate name** : An **8.3 name** that can optionally be generated when a file is created. A file will

not have an **alternate name** if the user wants to optimize performance, or if the name of the
file already uses the 8.3 format.

**binary large object (BLOB)** : A collection of binary data stored as a single entity in a database.

**chunk** : The amount of data that the operating system's implementation of the Lempel-Ziv

compression algorithm tries to compress at one time. The **compression unit** size used by the
file system is always a multiple of the underlying compression algorithm's chunk size. For more
information on the Lempel-Ziv compression algorithm, see [UASDC].

**cluster** : The smallest allocation unit on a **volume** .

**compression unit** : The amount of data that **NTFS** tries to compress at one time. Compression of

large files is accomplished as a series of compressions of data blocks, each at the most
compression unit bytes in size.

**compression unit shift** : The number of bits by which to left-shift a 1 bit to arrive at the

**compression unit** size.

**content indexing service** : A service that extracts content from files and constructs an indexed

catalog to facilitate efficient and rapid searching.

**disk quota** : Maximum amount of data a user can store on a disk **volume** .

**Distributed Link Tracking (DLT)** : A protocol that enables client applications to track sources that

have been sent to remote locations using remote procedure call (RPC) interfaces, and to
maintain links to files. It exposes methods that belong to two interfaces, one of which exists on
the server (trksvr) and the other on a workstation (trkwks).

**dot directory name** : In a pathname, a directory name component of "." (single period) or ".."

(two periods). For more details, see [MS-FSCC] section 2.1.5.1.

**FAT file system** : A file system used to organize and manage files. The **file allocation table**

**(FAT)** is a data structure that the operating system creates when a **volume** is formatted by
using **FAT** or FAT32 file systems. The operating system stores information about each file in the
**FAT** so that it can retrieve the file later.

**Fid** : A 16-bit value that the Server Message Block (SMB) server uses to represent an opened file,

named pipe, printer, or device. A **Fid** is returned by an SMB server in response to a client
request to open or create a file, named pipe, printer, or device. The SMB server guarantees that
the **Fid** value returned is unique for a given SMB connection until the SMB connection is closed,
at which time the **Fid** value can be reused. The **Fid** is used by the SMB client in subsequent SMB
commands to identify the opened file, named pipe, printer, or device.

**file allocation table (FAT)** : A data structure that the operating system creates when a volume is

formatted by using **FAT** or FAT32 file systems. The operating system stores information about
each file in the **FAT** so that it can retrieve the file later.

**file name component** : The portion of a file name between path separator characters (or

backslashes).

**file record segment** : A record in the **master file table** that contains attributes for a specific file

on an **NTFS** **volume** . The file record segment is always 1,024 bytes (1 kilobyte) in size.

**file stream** : See main stream and **named stream** .

**file system control (FSCTL)** : A command issued to a file system to alter or query the behavior of

the file system and/or set or query metadata that is associated with a particular file or with the
file system itself.

**filter** : Type of driver that is layered between the kernel and a base file system (such as **FAT** or

**NTFS** ) that receives I/O request packets on their way to and from the base file system. The
term **filter** can refer to legacy filters or minifilters.

**filter manager** : A file system **filter** driver that simplifies the development of other file system

**filter** drivers. Although it is possible to write a filter driver that manages other **filters**, for the
purposes of this document, the phrase **filter manager** refers only to the file system **filter**
**manager**, which is an operating system component. A **filter** driver developed to the **filter**
**manager** model is called a minifilter.

**globally unique identifier (GUID)** : A term used interchangeably with universally unique

identifier (UUID) in Microsoft protocol technical documents (TDs). Interchanging the usage of
these terms does not imply or require a specific algorithm or mechanism to generate the value.
Specifically, the use of this term does not imply or require that the algorithms described in

[[RFC4122]](https://go.microsoft.com/fwlink/?LinkId=90460) or [[C706] have to be used for generating the GUID. See also universally unique](https://go.microsoft.com/fwlink/?LinkId=89824)
identifier (UUID).

**GUIDString** : A **GUID** in the form of an ASCII or Unicode string, consisting of one group of 8

hexadecimal digits, followed by three groups of 4 hexadecimal digits each, followed by one
group of 12 hexadecimal digits. It is the standard representation of a GUID, as described in

[RFC4122] section 3. For example, "6B29FC40-CA47-1067-B31D-00DD010662DA". Unlike a
curly braced GUID string, a GUIDString is not enclosed in braces.

**I/O control (IOCTL)** : A command that is issued to a target file system or target device in order

to query or alter the behavior of the target; or to query or alter the data and attributes that are
associated with the target or the objects that are exposed by the target.

**independent software vendor (ISV)** : A company or organization that develops software

solutions that can utilize this specification.

**logical cluster number (LCN)** : The cluster number relative to the beginning of the volume. The

first cluster on a volume is zero (0).
**mailslot** : A mechanism for one-way interprocess communications (IPC). For more information, see

[[MSLOT]](https://go.microsoft.com/fwlink/?LinkId=90218) and [MS-MAIL].

**master file table (MFT)** : On an **NTFS** **volume**, the MFT is a relational database that consists of

rows of file records and columns of file attributes. It contains at least one entry for every file on
an **NTFS** **volume**, including the MFT itself. The MFT stores the information required to retrieve
files from the **NTFS** partition.

**master file table mirror (MFT2/MFTMirr)** : On an **NTFS** **volume**, the MFT2 is a redundant copy

of the first four (4) records of the **MFT** .

**named stream** : A place within a file in addition to the main stream where data is stored, or the

data stored therein. File systems support a mode in which it is possible to open either the main
stream of a file and/or to open a named stream. Named streams and the main stream each
have different data than each other and can be read and written independently. Not all file
systems support named streams. See also **stream** .

**NetBIOS name** : A 16-byte address that is used to identify a NetBIOS resource on the network.

[For more information, see [RFC1001]](https://go.microsoft.com/fwlink/?LinkId=90260) and [[RFC1002].](https://go.microsoft.com/fwlink/?LinkId=90261)

**NT file system (NTFS)** [: A proprietary Microsoft file system. For more information, see [MSFT-](https://go.microsoft.com/fwlink/?LinkId=90200)

[NTFS].](https://go.microsoft.com/fwlink/?LinkId=90200)

**Object ID** : See ObjectID.

**object identifier (OID)** : In the context of an object server, a 64-bit number that uniquely

identifies an object.

**object-oriented file system** : In the context of file system control codes, a file system that allows

the assignment of object IDs to files.

**Offload Read** : A variant to a normal read operation where a target device generates and returns a

**Token** instead of a buffer containing the data to be read. The **Token** is maintained by the
target device until it invalidates the **Token** for any vendor-specific reason. The data logically
represented by the **Token** cannot change, and the target device is required to maintain this
representation. An example of a target device is a SAN Storage Array with support for the
associated low-level storage commands. For more information on **Offload Read**, see [[INCITS-](https://go.microsoft.com/fwlink/?LinkId=239442)
[T10/11-059].](https://go.microsoft.com/fwlink/?LinkId=239442)

**Offload Write** : A variant to a normal write operation where the host provides a **Token** instead of

a buffer containing the data to be written. Upon receipt of the **Offload Write**, the target device
parses the **Token** and determines whether the data movement (the Write) can be completed to
the requested location. An example of a target device is a SAN Storage Array with support for
the associated low-level storage commands. For more information on **Offload Write**, see

[INCITS-T10/11-059].

**reparse point** : An attribute that can be added to a file to store a collection of user-defined data

that is opaque to **NTFS** or ReFS. If a file that has a reparse point is opened, the open will
normally fail with STATUS_REPARSE, so that the relevant file system **filter** driver can detect the
open of a file associated with (owned by) this reparse point. At that point, each installed **filter**
driver can check to see if it is the owner of the reparse point, and, if so, perform any special
processing required for a file with that reparse point. The format of this data is understood by
the application that stores the data and the file system **filter** that interprets the data and
processes the file. For example, an encryption **filter** that is marked as the owner of a file's
reparse point could look up the encryption key for that file. A file can have (at most) 1 reparse
point associated with it. For more information, see [MS-FSCC].

**reparse point tag** : A unique identifier for a file system **filter** driver stored within a file's optional

**reparse point** data that indicates the file system **filter** driver that performs additional filterdefined processing on a file during I/O operations. An implementer can request more than one
**reparse point** for use with a file system, a file system **filter** driver, or a minifilter driver. To
request a reparse point tag, use the reparse point tag request form. For more information, see

[[WHDC-RPTR].](https://go.microsoft.com/fwlink/?LinkId=90564)

**replica set** : In File Replication Service (FRS), the replication of files and directories according to a

predefined topology and schedule on a specific folder. The topology and schedule are collectively
called a replica set. A replica set contains a set of replicas, one for each machine that
participates in replication.

**sector** : The smallest addressable unit of a disk.

**security identifier (SID)** : An identifier for security principals that is used to identify an account

or a group. Conceptually, the **SID** is composed of an account authority portion (typically a
domain) and a smaller integer representing an identity relative to the account authority, termed
the relative identifier (RID). The **SID** format is specified in [MS-DTYP] section 2.4.2; a string
representation of **SIDs** is specified in [MS-DTYP] section 2.4.2 and [MS-AZOD] section 1.1.1.2.

**short name** : This has the same definition as **alternate name** .

**single-instance storage (SIS)** : An **NTFS** feature that implements links with the semantics of

copies for files stored on an **NTFS** **volume** . **SIS** uses copy-on-close to implement the copy
semantics of its links.

**sparse file** : A file containing large sections of data composed only of zeros. This file is marked as a

sparse file in the file system, which saves disk space by only allocating as many ranges on disk
as are required to completely reconstruct the non-zero data. When an attempt is made to read
in the nonallocated portions of the file (also known as holes), the file system automatically
returns zeros to the caller.

**stream** : A sequence of bytes written to a file on the target file system. Every file stored on a

**volume** that uses the file system contains at least one stream, which is normally used to store
the primary contents of the file. Additional streams within the file can be used to store file
attributes, application parameters, or other information specific to that file. Every file has a
default data stream, which is unnamed by default. That data stream, and any other data stream
associated with a file, can optionally be named.

**sub-read and sub-write** : An I/O operation sent by the file system to the storage stack that is

part of a larger file I/O operation. Sometimes large file reads and writes are broken down by the
file system into smaller reads and writes, which are then sent to the storage stack.

**symbolic link** : A **symbolic link** is a **reparse point** that points to another file system object. The

object being pointed to is called the target. **Symbolic links** are transparent to users; the links
appear as normal files or directories, and can be acted upon by the user or application in exactly
the same manner. **Symbolic links** can be created using the FSCTL_SET_REPARSE_POINT
request as specified in [MS-FSCC] section 2.3.81. They can be deleted using the
FSCTL_DELETE_REPARSE_POINT request as specified in [MS-FSCC] section 2.3.5. Implementing
**symbolic links** is optional for a file system.

**tag** : Another name for a **reparse point** . For instance, the file system **filter manager** FltTagFile

routine sets a **reparse point** on a file. Tag is also used to refer to the field in a **reparse point**
that identifies what software component put the **reparse point** there.

**token** : A 512-byte length opaque string that is generated and maintained by a supported target

device. A **Token** functions logically as an immutable point-in-time representation for a set of
data specified by a host and can be conceptualized as a compressed representation of the data
that only a certain class of storage subsystems can interpret. A **Token** can also be constructed
from a set of well-known **Tokens** to enable the client to describe a homogeneous attribute for a
set of data (for example, all zeros) or to enable a server to apply a homogeneous attribute to a
set of data (for example, a set of all zeros). For more information on **Tokens**, see [INCITST10/11-059].
**Unicode character** : Unless otherwise specified, a 16-bit UTF-16 code unit.

**Uniform Resource Locator (URL)** : A string of characters in a standardized format that identifies

[a document or resource on the World Wide Web. The format is as specified in [RFC1738].](https://go.microsoft.com/fwlink/?LinkId=90287)

**Universal Disk Format (UDF)** : A type of file system for storing files on optical media.

**update sequence number (USN)** : The offset from the beginning of the change journal stream

that uniquely identifies a change journal record.

**virtual cluster number (VCN)** : The cluster number relative to the beginning of the file, directory,

or **stream** within a file. The **cluster** describing byte 0 in a file is VCN 0.

**volume** : A group of one or more partitions that forms a logical region of storage and the basis for

a file system. A **volume** is an area on a storage device that is managed by the file system as a
discrete logical storage unit. A partition contains at least one **volume**, and a volume can exist
on one or more partitions.

**MAY, SHOULD, MUST, SHOULD NOT, MUST NOT:** These terms (in all caps) are used as defined

in [[RFC2119]. All statements of optional behavior use either MAY, SHOULD, or SHOULD NOT.](https://go.microsoft.com/fwlink/?LinkId=90317)

**1.2** **References**

Links to a document in the Microsoft Open Specifications library point to the correct section in the
most recently published version of the referenced document. However, because individual documents
in the library are not updated at the same time, the section numbers in the documents may not
[match. You can confirm the correct section numbering by checking the Errata.](https://go.microsoft.com/fwlink/?linkid=850906)

**1.2.1** **Normative References**

We conduct frequent surveys of the normative references to assure their continued availability. If you
[have any issue with finding a normative reference, please contact dochelp@microsoft.com. We will](mailto:dochelp@microsoft.com)
assist you in finding the relevant information.

[MS-DTYP] Microsoft Corporation, "Windows Data Types".

[MS-ERREF] Microsoft Corporation, "Windows Error Codes".

[MS-FSA] Microsoft Corporation, "File System Algorithms".

[MS-LSAD] Microsoft Corporation, "Local Security Authority (Domain Policy) Remote Protocol".

[MS-RDPBCGR] Microsoft Corporation, "Remote Desktop Protocol: Basic Connectivity and Graphics
Remoting".

[MS-SMB2] Microsoft Corporation, "Server Message Block (SMB) Protocol Versions 2 and 3".

[MS-SMB] Microsoft Corporation, "Server Message Block (SMB) Protocol".

[MS-SQLRS] Microsoft Corporation, "SQL Server Remote Storage Profile".

[RFC1094] Sun Microsystems, Inc., "NFS: Network File System Protocol Specification", RFC 1094,
March 1989, [https://www.rfc-editor.org/info/rfc1094](https://go.microsoft.com/fwlink/?LinkId=90267)

[RFC1813] Callaghan, B., Pawlowski, B., and Staubach, P., "NFS Version 3 Protocol Specification", RFC
[1813, June 1995, https://www.rfc-editor.org/info/rfc1813](https://go.microsoft.com/fwlink/?LinkId=90294)

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC
[2119, March 1997, https://www.rfc-editor.org/info/rfc2119](https://go.microsoft.com/fwlink/?LinkId=90317)
**1.2.2** **Informative References**

[FSBO] Microsoft Corporation, "File System Behavior in the Microsoft Windows Environment", June
2008, [http://download.microsoft.com/download/4/3/8/43889780-8d45-4b2e-9d3a-](https://go.microsoft.com/fwlink/?LinkId=140636)
[c696a890309f/File%20System%20Behavior%20Overview.pdf](https://go.microsoft.com/fwlink/?LinkId=140636)

[INCITS-T10/11-059] INCITS, "T10 specification 11-059", [http://www.t10.org/cgi-](https://go.microsoft.com/fwlink/?LinkId=239442)
[bin/ac.pl?t=d&f=11-059r9.pdf](https://go.microsoft.com/fwlink/?LinkId=239442)

[MS-CIFS] Microsoft Corporation, "Common Internet File System (CIFS) Protocol".

[MS-DFSC] Microsoft Corporation, "Distributed File System (DFS): Referral Protocol".

[MS-DLTW] Microsoft Corporation, "Distributed Link Tracking: Workstation Protocol".

[MS-EFSR] Microsoft Corporation, "Encrypting File System Remote (EFSRPC) Protocol".

[MS-WDVME] Microsoft Corporation, "Web Distributed Authoring and Versioning (WebDAV) Protocol:
Microsoft Extensions".

[[MSDFS] Microsoft Corporation, "How DFS Works", March 2003, http://technet.microsoft.com/en-](https://go.microsoft.com/fwlink/?LinkId=89945)
[us/library/cc782417%28WS.10%29.aspx](https://go.microsoft.com/fwlink/?LinkId=89945)

[[MSDN-CJ] Microsoft Corporation, "Change Journals", http://msdn.microsoft.com/en-](https://go.microsoft.com/fwlink/?LinkId=89970)
[us/library/aa363798.aspx](https://go.microsoft.com/fwlink/?LinkId=89970)

[MSDN-SECZONES] Microsoft Corporation, "About URL Security Zones",
[http://msdn.microsoft.com/en-us/library/ms537183.aspx](https://go.microsoft.com/fwlink/?LinkId=90660)

[MSFT-NTFSWorks] Microsoft Corporation, "How NTFS Works", March 2003,
[http://technet.microsoft.com/en-us/library/cc781134(WS.10).aspx](https://go.microsoft.com/fwlink/?LinkId=168880)

[MSFT-NTFS] Microsoft Corporation, "NTFS Technical Reference", March 2003,
[http://technet2.microsoft.com/WindowsServer/en/Library/81cc8a8a-bd32-4786-a849-](https://go.microsoft.com/fwlink/?LinkId=90200)
[03245d68d8e41033.mspx](https://go.microsoft.com/fwlink/?LinkId=90200)

[MSKB-5014019] Microsoft Corporation, "KB5014019 May 2022", KB5014019 May 2022,
[https://support.microsoft.com/en-us/topic/may-24-2022-kb5014019-os-build-22000-708-preview-](https://go.microsoft.com/fwlink/?linkid=2194206)
[442dbde4-ce28-4345-aecf-2d4744376418](https://go.microsoft.com/fwlink/?linkid=2194206)

[MSKB-5014021] Microsoft Corporation, "KB5014021 May 2022", KB5014021 May 2022,
[https://support.microsoft.com/en-us/topic/may-24-2022-kb5014021-os-build-20348-740-preview-](https://go.microsoft.com/fwlink/?linkid=2193970)
[2b180bd4-dceb-4c49-b8cf-402b342ebc84](https://go.microsoft.com/fwlink/?linkid=2193970)

[MSKB-5014022] Microsoft Corporation, "KB5014022 May 2022", KB5014022 May 2022,
[https://support.microsoft.com/en-us/topic/may-24-2022-kb5014022-os-build-17763-2989-preview-](https://go.microsoft.com/fwlink/?linkid=2194302)
[08f88943-2fc8-4fdb-a13b-ba89af313d06](https://go.microsoft.com/fwlink/?linkid=2194302)

[[MSKB-5014023] Microsoft Corporation, "KB5014023 June 2022", https://support.microsoft.com/en-](https://go.microsoft.com/fwlink/?linkid=2194303)
[us/topic/june-2-2022-kb5014023-os-builds-19042-1741-19043-1741-and-19044-1741-preview-](https://go.microsoft.com/fwlink/?linkid=2194303)
[65ac6a5d-439a-4e88-b431-a5e2d4e2516a](https://go.microsoft.com/fwlink/?linkid=2194303)

[MSKB-5014702] Microsoft Corporation, "KB5014702 June 2022", KB5014702, June 14, 2022,
[https://support.microsoft.com/en-us/topic/june-14-2022-kb5014702-os-build-14393-5192-e60ac0e1-](https://go.microsoft.com/fwlink/?linkid=2195314)
[44a4-49f9-871f-7c25eb0e5bb1](https://go.microsoft.com/fwlink/?linkid=2195314)

[[PIPE] Microsoft Corporation, "Named Pipes", http://msdn.microsoft.com/en-us/library/aa365590.aspx](https://go.microsoft.com/fwlink/?LinkId=90247)
[[REPARSE] Microsoft Corporation, "Reparse Points", http://msdn.microsoft.com/en-](https://go.microsoft.com/fwlink/?LinkId=90259)
[us/library/aa365503.aspx](https://go.microsoft.com/fwlink/?LinkId=90259)

[[SPARSE] Microsoft Corporation, "Sparse Files", http://msdn.microsoft.com/en-](https://go.microsoft.com/fwlink/?LinkId=90527)
[us/library/aa365564.aspx](https://go.microsoft.com/fwlink/?LinkId=90527)

[UASDC] Ziv, J. and Lempel, A., "A Universal Algorithm for Sequential Data Compression", May 1977,
[http://www.cs.duke.edu/courses/spring03/cps296.5/papers/ziv_lempel_1977_universal_algorithm.pdf](https://go.microsoft.com/fwlink/?LinkId=90549)

[UDF] Optical Storage Technology Association, "UDF Specification, Revision 2.60", March 2005,
[http://www.osta.org/specs/pdf/udf260.pdf](https://go.microsoft.com/fwlink/?LinkId=184845)

[[WHDC-RPTR] Microsoft Corporation, "Reparse Point Tag Request", https://learn.microsoft.com/en-](https://go.microsoft.com/fwlink/?LinkId=90564)
[us/windows-hardware/drivers/ifs/reparse-point-tag-request](https://go.microsoft.com/fwlink/?LinkId=90564)

[WININTERNALS] Russinovich, M., and Solomon, D., "Microsoft Windows Internals, Fourth Edition",
Microsoft Press, 2005, ISBN: 0735619174.

**1.3** **Overview**

This document describes the structure of common file system control ( **FSCTL** ) codes, file information
levels, and file system information levels that are issued in client/server and server/server
communications. These structures do not result in a protocol, but their structure is common across
multiple protocols. As such, they are placed in this document as a reference that can be used by other
protocols to ensure consistency and accuracy.

File system control codes are parameters to the device I/O control interface between applications and
the operating system. These device I/O control functions, like other I/O functions, accept a file handle
as a parameter, indicating the resource on which the requested operation is performed. When the
operating system detects that a handle corresponds to a file on a remote file server, the request can
be redirected over the network to the server where the file is stored.

The following topics are addressed in this specification:

- Common file system control operations, including the control code itself and the input/output
parameters.

- File information classes and their corresponding structures.

- File system information classes and their corresponding structures.

- File attribute definitions and NTSTATUS code definitions referenced by the file system control
code, file information level, and file system information-level documentation.

**1.4** **Relationship to Protocols and Other Structures**

Versions 1 and 2 of the Server Message Block (SMB) Protocol, as specified in [MS-SMB] and [MSSMB2], rely on the structures and definitions in this document to interpret certain fields that can be
sent or received as part of its processing.

**1.5** **Applicability Statement**

The structures and classes defined in this document are useful for any lower-level protocol that
serializes and exchanges file information levels, file system information levels, and file system control
operations without needing to remap this information into a protocol-specific representation.
**1.6** **Versioning and Localization**

None.

**1.7** **Vendor-Extensible Fields**

File system control codes that are used to set **reparse point** data specify a **ReparseTag** field value
that identifies the file system **filter** that understands the application-specific reparse point data
format. A vendor developing an application protocol that sets reparse point data MUST request a
unique reparse **tag** for that application from Microsoft by following the instructions described in

[[WHDC-RPTR]. For more information about reparse points, see [REPARSE].](https://go.microsoft.com/fwlink/?LinkId=90564)

This protocol uses NTSTATUS values, as specified in [MS-ERREF]. Vendors are free to choose their
own values for this field as long as the C bit (0x20000000) is set, indicating it is a customer code.
