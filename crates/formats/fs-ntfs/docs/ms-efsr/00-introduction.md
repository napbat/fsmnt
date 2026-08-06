# MS-EFSR: Introduction (v21.0, May 2014)

Glossary, references, and overview of the Encrypting File System Remote Protocol.

## 1  Introduction

The Encrypting File System Remote (EFSRPC) Protocol is used for performing maintenance and
management operations on encrypted data that is stored remotely and accessed over a network. It
is used in Windows to manage **files** that reside on remote file servers and are encrypted using the
**Encrypting File System (EFS)** .

Sections 1.8, 2, and 3 of this specification are normative and can contain the terms MAY, SHOULD,
MUST, MUST NOT, and SHOULD NOT as defined in RFC 2119. Sections 1.5 and 1.9 are also
normative but cannot contain those terms. All other sections and examples in this specification are
informative.

### 1.1  Glossary

The following terms are defined in [MS-GLOS]:

**access control list (ACL)**
**binary large object (BLOB)**
**binding**
**certificate**
**certificate template**
**decryption**
**domain**
**Encrypting File System (EFS)**
**encryption**
**endpoint**
**file system**
**flags**
**fully qualified domain name (FQDN)**
**globally unique identifier (GUID)**
**Kerberos constrained delegation**
**key**
**Lightweight Directory Access Protocol (LDAP)**
**named pipe**
**opnum**
**plaintext**
**private key**
**public key**
**Public Key Infrastructure (PKI)**
**remote procedure call (RPC)**
**Rivest-Shamir-Adleman (RSA)**
**RPC protocol sequence**
**RPC transport**
**security context**
**security identifier (SID)**
**security provider**
**Security Support Provider Interface (SSPI)**
**server**
**Server Message Block (SMB)**
**stream**
**UncPath**
**Unicode**
**Universal Naming Convention (UNC)**

**universally unique identifier (UUID)**
**well-known endpoint**
**X.509**

The following terms are specific to this document:

**Advanced Encryption Standard (AES):** A cryptographic algorithm that can be used to protect

electronic data. The AES algorithm can be used to encrypt (encipher) and decrypt (decipher)
information. **Encryption** converts data to an unintelligible form called ciphertext; decrypting
the ciphertext converts the data back into its original form, called **plaintext** . AES is a
symmetric cipher, meaning that the same **key** is used for the **encryption** and decryption
operations. It is also a block cipher, meaning that it operates on fixed-size blocks of **plaintext**
and ciphertext, and requires the size of the **plaintext** as well as the ciphertext to be an exact
[multiple of this block size. AES is specified in [FIPS197].](http://go.microsoft.com/fwlink/?LinkId=89870)

**Data Decryption Field (DDF):** The portion of the EFSRPC Metadata that contains information

that enables authorized users to **decrypt** the **file** .

**data recovery agent (DRA):** A logical entity corresponding to an asymmetric key pair that is

configured as part of administrative policy by an administrator. When an EFS **file** is created or
modified, it is also automatically configured to give all DRAs in effect at that time the ability to
**decrypt** it.

**data recovery field (DRF):** The portion of the EFSRPC Metadata that contains information that

enables authorized **DRAs** to **decrypt** the **file** .

**EFSRPC Raw Data Format:** The data format used by the EFSRPC raw methods to marshal the

contents and metadata of an encrypted **file** into a single-bit **stream** . It is specified in section
2.2.3.

**EFSRPC Metadata:** The additional data stored with an encrypted **file** to enable authorized users

to access the data in the **file** . The format of this metadata is implementation-dependent. The
EFSRPC Metadata general requirements are specified in detail in section 2.2.2 and the
Windows format is specified in associated endnotes in Appendix B of this specification.

**file:** A unit of data in the **file system** . An encrypted file consists of encrypted data along with the

metadata required for a user to **decrypt** the file. The file and its metadata are protected using
**public key** cryptography such that an authorized user's **private key** is required to **decrypt**
the file.

**File Encryption Key (FEK):** The symmetric key that is used to encrypt the data in an EFS
protected **file** . The FEK is further encrypted and stored in the **file** metadata such that only
authorized users can access it.

**folder:** A container for **files** and other folders. A folder may be encrypted. The semantics of

encrypting a folder are implementation-dependent. In the Windows implementation,
encrypting a folder does not directly cause any data to be encrypted. Encrypting a folder in
Windows has the following consequences:

EFSRPC Metadata is created and stored with the folder.

An **NTFS** attribute is set on the folder to signify that it is encrypted. **NTFS** checks this

attribute when any new **files** or folders are created in the folder. **NTFS** will automatically
encrypt any **files** or folders created within a folder that has this attribute set.

**New Technology File System (NTFS):** The native **file system** of Windows 2000, Windows XP,

Windows Vista, Windows 7, and Windows 8. Within this document, this term is occasionally

used to refer to the operating system subsystem that implements NTFS support. For more
[information, see [MSFT-NTFS].](http://go.microsoft.com/fwlink/?LinkId=90200)

**sparse file:** A **file** containing large sections of data composed only of zeros, which is marked as

such in the **NTFS** . The **file system** saves disk space by only allocating as many ranges on
disk as are required to completely reconstruct the non-zero data. When an attempt is made to
read in the nonallocated portions of the **file** (also known as holes), the **file system**
automatically returns zeros to the caller.

**valid data length (VDL):** In **NTFS**, there are two important concepts of **file** length: the end-of
file (EOF) marker and the valid data length (VDL). The EOF indicates the actual length of the
**file** . The VDL identifies the length of valid data on disk. Any reads between VDL and EOF
automatically return zeros.

**MAY, SHOULD, MUST, SHOULD NOT, MUST NOT:** These terms (in all caps) are used as

described in [[RFC2119]. All statements of optional behavior use either MAY, SHOULD, or](http://go.microsoft.com/fwlink/?LinkId=90317)
SHOULD NOT.

### 1.2  References

References to Microsoft Open Specifications documentation do not include a publishing year because
links are to the latest version of the documents, which are updated frequently. References to other
documents include a publishing year when one is available.

#### 1.2.1  Normative References

We conduct frequent surveys of the normative references to assure their continued availability. If
[you have any issue with finding a normative reference, please contact dochelp@microsoft.com. We](mailto:dochelp@microsoft.com)
will assist you in finding the relevant information.

[C706] The Open Group, "DCE 1.1: Remote Procedure Call", C706, August 1997,
[https://www2.opengroup.org/ogsys/catalog/c706](http://go.microsoft.com/fwlink/?LinkId=89824)

[MS-ADOD] Microsoft Corporation, "Active Directory Protocols Overview".

[MS-ADTS] Microsoft Corporation, "Active Directory Technical Specification".

[MS-CRTD] Microsoft Corporation, "Certificate Templates Structure".

[MS-DTYP] Microsoft Corporation, "Windows Data Types".

[MS-ERREF] Microsoft Corporation, "Windows Error Codes".

[MS-RPCE] Microsoft Corporation, "Remote Procedure Call Protocol Extensions".

[MS-SMB] Microsoft Corporation, "Server Message Block (SMB) Protocol".

[MS-SMB2] Microsoft Corporation, "Server Message Block (SMB) Protocol Versions 2 and 3".

[MS-WCCE] Microsoft Corporation, "Windows Client Certificate Enrollment Protocol".

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC
2119, March 1997, [http://www.rfc-editor.org/rfc/rfc2119.txt](http://go.microsoft.com/fwlink/?LinkId=90317)

[RFC2251] Wahl, M., Howes, T., and Kille, S., "Lightweight Directory Access Protocol (v3)", RFC
[2251, December 1997, http://www.ietf.org/rfc/rfc2251.txt](http://go.microsoft.com/fwlink/?LinkId=90325)

[RFC3394] Schaad, J., Housley, R., "Advanced Encryption Standard (AES) Key Wrap Algorithm",
[RFC 3394, September 2002, http://www.ietf.org/rfc/rfc3394.txt](http://go.microsoft.com/fwlink/?LinkId=131784)

[RFC5280] Cooper, D., Santesson, S., Farrell, S., et al., "Internet X.509 Public Key Infrastructure
Certificate and Certificate Revocation List (CRL) Profile", RFC 5280, May 2008,
[http://www.ietf.org/rfc/rfc5280.txt](http://go.microsoft.com/fwlink/?LinkId=131034)

#### 1.2.2  Informative References

[FIPS180] FIPS PUBS, "Secure Hash Standard", FIPS PUB 180-1, April 1995,
[http://www.itl.nist.gov/fipspubs/fip180-1.htm](http://go.microsoft.com/fwlink/?LinkId=89867)

[FIPS197] FIPS PUBS, "Advanced Encryption Standard (AES)", FIPS PUB 197, November 2001,
[http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf](http://go.microsoft.com/fwlink/?LinkId=89870)

[MS-GLOS] Microsoft Corporation, "Windows Protocols Master Glossary".

[MS-GPEF] Microsoft Corporation, "Group Policy: Encrypting File System Extension".

[MS-SFU] Microsoft Corporation, "Kerberos Protocol Extensions: Service for User and Constrained
Delegation Protocol".

[MS-WDV] Microsoft Corporation, "Web Distributed Authoring and Versioning (WebDAV) Protocol:
Client Extensions".

[[MSDN-CRYPTO] Microsoft Corporation, "Cryptography Reference", http://msdn.microsoft.com/en-](http://go.microsoft.com/fwlink/?LinkId=89984)
[us/library/aa380256.aspx](http://go.microsoft.com/fwlink/?LinkId=89984)

[MSDN-CSPCTX] Microsoft Corporation, "Cryptographic Service Provider Contexts",
[http://msdn.microsoft.com/en-us/library/Aa380246](http://go.microsoft.com/fwlink/?LinkId=89986)

[MSDN-CSPR] Microsoft Corporation, "Cryptographic Service Providers",
[http://msdn.microsoft.com/en-us/library/aa380245.aspx](http://go.microsoft.com/fwlink/?LinkId=89987)

[MSDN-RPCTSEC] Microsoft Corporation, "Using Transport-Level Security on the Client",
[http://msdn.microsoft.com/en-us/library/aa379194.aspx](http://go.microsoft.com/fwlink/?LinkId=90113)

[MSFT-EFS] Microsoft Corporation, "The Encrypting File System",
[http://www.microsoft.com/technet/security/guidance/cryptographyetc/efs.mspx](http://go.microsoft.com/fwlink/?LinkId=90185)

[MSFT-NTFS] Microsoft Corporation, "NTFS Technical Reference", March 2003,
[http://technet2.microsoft.com/WindowsServer/en/Library/81cc8a8a-bd32-4786-a849-](http://go.microsoft.com/fwlink/?LinkId=90200)
[03245d68d8e41033.mspx](http://go.microsoft.com/fwlink/?LinkId=90200)

[MSFT-XPUEFS] Microsoft Corporation, "Windows XP Professional Resource Kit: Using Encrypting File
[System", November 2005, http://technet.microsoft.com/en-us/library/bb457116.aspx](http://go.microsoft.com/fwlink/?LinkId=90713)

[TDEA] National Institute of Standards and Technology," Recommendation for the Triple Data
Encryption Algorithm (TDEA) Block Cipher", Special Publication 800-67, May 2004.

[X509] ITU-T, "Information Technology - Open Systems Interconnection - The Directory: Public-Key
and Attribute Certificate Frameworks", Recommendation X.509, August 2005,
[http://www.itu.int/rec/T-REC-X.509/en](http://go.microsoft.com/fwlink/?LinkId=90590)

**Note** There is a charge to download the specification.

[X690] ITU-T, "Information Technology - ASN.1 Encoding Rules: Specification of Basic Encoding
Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)",
[Recommendation X.690, July 2002, http://www.itu.int/rec/T-REC-X.690/en](http://go.microsoft.com/fwlink/?LinkId=90593)

**Note** There is a charge to download the specification.

### 1.3  Overview

The Encrypting File System Remote Protocol (hereafter referred to as EFSRPC) is a **Remote**
**Procedure Call (RPC)** interface that is used to manage data objects stored in an encrypted form.
The objective of encrypting data in this fashion is to enforce access control policies and to provide
confidentiality from unauthorized users.

EFSRPC is implemented in Windows to provide remote management for files encrypted by the
Encrypting File System (EFS). EFS is the ability of the **New Technology File System (NTFS)** file
system to encrypt files on disk in a manner that is transparent to the user. For more information on
EFS, see [[MSFT-EFS]. For more information about NTFS, see [MSFT-NTFS].](http://go.microsoft.com/fwlink/?LinkId=90185)

EFSRPC does not address how data is encrypted, how the encrypted data is stored, or how it is
accessed for routine operations such as reading, writing, creating, and deleting. All these actions are
specific to the server implementation. On Windows, NTFS provides the storage mechanism (the file
is the unit of storage) and the Server Message Block (SMB) Protocol provides remote access to such
files. For more information about **SMB**, see [MS-SMB] and [MS-SMB2].

EFSRPC models the underlying data **encryption** architecture using two basic constructs:

A set of data objects, each of which is encrypted independently and can be managed

independently.

A set of access control subjects, each of which is represented by a key pair generated by a

**public key** cryptographic algorithm. The public key of this key pair is embedded in a **certificate**
and may be widely distributed in that form. The corresponding **private key** is held solely by the
user or users who represent that subject. Thus, a given access control subject may correspond to
one or more users, and a given user may possess the private keys for zero or more access
control subjects. Access control subjects are further divided into two types:

Unprivileged user subjects, which are used for routine data access by ordinary users of the

system. For convenience, this specification refers to such subjects as user certificate.

 **Data Recovery Agents (DRAs)**, which are controlled by system administrators. The storage

system ensures that all active DRAs for the system are automatically authorized to access all
encrypted objects on the system. If an unprivileged user loses the private key, an
administrator can use a DRA's private key to recover the contents of encrypted objects.

EFSRPC also assumes that each encrypted object is associated with some security-related metadata,
which contains information required for authorized users and DRAs to access the **plaintext** of the
object. This specification refers to this security-related metadata as the EFSRPC Metadata.

EFSRPC does not specify how data is encrypted, stored, or accessed. It is possible to build a
compliant EFSRPC implementation that uses a mechanism, such as **access control lists (ACLs)**,
instead of encryption to control access to data objects. For the purposes of this specification, the
term encrypted is used to indicate that a data object and its metadata can be successfully
manipulated through the EFSRPC methods, with the exception of the **EfsRpcEncryptFileSrv**
method, which converts data objects from an unencrypted state to an encrypted state.

Within the preceding model, EFSRPC provides various categories of management routines. The
syntax of the individual methods and rules for how these methods are processed on the server are

specified in section 3.1.4.2. The categories of management routines that EFSRPC provides are as
follows:

Requesting the server to convert objects from encrypted state to unencrypted state and vice

versa.

 **EfsRpcEncryptFileSrv** (section 3.1.4.2.5)

 **EfsRpcDecryptFileSrv (section 3.1.4.2.6)**

Creating, querying, and manipulating the EFSRPC Metadata. Clients use the following methods to

query and change which user certificates can be used to **decrypt** an encrypted object. The set of
user certificates with access to an object needs to be changed when the set of users with access
to the object changes or when a user with access to the object changes the user certificate. The
following methods can also be used to copy the access rights from one object to another; the
**EfsRpcDuplicateEncryptionInfoFile** method is particularly well-suited for this
purpose.Methods:

 **EfsRpcQueryUsersOnFile (section 3.1.4.2.7)**

 **EfsRpcQueryRecoveryAgents (section 3.1.4.2.8)**

 **EfsRpcRemoveUsersFromFile (section 3.1.4.2.9)**

 **EfsRpcAddUsersToFile (section 3.1.4.2.10)**

 **EfsRpcFileKeyInfo (section 3.1.4.2.12)**

 **EfsRpcDuplicateEncryptionInfoFile (section 3.1.4.2.13)**

 **EfsRpcAddUsersToFileEx (section 3.1.4.2.14)**

 **EfsRpcFileKeyInfoEx (section 3.1.4.2.15)**

 **EfsRpcGetEncryptedFileMetadata (section 3.1.4.2.16)**

 **EfsRpcSetEncryptedFileMetadata (section 3.1.4.2.17)**

Performing backup of encrypted objects in ciphertext form along with their EFSRPC Metadata,

and restoring encrypted objects from such backups. Depending on the implementation of these
methods, the backups that are created may expose the implementation-specific EFSRPC
Metadata format to the client. The Windows implementation of these methods exposes the
Windows EFSRPC Metadata format; however, Windows applications do not manipulate this
information. The following methods are suitable for secure content archival or transferring
encrypted data securely between servers of the same implementation because they do not
require decrypting the data. Methods:

 **EfsRpcOpenFileRaw (section 3.1.4.2.1)**

 **EfsRpcReadFileRaw (section 3.1.4.2.2)**

 **EfsRpcWriteFileRaw (section 3.1.4.2.3)**

 **EfsRpcCloseRaw (section 3.1.4.2.4)**

Controlling the server's encryption subsystem. Methods:

 **EfsRpcFlushEfsCache (section 3.1.4.2.18)**

Most of the EFSRPC routines are stateless and can be called in any order. When one of these
routines is called, the message exchange is as follows.

**Figure 1: Message exchange for stateless routines**

There are two routines in EFSRPC that are an exception to the stateless nature of the protocol.
Several methods, collectively known as the EFSRPC raw methods, are an exception and need to be
called in a specific order. This includes the **EfsRpcOpenFileRaw**, **EfsRpcReadFileRaw**,
**EfsRpcWriteFileRaw**, and **EfsRpcCloseRaw** methods. The following two sequences are
permissible.

**Figure 2: Message sequence for opening a file**

**Figure 3: Message sequence for importing a file**

### 1.4  Relationship to Other Protocols

The Encrypting File System Remote Protocol is built on the Microsoft Remote Procedure Call (RPC)
[interface (as specified in [C706]](http://go.microsoft.com/fwlink/?LinkId=89824) and [MS-RPCE]). EFSRPC uses the Server Message Block (SMB)
Protocol [MS-SMB] [MS-SMB2] as its **RPC transport** . Specifically, it uses **named pipes** over SMB
(that is, **RPC protocol sequence** ncacn_np) as its transport mechanism. Either version 1 or version
2 of SMB may be used. The client has to connect to the server over SMB and negotiate a version of
SMB before it can access the named pipe that is the RPC **endpoint** on the server.

Windows also supports the storage of encrypted files via WebDAV [MS-WDV]. However, this feature
does not use EFSRPC. This feature does not alter the WebDAV Protocol. Windows clients store
encrypted files on WebDAV servers in the **EFSRPC Raw Data Format**, but the Windows WebDAV
client performs all encryption and decryption operations locally. It also performs the local operations
necessary to transform the file to and from the EFSRPC Raw Data Format during upload and
[download respectively. For more information, see [MSFT-XPUEFS].](http://go.microsoft.com/fwlink/?LinkId=90713)

This specification provides an interface (see section 3.1.4.1) for applications to request a user
certificate. This interface uses methods outlined in [MS-WCCE] to enroll for a certificate and key.

**Figure 4: Protocol relationships**

### 1.5  Prerequisites/Preconditions

To use EFSRPC with a remote server, the client is required to possess valid credentials recognized
by the server and be able to pass authentication and authorization checks for access to the
encrypted data on the server. If secure operation is desired, the server is required to register an
appropriate server principal name/authentication service pair that supports a protection level that
provides packet integrity. Additionally, the client must be configured to associate the appropriate
server principal name and authentication, and authorization and protection level with its **binding**,
when connecting to the server.<1>

The User-Certificate Binding interface described in section 3.1.1.1 stores user keys protected to the
user credentials and requires that the EFSRPC server be joined to the **domain** and configured for
Kerberos delegation.<2> Alternatively, the server can be configured for **Kerberos constrained**
**delegation** (as specified in [MS-SFU]) for only the services used for user key storage.

### 1.6  Applicability Statement

This protocol is appropriate for remotely managing encrypted data objects on a server. It is used by
Windows clients to manage EFSRPC-protected files on remote file servers using either version 1 or
version 2 of the SMB Protocol. It does not specify any particular data protection mechanism.

### 1.7  Versioning and Capability Negotiation

This document covers versioning issues in the following areas.

Supported Transports: This protocol uses RPC for communication. It uses named pipes as the
transport mechanism, as specified in section 2.1.

Protocol Versions: The RPC runtime negotiates the version of the EFSRPC interface, as specified in

[[C706]. The only supported version of this protocol is 1.0, as specified in section 3.1.4.2.](http://go.microsoft.com/fwlink/?LinkId=89824)

Security and Authentication Methods: EFSRPC does not specify any methods for authenticating
access to the objects it operates on. The underlying data encryption and storage system may
implement any authentication mechanism. In Windows, such authentication is provided by SMB, as
specified in [MS-SMB] and [MS-SMB2]. An EFSRPC server may register a server principal
name/authentication service pair to enable secure RPC communications, and a client may choose to
associate this security service with its binding when connecting to the server, as specified in section
3.

Capability Negotiation: Implicit negotiation of RPC security mechanisms may be performed through
[the security-related APIs specified in [C706]](http://go.microsoft.com/fwlink/?LinkId=89824) [Chapter 13. The security mechanisms negotiated by](http://go.microsoft.com/fwlink/?LinkId=89826)
Windows clients and servers are as specified in section 2.1.

### 1.8  Vendor-Extensible Fields

EFSRPC does not include any vendor-extensible fields.

This protocol uses Win32 error codes. These values are taken from the Windows error number space
as specified in [MS-ERREF] section 2.2. Vendors SHOULD reuse those values with their indicated
meaning. Using any other value runs the risk of a collision in the future.

### 1.9  Standards Assignments

|Parameter|Value|
|---|---|
|RPC Well-Known Endpoint|\pipe\lsarpc|
|RPC Interface UUID|{c681d488-d850-11d0-8c52-00c04fd90f7e}|

|Parameter|Value|
|---|---|
|RPC Well-Known Endpoint|\pipe\efsrpc|
|RPC Interface UUID|{df1941c5-fe89-4e79-bf10-463657acf44d}|
