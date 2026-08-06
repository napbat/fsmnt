# Product Behavior (§7)

Windows version-specific behavior footnotes. Maps `<N>` references in the spec to Windows versions.

## 7  Appendix B: Product Behavior

The information in this specification is applicable to the following Microsoft products or supplemental
software. References to product versions include released service packs:

Windows 2000 operating system

Windows XP operating system

Windows Server 2003 operating system

Windows Vista operating system

Windows Server 2008 operating system

Windows 7 operating system

Windows Server 2008 R2 operating system

Windows 8 operating system

Windows Server 2012 operating system

Windows 8.1 operating system

Windows Server 2012 R2 operating system

Exceptions, if any, are noted below. If a service pack or Quick Fix Engineering (QFE) number
appears with the product version, behavior changed in that service pack or QFE. The new behavior
also applies to subsequent service packs of the product unless otherwise specified. If a product
edition appears with the product version, behavior is different in that product edition.

Unless otherwise specified, any statement of optional behavior in this specification that is prescribed
using the terms SHOULD or SHOULD NOT implies product behavior in accordance with the SHOULD
or SHOULD NOT prescription. Unless otherwise specified, the term MAY implies that the product
does not follow the prescription.

<1> Section 1.5: EFSRPC calls to a Windows-based EFSRPC server will fail, returning an error, if the
server is running an edition of the operating system that does not include EFS. Specifically,
Windows XP Home Edition and Windows XP Starter Edition editions of Windows do not include EFS
functionality and do not support EFSRPC.

Windows Vista, Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8, Windows
Server 2012, Windows 8.1, and Windows Server 2012 R2 use **SSPI** to secure the EFSRPC raw
methods. For more details, see the product behavior notes in Appendix B regarding section 2.1.

<2> Section 1.5: The Windows 2000 implementation supports EFSRPC in workgroup settings and on
domain-joined computers that are not configured for Kerberos delegation.

<3> Section 2.1: Windows 2000, Windows XP, Windows Server 2003, Windows Vista, and Windows
Server 2008 servers listen for EFSRPC messages only on the well-known endpoint \pipe\lsarpc.

Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, and
Windows Server 2012 R2 servers listen for EFSRPC messages on both \pipe\lsarpc and \pipe\efsrpc.

<4> Section 2.1: Windows Vista, Windows Server 2008, Windows 7, Windows Server 2008 R2,
Windows 8, Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 EFSRPC servers
register the RPC_C_AUTHN_LEVEL_PKT_PRIVACY **security provider** .

Windows Vista, Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8, Windows
Server 2012, Windows 8.1, and Windows Server 2012 R2 clients attempt to negotiate the use of this
provider for the EFSRPC raw methods with RPC_C_AUTHN_GSS_NEGOTIATE, and can be configured
to require its use.

Windows 2000, Windows XP, and Windows Server 2003 neither register this provider on the server
nor attempt to use it on the client.

<5> Section 2.2.1: Windows implementations restrict file and folder names to 5,120 Unicode
characters, not including the null terminator. An error is returned if this limit is exceeded.

<6> Section 2.2.2.1: Windows implementations place an upper limit of 262,144 bytes on the length
of the EFSRPC Metadata. Windows servers will return an error when passed EFSRPC Metadata that
exceeds this limit, or when an EFSRPC call would require Windows servers to create or extend a
file's EFSRPC Metadata beyond this limit.

<7> Section 2.2.2.1: Windows 2000 supports only version 1. Windows XP and Windows
Server 2003 support only versions 1 and 2.

<8> Section 2.2.2.1: The Windows 2000 implementation sets this field to the MD5 hash of the
complete EFSRPC Metadata, computed with the EFS hash field set to zero. The Windows 2000
implementation will also verify the checksum whenever EFSRPC Metadata is passed to it, and will
return an error in case of a mismatch.

<9> Section 2.2.2.1.2: This value is unsupported on Windows 2000, Windows XP, and Windows
Server 2003. These versions of Windows set this field to zero when creating the EFSRPC Metadata,
ignore its value when processing the metadata, and expect the FEK to be encrypted using RSA.

<10> Section 2.2.2.1.5: A Windows EFSRPC server will return an error if the total length of this
structure exceeds 1,086 bytes.

<11> Section 2.2.2.2:

Windows 2000, Windows XP, Windows Server 2003, Windows Vista, and Windows Server 2008 do
not support Version 2 of the EFSRPC Metadata.

Windows servers only generate Version 2 metadata for encrypted files when an ECDH protector is
added to an encrypted file. This could happen through any of the below procedures:

Calling EfsRpcAddUsers* with at least one ECDH certificate. If the existing file has version 1

metadata, it is updated to version 2 before adding the new certificate.

A file is encrypted and the user's current key is an ECDH certificate.

DRA policy specifies at least one ECDH certificate.

<12> Section 2.2.2.2: Windows implementations place an upper limit of 262,144 bytes on the
length of the EFSRPC Metadata. Windows servers will return an error when passed EFSRPC Metadata
that exceeds this limit, or when an EFSRPC call would require Windows servers to create or extend a
file's EFSRPC Metadata beyond this limit.

<13> Section 2.2.3.3: Windows 2000, Windows XP, Windows Server 2003, Windows Vista, and
Windows Server 2008 ignore this field.

<14> Section 2.2.6: The Windows implementation of the EFSRPC server returns an error if the size
of this encoded certificate exceeds 32 kilobytes. This restriction is represented in the range attribute
of cbData.

<15> Section 2.2.7: As a defensive measure against overflow attacks, the Windows implementation
of the EFSRPC server restricts the size of the **bData** field to 100 bytes, and returns an error if this
size is exceeded. This restriction is represented by the range attribute of cbData.

<16> Section 2.2.9: As a defensive measure against overflow attacks, the Windows implementation
of the EFSRPC server restricts the number of entries in this array to 500, and returns an error if this
size is exceeded. This restriction is represented in the range attribute of nUsers.

<17> Section 2.2.11: As a defensive measure against overflow attacks, the Windows
implementation of the EFSRPC server restricts the number of entries in this array to 500, and
returns an error if this size is exceeded. This restriction is represented in the range attribute of
nCert_Hash.

<18> Section 2.2.12: As a defensive measure against overflow attacks, the Windows
implementation of the EFSRPC server restricts the size of this object to 260 kilobytes, and returns
an error if this size is exceeded. This restriction is represented in the range attribute of cbData.

<19> Section 2.2.13: Windows 2000 does not support either of these algorithms. Windows XP only
supports CALG_3DES.

<20> Section 2.2.13: Windows 2000 supports only the following algorithms.

|Algorithm used|Value for ALG_ID|Entropy|Key length|
|---|---|---|---|
|CALG_DESX (domestic)|0x6604|128|16|
|CALG_DESX (export)|0x6604|56|16|

In the preceding table, the difference between entropy and key length for CALG_DESX (export)
exists only because the first 56 bits are random and the rest are set to zero.

When accessing existing encrypted objects, Windows XP, Windows Server 2003, Windows Vista,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012,
Windows 8.1, and Windows Server 2012 R2 support the two CALG_DESX algorithms.

When creating new encrypted objects, Windows XP, Windows Server 2003, Windows Vista, and
Windows Server 2008 support the two CALG_DESX algorithms only if allowed by the prevailing
policy.

<21> Section 2.2.13: When accessing existing encrypted objects, Windows implementations do not
restrict the set of supported algorithms according to policy.

When creating new encrypted objects, Windows implementations restrict the algorithm according to
the **FIPSAlgorithmPolicy** setting defined in the following registry locations.

|Operating<br>system|Registry key|Registry value|Type|
|---|---|---|---|
|Windows XP/Win<br>dows<br>Server 2003|HKLM\System\CurrentControlSet\Control\Lsa|**FIPSAlgorithmP**<br>**olicy**|**REG_DWO**<br>**RD**|

|Operating<br>system|Registry key|Registry value|Type|
|---|---|---|---|
|Windows Vista/<br>Windows<br>Server 2008<br>Windows 7/Wind<br>ows<br>Server 2008 R2<br>Windows<br>8/Windows<br>Server 2012|HKLM\System\CurrentControlSet\Control\Lsa\FIPSAl<br>gorithmPolicy|**Enabled**|**REG_DWO**<br>**RD**|

On Windows XP and Windows Server 2003, if the value is nonzero (enabled), newly created
encrypted objects are restricted to using the CALG_3DES algorithm.

On Windows Vista, Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2, if the value is not zero
(enabled), newly created encrypted objects are restricted to using the CALG_AES_256 algorithm.

<22> Section 2.2.15: Windows compatibility with EFSRPC Metadata versions is summarized by the
following table.

|EfsVersion|Minimum operating system|
|---|---|
|1|Windows 2000|
|2|Windows XP / Windows Server 2003|
|3|Windows Vista / Windows Server 2008|
|4|Windows 7 / Windows Server 2008 R2|

<23> Section 3: Windows Vista, Windows Server 2008, Windows 7, Windows Server 2008 R2,
Windows 8, Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 EFSRPC client
implementations attempt to negotiate the RPC_C_AUTHN_LEVEL_PKT_PRIVACY option with
RPC_C_AUTHN_GSS_NEGOTIATE. If an error is encountered and the client is not configured to
require security, the client falls back to connecting over an unsecured RPC connection.

Windows 2000, Windows XP, and Windows Server 2003 do not support this option; they neither
register any SSPI providers on the server side nor request any on the client.

<24> Section 3.1.3: Windows Vista, Windows Server 2008, Windows 7, Windows Server 2008 R2,
Windows 8, Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 register an SSPI
provider to support RPC_C_AUTHN_LEVEL_PKT_PRIVACY.

<25> Section 3.1.4.2: Windows 2000 supports methods with opnums 0 through 11. For opnum 11,
it behaves as the **EfsRpcDuplicateEncryptionInfoFile** method. Windows XP and Windows
Server 2003 support opnum 0 through opnum 13, with opnum 11 being implemented as the
**EfsRpcNotSupported** method.

<26> Section 3.1.4.2: Gaps in the opnum numbering sequence apply to Windows as follows.

|Opnum|Description|
|---|---|
|10|Only used locally by Windows, never remotely.|
|14|Only used locally by Windows, never remotely.|
|17|Only used locally by Windows, never remotely.|

<27> Section 3.1.4.2: Implementations of nonstandard behavior for deprecated methods in
Windows are summarized below. See the behavior notes for each corresponding method section for
details of nonstandard behavior on each Windows implementation.

|Method|Opnum|Operating System|
|---|---|---|
|**EfsRpcNotSupported**|11|Windows 2000|
|**EfsRpcFileKeyInfoEx**|16|Windows Vista, Windows Server 2008|
|**EfsRpcGetEncryptedFileMetadata**|18|Windows Vista, Windows Server 2008|
|**EfsRpcSetEncryptedFileMetadata**|19|Windows Vista, Windows Server 2008|

<28> Section 3.1.4.2: Windows 2000 returns ERROR_NO_RECOVERY_POLICY (specified in [MSERREF]).

<29> Section 3.1.4.2.1: If the **CREATE_FOR_DIR** flag is set, and the **CREATE_FOR_IMPORT** flag
is also set, Windows will attempt to create a folder with the specified name instead of a file.

<30> Section 3.1.4.2.11: Windows 2000 responds to this opnum as described in section 3.1.4.2.13.

<31> Section 3.1.4.2.11: Windows 2000 performs the processing specified in section 3.1.4.2.13.

<32> Section 3.1.4.2.12: UPDATE_KEY_USED is only supported on Windows Server 2003.
CHECK_DECRYPTION_STATUS and CHECK_ENCRYPTION_STATUS are not supported on Windows XP
or Windows Server 2003. CHECK_COMPATIBILITY_INFO is not supported on Windows XP, Windows
Server 2003, Windows Vista, or Windows Server 2008.

<33> Section 3.1.4.2.12: Windows Server 2003 requires that UPDATE_KEY_USED only be used with
a folder name. If not, an error is returned.

<34> Section 3.1.4.2.12: Windows Server 2003 updates the EFSRPC Metadata of all the encrypted
files and folders accessible by the calling user in the _FileName_ parameter or one of its subfolders to
use a single user certificate for that user.

<35> Section 3.1.4.2.13: The data portion of the EFS_RPC_BLOB structure is expected to contain a
security descriptor. This is an opaque data type in Windows that is best manipulated only indirectly
through the APIs provided for this purpose, as specified in [MS-DTYP] sections 2.4.6 and 2.5.

<36> Section 3.1.4.2.13: The **EfsRpcDuplicateEncryptionInfoFile** method was associated with
opnum 11 in Windows 2000; therefore, it cannot be used between a Windows 2000 client and a
server running a different version of Windows, or vice versa.

<37> Section 3.1.4.2.13: For files using version 1 of the EFSRPC Metadata, Windows Vista,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012,
Windows 8.1, and Windows Server 2012 R2 servers will generate a new FEK for the _DestFileName_
parameter if only one user has access to the _SrcFileName_ parameter. This is to ensure that users

who get access to one of the two files at a later date do not automatically get the ability to decrypt
the other file.

For files using version 2 of the EFSRPC Metadata, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 servers will always generate a
new file IV for the _DestFileName_ parameter, and will generate a new FEK/FMK for the _DestFileName_
parameter if no legacy RSA user protectors exist on the _SrcFileName_ parameter.

<38> Section 3.1.4.2.15: Windows Vista and Windows Server 2008 implement this method
identically to the implementation of **EfsRpcFileKeyInfo**, ignoring the _dwFileKeyInfoFlags_ and
_Reserved_ parameters.

<39> Section 3.1.4.2.15: Windows Vista and Windows Server 2008 use this parameter in the
manner identical to how it is used in the implementation of **EfsRpcFileKeyInfo** .

<40> Section 3.1.4.2.15: Windows Vista and Windows Server 2008 return "0" if all conditions listed
in the description for **EfsRpcFileKeyInfo** are met.

<41> Section 3.1.4.2.16: Windows Vista and Windows Server 2008 implement this method in the
following way:

If no object exists with the name specified in the _FileName_ parameter, or if it exists and is not
encrypted, the server returns a nonzero value. Otherwise, the server returns the EFSRPC Metadata
of the object in the _EfsStreamBlob_ parameter, and returns 0 for the method.

<42> Section 3.1.4.2.16: Windows Vista and Windows Server 2008 use this parameter to return the
EFSRPC Metadata associated with the object referred to by _FileName_ .

<43> Section 3.1.4.2.16: Windows Vista and Windows Server 2008 return "0" if all conditions listed
in the first Product Behavior note for this section are met.

<44> Section 3.1.4.2.17: Windows Vista and Windows Server 2008 implement this method in the
following way:

If no object exists on the server with the name specified in the _FileName_ parameter, or if it exists
and is not encrypted, the server returns a nonzero value.

If an encrypted object exists with the name specified in the _FileName_ parameter, and its metadata
does not match exactly with the contents of the _OldEfsStreamBlob_ parameter, the server returns a
nonzero value.

If the **NewEfsSignature** field is non-NULL and the certificate thumbprint in that field does not
correspond to a certificate whose corresponding private key is capable of decrypting the object, the
server returns a nonzero value.

If the **NewEfsSignature** field is NULL and the calling user does not have access to any private key
that can decrypt the object, the server returns a nonzero value.

If the **NewEfsStreamBlob** parameter does not satisfy the Windows Vista and Windows Server 2008
requirements for the syntax of EFSRPC Metadata, the server returns a nonzero value.

If none of the preceding conditions are true, then the server replaces the object's EFSRPC Metadata
with the contents of the _NewEfsStreamBlob_ and returns a 0 value.

<45> Section 3.1.4.2.17: Windows Vista and Windows Server 2008 expect this parameter to be the
existing EFSRPC Metadata on the object referred to by _FileName_ . If this parameter is not NULL,

Windows Vista and Windows Server 2008 will return an error if the metadata does not match the
existing EFSRPC Metadata on the object.

<46> Section 3.1.4.2.17: Windows Vista and Windows Server 2008 expect this parameter to be the
new EFSRPC Metadata (as specified in section 2.2.2) intended for the object, and will return an error
if this is not so.

<47> Section 3.1.4.2.17: Windows Vista and Windows Server 2008 expect that if this parameter is
not NULL, it contains an X.509 certificate whose corresponding private key already has the ability to
decrypt the object and the signature over the new EFSRPC Metadata with this key, and will return
an error if this is not so.

<48> Section 3.1.4.2.17: Windows Vista and Windows Server 2008 return 0 if all conditions listed in
the first Product Behavior note for this section are met and the new EFSRPC Metadata on the file or
folder is successfully modified.
