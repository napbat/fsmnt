# EFSRPC Raw Data Format (§2.2.3+)

Marshaled stream format used by backup/restore APIs (`ReadEncryptedFileRaw`/`WriteEncryptedFileRaw`).
Also includes algorithm identifiers and RPC data types.

#### 2.2.3  EFSRPC Raw Data Format

The EFSRPC raw data format is used by the EFSRPC raw methods. The output of the
**EfsRpcReadFileRaw** method MUST conform to this format. The input to the **EfsRpcWriteFileRaw**
method MUST conform to the EFSRPC Raw Data Format. The details of this format are
implementation dependent. An EFSRPC client SHOULD NOT parse this format and SHOULD NOT rely
on it having any particular structure. An EFSRPC server MUST validate input data passed to it by the
**EfsRpcWriteFileRaw** method, and SHOULD abort the EfsRpcWriteFileRaw operation with an RPC
exception if this data is in an unsupported format.

The EFSRPC Raw Data Format SHOULD be formatted as follows.

|--- (32 bits)|
|0x00|0x01|
|0x52|0x00|0x4f|
|0x42|0x00|0x53|
|Reserved (32 bits)|
||
|EFSRPC Metadata Stream (variable) (32 bits)|
||
|Additional Stream 1 (variable) (32 bits)|
||
|Additional Stream n (variable) (32 bits)|
||

**Reserved (8 bytes):** MUST be set to zero and ignored.

**EFSRPC Metadata Stream (variable):** This field MUST be formatted as specified in section

2.2.3.1. This field MUST contain the EFSRPC Metadata for the file, along with a header. The
structure of the EFSRPC Metadata is specified in section 2.2.2.

**Additional Stream 1 ... n:** These MUST correspond to marshaled versions of all the **streams**

(except for EFSRPC Metadata) in the given file. They are optional and might not exist (for
example, for **folders** with no alternate streams). For more information on NTFS file streams,
see [[MSFT-NTFS]. These fields MUST be formatted as specified in section 2.2.3.1.](http://go.microsoft.com/fwlink/?LinkId=90200)

##### 2.2.3.1  Marshaled Stream

A Marshaled Stream (including the EFSRPC Metadata stream) MUST be formatted as follows.

|--- (32 bits)|
|Length (32 bits)|
|0x4e|0x00|0x54|
|0x46|0x00|0x53|
|Flag (32 bits)|
|Reserved (32 bits)|
||
|Name Length (32 bits)|
|Stream Name (variable) (32 bits)|
||
|Stream Data Segment 1 (variable) (32 bits)|
||
|Stream Data Segment n (variable) (32 bits)|
||

**Length (4 bytes):** The length, in bytes, of this stream header from the start of this field to the

end of the **Stream Name** field. It MUST be a 32-bit unsigned integer in little-endian format.

**Flag (4 bytes):** This MUST be a 32-bit unsigned integer in little-endian format. It MUST be set

to 0x00000000 if the stream data is encrypted with the FEK. Otherwise, it MUST be set to
0x00000001. It MUST always be set to zero in the case of the **EFSRPC Metadata** stream, and
ignored by the server in that case.

|Value|Meaning|
|---|---|
|0x00000000|FEK encryption present|
|0x00000001|FEK encryption not present|

**Reserved (8 bytes):** This field MUST be set to zero and ignored.

**Name Length (4 bytes):** The length, in bytes, of the **Stream Name** field. It MUST be a 32-bit

unsigned integer in little-endian format. This field MUST be set to 0x00000002 for the EFSRPC
Metadata stream.

**Stream Name (variable):** The name of the stream. This is set to either a null-terminated

Unicode string in UTF-16 encoding, or an integer value stored in binary form. For the EFSRPC
Metadata stream, this is always set to 0x1910.

|Value|Meaning|
|---|---|
|0x1910|EFSRPC Metadata stream|

**Stream Data Segment 1 ... n:** These segments MUST contain the contents of the stream as

well as some metadata for reassembling the segments. For encrypted streams, these
segments MUST also contain some metadata to aid in decryption. They MUST be formatted as
specified in section 2.2.3.2.

##### 2.2.3.2  Stream Data Segment

Each stream data segment MUST be formatted as follows.

|--- (32 bits)|
|Length (32 bits)|
|0x47|0x00|0x55|
|0x52|0x00|0x45|
|Reserved (32 bits)|
|Data Segment Encryption Header (variable) (32 bits)|
||
|Stream Data (variable) (32 bits)|
||

**Length (4 bytes):** The length, in bytes, of this segment. It MUST be a 32-bit unsigned integer

in little-endian format. The length MUST be measured from the start of this field to the end of
the **Stream Data** field.

**Reserved (4 bytes):** This field is set to zero and is ignored by the server.

**Data Segment Encryption Header (variable):** This header MUST be present only if the

stream is encrypted (that is, if the **Flag** field in the stream header is set to zero and this is not
the EFSRPC Metadata stream). It MUST be formatted as specified in section 2.2.3.3.

**Stream Data (variable):** This field MUST contain part or all of the stream data. If the **Data**

**Segment Encryption Header** field is present, **Stream Data** MUST be consistent with it.
**Stream Data** MUST consist of contiguous bytes taken from the stream except for zero bytes
that are omitted in accordance with the Data Segment Encryption Header. If the stream is
encrypted, its data MUST be encrypted with the FEK, using the algorithm indicated by the
**Algorithm** field in the EFSRPC Metadata (specified in section 2.2.2) in the Cipher Block
Chaining (CBC) mode.

##### 2.2.3.3  Data Segment Encryption Header

The Data Segment Encryption Header MUST be formatted as follows.

|--- (32 bits)|
|Starting File Offset (32 bits)|
||
|Length (32 bits)|
|Bytes Within Stream Size (32 bits)|
|Bytes Within VDL (32 bits)|
|0x0000|Data Unit Shift|Chunk Shift|
|Cluster Shift|0x01|Number of Data Blocks|
|Data Block Sizes (variable) (32 bits)|
||
|Extended Header (optional) (32 bits)|
||
||
||

**Starting File Offset (8 bytes):** This field MUST contain an unsigned 64-bit integer in little
endian format denoting the offset, in bytes, into the stream being serialized of the first data
byte contained in this data segment.

**Length (4 bytes):** The length of this header, in bytes, measured from the beginning of the

**Starting File Offset** field to the end of the **Data Segment Encryption Header** . It MUST be
a 32-bit unsigned integer in little-endian format. Any unused bytes within this structure MUST
be set to zero and ignored by the server.

**Bytes Within Stream Size (4 bytes):** The number of bytes contained within this stream data

segment that fall within the stream size. It MUST be a 32-bit unsigned integer in little-endian
format. This may be less than the number of bytes actually present due to padding required
by the encryption algorithm.

**Bytes Within VDL (4 bytes):** The number of bytes contained within this stream data segment

that fall within the **valid data length (VDL)** . It MUST be a 32-bit unsigned integer in littleendian format. This may be less than the number of bytes actually present due to padding
required by the encryption algorithm. Bytes beyond the VDL MUST be set to zero after
decryption.

**Data Unit Shift (1 byte):** The base-2 logarithm of the data unit size. It MUST be an 8-bit

unsigned integer. For files that are not **sparse files**, the data unit size MUST be set to the
size of the data in this segment. For sparse files, it MUST be equal to the size of a
compression unit, which is the smallest unit that all holes MUST be a multiple of.

**Chunk Shift (1 byte):** The base-2 logarithm of the chunk size. It MUST be an 8-bit unsigned

integer. The chunk size MUST be equal to the data unit size.

**Cluster Shift (1 byte):** The base-2 logarithm of the cluster size in bytes. It MUST be an 8-bit

unsigned integer. It MUST be equal to the smallest unit of allocation in the underlying **file**
**system** .

**Number of Data Blocks (2 bytes):** This field MUST contain the number of data blocks

specified in this segment. It MUST be a 16-bit unsigned integer in little-endian format. It
MUST be equal to the number of entries in the **Data Block Sizes** field specified next.

**Data Block Sizes (variable):** This field MUST consist of a sequence of unsigned 32-bit values

in little-endian format, denoting the sizes of the successive data blocks in the **Stream Data**
field that follows this header. Each value in the sequence MUST be less than or equal to the
data unit size, unless it spans the VDL or a hole in the case of a sparse file.

**Extended Header (16 bytes):** This field is optional, and its presence is indicated by the four
byte signature located at the start of this field. If this field is present, the server SHOULD
interpret it as defined in section 2.2.3.4. The server MAY ignore this field.<13>

##### 2.2.3.4  Extended Header

The Extended Header is an optional field within the Data Segment Encryption Header (section
2.2.3.3). If present, it MUST be formatted as follows.

|--- (32 bits)|
|0x45|0x45|0x45|0x45|0x45|0x45|0x45|0x45|0x58|0x58|0x58|0x58|0x58|0x58|0x58|0x58|0x54|0x54|0x54|0x54|0x54|0x54|0x54|0x54|0x44|0x44|0x44|0x44|0x44|0x44|0x44|0x44|
|0x10|0x00|
|Flags (32 bits)|

Reserved

**Flags (4 bytes):** This MUST be a 32-bit unsigned integer in little-endian format. It MUST be

either zero or the following value.

|Value|Meaning|
|---|---|
|0x00000001|Used to indicate that the stream is contained within a sparse file.|

**Reserved (4 bytes):** This field MUST be set to zero and ignored by the server.

#### 2.2.4  PEXIMPORT_CONTEXT_HANDLE

The **PEXIMPORT_CONTEXT_HANDLE** data type is used to represent a pointer to a context
[handle. It MUST be treated as opaque by the client and used by the server, as specified in [C706].](http://go.microsoft.com/fwlink/?LinkId=89824)

This type is declared as follows:

```
   typedef [context_handle] void* PEXIMPORT_CONTEXT_HANDLE;

```

#### 2.2.5  EFS_EXIM_PIPE

The **EFS_EXIM_PIPE** type is used to represent a pipe for the EFSRPC raw methods. It consists of a
[set of callback routines for sending and receiving data, as specified in [C706].](http://go.microsoft.com/fwlink/?LinkId=89824)

This type is declared as follows:

```
   typedef pipe unsigned char EFS_EXIM_PIPE;

```

#### 2.2.6  EFS_CERTIFICATE_BLOB

The **EFS_CERTIFICATE_BLOB** type is used to represent the encoded contents of an X.509
certificate.

```
   typedef struct _CERTIFICATE_BLOB {
   DWORD dwCertEncodingType;
   [range(0,32768)] DWORD cbData;
   [size_is(cbData)] unsigned char* bData;
   } EFS_CERTIFICATE_BLOB;

```

**dwCertEncodingType:** The certificate encoding type. This MUST be set to one of the following

values. If set to any other value, the certificate is considered invalid and behavior is
undefined.

|Value|Meaning|
|---|---|
|0x00000001|Certificate uses X.509 ASN.1 encoding.|
|0x00000002|Certificate uses X.509 NDR encoding.|

**cbData:** The number of bytes in the bData buffer.

**bData:** An encoded X.509 certificate. Its format is specified by the **dwCertEncodingType**

[member. For more information on ASN encoding, see [X690]. NDR encoding is specified in](http://go.microsoft.com/fwlink/?LinkId=90593)

[[C706].<14>](http://go.microsoft.com/fwlink/?LinkId=89824)

#### 2.2.7  EFS_HASH_BLOB

The **EFS_HASH_BLOB** type is used to represent an X.509 certificate hash.

```
   typedef struct _EFS_HASH_BLOB {
   [range(0, 100)] DWORD cbData;
   [size_is(cbData)] unsigned char* bData;
   } EFS_HASH_BLOB;

```

**cbData:** The number of bytes in the bData buffer.

**bData:** The SHA-1 hash of an X.509 certificate. For more information on SHA-1, see

[[FIPS180].<15>](http://go.microsoft.com/fwlink/?LinkId=89867)

#### 2.2.8  ENCRYPTION_CERTIFICATE

The **ENCRYPTION_CERTIFICATE** type is used to represent a single X.509 certificate.

```
   typedef struct _ENCRYPTION_CERTIFICATE {
   DWORD cbTotalLength;
   RPC_SID* UserSid;
   EFS_CERTIFICATE_BLOB* CertBlob;
   } ENCRYPTION_CERTIFICATE;

```

**cbTotalLength:** The length, in bytes, of the structure.

**UserSid:** The SID of the user who owns the certificate. This is intended as a hint only. It MAY be

set to zero if no such hint is available. The structure of an RPC SID is as specified in [MSDTYP] section 2.4.2.3.

**CertBlob:** A pointer to an **EFS_CERTIFICATE_BLOB** (2.2.6) structure.

#### 2.2.9  ENCRYPTION_CERTIFICATE_LIST

The **ENCRYPTION_CERTIFICATE_LIST** type is used to represent a set of X.509 certificates. For
[more information on certificates, see [X509].](http://go.microsoft.com/fwlink/?LinkId=90590)

```
   typedef struct _ENCRYPTION_CERTIFICATE_LIST {
   [range(0,500)] DWORD nUsers;
   [size_is(nUsers,)] ENCRYPTION_CERTIFICATE** Users;

```

```
   } ENCRYPTION_CERTIFICATE_LIST;

```

**nUsers:** The number of certificates in the list.

**Users:** A pointer to an array of pointers to **ENCRYPTION_CERTIFICATE** (2.2.8) structures.

This array is of size nUsers.<16>

#### 2.2.10  ENCRYPTION_CERTIFICATE_HASH

The **ENCRYPTION_CERTIFICATE_HASH** type is used to represent a single certificate hash. For
[more information on certificates, see [X509].](http://go.microsoft.com/fwlink/?LinkId=90590)

```
   typedef struct _ENCRYPTION_CERTIFICATE_HASH {
   DWORD cbTotalLength;
   RPC_SID* UserSid;
   EFS_HASH_BLOB* Hash;
   [string] wchar_t* lpDisplayInformation;
   } ENCRYPTION_CERTIFICATE_HASH;

```

**cbTotalLength:** The length, in bytes, of the structure.

**UserSid:** The SID of the user who owns the certificate. This is intended only as a hint. It MAY be

set to zero if no such hint is available. The structure of an RPC SID is specified in [MS-DTYP],
section 2.4.2.3.

**Hash:** A pointer to an **EFS_HASH_BLOB** (2.2.7) structure.

**lpDisplayInformation:** A string that contains the subject or principal name of the account the

certification is assigned to. The subject name and the principal name can be the same. This is
only intended as a hint for display purposes, and is implementation-dependent. This field MAY
be set to NULL if no such information is available.

#### 2.2.11  ENCRYPTION_CERTIFICATE_HASH_LIST

The **ENCRYPTION_CERTIFICATE_HASH_LIST** type is used to represent a set of certificate
hashes.

```
   typedef struct _ENCRYPTION_CERTIFICATE_HASH_LIST {
   [range(0,500)] DWORD nCert_Hash;
   [size_is(nCert_Hash,)] ENCRYPTION_CERTIFICATE_HASH** Users;
   } ENCRYPTION_CERTIFICATE_HASH_LIST;

```

**nCert_Hash:** The number of certificate hashes in the list.

**Users:** A pointer to an array of pointers to **ENCRYPTION_CERTIFICATE_HASH** (2.2.10)

structures. This array is of size nCert_Hash.<17>

#### 2.2.12  EFS_RPC_BLOB

The **EFS_RPC_BLOB** type is used to represent a generic **binary large object (BLOB)** (that is, an
opaque data type).

```
   typedef struct _EFS_RPC_BLOB {
   [range(0,266240)] DWORD cbData;
   [size_is(cbData)] unsigned char* bData;
   } EFS_RPC_BLOB,
   *PEFS_RPC_BLOB;

```

**cbData:** The length, in bytes, of the data object in the bData field.

**bData:** The contents of the data object.<18>

#### 2.2.13  ALG_ID

The **ALG_ID** type is used to denote an algorithm type for cryptographic keys. An implementation
SHOULD<19> support all of the values shown in the following table. Implementations MAY<20>
choose to support other algorithms and values not shown here; if they do, they SHOULD reuse the
values specified in [[MSDN-CRYPTO] in order to avoid collisions. Implementations MAY<21>](http://go.microsoft.com/fwlink/?LinkId=89984) restrict
the set of supported algorithms based on administrative policy.

|Algorithm used|Value for ALG_ID|Entropy|Key length|
|---|---|---|---|
|CALG_AES_256|0x6610|256|32|
|CALG_3DES|0x6603|168|24|

In this table, Entropy represents the number of bits of true randomness in the algorithm's key
material, while Key length represents the total size of the key in bytes. For CALG_3DES, the
difference between entropy and key length is due to the parity bits included in the key. For more
information, see [TDEA].

This type is declared as follows:

```
   typedef unsigned int ALG_ID;

```

#### 2.2.14  EFS_KEY_INFO

The **EFS_KEY_INFO** type is used to represent information about a key of a symmetric
cryptosystem.

```
   typedef struct {
   DWORD dwVersion;
   unsigned long Entropy;
   ALG_ID Algorithm;
   unsigned long KeyLength;
   } EFS_KEY_INFO;

```

**dwVersion:** The version of this data structure. It MUST be equal to 0x00000001.

**Entropy:** The actual number of bits of entropy or true randomness in the key. This value,

divided by 8, MUST be less than or equal to the value of the **KeyLength** member.

**Algorithm:** The cryptographic algorithm with which the key is intended to be used.

**KeyLength:** The total length, in bytes, of the key. This value, multiplied by 8, MUST be greater

than or equal to the value of the **Entropy** member. Valid combinations of Entropy, Algorithm,
and KeyLength are specified in section 2.2.13.

#### 2.2.15  EFS_COMPATIBILITY_INFO

The **EFS_COMPATIBILITY_INFO** type is used to represent information about the compatibility
restrictions of an encrypted file.

```
   typedef struct {
   DWORD EfsVersion;
   } EFS_COMPATIBILITY_INFO;

```

**EfsVersion:** The **EfsVersion** associated with the EFSRPC Metadata. Valid values for the

**EfsVersion** field are described in sections 2.2.2.1 and 2.2.2.2.<22>

#### 2.2.16  EFS_ENCRYPTION_STATUS_INFO

The **EFS_ENCRYPTION_STATUS_INFO** structure is used to represent the predicted outcome if an
attempt were made to convert an unencrypted object to an encrypted state.

```
   typedef struct {
   BOOL bHasCurrentKey;
   DWORD dwEncryptionError;
   } EFS_ENCRYPTION_STATUS_INFO;

```

**bHasCurrentKey:** A Boolean value signifying whether an appropriate key was found that could

be used for encryption.

**dwEncryptionError:** The error code returned if encryption were attempted. If the operation

were to succeed, this value MUST be zero. Otherwise, it MUST be set to a nonzero value.

#### 2.2.17  EFS_DECRYPTION_STATUS_INFO

The **EFS_DECRYPTION_STATUS_INFO** type is used to represent the predicted outcome if an
attempt were made to read the plaintext of an encrypted object.

```
   typedef struct {
   DWORD dwDecryptionError;
   DWORD dwHashOffset;
   DWORD cbHash;
   } EFS_DECRYPTION_STATUS_INFO;

```

**dwDecryptionError:** The error code returned if decryption were attempted. If the operation

were to succeed, this value MUST be zero. Otherwise it MUST be set to a nonzero value.

**dwHashOffset:** The offset of the appended certificate hash in bytes from the start of this

structure.

**cbHash:** The length in bytes of the appended certificate hash.

If dwDecryptionError is nonzero, the preceding fields are followed by the hash of a certificate whose
corresponding private key is required for the decryption to succeed.

#### 2.2.18  ENCRYPTED_FILE_METADATA_SIGNATURE

The **ENCRYPTED_FILE_METADATA_SIGNATURE** structure is used by the client to prove to the
server that it possesses a private key that is authorized to decrypt a given object.

```
   typedef struct _ENCRYPTED_FILE_METADATA_SIGNATURE {
   DWORD dwEfsAccessType;
   ENCRYPTION_CERTIFICATE_HASH_LIST* CertificatesAdded;
   ENCRYPTION_CERTIFICATE* EncryptionCertificate;
   EFS_RPC_BLOB* EfsStreamSignature;
   } ENCRYPTED_FILE_METADATA_SIGNATURE;

```

**dwEfsAccessType:** The operation being performed. It MUST be set to one of the following

values.

|Value|Meaning|
|---|---|
|EFS_METADATA_ADD_USER<br>0x00000001|One or more additional user certificates are being granted<br>access to the object.|
|EFS_METADATA_REMOVE_USER<br>0x00000002|One or more user certificates are having their access to the<br>object revoked.|
|EFS_METADATA_REPLACE_USER<br>0x00000004|One or more user certificates with access to the object are<br>being replaced.|
|EFS_METADATA_GENERAL_OP<br>0x00000008|A change is being made to the metadata that is not fully<br>described by exactly one of the previous options.|

**CertificatesAdded:** The X.509 certificates whose corresponding private keys are to be granted

or denied the ability to decrypt the object.

**EncryptionCertificate:** The X.509 certificates whose corresponding private key the caller claims

to possess.

**EfsStreamSignature:** The signature obtained by signing the SHA-1 hash of the new EFSRPC

Metadata with the private RSA key corresponding to EncryptionCertificate.
