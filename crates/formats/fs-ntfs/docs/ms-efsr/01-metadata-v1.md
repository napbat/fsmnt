# EFSRPC Metadata Version 1 (§2.2.2)

On-disk metadata format for EFS Version 1–3 (Windows 2000/XP/2003).
Stored as `$LOGGED_UTILITY_STREAM` (0x100) attribute named `$EFS`.

#### 2.2.2  EFSRPC Metadata

The EFSRPC Metadata is attached to an encrypted object and contains information required to
decrypt it. The EFSRPC Metadata is used implicitly by the EFSRPC raw methods, because it forms
part of the EFSRPC Raw Data Format.

The structure of the EFSRPC Metadata is implementation dependent. An EFSRPC server SHOULD
return an error if EFSRPC Metadata is passed to it in an unsupported format. An EFSRPC client
SHOULD NOT parse the EFSRPC Metadata, and SHOULD NOT rely on it being in any particular
format.

The EFSRPC Metadata SHOULD be represented on the server as follows.

##### 2.2.2.1  EFSRPC Metadata Version 1

|--- (32 bits)|
|Length (32 bits)|
|Reserved1 (32 bits)|
|EFS_Version (32 bits)|
|Reserved2 (32 bits)|
|EFS_ID (32 bits)|
||
||
||
|EFS_Hash (32 bits)|
||
||
||
|Reserved3 (32 bits)|
||
||
||
|DDF_Offset (32 bits)|
|DRF_Offset (32 bits)|
|Reserved4 (32 bits)|
||

**Length (4 bytes):** This field MUST contain a 32-bit unsigned integer equal to the length, in

bytes, of the EFSRPC Metadata.<6>

**Reserved1 (4 bytes):** MUST be set to zero and ignored upon receipt.

**EFS_Version (4 bytes):** This field represents the highest EFS version supported by the

implementation that created this metadata. It MUST be a 32-bit unsigned integer in littleendian format. It MUST be set to one of the following values.

|Value|Meaning|
|---|---|
|Version_1<br>0x00000001|The**file encryption key (FEK)** will be a DESX key, and encrypted with**RSA** only.<br>The**Flags** field in all**key** list entries will be zero.|
|Version_2<br>0x00000002|The FEK will use DESX, 3DES, or AES-256. The FEK will be encrypted with RSA only.<br>The**Flags** field in all key list entries will be zero.|
|Version_3<br>0x00000003|The FEK will use DESX, 3DES, or AES-256. The FEK will be encrypted with either<br>RSA or AES-256.|

A server that supports a given version number MUST also support all lower numbered
versions. A server SHOULD support all versions listed.<7>

**Reserved2 (4 bytes):** MUST be set to zero and ignored upon receipt.

**EFS_ID (16 bytes):** A 16-byte **GUID** value that MUST be unique for the computer that created

this metadata.

**EFS_Hash (16 bytes):** This field SHOULD be set to zero and ignored by the server.<8>

**Reserved3 (16 bytes):** MUST be set to zero and ignored upon receipt.

**DDF_Offset (4 bytes):** This field MUST contain the offset, in bytes, of the **data decryption**

**field (DDF)** key list from the start of the EFSRPC Metadata. It MUST be a 32-bit unsigned
integer in little-endian format. The DDF key list lies completely within the **Data Fields** and
does not overlap the **data recovery field (DRF)** key list (if present).

**DRF_Offset (4 bytes):** This field MUST contain the offset, in bytes, of the DRF key list from the

start of the EFSRPC Metadata. It MUST be a 32-bit unsigned integer in little-endian format. A
zero value in this field indicates that the DRF key list is absent and no DRAs have been applied
to the file. If present, the DRF key list MUST lie completely within **Data Fields** and MUST NOT
overlap the DDF key list.

**Reserved4 (12 bytes):** MUST be set to zero and ignored upon receipt.

**Data_Fields (variable):** This field MUST contain the following two items in any order at the

locations indicated by the respective Offset fields previously listed. Both items MUST conform
to the key list format specified in section 2.2.2.1.1. The DDF key list MUST NOT overlap with
the DRF key list (if present). There MUST NOT be any unused areas within this field spanning

more than 8 contiguous bytes. Any unused areas within this field MUST be set to zero bytes
and ignored by the server.

|--- (32 bits)|
|DDF_key_list (variable) (32 bits)|
||
|DRF_key_list (variable) (32 bits)|
||

**DDF_key_list (variable):** This field MUST contain one or more entries. Each entry

consists of the file's FEK, encrypted with the public key of a user authorized to access
the file.

**DRF_key_list (variable):** This MUST contain one or more entries. Each entry consists of

the file's FEK, encrypted with the public key of a DRA authorized to access the file. This
MUST only be present if the value in the DRF offset field is nonzero.

###### 2.2.2.1.1  Key List Structure

The DDF and Key List structure in the EFSRPC Metadata MUST be formatted as follows.

|--- (32 bits)|
|Length (32 bits)|
|Key_List_1 (variable) (32 bits)|
||
|Key_List_n (variable) (32 bits)|
||

**Length (4 bytes):** The number of entries in this key list. It MUST be a 32-bit unsigned integer

in little-endian format.

**Key List entries 1 ... n:** A number of entries equal to the value in the **length of key list** field.

The individual entries MUST be formatted as specified in section 2.2.2.1.2.

###### 2.2.2.1.2  Key List Entry

Each individual Key List Entry MUST be formatted as follows.

|--- (32 bits)|
|Length (32 bits)|
|Offset to Public Key Information (32 bits)|
|Encrypted FEK Length (32 bits)|
|Offset to Encrypted FEK (32 bits)|
|Flags (32 bits)|
|Data Fields (variable) (32 bits)|
||

**Length (4 bytes):** MUST be equal to the length of this key list entry in bytes. It MUST be a 32
bit unsigned integer in little-endian format.

**Offset to Public Key Information (4 bytes):** MUST contain the offset to the **Public Key**

**Information** field in bytes from the start of this entry. It MUST be a 32-bit unsigned integer
in little-endian format. The **Public Key Information** field MUST be completely contained
inside the **Data Fields** .

**Encrypted FEK Length (4 bytes):** MUST be set to the length of the data in the **Encrypted**

**FEK** field, in bytes. It MUST be a 32-bit unsigned integer in little-endian format.

**Offset to Encrypted FEK (4 bytes):** MUST contain the offset to the **Encrypted FEK** field, in

bytes from the start of this entry. It MUST be a 32-bit unsigned integer in little-endian format.
The **Encrypted FEK** MUST be completely contained inside the **Data** fields.

**Flags (4 bytes):** This field MUST indicate the algorithm used to encrypt the FEK in this key list

entry. It MUST be a 32-bit unsigned integer in little-endian format. EFSRPC servers SHOULD
support all the values listed below, and MUST ignore any unsupported values.

|Value|Meaning|
|---|---|
|0x00000000|The**Encrypted FEK** field is encrypted using RSA, with a public key belonging to a<br>user or DRA.|
|0x00000001|The**Encrypted FEK** field is encrypted using AES-256, with a key that is obtained by<br>signing the non-terminated Unicode string "MICROSOFTE" (20 bytes long) with the<br>user's RSA and computing the SHA-256 hash of the result.<br>This value is used when a user's private key is stored on a smart card to improve<br>performance by minimizing the number of smart card accesses.<9>|

**Data Fields (variable):** This field MUST contain the following items, in any order, at the

locations indicated by the respective **Offset** fields previously listed. These items MUST be
completely contained inside this field and MUST NOT overlap each other. There MUST NOT be
unused areas within this field spanning more than 8 contiguous bytes.

|--- (32 bits)|
|Public Key Information (variable) (32 bits)|
||
|Encrypted FEK (variable) (32 bits)|
||

**Public Key Information (variable):** This field MUST contain information about the

**X.509** certificate that contains the RSA public key, which is used to encrypt the
**Encrypted FEK** field. It MUST be formatted as specified in section 2.2.2.1.3.

**Encrypted FEK (variable):** This field MUST contain information about the FEK, encrypted

as indicated by the contents of the **Flags** field. It MUST be formatted as specified in
section 2.2.2.1.5.

###### 2.2.2.1.3  Public Key Information

The Public Key Information structure MUST be formatted as follows.

|--- (32 bits)|
|Length (32 bits)|
|Offset to Owner Hint (32 bits)|
|0x03|0x00|
|Length of Certificate Data (32 bits)|
|Offset to Certificate Data (32 bits)|
|Reserved (32 bits)|
||
|Data Fields (variable) (32 bits)|
||

**Length (4 bytes):** This MUST be set to the length, in bytes, of this structure. It MUST be a 32
bit unsigned integer in little-endian format.

**Offset to Owner Hint (4 bytes):** If the **Owner Hint** field is present, this field MUST be set to

the offset of the **Owner Hint** from the beginning of this structure, measured in bytes. If this

field is zero, then the **Owner Hint** field MUST NOT be present. This field MUST be a 32-bit
unsigned integer in little-endian format.

**Length of Certificate Data (4 bytes):** The size, in bytes, of the **Certificate Data** field. It

MUST be a 32-bit unsigned integer in little-endian format.

**Offset to Certificate Data (4 bytes):** The offset, in bytes, of the **Certificate Data** field from

the start of this structure. It MUST be a 32-bit unsigned integer in little-endian format.

**Reserved (8 bytes):** MUST be set to zero and ignored upon receipt.

**Data Fields (variable):** This field MUST contain the following items, in any order, and at the

locations indicated by the respective **Offset** fields above. These items MUST be completely
contained inside this field and MUST NOT overlap each other. There MUST NOT be any unused
areas within this field that span more than eight contiguous bytes.

|--- (32 bits)|
|Owner Hint (variable) (32 bits)|
||
|Certificate Data (variable) (32 bits)|
||

**Owner Hint (variable):** A **security identifier (SID)** in RPC marshaling format that is

intended to be used as a hint regarding the identity of the key owner. This item MUST
be present only if the **Offset to Owner Hint** field is nonzero. The structure of an RPC
SID is specified in [MS-DTYP] section 2.4.2.3.

**Certificate Data (variable):** This field MUST contain information about the X.509

certificate associated with the public key that is used to encrypt the FEK data in this key
list entry. It MUST be formatted as specified in section 2.2.2.1.4.

###### 2.2.2.1.4  Certificate Data

The Certificate Data structure MUST be formatted as follows.

|--- (32 bits)|
|Offset to Certificate Thumbprint (32 bits)|
|Length of Certificate Thumbprint (32 bits)|
|Offset of Container Name (32 bits)|
|Offset of Provider Name (32 bits)|

**Offset to Certificate Thumbprint (4 bytes):** Offset of the **Certificate Thumbprint** field from

the start of this structure. It MUST be a 32-bit unsigned integer in little-endian format.

**Length of Certificate Thumbprint (4 bytes):** The length of the **Certificate Thumbprint**

field. It MUST be a 32-bit unsigned integer in little-endian format.

**Offset of Container Name (4 bytes):** Offset of the **Container Name** field (in bytes) from the

start of this structure. It MUST be a 32-bit unsigned integer in little-endian format. If this field
is set to zero, then the **Container Name** field MUST be absent.

**Offset of Provider Name (4 bytes):** Offset of the **Provider Name** field (in bytes) from the

start of this structure. It MUST be a 32-bit unsigned integer in little-endian format. If this field
is set to zero, the **Provider Name** field MUST be absent. If a **Provider Name** field is present,
a **Container Name** field MUST also be present.

**Offset of Display Name (4 bytes):** Offset of the **Display Name** field, (in bytes) from the start

of this structure. It MUST be a 32-bit unsigned integer in little-endian format. If this field is
set to zero, then the **Display Name** field MUST be absent.

**Data Fields (variable):** This field MUST contain the following items, in any order, and at the

locations indicated by the respective **Offset** fields previously listed. These items MUST be
completely contained inside this field and MUST NOT overlap each other. There MUST NOT be
any unused areas within this field that span more than 8 contiguous bytes.

|--- (32 bits)|
|Certificate Thumbprint (variable) (32 bits)|
||
|Container Name (variable) (32 bits)|
||
|Provider Name (variable) (32 bits)|
||
|Display Name (variable) (32 bits)|
||

**Certificate Thumbprint (variable):** The SHA-1 hash of the DER-encoded form of the

certificate. For more information on SHA-1, see [[FIPS180]. For more information on DER](http://go.microsoft.com/fwlink/?LinkId=89867)
[encoding, see [X690].](http://go.microsoft.com/fwlink/?LinkId=90593)

**Container Name (variable):** A null-terminated Unicode string in UTF-16 encoding that

provides a hint as to the public key container in which the key is stored. This field MUST
always be present if the **Provider Name** is present. When the **Container Name** field is
present, the **Offset of Container Name** field MUST be nonzero; otherwise, this field is
ignored by the server and does not affect protocol behavior.

**Provider Name (variable):** A null-terminated Unicode string in UTF-16 encoding. This

field MUST always be present if the **Container Name** is present. It MUST be omitted if
the **Offset of Provider Name** field is 0; otherwise, this field is ignored by the server
and does not affect protocol behavior.

**Display Name (variable):** A null-terminated Unicode string in UTF-16 encoding that

provides a hint as to the friendly name that can be used to identify this certificate for
display purposes. This field MUST be omitted if the **Offset of Display Name** field is 0.

###### 2.2.2.1.5  Encrypted FEK

The **Encrypted FEK** field in the DDF and DRF key list entries MUST consist of the following
structure, encrypted as specified in the description of the **Flags** field for the key list entry.

|--- (32 bits)|
|Key Length (32 bits)|
|Entropy (32 bits)|
|Algorithm (32 bits)|
|Reserved (32 bits)|
|Key (variable) (32 bits)|
||

**Key Length (4 bytes):** The length, in bytes, of the **Key** field. It MUST be a 32-bit unsigned

integer in little-endian format. Possible values depend on the algorithm ID ( **ALG_ID** ) as
specified in section 2.2.13.<10>

**Entropy (4 bytes):** The number of bits of true randomness in the key contained in this

structure. It MUST be a 32-bit unsigned integer in little-endian format. Possible values depend
on the **Algorithm** as specified in section 2.2.13.

**Algorithm (4 bytes):** The symmetric cryptographic algorithm associated with this key. It MUST

be a 32-bit unsigned integer in little-endian format. Possible values are specified in section
2.2.13. The possible values for this field are constrained by the value of the EFS version field
in the EFSRPC Metadata.

**Reserved (4 bytes):** MUST be set to zero and ignored.

**Key (variable):** The FEK for the file.
