# EFSRPC Metadata Version 2 (§2.2.2.2)

On-disk metadata format for EFS Version 4–5 (Windows Vista+).
Uses EFSX Datum tagged structures instead of flat key lists.

##### 2.2.2.2  EFSRPC Metadata Version 2

This metadata format is specified by an EFS Version of 4 in the EFSRPC metadata header. This new
metadata format is referred to as "Version 2" of the EFSRPC metadata, but do not confuse this with
the EFS Version field specified within the metadata header. The format used for Version 2 EFSRPC
metadata is significantly different from Version 1 described in section 2.2.2.1. Servers SHOULD
support Version 2 of the EFSRPC Metadata.<11> A server that supports Version 2 of the EFSRPC
Metadata MUST also fully support EFSRPC Metadata Version 1.

|--- (32 bits)|
|Length (32 bits)|
|Reserved1 (32 bits)|
|EFS_Version (32 bits)|
|Reserved2 (32 bits)|
|EFS_ID (32 bits)|
||
||
||
|DDF_Offset (32 bits)|
|DRF_Offset (32 bits)|
|FekInfo_Datum (32 bits)|
||
||
|Data_Fields (variable) (32 bits)|
||

**Length (4 bytes):** This field MUST contain a 32-bit unsigned integer equal to the length, in

bytes, of the EFSRPC Metadata.<12>

**Reserved1 (4 bytes):** MUST be set to zero and ignored upon receipt.

**EFS_Version (4 bytes):** This field represents the highest EFS version supported by the

implementation that created this metadata. It MUST be a 32-bit unsigned integer in littleendian format. It MUST be set to 0x00000004.

**Reserved2 (4 bytes):** MUST be set to zero and ignored upon receipt.

**EFS_ID (16 bytes):** A 16-byte GUID value that MUST be unique for the computer that created

this metadata.

**DDF_Offset (4 bytes):** This field MUST contain the offset, in bytes, of the DDF protector list

from the start of the EFSRPC Metadata. It MUST be a 32-bit unsigned integer in little-endian
format. The DDF protector list lies completely within the **Data Fields** and does not overlap the
DRF protector list (if present).

**DRF_Offset (4 bytes):** This field MUST contain the offset, in bytes, of the DRF protector list

from the start of the EFSRPC Metadata. It MUST be a 32-bit unsigned integer in little-endian
format. A zero value in this field indicates that the DRF protector list is absent and no DRAs
have been applied to the file. If present, the DRF protector list MUST lie completely within
**Data Fields** and MUST NOT overlap the DDF protector list.

**FekInfo_Datum (12 bytes):** This field contains the encrypted Fek and the File IV. It also

contains the **ALG_ID** for the Fek. The **FekInfo Datum** MUST conform to the format described
in section 2.2.2.2.8.

**Data_Fields (variable):** This field MUST contain the following two items in any order at the

locations indicated by the respective **Offset** fields previously listed. Both items MUST conform
to the protector list format specified in section 2.2.2.2.1. The DDF key list MUST NOT overlap
with the DRF key list (if present).

|--- (32 bits)|
|DDF_protector_list (variable) (32 bits)|
||
|DRF_protector_list (variable) (32 bits)|
||

**DDF_protector_list (variable):** This field MUST contain one or more entries, each of

which consists of a key protector as specified in section 2.2.2.2.5. Each key protector in
this list is protected with a user public key.

**DRF_protector_list (variable):** This MUST contain one or more entries, each of which

consists of a key protector as specified in section 2.2.2.2.5. Each key protector in this
list is protected with the public key of a DRA authorized to access the file. This MUST
only be present if the value in the DRF offset field is nonzero.

###### 2.2.2.2.1  Protector List Structure

The DDF and DRF Protector List structure in the Version 4 EFSRPC Metadata MUST be formatted as
follows.

|--- (32 bits)|
|StructureSize (32 bits)|
|ProtectorsCount|Protector_List_Entry 1 (variable)|
||
|Protector_List_Entries (variable) (32 bits)|
||
|Protector_List_Entry ProtectorsCount (variable) (32 bits)|
||

**StructureSize (4 bytes):** The size in bytes of the protector list. It MUST be a 32-bit unsigned

integer in little-endian format.

**ProtectorsCount (2 bytes):** This represents the number of protectors in the protector list. It

MUST be a 16-bit unsigned integer in little-endian format.

**Protector_List_Entries (variable):** A number of entries equal to the value in the

ProtectorsCount field. The individual entries MUST be formatted as specified in section
2.2.2.2.5.

###### 2.2.2.2.2  EFSX Datum

The EFSX Datum represents the base type for every datum within the Version 4 EFSRPC Metadata
and MUST be formatted as follows.

|--- (32 bits)|
|StructureSize|Role|
|Type|Flags|

**StructureSize (2 bytes):** The size in bytes of the EFSX Datum. It MUST be a 16-bit unsigned

integer in little-endian format.

**Role (2 bytes):** Specifies the EFSX Datum role. It MUST be a 16-bit unsigned integer in little
endian format.

|Value|Meaning|
|---|---|
|0x0000|The EFSX Datum has no defined role.|
|0x0001|The EFSX Datum contains a reference to a user's certificate store. This reference could|

|Value|Meaning|
|---|---|
||be, for example, a certificate hash or the public key from a certificate.|
|0x0002|The EFSX Datum contains data specific to a protector type. See section2.2.2.2.5 for<br>valid protector types and their associated protector data format.|
|0x0003|The EFSX Datum contains information that is suitable for user display. For example, this<br>could be the user name associated with a protector.|
|0x0004|The EFSX Datum contains information that identifies a private key container.|
|0x0005|The EFSX Datum contains information that identifies the provider name of a CSP or KSP.|
|0x0006|The EFSX Datum contains a user**SID**.|
|0x0007|The EFSX Datum contains the encrypted File Master Key (FMK).|
|0x0008|The EFSX Datum contains a user's public key.|
|0x0009|The EFSX Datum contains an ephemeral public key.|
|0x000a|The EFSX Datum contains the encrypted File Encryption Key (FEK).|
|0x000b|The EFSX Datum contains the file Initialization Vector (IV).|

**Type (2 bytes):** Specifies the EFSX Datum type. It MUST be a 16-bit unsigned integer in little
endian format.

|Value|Meaning|
|---|---|
|Reserved<br>0x0000|Reserved. Local use only.|
|EFSX_TYPE_BLOB<br>0x0001|The EFSX Datum MUST be formatted as specified in section<br>2.2.2.2.3.|
|EFSX_TYPE_DESCRIPTOR<br>0x0002|The EFSX Datum MUST be formatted as specified in section<br>2.2.2.2.4.|
|EFSX_TYPE_KEY_PROTECTOR<br>0x0003|The EFSX Datum MUST be formatted as specified in section<br>2.2.2.2.5.|
|EFSX_TYPE_PROTECTOR_INFO<br>0x0004|The EFSX Datum MUST be formatted as specified in section<br>2.2.2.2.6.|
|EFSX_TYPE_KEY_AGMT_DATA<br>0x0005|The EFSX Datum MUST be formatted as specified in section<br>2.2.2.2.7.|
|EFSX_TYPE_FEK_INFO<br>0x0006|The EFSX Datum MUST be formatted as specified in section<br>2.2.2.2.8.|

**Flags (2 bytes):** Specifies datum flags. It MUST be a 16-bit unsigned integer in little-endian

format. The value of this field MUST be zero (0x0000) or a union of one or more of the
following values.

|Value|Meaning|
|---|---|
|0x0001|The EFSX Datum is nested inside a parent structure.|
|0x0002|The EFSX Datum is a complex datum containing nested datum structures.|

###### 2.2.2.2.3  Blob Datum

The Blob Datum encapsulates an opaque binary object. It MUST be formatted as below.

|--- (32 bits)|
|EFSX_Datum (32 bits)|
||
|BlobType|BlobFlags|
|Blob_Data (variable) (32 bits)|
||

**EFSX_Datum (8 bytes):** MUST be formatted as specified in section 2.2.2.2.2. The datum Type

MUST be EFSX_TYPE_BLOB (0x0001). The datum **Flags** MUST NOT include 0x0002.

**BlobType (2 bytes):** The type of the blob, which provides a hint to the format of the **Blob**

**Data** . It MUST be a 16-bit unsigned integer in little-endian format.

|Value|Meaning|
|---|---|
|0x0000|The blob has no special formatting.|
|0x0001|The blob contains a public key formatted as a BCRYPT_PUBLIC_KEY_BLOB.|
|0x0002|The blob contains a SHA-1 hash of a DER-encoded form of a certificate.|
|0x0003|The blob contains the encrypted form of an Encrypted FEK structure, as defined in<br>section 2.2.2.1.5. The contents of the key may be either the FEK or the FMK, see section<br>2.2.2.2.5.|
|0x0004|The blob contains key material wrapped with an AES-256 key wrapping key, as defined<br>by[RFC3394].|

**BlobFlags (2 bytes):** Reserved, MUST be 0x0000.

**Blob_Data (variable):** Contains opaque, variable-length data. The **Blob Data** MUST be entirely

contained within the Blob Datum.

###### 2.2.2.2.4  Descriptor Datum

The Descriptor Datum encapsulates a Unicode string in UTF-16 encoding. It MUST be formatted as
below.

|--- (32 bits)|
|EFSX_Datum (32 bits)|
||
|Descriptor_Text (variable) (32 bits)|
||

**EFSX_Datum (8 bytes):** MUST be formatted as specified in section 2.2.2.2.2. The datum **Type**

MUST be EFSX_TYPE_DESCRIPTOR (0x0002). The datum **Flags** MUST NOT include 0x0002.

**Descriptor_Text (variable):** Contains a null-terminated, variable-sized Unicode string in UTF
16 encoding. The **Descriptor Text** MUST be entirely contained within the **Descriptor** Datum.
The length of the **Descriptor Text** MUST be at least 2 bytes to include the null terminator
(0x0000).

###### 2.2.2.2.5  Protector List Entry

Each individual Protector List Entry MUST be formatted as follows.

|--- (32 bits)|
|EFSX_Datum (32 bits)|
||
|ProtectorType|ProtectorFlags|
|Data_Fields (variable) (32 bits)|
||

**EFSX_Datum (8 bytes):** MUST be formatted as specified in section 2.2.2.2.2. The datum **Type**

MUST be EFSX_TYPE_KEY_PROTECTOR (0x0003) and SHOULD have a **Role** of
EFSX_ROLE_IGNORE (0x0000). The datum **Flags** SHOULD include 0x0002 indicating a
complex datum.

**ProtectorType (2 bytes):** The type of the protector. It MUST be a 16-bit unsigned integer in

little-endian format. Possible values are specified below.

|Value|Meaning|
|---|---|
|0x0002|The protector was derived from a public/private key pair using a key agreement. The<br>Data Fields SHOULD include an EFSX_Datum of**Type** EFSX_TYPE_KEY_AGMT_DATA<br>(0x0005) and**Role** 0x0002.|

|Value|Meaning|
|---|---|
|0x0001|The protector was derived from a public/private key pair capable of performing<br>asymmetric encryption. The**Data Fields** SHOULD include an EFSX_Datum of**Type** <br>EFSX_TYPE_BLOB (0x0005) and**Role** 0x0002.|

**ProtectorFlags (2 bytes):** The flags for the protector. It MUST be a 16-bit unsigned integer in

little-endian format. The value MUST be 0x0000 or a union of one or more of the following
values.

|Value|Meaning|
|---|---|
|0x0001|The protector is a legacy protector, and stores the Encrypted FEK as specified in section<br>2.2.2.1.5.|
|0x0002|If this is a legacy protector (flag 0x0001 is also set), the Encrypted FEK is encrypted<br>using AES 256, with a key that is obtained by signing the non-terminated Unicode string<br>"MICROSOFTE" (20 bytes long) with the user's RSA and computing the SHA-256 hash of<br>the result.|
|0x0004|If this bit is set, bit 0x0001 MUST also be set to indicate a legacy protector. This bit<br>indicates that the legacy protector stores the File Master Key (FMK) encrypted in the<br>Encrypted FEK structure instead of the File Encryption Key (FEK).|

**Data_Fields (variable):** This field contains any number of nested EFSX_Datum structures. The

nested datum structures MUST NOT overlap, and MUST be entirely contained within the
protector list entry. It SHOULD contain a datum with a **Role** of 0x0001 (certificate store
reference), a datum with a **Role** of 0x0002 (protector data), and a datum with a **Type** of
EFSX_TYPE_PROTECTOR_INFO (0x0004).

###### 2.2.2.2.6  Protector Info Datum

The Protector Info Datum encapsulates information describing the origin of a protector. It MUST be
formatted as below.

|--- (32 bits)|
|EFSX_Datum (32 bits)|
||
|Data_Fields (variable) (32 bits)|
||

**EFSX_Datum (8 bytes):** MUST be formatted as specified in section 2.2.2.2.2. The datum **Type**

MUST be EFSX_TYPE_PROTECTOR_INFO (0x0004). The datum **Flags** SHOULD include 0x0002
indicating a complex datum.

**Data_Fields (variable):** This field contains any number of nested EFSX_Datum structures. The

nested datum structures MUST NOT overlap, and MUST be entirely contained within the
protector info datum.

###### 2.2.2.2.7  Key Agreement Datum

The Key Agreement datum encapsulates the parameters necessary to decrypt a key agreement
protector ( **ProtectorType** of 0x0001).

|--- (32 bits)|
|EFSX_Datum (32 bits)|
||
|KeyAgmtFlags|Data_Fields (variable)|
||

**EFSX_Datum (8 bytes):** MUST be formatted as specified in section 2.2.2.2.2. The datum **Type**

MUST be EFSX_TYPE_KEY_AGMT_DATA (0x0005). The datum **Flags** SHOULD include 0x0002,
indicating a complex datum.

**KeyAgmtFlags (2 bytes):** This field is reserved and SHOULD be set to 0x0000.

**Data_Fields (variable):** This field contains any number of nested EFSX_Datum structures. The

nested datum structures MUST NOT overlap, and MUST be entirely contained within the Key
Agreement datum. This field SHOULD contain three datum structures of type
EFSX_TYPE_BLOB (0x0001) and **Roles** of 0x0007, 0x0008, and 0x0009. The public keys
referenced by **Roles** 0x0008 and 0x0009 MUST have **BlobType** set to 0x0001.

###### 2.2.2.2.8  Fek Info Datum

The Fek Info datum encapsulates the algorithm ID ( **ALG_ID** ) used for the FEK, the encrypted FEK,
and the File IV. The FEK and File IV are both protected using **advanced encryption standard**
**(AES)** keywrap, with the FMK as the wrapping key.

|--- (32 bits)|
|EFSX_Datum (32 bits)|
||
|AlgorithmID (32 bits)|
|Data_Fields (variable) (32 bits)|
||

**EFSX_Datum (8 bytes):** MUST be formatted as specified in section 2.2.2.2.2. The datum **Type**

MUST be EFSX_TYPE_FEK_INFO (0x0006). The datum **Flags** SHOULD include 0x0002,
indicating a complex datum.

**AlgorithmID (4 bytes):** The symmetric cryptographic algorithm associated with this key. It

MUST be a 32-bit unsigned integer in little-endian format. Possible values are specified in
section 2.2.13.

**Data_Fields (variable):** This field contains any number of nested EFSX_Datum structures. The

nested datum structures MUST NOT overlap, and MUST be entirely contained within the Fek
Info datum. This field MUST contain at least two datum structures of type EFSX_TYPE_BLOB
(0x0001). These blobs MUST have **Role** fields set to 0x000a (for the encrypted FEK) and
0x000b (for the encrypted File IV), respectively. The **BlobType** for these blobs MUST be
0x0004, indicating that the blob data contains a key wrapped with an AES 256 key encryption
[key, as defined in [RFC3394].](http://go.microsoft.com/fwlink/?LinkId=131784)
