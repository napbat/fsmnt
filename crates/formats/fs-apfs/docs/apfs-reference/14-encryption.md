<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Encryption

Apple File System supports encryption in the data structures used for containers, volumes, and files. When a volume is encrypted, both its file-system tree and the contents of files in that volume are encrypted.

Depending on the deviceʼs capabilities, Apple File System uses either hardware or software encryption, which impacts encryption process and the meaning of several data structures. Hardware encryption is used for internal storage on devices that support it, including macOS (with T2 security chip) and iOS devices. Software encryption is used for external storage, and for internal storage on devices that donʼt support hardware encryption. When hardware encryption is in use, only the kernel can interact with internal storage.

## **Important**

This document describes only software encryption.

The keys used to access file data are stored on disk in a wrapped state. You access these keys through a chain of key-unwrapping operations. The _volume encryption key_ (VEK) is the default key used to access encrypted content on the volume. The _key encryption key_ (KEK) is used to unwrap the VEK. The KEK is unwrapped in one of several ways:

- **User password.** The user enters their password, which is used to unwrap the KEK.

- **Personal recovery key.** This key is generated when the drive is formatted and is saved by the user on a paper printout. The string on that printout is used to unwrap the KEK.

- **Institutional recovery key.** This key is enabled by the user in Settings and allows the corresponding corporate master key to unwrap the KEK.

- **iCloud recovery key.** This key is used by customers working with Apple Support, and isnʼt described in this document.

For example, to access a file given the userʼs password on a volume that uses per-volume encryption, the chain of key unwrapping and data decryption consists of the following high-level operations:

1. Unwrap the KEK using the userʼs password.

2. Unwrap the VEK using the KEK.

3. Decrypt the file-system B-tree using the VEK.

4. Decrypt the file data using the VEK.

The detailed steps are described in Accessing Encrypted Objects below.

## **Keybag**

On macOS devices, both the container and the volume have a keybag (an instance of _`kb_locker_t`_ ). The containerʼs keybag is stored at the location indicated by the _`nx_keylocker`_ field of _`nx_superblock_t`_ . For each volume, the containerʼs keybag stores the volumeʼs wrapped VEK and the location of the volumeʼs keybag. The volumeʼs keybag contains several copies of the volumeʼs KEK, wrapped using user passwords and recovery keys.


135

**Encryption** Accessing Encrypted Objects

**==> picture [296 x 290] intentionally omitted <==**

Keybags are encrypted using the UUID of the container or volume, which makes it possible to quickly and securely destroy the contents of an encrypted volume by changing or deleting the UUID. For a volume, destroying the UUID by securely erasing a volume superblock makes the corresponding keybag unreadable, which in turn makes the encrypted content of that volume inaccessible. For a container superblock, you need to destroy all of the copies of that block in the checkpoint descriptor area and the copy at block zero.

## Accessing Encrypted Objects

Before accessing an encrypted object, confirm that the _`APFS_FS_ONEKEY`_ flag is set on the volume. Volumes that use per-file encryption require hardware encryption, and the steps below describe only software encryption.

To obtain the unwrapped VEK for a volume, do the following:

1. Locate the containerʼs keybag using the _`nx_keylocker`_ field of _`nx_superblock_t`_ .

2. Unwrap the containerʼs keybag using the containerʼs UUID, according to the algorithm described in RFC 3394.

3. Find an entry in the containerʼs keybag whose UUID matches the volumeʼs UUID and whose tag is _`KB_TAG_VOLUME_KEY`_ . The key data for that entry is the wrapped VEK for this volume.

4. Find an entry in the containerʼs keybag whose UUID matches the volumeʼs UUID and whose tag is _`KB_TAG_VOLUME_UNLOCK_RECORDS`_ . The key data for that entry is the location of the volumeʼs keybag.

5. Unwrap the volumeʼs keybag using the volumeʼs UUID according to the algorithm described in RFC 3394.

6. Find an entry in the volumeʼs keybag whose UUID matches the userʼs Open Directory UUID and whose tag is _`KB_TAG_VOLUME_UNLOCK_RECORDS`_ . The key data for that entry is the wrapped KEK for this volume.

7. Unwrap the KEK using the userʼs password, and then unwrap the VEK using the KEK, both according to the algorithm described in RFC 3394.


136

**Encryption** _`j_crypto_key_t`_

The volumeʼs keybag might contain a passphrase hint for the user ( _`KB_TAG_VOLUME_PASSPHRASE_HINT`_ ), which you can display when prompting for the password. It also might contain an entry for a personal recovery key, using _`APFS_FV_PERSONAL_RECOVERY_KEY_UUID`_ as the UUID. You follow the same process for a personal recovery key as you do for a password: Unwrap the KEK with the user-entered string, and then use the unwrapped KEK to unwrap the VEK, both according to the algorithm described in RFC 3394.

To decrypt a file, do the following:

1. Decrypt the blocks where the volumeʼs root file-system tree is stored, using the VEK as an AES-XTS key. The file-system tree is accessed using the _`apfs_root_tree_oid`_ field of _`apfs_superblock_t`_ .

2. Find the file extent record ( _`APFS_TYPE_FILE_EXTENT`_ ) for the encrypted file.

3. Find the encryption state record ( _`APFS_TYPE_CRYPTO_STATE`_ ) whose identifier matches the _`crypto_id`_ field of _`j_file_extent_val_t`_ .

4. Decrypt the blocks where the fileʼs data is stored, using the VEK as an AES-XTS key and the value of _`crypto_id`_ as the tweak.

## _`j_crypto_key_t`_

The key half of a per-file encryption state record.

```
structj_crypto_key{
j_key_thdr;
}__attribute__((packed));
typedefstructj_crypto_keyj_crypto_key_t;
```

Several encryption state objects always have the same identifier, as listed in Encryption Identifiers.

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the file-system objectʼs identifier. The type in the header is always _`APFS_TYPE_CRYPTO_STATE`_ .

## _`j_crypto_val_t`_

The value half of a per-file encryption state record.

```
structj_crypto_val{
uint32_trefcnt;
wrapped_crypto_state_tstate;
}__attribute__((aligned(4),packed));
typedefstructj_crypto_valj_crypto_val_t;
```

## _`refcnt`_

The reference count.

```
int32_trefcnt;
```


137

**Encryption** _`wrapped_crypto_state_t`_

The encryption state record can be deleted when its reference count reaches zero.

## _`state`_

The encryption state information.

```
wrapped_crypto_state_tstate;
```

If this encryption state record is used by the file-system tree rather than by a file, this field is an instance of _`wrapped_meta_crypto_state_t`_ and the key used is always the volume encryption key (VEK).

## _`wrapped_crypto_state_t`_

A wrapped key used for per-file encryption.

```
structwrapped_crypto_state{
uint16_tmajor_version;
uint16_tminor_version;
crypto_flags_tcpflags;
cp_key_class_tpersistent_class;
cp_key_os_version_tkey_os_version;
cp_key_revision_tkey_revision;
uint16_tkey_len;
uint8_tpersistent_key[0];
}__attribute__((aligned(2),packed));
typedefstructwrapped_crypto_statewrapped_crypto_state_t;
```

```
#defineCP_MAX_WRAPPEDKEYSIZE128
```

This structure is used inside of _`j_crypto_val_t`_ .

## _`major_version`_

The major version for this structureʼs layout.

```
uint16_tmajor_version;
```

The current value of this field is five. If backward-incompatible changes are made to this data structure in the future, the major version number will be incremented.

This structure is equivalent to a structure used by iOS for per-file encryption on HFS-Plus; versions four and earlier were used by previous versions of that structure.

## _`minor_version`_

The major version for this structureʼs layout.

```
uint16_tminor_version;
```

The current value of this field is zero. If backward-compatible changes are made to this data structure in the future, the minor version number will be incremented.


138

**Encryption** _`wrapped_crypto_state_t`_

## _`cpflags`_

The encryption stateʼs flags.

```
crypto_flags_tcpflags;
```

There are currently none defined.

## _`persistent_class`_

The protection class associated with the key.

```
cp_key_class_tpersistent_class;
```

For possible values and the bit mask that must be used, see Protection Classes.

## _`key_os_version`_

The version of the OS that created this structure.

```
cp_key_os_version_tkey_os_version;
```

This field is used as part of key rolling. For information about how the major version number, minor version number, and build number are packed into 32 bits, see _`cp_key_os_version_t`_ .

## _`key_revision`_

The version of the key.

```
cp_key_revision_tkey_revision;
```

Set this field to one when creating a new instance, and increment it by one when rolling to a new key.

## _`key_len`_

The size, in bytes, of the wrapped key data.

```
uint16_tkey_len;
```

The maximum value of this field is _`CP_MAX_WRAPPEDKEYSIZE`_ .

## _`persistent_key`_

The wrapped key data.

```
uint8_tpersistent_key[0];
```

## _`CP_MAX_WRAPPEDKEYSIZE`_

The size, in bytes, of the largest possible key.

```
#defineCP_MAX_WRAPPEDKEYSIZE128
```


139

**Encryption** _`wrapped_meta_crypto_state_t`_

## _`wrapped_meta_crypto_state_t`_

Information about how the volume encryption key (VEK) is used to encrypt a file.

```
structwrapped_meta_crypto_state{
uint16_tmajor_version;
uint16_tminor_version;
crypto_flags_tcpflags;
cp_key_class_tpersistent_class;
cp_key_os_version_tkey_os_version;
cp_key_revision_tkey_revision;
uint16_tunused;
}__attribute__((aligned(2),packed));
typedefstructwrapped_meta_crypto_statewrapped_meta_crypto_state_t;
```

This structure is used inside of _`j_crypto_val_t`_ . The fields in this structure are the same as _`wrapped_crypto_ state_t`_ , except this structure doesnʼt contain a wrapped key.

## _`major_version`_

The major version for this structureʼs layout.

```
uint16_tmajor_version;
```

The value of this field is always five. This structure is equivalent to a structure used by iOS for per-file encryption on HFS-Plus; versions four and earlier were used by previous versions of that structure.

## _`minor_version`_

The major version for this structureʼs layout.

```
uint16_tminor_version;
```

The value of this field is always zero.

## _`cpflags`_

The encryption stateʼs flags.

```
crypto_flags_tcpflags;
```

There are currently none defined.

## _`persistent_class`_

The protection class associated with the key.

```
cp_key_class_tpersistent_class;
```

For possible values, see Protection Classes.


140

**Encryption** Encryption Types

## _`key_os_version`_

The version of the OS that created this structure.

```
cp_key_os_version_tkey_os_version;
```

For information about how the major version number, minor version number, and build number are packed into 32 bits, see _`cp_key_os_version_t`_ .

## _`key_revision`_

The version of the key.

```
cp_key_revision_tkey_revision;
```

Set this field to one when creating a new instance.

## _`unused`_

Reserved.

```
uint16_tunused;
```

Populate this field with zero when you create a new instance of this structure, and preserve its value when you modify an existing instance.

## Encryption Types

Data types used in encryption-related structures.

```
typedefuint32_tcp_key_class_t;
typedefuint32_tcp_key_os_version_t;
typedefuint16_tcp_key_revision_t;
typedefuint32_tcrypto_flags_t;
```

```
cp_key_class_t
```

A protection class.

```
typedefuint32_tcp_key_class_t;
```

For possible values, see Protection Classes.

```
cp_key_os_version_t
```

An OS version and build number.

```
typedefuint32_tcp_key_os_version_t;
```

This type stores an OS version and build number as follows:

- Two bytes for the major version number as an unsigned integer

- Two bytes for the minor version letter as an ASCII character

- Four bytes for the build number as an unsigned integer

For example, to store the build number 18A391:


141

**Encryption** Protection Classes

1. Store the number 18 ( _`0x12`_ ) in the highest two bytes, yielding _`0x12000000`_ .

2. Store the character A ( _`0x41`_ ) in the next two bytes, yielding _`0x12410000`_ .

3. Store the number 391 ( _`0x0187`_ ) in the lowest four bytes, yielding _`0x12410187`_ .

```
cp_key_revision_t
```

A version number for an encryption key.

```
typedefuint16_tcp_key_revision_t;
```

## _`crypto_flags_t`_

Flags used by an encryption state.

```
typedefuint32_tcrypto_flags_t;
```

These flags are used by the _`cpflags`_ field of _`wrapped_crypto_state_t`_ and _`wrapped_meta_crypto_state_t`_ . There are currently none defined.

## Protection Classes

Constants that indicate the data protection class of a file.

```
#definePROTECTION_CLASS_DIR_NONE0
#definePROTECTION_CLASS_A1
#definePROTECTION_CLASS_B2
#definePROTECTION_CLASS_C3
#definePROTECTION_CLASS_D4
#definePROTECTION_CLASS_F6
#definePROTECTION_CLASS_M14
```

```
#defineCP_EFFECTIVE_CLASSMASK0x0000001f
```

These values are used by the _`persistent_class`_ field of _`wrapped_meta_crypto_state_t`_ .

For more information about protection classes, see iOS Security Guide and FileProtectionType.

## _`PROTECTION_CLASS_DIR_NONE`_

Directory default.

```
#definePROTECTION_CLASS_DIR_NONE0
```

This protection class is used only on devices running iOS.

Files with this protection class use their containing directoryʼs default protection class, which is set by the _`default_protection_class`_ field of _`j_inode_val_t`_ .

## _`PROTECTION_CLASS_A`_

Complete protection.

```
#definePROTECTION_CLASS_A1
```


142

**Encryption** Protection Classes

This value corresponds to _`FileProtectionType.complete`_ .

## _`PROTECTION_CLASS_B`_

Protected unless open.

```
#definePROTECTION_CLASS_B2
```

This value corresponds to _`FileProtectionType.completeUnlessOpen`_ .

## _`PROTECTION_CLASS_C`_

Protected until first user authentication.

```
#definePROTECTION_CLASS_C3
```

This value corresponds to _`FileProtectionType.completeUntilFirstUserAuthentication`_ .

## _`PROTECTION_CLASS_D`_

No protection.

```
#definePROTECTION_CLASS_D4
```

This value corresponds to _`FileProtectionType.none`_ .

## _`PROTECTION_CLASS_F`_

No protection with nonpersistent key.

```
#definePROTECTION_CLASS_F6
```

The behavior of this protection class is the same as Class D, except the key isnʼt stored in any persistent way. This protection class is suitable for temporary files that arenʼt needed after rebooting the device, such as a virtual machineʼs swap file.

## _`PROTECTION_CLASS_M`_

_No overview available._

```
#definePROTECTION_CLASS_M14
```

## _`CP_EFFECTIVE_CLASSMASK`_

The bit mask used to access the protection class.

```
#defineCP_EFFECTIVE_CLASSMASK0x0000001f
```

All other bits are reserved. Populate those bits with zero when you create a wrapped key, and preserve their value when you modify an existing wrapped key.


143

**Encryption** Encryption Identifiers

## Encryption Identifiers

Encryption state objects whose identifier is always the same.

```
#defineCRYPTO_SW_ID4
#defineCRYPTO_RESERVED_55
```

```
#defineAPFS_UNASSIGNED_CRYPTO_ID(~0ULL)
```

## _`CRYPTO_SW_ID`_

The identifier of a placeholder encryption state used when software encryption is in use.

## _`#define CRYPTO_SW_ID 4`_

There is no associated encryption key for this encryption state. All the fields of the corresponding _`j_crypto_val_t`_ structure have a value of zero.

## _`CRYPTO_RESERVED_5`_

## Reserved.

## _`#define CRYPTO_RESERVED_5 5`_

Donʼt create an encryption state object with this identifier. If you find an object with this identifier in production, file a bug against the Apple File System implementation.

## _`APFS_UNASSIGNED_CRYPTO_ID`_

The identifier of a placeholder encryption state used when cloning files.

## _`#define APFS_UNASSIGNED_CRYPTO_ID (~0ULL)`_

As a performance optimization when cloning a file, Appleʼs implementation sets this placeholder value on the clone and continues to use the original fileʼs encryption state for both that file and its clone. If the clone is modified, a new encryption state object is created for the clone. Creating a new encryption state object is relatively expensive, and usually takes longer than the cloning process.

## _`kb_locker_t`_

## A keybag.

```
structkb_locker{
uint16_tkl_version;
uint16_tkl_nkeys;
uint32_tkl_nbytes;
uint8_tpadding[8];
keybag_entry_tkl_entries[];
};
```

```
typedefstructkb_lockerkb_locker_t;
```

```
#defineAPFS_KEYBAG_VERSION2
```


144

**Encryption** _`kb_locker_t`_

A keybag stores wrapped encryption keys and information thatʼs needed to unwrap them. The container and each volume have their own keybag.

The containerʼs keybag stores wrapped VEKs and the location of each volumeʼs keybag. A volumeʼs keybag stores wrapped KEKs.

```
kl_version
```

The keybag version.

```
uint16_tkl_version;
```

The value of this field is _`APFS_KEYBAG_VERSION`_ .

```
kl_nkeys
```

The number of entries in the keybag.

```
uint16_tkl_nkeys;
```

## _`kl_nbytes`_

The size, in bytes, of the data stored in the _`kl_entries`_ field.

```
uint32_tkl_nbytes;
```

```
padding
```

Reserved.

```
uint8_tpadding[8];
```

Populate this field with zero when you create a new keybag, and preserve its value when you modify an existing keybag.

This field is padding.

```
kl_entries
```

The entries.

```
keybag_entry_tkl_entries[];
```

```
APFS_KEYBAG_VERSION
```

The first version of the keybag.

```
#defineAPFS_KEYBAG_VERSION2
```

Version one was used during prototyping of Apple File System, and uses an incompatible, undocumented layout. If you find a keybag in production whose version is less than two, file a bug against the Apple File System implementation.


145

**Encryption** _`keybag_entry_t`_

## _`keybag_entry_t`_

An entry in a keybag.

```
structkeybag_entry{
uuid_tke_uuid;
uint16_tke_tag;
uint16_tke_keylen;
uint8_tpadding[4];
uint8_tke_keydata[];
```

```
};
typedefstructkeybag_entrykeybag_entry_t;
```

```
#defineAPFS_VOL_KEYBAG_ENTRY_MAX_SIZE512
#defineAPFS_FV_PERSONAL_RECOVERY_KEY_UUID”EBC6C064-0000-11AA-AA11-00306543ECAC”
```

## _`ke_uuid`_

In a containerʼs keybag, the UUID of a volume; in a volumeʼs keybag, the UUID of a user.

```
uuid_tke_uuid;
```

## _`ke_tag`_

A description of the kind of data stored in this keybag entry.

```
uint16_tke_tag;
```

For possible values, see Keybag Tags.

## _`ke_keylen`_

The length, in bytes, of the keybag entryʼs data.

```
uint16_tke_keylen;
```

The value of this field must be less than _`APFS_VOL_KEYBAG_ENTRY_MAX_SIZE`_ .

## _`padding`_

Reserved.

```
uint8_tpadding[4];
```

Populate this field with zero when you create a new keybag entry, and preserve its value when you modify an existing entry.

This field is padding.

```
ke_keydata
```

The keybag entryʼs data.

```
uint8_tke_keydata[];
```


146

**Encryption** _`media_keybag_t`_

The data stored this field depends on the tag and whether this is an entry in a container or volumeʼs keybag, as described in Keybag Tags.

```
APFS_VOL_KEYBAG_ENTRY_MAX_SIZE
```

The largest size, in bytes, of a keybag entry.

```
#defineAPFS_VOL_KEYBAG_ENTRY_MAX_SIZE512
```

```
APFS_FV_PERSONAL_RECOVERY_KEY_UUID
```

The user UUID used by a keybag record that contains a personal recovery key.

```
#defineAPFS_FV_PERSONAL_RECOVERY_KEY_UUID”EBC6C064-0000-11AA-AA11-00306543ECAC”
```

The personal recovery key is generated during the initial volume-encryption process, and itʼs stored by the user as a paper printout. You use it the same way you use a userʼs password to unwrap the corresponding KEK.

## _`media_keybag_t`_

A keybag, wrapped up as a container-layer object.

```
structmedia_keybag{
obj_phys_tmk_obj;
kb_locker_tmk_locker;
```

```
};
typedefstructmedia_keybagmedia_keybag_t;
```

```
mk_obj
```

The objectʼs header.

```
obj_phys_tmk_obj;
```

```
mk_locker
```

The keybag data.

```
kb_locker_tmk_locker;
```

## Keybag Tags

A description of what kind of information is stored by a keybag entry.

```
enum{
```

|_`{`_|||
|---|---|---|
|_`KB_TAG_UNKNOWN`_|_`= `_|_`0,`_|
|_`KB_TAG_RESERVED_1`_|_`= `_|_`1,`_|
|_`KB_TAG_VOLUME_KEY`_|_`= `_|_`2,`_|
|_`KB_TAG_VOLUME_UNLOCK_RECORDS`_|_`= `_|_`3,`_|
|_`KB_TAG_VOLUME_PASSPHRASE_HINT`_|_`= `_|_`4,`_|
|_`KB_TAG_WRAPPING_M_KEY`_|_`= `_|_`5,`_|




147

**Encryption** Keybag Tags

```
KB_TAG_VOLUME_M_KEY=6,
KB_TAG_RESERVED_F8=0xF8
```

```
};
```

```
KB_TAG_UNKNOWN
```

Reserved.

## _`KB_TAG_UNKNOWN = 0`_

This tag never appears on disk. If you find a keybag entry with this tag in production, file a bug against the Apple File System implementation.

This value isnʼt reserved by Apple; non-Apple implementations of Apple File System can use it in memory. For example, Appleʼs implementation uses this value as a wildcard that matches any tag.

```
KB_TAG_RESERVED_1
```

Reserved.

```
KB_TAG_RESERVED_1=1
```

Donʼt create keybag entries with this tag, but preserve any existing entries.

```
KB_TAG_VOLUME_KEY
```

The key data stores a wrapped VEK.

```
KB_TAG_VOLUME_KEY=2
```

This tag is valid only in a containerʼs keybag.

```
KB_TAG_VOLUME_UNLOCK_RECORDS
```

In a containerʼs keybag, the key data stores the location of the volumeʼs keybag; in a volume keybag, the key data stores a wrapped KEK.

```
KB_TAG_VOLUME_UNLOCK_RECORDS=3
```

This tag is used only on devices running macOS.

The volumeʼs keybag location is stored as an instance of _`prange_t`_ ; the data at that location is an instance of _`kb_locker_t`_ .

```
KB_TAG_VOLUME_PASSPHRASE_HINT
```

The key data stores a userʼs password hint as plain text.

```
KB_TAG_VOLUME_PASSPHRASE_HINT=4
```

This tag is valid only in a volumeʼs keybag, and itʼs used only on devices running macOS.


148

**Encryption** Keybag Tags

## _`KB_TAG_WRAPPING_M_KEY`_

The key data stores a key thatʼs used to wrap a media key.

```
KB_TAG_WRAPPING_M_KEY=5
```

This tag is used only on devices running iOS.

```
KB_TAG_VOLUME_M_KEY
```

The key data stores a key thatʼs used to wrap media keys on this volume.

```
KB_TAG_VOLUME_M_KEY=6
```

This tag is used only on devices running iOS.

```
KB_TAG_RESERVED_F8
```

Reserved.

```
KB_TAG_RESERVED_F8=0xF8
```

Donʼt create keybag entries with this tag, but preserve any existing entries.


149
