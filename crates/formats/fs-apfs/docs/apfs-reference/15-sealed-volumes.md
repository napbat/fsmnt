<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Sealed Volumes

Sealed volumes contain a hash of their file system, which can be compared to their current content to determine whether the volume has been modified after it was sealed, or compared to a known value to determine whether the volume contains the expected content. On a sealed volume, all of the following must be true:

- The volumeʼs role is _`APFS_VOL_ROLE_SYSTEM`_ .

- The _`APFS_INCOMPAT_SEALED_VOLUME`_ flag is set on the volume.

- The _`apfs_integrity_meta_oid`_ field of _`apfs_superblock_t`_ has a nonzero value.

- The _`apfs_fext_tree_oid`_ field of _`apfs_superblock_t`_ has a nonzero value.

- The _`BTREE_HASHED`_ and _`BTREE_NOHEADER`_ flags are set on the B-tree object that stores the volumeʼs file system.

The B-tree that stores the volumeʼs file system also stores a hash of its contents. A hashed B-tree differs from an nonhashed B-tree as follows:

- The _`BTREE_HASHED`_ flag is set on the root node.

- The _`BTNODE_HASHED`_ flag is set on the nonroot nodes.

- The values stored in nonleaf B-trees are instances of _`btn_index_node_val_t`_ , containing the object identifier of the child node and the hash of the child node.

Conceptually, the hashed B-trees used by sealed volumes are similar to Merkle trees. However, unlike Merkle trees, these hashed B-trees store data as well as a hash of that data.

## _`integrity_meta_phys_t`_

Integrity metadata for a sealed volume.

```
structintegrity_meta_phys{
obj_phys_tim_o;
uint32_tim_version;
uint32_tim_flags;
apfs_hash_type_tim_hash_type;
uint32_tim_root_hash_offset;
xid_tim_broken_xid;
uint64_tim_reserved[9];
}__attribute__((packed));
typedefstructintegrity_meta_physintegrity_meta_phys_t;
```

```
im_o
```

The objectʼs header.

```
obj_phys_tim_o;
```

## _`im_version`_

The version of this data structure.

```
uint32_tim_version;
```


150

**Sealed Volumes** Integrity Metadata Version Constants

The value of this field must be one of the constants listed in Integrity Metadata Version Constants.

## _`im_flags`_

The flags used to describe configuration options.

```
uint32_tim_flags;
```

For the values used in this bit field, see Integrity Metadata Flags.

This field appears in version 1 and later of this data structure.

## _`im_hash_type`_

The hash algorithm being used.

```
apfs_hash_type_tim_hash_type;
```

This field appears in version 1 and later of this data structure.

## _`im_root_hash_offset`_

The offset, in bytes, of the root hash relative to the start of this integrity metadata object.

```
uint32_tim_root_hash_offset;
```

This field appears in version 1 and later of this data structure.

## _`im_broken_xid`_

The identifier of the transaction that unsealed the volume.

```
xid_tim_broken_xid;
```

When a sealed volume is modified, breaking its seal, that transaction identifier is recorded in this field and the _`APFS_SEAL_BROKEN`_ flag is set. Otherwise, the value of this field is zero.

This field appears in version 1 and later of this data structure.

```
im_reserved
```

Reserved.

```
uint64_tim_reserved[9];
```

This field appears in version 2 and later of this data structure.

## Integrity Metadata Version Constants

Version numbers for the integrity metadata structure.

```
enum{
```

```
INTEGRITY_META_VERSION_INVALID=0,
INTEGRITY_META_VERSION_1=1,
INTEGRITY_META_VERSION_2=2,
INTEGRITY_META_VERSION_HIGHEST=INTEGRITY_META_VERSION_2
```


151

**Sealed Volumes** Integrity Metadata Flags

## _`};`_

These constants are used as the value of the _`im_version`_ field of the _`integrity_meta_phys_t`_ structure.

```
INTEGRITY_META_VERSION_INVALID
```

An invalid version.

```
INTEGRITY_META_VERSION_INVALID=0
```

```
INTEGRITY_META_VERSION_1
```

The first version of the structure.

```
INTEGRITY_META_VERSION_1=1
```

```
INTEGRITY_META_VERSION_1
```

The second version of the structure.

```
INTEGRITY_META_VERSION_2=2
```

```
INTEGRITY_META_VERSION_HIGHEST
```

The highest valid version number.

```
INTEGRITY_META_VERSION_HIGHEST=INTEGRITY_META_VERSION_2
```

## Integrity Metadata Flags

Flags used by integrity metadata.

```
#defineAPFS_SEAL_BROKEN(1U<<0)
```

These flags are used by the _`im_flags`_ field of _`integrity_meta_phys_t`_ .

```
APFS_SEAL_BROKEN
```

The volume was modified after being sealed, breaking its seal.

```
#defineAPFS_SEAL_BROKEN(1U<<0)
```

If this flag is set, the _`im_broken_xid`_ field of _`integrity_meta_phys_t`_ contains the transaction identifier for the modification that broke the seal.

## _`apfs_hash_type_t`_

Constants used to identify hash algorithms.

|_`typedef enum {`_||
|---|---|
|_`APFS_HASH_INVALID`_|_`= 0,`_|
|_`APFS_HASH_SHA256`_|_`= 0x1,`_|
|_`APFS_HASH_SHA512_256`_|_`= 0x2,`_|
|_`APFS_HASH_SHA384`_|_`= 0x3,`_|
|_`APFS_HASH_SHA512`_|_`= 0x4,`_|




152

**Sealed Volumes** _`apfs_hash_type_t`_

```
APFS_HASH_MIN=APFS_HASH_SHA256,
APFS_HASH_MAX=APFS_HASH_SHA512,
APFS_HASH_DEFAULT=APFS_HASH_SHA256,
}apfs_hash_type_t;
```

```
#defineAPFS_HASH_CCSHA256_SIZE32
#defineAPFS_HASH_CCSHA512_256_SIZE32
#defineAPFS_HASH_CCSHA384_SIZE48
#defineAPFS_HASH_CCSHA512_SIZE64
#defineAPFS_HASH_MAX_SIZE64
```

These constants are used as the value of the _`im_hash_type`_ field of the _`integrity_meta_phys_t`_ structure. The corresponding hash size is used as the value of the _`hash_size`_ field of the _`j_file_data_hash_val_t`_ structure.

```
APFS_HASH_INVALID
```

An invalid hash algorithm.

```
APFS_HASH_INVALID=0
```

```
APFS_HASH_SHA256
```

The SHA-256 variant of Secure Hash Algorithm 2.

```
APFS_HASH_SHA256=0x1
```

```
APFS_HASH_SHA512_256
```

The SHA-512/256 variant of Secure Hash Algorithm 2.

```
APFS_HASH_SHA512_256=0x2,
```

```
APFS_HASH_SHA384
```

The SHA-384 variant of Secure Hash Algorithm 2.

```
APFS_HASH_SHA384=0x3
```

```
APFS_HASH_SHA512
```

The SHA-512 variant of Secure Hash Algorithm 2.

```
APFS_HASH_SHA512=0x4
```

```
APFS_HASH_MIN
```

The smallest valid value for identifying a hash algorithm.

```
APFS_HASH_MIN=APFS_HASH_SHA256
```


153

**Sealed Volumes** _`fext_tree_key_t`_

## _`APFS_HASH_MAX`_

The largest valid value for identifying a hash algorithm.

```
APFS_HASH_MAX=APFS_HASH_SHA512
```

```
APFS_HASH_DEFAULT
```

The default hash algorithm.

```
APFS_HASH_DEFAULT=APFS_HASH_SHA256
```

```
APFS_HASH_CCSHA256_SIZE
```

The size of a SHA-256 hash.

```
#defineAPFS_HASH_CCSHA256_SIZE32
```

```
APFS_HASH_CCSHA512_256_SIZE
```

The size of a SHA-512/256 hash.

```
#defineAPFS_HASH_CCSHA512_256_SIZE32
APFS_HASH_CCSHA384_SIZE
```

The size of a SHA-384 hash.

```
#defineAPFS_HASH_CCSHA384_SIZE48
APFS_HASH_CCSHA512_SIZE
```

The size of a SHA-512 hash.

```
#defineAPFS_HASH_CCSHA512_SIZE64
```

```
APFS_HASH_MAX_SIZE
```

The maximum valid hash size.

_`#define APFS_HASH_MAX_SIZE 64`_ This value is the same as _`BTREE_NODE_HASH_SIZE_MAX`_ .

```
fext_tree_key_t
```

The key half of a record from a file extent tree.

```
structfext_tree_key{
uint64_tprivate_id;
uint64_tlogical_addr;
}__attribute__((packed));
typedefstructfext_tree_keyfext_tree_key_t;
```


154

**Sealed Volumes** _`fext_tree_val_t`_

## _`private_id`_

The object identifier of the file.

```
uint64_tprivate_id;
```

This value corresponds the object identifier portion of the _`obj_id_and_type`_ field of _`j_key_t`_ .

## _`logical_addr`_

The offset within the fileʼs data, in bytes, for the data stored in this extent.

```
uint64_tlogical_addr;
```

## _`fext_tree_val_t`_

The value half of a record from a file extent tree.

```
structfext_tree_val{
uint64_tlen_and_flags;
uint64_tphys_block_num;
}__attribute__((packed));
typedefstructfext_tree_valfext_tree_val_t;
```

## _`len_and_flags`_

A bit field that contains the length of the extent and its flags.

```
uint64_tlen_and_flags;
```

The extentʼs length is a _`uint64_t`_ value, accessed as _`len_and_kind & J_FILE_EXTENT_LEN_MASK`_ , and measured in bytes. The length must be a multiple of the block size defined by the _`nx_block_size`_ field of _`nx_superblock_t`_ . The extentʼs flags are accessed as _`(len_and_kind & J_FILE_EXTENT_FLAG_MASK) >> J_FILE_EXTENT_FLAG_SHIFT`_ .

There are currently no flags defined.

## _`phys_block_num`_

The physical block address that the extent starts at.

```
uint64_tphys_block_num;
```

## _`j_file_info_key_t`_

The key half of a file-info record.

```
structj_file_info_key{
j_key_thdr;
uint64_tinfo_and_lba;
}__attribute__((packed));
typedefstructj_key_tj_file_info_key_t;
```


155

**Sealed Volumes** _`j_file_info_val_t`_

```
#defineJ_FILE_INFO_LBA_MASK0x00ffffffffffffffULL
#defineJ_FILE_INFO_TYPE_MASK0xff00000000000000ULL
#defineJ_FILE_INFO_TYPE_SHIFT56
```

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the file-system objectʼs identifier. The type in the header is always _`APFS_TYPE_FILE_INFO`_ .

## _`info_and_lba`_

A bit field that contains the address and other information.

```
uint64_tinfo_and_lba;
```

The address is a _`paddr_t`_ value accessed as _`info_and_lba & J_FILE_INFO_LBA_MASK`_ . The type is a _`j_obj_file_info_type`_ value accessed as _`(info_and_lba & J_FILE_INFO_TYPE_MASK) >> J_FILE_ INFO_TYPE_SHIFT`_ .

## _`J_FILE_INFO_LBA_MASK`_

The bit mask used to access file-info addresses.

```
#defineJ_FILE_INFO_LBA_MASK0x00ffffffffffffffULL
```

```
J_FILE_INFO_TYPE_MASK
```

The bit mask used to access file-info types.

```
#defineJ_FILE_INFO_TYPE_MASK0xff00000000000000ULL
```

```
J_FILE_INFO_TYPE_SHIFT
```

The bit shift used to access file-info types.

```
#defineJ_FILE_INFO_TYPE_SHIFT56
```

## _`j_file_info_val_t`_

The value half of a file-info record.

```
structj_file_info_val{
union{
j_file_data_hash_val_tdhash;
};
}__attribute__((packed));
typedefstructj_file_data_hash_val_tj_file_info_val_t;
```

Use the type stored in the _`j_file_info_key_t`_ half of this record to determine which of the unionʼs fields to use.


156

**Sealed Volumes** _`j_obj_file_info_type`_

## _`dhash`_

A hash of the file data.

```
j_file_data_hash_val_tdhash;
```

Use this field of the union if the type stored in the _`info_and_lba`_ field of _`j_file_info_val_t`_ is _`APFS_FILE_ INFO_DATA_HASH`_ .

## _`j_obj_file_info_type`_

The type of a file-info record.

```
typedefenum{
APFS_FILE_INFO_DATA_HASH=1,
}j_obj_file_info_type;
```

These values are used by the _`info_and_lba`_ field of _`j_file_info_key_t`_ , to indicate how to interpret the data in the corresponding _`j_file_info_val_t`_ .

```
APFS_FILE_INFO_DATA_HASH
```

The file-info record contains a hash of file data.

```
APFS_FILE_INFO_DATA_HASH=1
```

## _`j_file_data_hash_val_t`_

A hash of file data.

```
structj_file_data_hash_val{
uint16_thashed_len;
uint8_thash_size;
uint8_thash[0];
}__attribute__((packed));
typedefstructj_file_data_hash_valj_file_data_hash_val_t;
```

```
hashed_len
```

The length, in blocks, of the data segment that was hashed.

```
uint16_thashed_len;
```

```
hash_size
```

The length, in bytes, of the hash data.

```
uint8_thash_size;
```

The value of this field must match the constant that corresponds to the hash algorithm specified in the _`im_hash_type`_ field of _`integrity_meta_phys_t`_ . For a list of algorithms and hash sizes, see _`apfs_hash_type_t`_ .


157

**Sealed Volumes** _`j_file_data_hash_val_t`_

## _`hash`_

The hash data.

```
uint8_thash[0];
```


158
