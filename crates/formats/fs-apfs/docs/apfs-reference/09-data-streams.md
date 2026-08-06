<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Data Streams

Short pieces of information like a fileʼs name are stored inside the data structures that contain metadata. Data thatʼs too large to store inline is stored separately, in a data stream. This includes the contents of files, and the value of some attributes.

## _`j_phys_ext_key_t`_

The key half of a physical extent record.

```
structj_phys_ext_key{
j_key_thdr;
}__attribute__((packed));
typedefstructj_phys_ext_keyj_phys_ext_key_t;
```

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the physical block address of the start of the extent. The type in the header is always _`APFS_TYPE_EXTENT`_ .

## _`j_phys_ext_val_t`_

The value half of a physical extent record.

```
structj_phys_ext_val{
uint64_tlen_and_kind;
uint64_towning_obj_id;
int32_trefcnt;
}__attribute__((packed));
typedefstructj_phys_ext_valj_phys_ext_val_t;
#definePEXT_LEN_MASK0x0fffffffffffffffULL
#definePEXT_KIND_MASK0xf000000000000000ULL
#definePEXT_KIND_SHIFT60
```

## _`len_and_kind`_

A bit field that contains the length of the extent and its kind.

```
uint64_tlen_and_kind;
```

The extentʼs length is a _`uint64_t`_ value, accessed as _`len_and_kind & PEXT_LEN_MASK`_ , and measured in blocks. The extentʼs kind is a _`j_obj_kinds`_ value, accessed as _`(len_and_kind & PEXT_KIND_MASK) >> PEXT_KIND_SHIFT`_ .

For a volume that has no snapshots, the kind is always _`APFS_KIND_NEW`_ .


102

**Data Streams** _`j_file_extent_key_t`_

## _`owning_obj_id`_

The identifier of the file system record thatʼs using this extent.

```
uint64_towning_obj_id;
```

If the owning record is an inode, this field contains the inodeʼs private identifier (the _`private_id`_ field of _`j_inode_val_t`_ ). If the owning record is an extended attribute, this field contains the extended attributeʼs record identifier (the identifier from the _`hdr`_ field of _`j_xattr_key_t`_ ).

## _`refcnt`_

The reference count.

```
int32_trefcnt;
```

The extent can be deleted when its reference count reaches zero.

## _`PEXT_LEN_MASK`_

The bit mask used to access the extent length.

```
#definePEXT_LEN_MASK0x0fffffffffffffffULL
```

## _`PEXT_KIND_MASK`_

The bit mask used to access the extent kind.

```
#definePEXT_KIND_MASK0xf000000000000000ULL
```

## _`PEXT_KIND_SHIFT`_

The bit shift used to access the extent kind.

```
#definePEXT_KIND_SHIFT60
```

## _`j_file_extent_key_t`_

The key half of a file extent record.

```
structj_file_extent_key{
j_key_thdr;
uint64_tlogical_addr;
}__attribute__((packed));
typedefstructj_file_extent_keyj_file_extent_key_t;
```

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the file-system objectʼs identifier. The type in the header is always _`APFS_TYPE_FILE_EXTENT`_ .


103

**Data Streams** _`j_file_extent_val_t`_

## _`logical_addr`_

The offset within the fileʼs data, in bytes, for the data stored in this extent.

```
uint64_tlogical_addr;
```

## _`j_file_extent_val_t`_

The value half of a file extent record.

```
structj_file_extent_val{
uint64_tlen_and_flags;
uint64_tphys_block_num;
uint64_tcrypto_id;
}__attribute__((packed));
typedefstructj_file_extent_valj_file_extent_val_t;
#defineJ_FILE_EXTENT_LEN_MASK0x00ffffffffffffffULL
#defineJ_FILE_EXTENT_FLAG_MASK0xff00000000000000ULL
#defineJ_FILE_EXTENT_FLAG_SHIFT56
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

## _`crypto_id`_

The encryption key or the encryption tweak used in this extent.

## _`uint64_t crypto_id;`_

If the _`APFS_FS_ONEKEY`_ flag is set on the volume, this field contains the AES-XTS tweak value. Otherwise, this value matches the _`obj_id`_ field of the _`j_crypto_key_t`_ record that contains information about how this file extent is encrypted, including the per-file encryption key.

The default value for this field is the value of the _`default_crypto_id`_ field of the _`j_dstream_t`_ for the data stream that this extent is part of.


104

**Data Streams** _`j_dstream_id_key_t`_

## _`J_FILE_EXTENT_LEN_MASK`_

The bit mask used to access the extent length.

```
#defineJ_FILE_EXTENT_LEN_MASK0x00ffffffffffffffULL
```

## _`J_FILE_EXTENT_FLAG_MASK`_

The bit mask used to access the flags.

```
#defineJ_FILE_EXTENT_FLAG_MASK0xff00000000000000ULL
```

## _`J_FILE_EXTENT_FLAG_SHIFT`_

The bit shift used to access the flags.

```
#defineJ_FILE_EXTENT_FLAG_SHIFT56
```

## _`j_dstream_id_key_t`_

The key half of a directory-information record.

```
structj_dstream_id_key{
j_key_thdr;
}__attribute__((packed));
typedefstructj_dstream_id_keyj_dstream_id_key_t;
```

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the file-system objectʼs identifier. The type in the header is always _`APFS_TYPE_DSTREAM_ID`_ .

## _`j_dstream_id_val_t`_

The value half of a data stream record.

```
structj_dstream_id_val{
uint32_trefcnt;
}__attribute__((packed));
typedefstructj_dstream_id_valj_dstream_id_val_t;
```

## _`refcnt`_

The reference count.

```
uint32_trefcnt;
```

The data stream record can be deleted when its reference count reaches zero.


105

**Data Streams** _`j_xattr_dstream_t`_

## _`j_xattr_dstream_t`_

A data stream for extended attributes.

```
structj_xattr_dstream{
uint64_txattr_obj_id;
j_dstream_tdstream;
};
typedefstructj_xattr_dstreamj_xattr_dstream_t;
```

To access the data in the stream, read the object identifier and then find the corresponding extents.

```
xattr_obj_id
```

The identifier for the data stream.

```
uint64_txattr_obj_id;
```

This field contains the record identifier of the data stream that owns this record.

```
dstream
```

Information about the data stream.

```
j_dstream_tdstream;
```

## _`j_dstream_t`_

Information about a data stream.

```
structj_dstream{
uint64_tsize;
uint64_talloced_size;
uint64_tdefault_crypto_id;
uint64_ttotal_bytes_written;
uint64_ttotal_bytes_read;
}__attribute__((aligned(8),packed));
typedefstructj_dstreamj_dstream_t;
```

This structure is used inside _`j_xattr_dstream_t`_ .

```
size
```

The size, in bytes, of the data.

```
uint64_tsize;
```

```
alloced_size
```

The total space allocated for the data stream, including any unused space.

```
uint64_talloced_size;
```


106

**Data Streams** _`j_dstream_t`_

## _`default_crypto_id`_

The default encryption key or encryption tweak used in this data stream.

```
uint64_tdefault_crypto_id;
```

This value matches the _`obj_id`_ field in the _`j_key_t`_ key that corresponds to a _`j_crypto_val_t`_ value. For a volume that uses software encryption, the value of this field is always _`CRYPTO_SW_ID`_ .

This value is used as the default value by file extents ( _`j_file_extent_val_t`_ ) that make up this data stream.

## _`total_bytes_written`_

The total number of bytes that have been written to this data stream.

```
uint64_ttotal_bytes_written;
```

The value of this field increases every time a write operation occurs. This value is allowed to overflow and restart from zero.

## _`total_bytes_read`_

The total number of bytes that have been read from this data stream.

```
uint64_ttotal_bytes_read;
```

The value of this field increases every time a read operation occurs. This value is allowed to overflow and restart from zero.


107
