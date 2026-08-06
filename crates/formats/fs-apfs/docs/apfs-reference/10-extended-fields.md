<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Extended Fields

Directory entries and inodes use extended fields to store a dynamically extensible set of member fields.

To determine whether a directory entry or an inode has any extended fields, find the table of contents entry for the file-system record, and then compare the recorded size to the size of the structure. For example:

```
kvloc_ttoc_entry=/*assumethisexists*/
```

```
if(toc_entry.v.len==sizeof(j_drec_val_t)){
```

```
//noextendedfields
```

- _`} else {`_

   - _`// at least one extended field`_

```
}
```

Both _`j_drec_val_t`_ and _`j_inode_val_t`_ have an _`xfields`_ field that contains several kinds of data, stored one after another, ordered as follows:

1. An instance of _`xf_blob_t`_ , which tells you how many extended fields there are, and how many bytes they take up on disk.

2. An array of instances of _`x_field_t`_ , one for each extended field, which tells you the fieldʼs type and size.

3. An array of extended-field data, aligned to eight-byte boundaries.

The arrays of extended-field metadata ( _`x_field_t`_ ) and extended-field data are stored in the same order. The extended-field dataʼs type depends on the field. For a list of field types, see Extended-Field Types.

## _`xf_blob_t`_

A collection of extended attributes.

```
structxf_blob{
```

```
uint16_txf_num_exts;
uint16_txf_used_data;
uint8_txf_data[];
```

```
};
typedefstructxf_blobxf_blob_t;
```

Directory entries ( _`j_drec_val_t`_ ) and inodes ( _`j_inode_val_t`_ ) use this data type to store their extended fields.

## _`xf_num_exts`_

The number of extended attributes.

```
uint16_txf_num_exts;
```

## _`xf_used_data`_

The amount of space, in bytes, used to store the extended attributes.

```
uint16_txf_used_data;
```

This total includes both the space used to store metadata, as instances of _`x_field_t`_ , and values.


108

**Extended Fields** _`x_field_t`_

## _`xf_data[]`_

The extended fields.

```
uint8_txf_data[];
```

This field contains an array of instances of _`x_field_t`_ , followed by the extended field data.

## _`x_field_t`_

An extended fieldʼs metadata.

```
structx_field{
uint8_tx_type;
uint8_tx_flags;
uint16_tx_size;
};
typedefstructx_fieldx_field_t;
```

This type is used by _`xf_blob_t`_ to store an array of extended fields. Within the array, each extended field must have a unique type.

The extended fieldʼs data is stored outside of this structure, as part of the space set aside by the directory entry or inode.

## _`x_type`_

The extended fieldʼs data type.

```
uint8_tx_type;
```

For possible values, see Extended-Field Types.

## _`x_flags`_

The extended fieldʼs flags.

```
uint8_tx_flags;
```

For the values used in this bit field, see Extended-Field Flags.

## _`x_size`_

The size, in bytes, of the data stored in the extended field.

```
uint16_tx_size;
```

## Extended-Field Types

Values used by the _`x_type`_ field of _`x_field_t`_ to indicate an extended fieldʼs type.

```
#defineDREC_EXT_TYPE_SIBLING_ID1
#defineINO_EXT_TYPE_SNAP_XID1
```


109

**Extended Fields** Extended-Field Types

```
#defineINO_EXT_TYPE_DELTA_TREE_OID2
#defineINO_EXT_TYPE_DOCUMENT_ID3
#defineINO_EXT_TYPE_NAME4
#defineINO_EXT_TYPE_PREV_FSIZE5
#defineINO_EXT_TYPE_RESERVED_66
#defineINO_EXT_TYPE_FINDER_INFO7
#defineINO_EXT_TYPE_DSTREAM8
#defineINO_EXT_TYPE_RESERVED_99
#defineINO_EXT_TYPE_DIR_STATS_KEY10
#defineINO_EXT_TYPE_FS_UUID11
#defineINO_EXT_TYPE_RESERVED_1212
#defineINO_EXT_TYPE_SPARSE_BYTES13
#defineINO_EXT_TYPE_RDEV14
#defineINO_EXT_TYPE_PURGEABLE_FLAGS15
#defineINO_EXT_TYPE_ORIG_SYNC_ROOT_ID16
```

```
DREC_EXT_TYPE_SIBLING_ID
```

The sibling identifier for a directory record ( _`uint64_t`_ ).

```
#defineDREC_EXT_TYPE_SIBLING_ID1
```

The corresponding sibling-link record has the same identifier in the _`sibling_id`_ field of _`j_sibling_key_t`_ .

This extended field is used only for hard links.

```
INO_EXT_TYPE_SNAP_XID
```

The transaction identifier for a snapshot ( _`xid_t`_ ).

```
#defineINO_EXT_TYPE_SNAP_XID1
```

```
INO_EXT_TYPE_DELTA_TREE_OID
```

The virtual object identifier of the file-system tree that corresponds to a snapshotʼs extent delta list ( _`oid_t`_ ).

```
#defineINO_EXT_TYPE_DELTA_TREE_OID2
```

The tree objectʼs subtype is always _`OBJECT_TYPE_FSTREE`_ .

```
INO_EXT_TYPE_DOCUMENT_ID
```

The fileʼs document identifier ( _`uint32_t`_ ).

```
#defineINO_EXT_TYPE_DOCUMENT_ID3
```

The document identifier lets applications keep track of the document during operations like atomic save, where one folder replaces another. The document identifier remains associated with the full path, not just with the inode thatʼs currently at that path. Implementations of Apple File System must preserve the document identifier when the inode at that path is replaced.

Both documents that are stored as a bundle and documents that are stored as a single file can have a document identifier assigned.


110

**Extended Fields** Extended-Field Types

Valid document identifiers are greater than _`MIN_DOC_ID`_ and less than _`UINT32_MAX - 1`_ . For the next document identifier that will be assigned, see the _`apfs_next_doc_id`_ field of _`apfs_superblock_t`_ .

```
INO_EXT_TYPE_NAME
```

The name of the file, represented as a null-terminated UTF-8 string.

```
#defineINO_EXT_TYPE_NAME4
```

This extended field is used only for hard links: The name stored in the inode is the name of the primary link to the file, and the name of the hard link is stored in this extended field.

```
INO_EXT_TYPE_PREV_FSIZE
```

The fileʼs previous size ( _`uint64_t`_ ).

```
#defineINO_EXT_TYPE_PREV_FSIZE5
```

This extended field is used for recovering after a crash. If itʼs set on an inode, truncate the file back to the size contained in this field.

```
INO_EXT_TYPE_RESERVED_6
```

Reserved.

```
#defineINO_EXT_TYPE_RESERVED_66
```

Donʼt create extended fields of this type in your own code. Preserve the value of any extended fields of this type.

```
INO_EXT_TYPE_FINDER_INFO
```

Opaque data stored and used by Finder (32 bytes).

```
#defineINO_EXT_TYPE_FINDER_INFO7
```

```
INO_EXT_TYPE_DSTREAM
```

A data stream ( _`j_dstream_t`_ ).

```
#defineINO_EXT_TYPE_DSTREAM8
```

```
INO_EXT_TYPE_RESERVED_9
```

Reserved.

```
#defineINO_EXT_TYPE_RESERVED_99
```

Donʼt create extended fields of this type. When you modify an existing volume, preserve the contents of any extended fields of this type.

```
INO_EXT_TYPE_DIR_STATS_KEY
```

Statistics about a directory ( _`j_dir_stats_val_t`_ ).

```
#defineINO_EXT_TYPE_DIR_STATS_KEY10
```


111

**Extended Fields** Extended-Field Flags

## _`INO_EXT_TYPE_FS_UUID`_

The UUID of a file system thatʼs automatically mounted in this directory ( _`uuid_t`_ ).

```
#defineINO_EXT_TYPE_FS_UUID11
```

This value matches the value of the _`apfs_vol_uuid`_ field of _`apfs_superblock_t`_ .

## _`INO_EXT_TYPE_RESERVED_12`_

## Reserved.

```
#defineINO_EXT_TYPE_RESERVED_1212
```

Donʼt create extended fields of this type. If you find an object of this type in production, file a bug against the Apple File System implementation.

## _`INO_EXT_TYPE_SPARSE_BYTES`_

The number of sparse bytes in the data stream ( _`uint64_t`_ ).

```
#defineINO_EXT_TYPE_SPARSE_BYTES13
```

## _`INO_EXT_TYPE_RDEV`_

The device identifier for a block- or character-special device ( _`uint32_t`_ ).

```
#defineINO_EXT_TYPE_RDEV14
```

This extended field stores the same information as the _`st_rdev`_ field of the _`stat`_ structure defined in _`<sys/stat.h>`_ .

## _`INO_EXT_TYPE_PURGEABLE_FLAGS`_

Information about a purgeable file.

```
#defineINO_EXT_TYPE_PURGEABLE_FLAGS15
```

The value of this extended field is reserved. Donʼt create new extended fields of this type. When duplicating a file or directory, omit this extended field from the new copy.

Purgeable files have the _`INODE_IS_PURGEABLE`_ flag set on the _`internal_flags`_ field of _`j_inode_val_t`_ .

```
INO_EXT_TYPE_ORIG_SYNC_ROOT_ID
```

The inode number of the sync-root hierarchy that this file originally belonged to.

```
#defineINO_EXT_TYPE_ORIG_SYNC_ROOT_ID16
```

The specified inode always has the _`INODE_IS_SYNC_ROOT`_ flag set.

## Extended-Field Flags

The flags used by an extended fieldʼs metadata.


112

**Extended Fields** Extended-Field Flags

```
#defineXF_DATA_DEPENDENT0x0001
#defineXF_DO_NOT_COPY0x0002
#defineXF_RESERVED_40x0004
#defineXF_CHILDREN_INHERIT0x0008
#defineXF_USER_FIELD0x0010
#defineXF_SYSTEM_FIELD0x0020
#defineXF_RESERVED_400x0040
#defineXF_RESERVED_800x0080
```

These flags are used by the _`x_flags`_ field of _`x_field_t`_ .

## _`XF_DATA_DEPENDENT`_

The data in this extended field depends on the fileʼs data.

```
#defineXF_DATA_DEPENDENT0x0001
```

When the file data changes, this extended field must be updated to match the new data. If itʼs not possible to update the field — for example, because the Apple File System implementation doesnʼt recognize the fieldʼs type — the field must be removed.

## _`XF_DO_NOT_COPY`_

When copying this file, omit this extended field from the copy.

```
#defineXF_DO_NOT_COPY0x0002
```

## _`XF_RESERVED_4`_

Reserved.

```
#defineXF_RESERVED_40x0004
```

Donʼt set this flag, but preserve it if itʼs already set.

## _`XF_CHILDREN_INHERIT`_

When creating a new entry in this directory, copy this extended field to the new directory entry.

```
#defineXF_CHILDREN_INHERIT0x0008
```

## _`XF_USER_FIELD`_

This extended field was added by a user-space program.

```
#defineXF_USER_FIELD0x0010
```

## _`XF_SYSTEM_FIELD`_

This extended field was added by the kernel, by the implementation of Apple File System, or by another system component.

```
#defineXF_SYSTEM_FIELD0x0020
```


113

**Extended Fields** Extended-Field Flags

Extended fields with this flag set canʼt be removed or modified by a program running in user space.

```
XF_RESERVED_40
```

## Reserved.

```
#defineXF_RESERVED_400x0040
```

Donʼt set this flag, but preserve it if itʼs already set.

```
XF_RESERVED_80
```

## Reserved.

```
#defineXF_RESERVED_800x0080
```

Donʼt set this flag, but preserve it if itʼs already set.


114
