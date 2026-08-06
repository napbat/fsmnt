<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## File-System Objects

A file-system object stores information about a part of the file system, like a directory or a file on disk. These objects are stored as one or more records. For example, the file-system object for a directory that contains two files is stored as three records: a record of type _`APFS_TYPE_INODE`_ for the inode, and two records of type _`APFS_TYPE_DIR_REC`_ for the directory entries. This record-based method of storing file-system objects helps make efficient use of disk space.

File-system records are stored as key/value pairs in a B-tree. The key contains information, like the object identifier and the record type, used to look up a record. Keys begin with an instance of _`j_key_t`_ , and many records use _`j_key_t`_ as their entire key.

For sorting file-system records — for example, to keep them ordered in a B-tree — the following comparison rules are used:

1. Compare the object identifiers numerically:

```
j_key_t.obj_id_and_type&OBJ_ID_MASK
```

2. Compare the object types numerically:

   - _`(j_key_t.obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT`_

3. For extended attribute records and directory entry records, compare the names lexicographically:

```
j_drec_key_t.name
```

Because all of the records for a file-system object have the same object identifier, all of the records that make up a single object are sorted next to each other.

The relationship between file-system objects and the records theyʼre made up from is as follows:

## **Files**

- _`APFS_TYPE_INODE`_ Required

- _`APFS_TYPE_CRYPTO_STATE`_

- _`APFS_TYPE_DSTREAM_ID`_

- _`APFS_TYPE_EXTENT`_

- _`APFS_TYPE_FILE_EXTENT`_

- _`APFS_TYPE_SIBLING_LINK`_

- _`APFS_TYPE_XATTR`_

## **Directories**

- _`APFS_TYPE_INODE`_ Required

- _`APFS_TYPE_CRYPTO_STATE`_

- _`APFS_TYPE_DIR_REC`_

- _`APFS_TYPE_DIR_STATS`_

- _`APFS_TYPE_XATTR`_

## **Symbolic Links**

- _`APFS_TYPE_INODE`_ Required

- _`APFS_TYPE_XATTR`_ Required


71

**File-System Objects** _`j_key_t`_

- _`APFS_TYPE_CRYPTO_STATE`_

- _`APFS_TYPE_DSTREAM_ID`_

- _`APFS_TYPE_EXTENT`_

- _`APFS_TYPE_FILE_EXTENT`_

There must be an extended attribute whose name is _`SYMLINK_EA_NAME`_ and whose value is the path to the target file.

## **Snapshots**

- _`APFS_TYPE_SNAP_METADATA`_ Required

- _`APFS_TYPE_SNAP_NAME`_ Required

- _`APFS_TYPE_CRYPTO_STATE`_

- _`APFS_TYPE_EXTENT`_

## **Sibling Maps**

- _`APFS_TYPE_SIBLING_MAP`_ Required

## **Tip**

To simplify manipulating file-system objects, define custom types that combine the key and value of a record, and custom types that combine the objectʼs records.

## _`j_key_t`_

A header used at the beginning of all file-system keys.

```
structj_key{
uint64_tobj_id_and_type;
}__attribute__((packed));
typedefstructj_keyj_key_t;
#defineOBJ_ID_MASK0x0fffffffffffffffULL
#defineOBJ_TYPE_MASK0xf000000000000000ULL
#defineOBJ_TYPE_SHIFT60
#defineSYSTEM_OBJ_ID_MARK0x0fffffff00000000ULL
```

All file-system objects have a key that begins with this information. The key for some object types have additional fields that follow this header, and other object types use _`j_key_t`_ as their entire key.

The following record types use this structure as their key without adding any additional fields:

## _`obj_id_and_type`_

A bit field that contains the objectʼs identifier and its type.

```
uint64_tobj_id_and_type;
```


72

**File-System Objects** _`j_inode_key_t`_

The objectʼs identifier is a _`uint64_t`_ value accessed as _`obj_id_and_type & OBJ_ID_MASK`_ . The objectʼs type is a _`uint8_t`_ value accessed as _`(obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT`_ . The objectʼs type is one of the constants defined by _`j_obj_types`_ .

```
OBJ_ID_MASK
```

The bit mask used to access the object identifier.

```
#defineOBJ_ID_MASK0x0fffffffffffffffULL
```

## _`OBJ_TYPE_MASK`_

The bit mask used to access the object type.

```
#defineOBJ_TYPE_MASK0xf000000000000000ULL
```

## _`OBJ_TYPE_SHIFT`_

The bit shift used to access the object type.

```
#defineOBJ_TYPE_SHIFT60
```

```
SYSTEM_OBJ_ID_MARK
```

The smallest object identifier used by the system volume.

```
#defineSYSTEM_OBJ_ID_MARK0x0fffffff00000000ULL
```

In a volume group, objects with an identifier less than this number are part of the data volume, and objects with an identifier greater than or equal to this number are part of the system volume.

## _`j_inode_key_t`_

The key half of a directory-information record.

```
structj_inode_key{
j_key_thdr;
}__attribute__((packed));
typedefstructj_inode_key_tj_inode_key_t;
```

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the file-system objectʼs identifier, also known as its inode number. The type in the header is always _`APFS_TYPE_INODE`_ .

## _`j_inode_val_t`_

The value half of an inode record.


73

**File-System Objects** _`j_inode_val_t`_

```
structj_inode_val{
```

```
uint64_tparent_id;
uint64_tprivate_id;
uint64_tcreate_time;
uint64_tmod_time;
uint64_tchange_time;
uint64_taccess_time;
uint64_tinternal_flags;
union{
int32_tnchildren;
int32_tnlink;
};
cp_key_class_tdefault_protection_class;
uint32_twrite_generation_counter;
uint32_tbsd_flags;
uid_towner;
gid_tgroup;
mode_tmode;
uint16_tpad1;
uint64_tuncompressed_size;
uint8_txfields[];
}__attribute__((packed));
typedefstructj_inode_valj_inode_val_t;
typedefuint32_tuid_t;
typedefuint32_tgid_t;
```

```
parent_id
```

The identifier of the file system record for the parent directory.

```
uint64_tparent_id;
```

```
private_id
```

The unique identifier used by this fileʼs data stream.

```
uint64_tprivate_id;
```

This identifier appears in the _`owning_obj_id`_ field of _`j_phys_ext_val_t`_ records that describe the extents where the data is stored.

For an inode that doesnʼt have data, the value of this field is the file-system objectʼs identifier.


74

**File-System Objects** _`j_inode_val_t`_

## _`create_time`_

The time that this record was created.

## _`uint64_t create_time;`_

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds.

## _`mod_time`_

The time that this record was last modified.

## _`uint64_t mod_time;`_

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds.

## _`change_time`_

The time that this recordʼs attributes were last modified.

```
uint64_tchange_time;
```

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds.

## _`access_time`_

The time that this record was last accessed.

```
uint64_taccess_time;
```

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds.

For details about when this field is updated, see _`APFS_FEATURE_STRICTATIME`_ .

## _`internal_flags`_

The inodeʼs flags.

```
uint64_tinternal_flags;
```

For the values used in this bit field, see _`j_inode_flags`_ .

## _`nchildren`_

The number of directory entries.

```
int32_tnchildren;
```

This union field is valid only if the inode is a directory.


75

**File-System Objects** _`j_inode_val_t`_

## _`nlink`_

The number of hard links whose target is this inode.

## _`int32_t nlink;`_

This union field is valid only if the inode isnʼt a directory.

Inodes with multiple hard links — as indicated by a value greater than one in this field — have additional invariants:

- The _`parent_id`_ field refers to the parent directory of the primary link.

- The _`name`_ field contains the name of the primary link.

- The _`INO_EXT_TYPE_NAME`_ extended field contains the name of this link.

- The file-system object includes sibling-link records, as discussed in Siblings.

## _`default_protection_class`_

The default protection class for this inode.

```
cp_key_class_tdefault_protection_class;
```

Files in this directory that have a protection class of _`PROTECTION_CLASS_DIR_NONE`_ use the directoryʼs default protection class.

## _`write_generation_counter`_

A monotonically increasing counter thatʼs incremented each time this inode or its data is modified.

```
uint32_twrite_generation_counter;
```

This value is allowed to overflow and restart from zero.

## _`bsd_flags`_

The inodeʼs BSD flags.

```
uint32_tbsd_flags;
```

For information about these flags, see the _`chflags(2)`_ man page and the _`<sys/stat.h>`_ header file.

## _`owner`_

The user identifier of the inodeʼs owner.

```
uid_towner;
```

## _`group`_

The group identifier of the inodeʼs group.

```
gid_tgroup;
```


76

**File-System Objects** _`j_inode_val_t`_

## _`mode`_

The fileʼs mode.

```
mode_tmode;
```

For possible values, see File Modes.

## _`pad1`_

Reserved.

```
uint16_tpad1;
```

Populate this field with zero when you create a new inode, and preserve its value when you modify an existing inode.

This field is padding.

## _`uncompressed_size`_

The size of the file without compression.

## _`uint64_t uncompressed_size;`_

This field is populated only for files that have the _`INODE_HAS_UNCOMPRESSED_SIZE`_ flag set on the _`internal_ flags`_ field.

For files that donʼt have the flag set, this field is treated as padding: Populate this field with zero when you create a new inode, and preserve its value when you modify an existing inode.

## _`xfields`_

The inodeʼs extended fields.

## _`uint8_t xfields[];`_

This location on disk contains several pieces of data that have variable sizes. For information about reading extended fields, see Extended Fields.

## _`uid_t`_

A user identifier.

```
typedefuint32_tuid_t;
```

## _`gid_t`_

A group identifier.

```
typedefuint32_tgid_t;
```


77

**File-System Objects** _`j_drec_key_t`_

## _`j_drec_key_t`_

The key half of a directory entry record.

```
structj_drec_key{
j_key_thdr;
uint16_tname_len;
uint8_tname[0];
}__attribute__((packed));
typedefstructj_drec_keyj_drec_key_t;
```

```
hdr
```

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the file-system objectʼs identifier. The type in the header is always _`APFS_TYPE_ DIR_REC`_ .

```
name_len_and_hash
```

The length of the name, including the final null character (U+0000).

```
uint32_tname_len_and_hash;
```

## _`name`_

The name, represented as a null-terminated UTF-8 string.

```
uint8_tname[0];
```

## _`j_drec_hashed_key_t`_

The key half of a directory entry record, including a precomputed hash of its name.

```
structj_drec_hashed_key{
j_key_thdr;
uint32_tname_len_and_hash;
uint8_tname[0];
}__attribute__((packed));
typedefstructj_drec_hashed_keyj_drec_hashed_key_t;
#defineJ_DREC_LEN_MASK0x000003ff
#defineJ_DREC_HASH_MASK0xfffff400
#defineJ_DREC_HASH_SHIFT10
```

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```


78

**File-System Objects** _`j_drec_val_t`_

## _`name_len_and_hash`_

The hash and length of the name.

```
uint32_tname_len_and_hash;
```

The length is a 10-bit unsigned integer, accessed as _`name_len_and_hash & J_DREC_LEN_MASK`_ . The length includes the final null character (U+0000).

The hash is an unsigned 22-bit integer, accessed as _`(name_len_and_hash & J_DREC_HASH_MASK) >> J_DREC_HASH_SHIFT`_ . The hash is computed as follows:

1. Start with the filename, represented as a null-terminated UTF-8 string.

2. Normalize the string using canonical decomposition (NFD).

3. Represent the normalized filename as a null-terminated UTF-32 string.

4. Compute the CRC-32C hash of the UTF-32 string.

5. Complement the bits of the hash.

6. Keep only the low 22 bits of the hash.

If you implement your own CRC function, rather than calling one from a library, you can omit both the complement operation thatʼs part of computing a CRC and the complement operation in the instructions above.

## _`name`_

The name, represented as a null-terminated UTF-8 string.

```
uint8_tname[0];
```

## _`J_DREC_LEN_MASK`_

The bit mask used to access the length of the name.

```
#defineJ_DREC_LEN_MASK0x000003ff
```

## _`J_DREC_HASH_MASK`_

The bit mask used to access the hash of the name.

```
#defineJ_DREC_HASH_MASK0xfffff400
```

## _`J_DREC_HASH_SHIFT`_

The bit shift used to access the hash of the name.

```
#defineJ_DREC_HASH_SHIFT10
```

## _`j_drec_val_t`_

The value half of a directory entry record.

```
structj_drec_val{
uint64_tfile_id;
uint64_tdate_added;
uint16_tflags;
```


79

**File-System Objects** _`j_dir_stats_key_t`_

```
uint8_txfields[];
}__attribute__((packed));
typedefstructj_drec_valj_drec_val_t;
```

## _`file_id`_

The identifier of the inode that this directory entry represents.

```
uint64_tfile_id;
```

## _`date_added`_

The time that this directory entry was added to the directory.

```
uint64_tdate_added;
```

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds. Itʼs not updated when modifying the directory entry — for example, by renaming a file without moving it to a different directory.

## _`flags`_

The directory entryʼs flags.

```
uint16_tflags;
```

The bits that are set in _`DREC_TYPE_MASK`_ store the inodeʼs file type, and the remaining bits are reserved. Populate the reserved bits with zeros when you create a new directory entry, and preserve their values when you modify an existing directory entry.

For possible values, see Directory Entry File Types.

## _`xfields`_

The directory entryʼs extended fields.

## _`uint8_t xfields[];`_

This location on disk contains several pieces of data that have variable sizes. For information about reading extended fields, see Extended Fields.

## _`j_dir_stats_key_t`_

The key half of a directory-information record.

```
structj_dir_stats_key{
j_key_thdr;
}__attribute__((packed));
typedefstructj_dir_stats_keyj_dir_stats_key_t;
```


80

**File-System Objects** _`j_dir_stats_val_t`_

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the file-system objectʼs identifier. The type in the header is always _`APFS_TYPE_DIR_REC`_ .

## _`j_dir_stats_val_t`_

The value half of a directory-information record.

```
structj_dir_stats_val{
```

```
uint64_tnum_children;
uint64_ttotal_size;
uint64_tchained_key;
uint64_tgen_count;
}__attribute__((packed));
typedefstructj_dir_stats_valj_dir_stats_val_t;
```

## _`num_children`_

The number of files and folders contained by the directory.

```
uint64_tnum_children;
```

## _`total_size`_

The total size, in bytes, of all the files stored in this directory and all of this directoryʼs descendants.

```
uint64_ttotal_size;
```

Hard links contribute to the _`total_size`_ of every directory they appear in.

## _`chained_key`_

The parent directoryʼs file system object identifier.

```
uint64_tchained_key;
```

## _`gen_count`_

A monotonically increasing counter thatʼs incremented each time this inode or any of its children is modified.

```
uint64_tgen_count;
```

Modifying the contents of a file requires updating the inodeʼs modification time and write generation, which means this counter must be incremented for the directory that contains the file.

If this counter canʼt be incremented without overflow, thatʼs an unrecoverable error.


81

**File-System Objects** _`j_xattr_key_t`_

## _`j_xattr_key_t`_

The key half of an extended attribute record.

```
structj_xattr_key{
j_key_thdr;
uint16_tname_len;
uint8_tname[0];
}__attribute__((packed));
typedefstructj_xattr_keyj_xattr_key_t;
```

```
hdr
```

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the file-system objectʼs identifier. The type in the header is always _`APFS_TYPE_XATTR`_ .

```
name_len
```

The length of the extended attributeʼs name, including the final null character (U+0000).

```
uint16_tname_len;
```

```
name
```

The extended attributeʼs name, represented as a null-terminated UTF-8 string.

```
uint8_tname[0];
```

## _`j_xattr_val_t`_

The value half of an extended attribute record.

```
structj_xattr_val{
uint16_tflags;
uint16_txdata_len;
uint8_txdata[0];
}__attribute__((packed));
typedefstructj_xattr_valj_xattr_val_t;
```

```
flags
```

The extended attribute recordʼs flags.

```
uint16_tflags;
```

For the values used in this bit field, see _`j_xattr_flags`_ . Either the _`XATTR_DATA_EMBEDDED`_ or _`XATTR_DATA_ STREAM`_ flag must be set.


82

**File-System Objects** _`j_xattr_val_t`_

## _`xdata_len`_

The length of the extended attribute data.

```
uint16_txdata_len;
```

If the _`XATTR_DATA_EMBEDDED`_ flag is set, this field is the length of the data in the _`xdata`_ field. Otherwise, this field is ignored.

## _`xdata`_

The extended attribute data or the identifier of a data stream that contains the data.

## _`uint8_t xdata[0];`_

If the _`XATTR_DATA_EMBEDDED`_ flag is set, the extended attribute data is stored directly in this field. Otherwise, this field contains the identifier ( _`uint64_t`_ ) for a data stream record that stores the extended attribute data. See also _`j_xattr_dstream_t`_ .


83
