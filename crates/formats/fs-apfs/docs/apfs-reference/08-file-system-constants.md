<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## File-System Constants

File-system objects use several groups of constants to define values for record types, reserved inode numbers, and flags and bit masks used in bit fields.

## _`j_obj_types`_

The type of a file-system record.

```
typedefenum{
```

|_`enum {`_|||
|---|---|---|
|_`APFS_TYPE_ANY`_|_`= `_|_`0,`_|
|_`APFS_TYPE_SNAP_METADATA`_|_`= `_|_`1,`_|
|_`APFS_TYPE_EXTENT`_|_`= `_|_`2,`_|
|_`APFS_TYPE_INODE`_|_`= `_|_`3,`_|
|_`APFS_TYPE_XATTR`_|_`= `_|_`4,`_|
|_`APFS_TYPE_SIBLING_LINK`_|_`= `_|_`5,`_|
|_`APFS_TYPE_DSTREAM_ID`_|_`= `_|_`6,`_|
|_`APFS_TYPE_CRYPTO_STATE`_|_`= `_|_`7,`_|
|_`APFS_TYPE_FILE_EXTENT`_|_`= `_|_`8,`_|
|_`APFS_TYPE_DIR_REC`_|_`= `_|_`9,`_|
|_`APFS_TYPE_DIR_STATS`_|_`= `_|_`10,`_|
|_`APFS_TYPE_SNAP_NAME`_|_`= `_|_`11,`_|
|_`APFS_TYPE_SIBLING_MAP`_|_`= `_|_`12,`_|
|_`APFS_TYPE_FILE_INFO`_|_`= `_|_`13,`_|
|_`APFS_TYPE_MAX_VALID`_|_`= `_|_`13,`_|
|_`APFS_TYPE_MAX`_|_`= `_|_`15,`_|
|_`APFS_TYPE_INVALID`_|_`= `_|_`15,`_|



```
}j_obj_types;
```

This value is stored in the type bits of a _`j_key_t`_ structureʼs _`obj_id_and_type`_ field.

```
APFS_TYPE_ANY
```

A record of any type.

```
APFS_TYPE_ANY=0
```

This enumeration case is used only in search queries and in tests when iterating over objects. Itʼs not valid as the type of a file-system object.

```
APFS_TYPE_SNAP_METADATA
```

Metadata about a snapshot.

```
APFS_TYPE_SNAP_METADATA=1
```

The key is an instance of _`j_snap_metadata_key_t`_ and the value is an instance of _`j_snap_metadata_val_t`_ .


84

**File-System Constants** _`j_obj_types`_

## _`APFS_TYPE_EXTENT`_

A physical extent record.

```
APFS_TYPE_EXTENT=2
```

The key is an instance of _`j_phys_ext_key_t`_ and the value is an instance of _`j_phys_ext_val_t`_ .

```
APFS_TYPE_INODE
```

An inode.

```
APFS_TYPE_INODE=3
```

The key is an instance of _`j_inode_key_t`_ and the value is an instance of _`j_inode_val_t`_ .

```
APFS_TYPE_XATTR
```

An extended attribute.

```
APFS_TYPE_XATTR=4
```

The key is an instance of _`j_xattr_key_t`_ and the value is an instance of _`j_xattr_val_t`_ .

```
APFS_TYPE_SIBLING_LINK
```

A mapping from an inode to hard links that the inode is the target of.

```
APFS_TYPE_SIBLING_LINK=5
```

The key is an instance of _`j_sibling_key_t`_ and the value is an instance of _`j_sibling_val_t`_ .

```
APFS_TYPE_DSTREAM_ID
```

A data stream.

```
APFS_TYPE_DSTREAM_ID=6
```

The key is an instance of _`j_dstream_id_key_t`_ and the value is an instance of _`j_dstream_id_val_t`_ .

```
APFS_TYPE_CRYPTO_STATE
```

A per-file encryption state.

```
APFS_TYPE_CRYPTO_STATE=7
```

The key is an instance of _`j_crypto_key_t`_ and the value is an instance of _`j_crypto_val_t`_ . This object type is used only by iOS devices, except for a placeholder object whose identifier is always _`CRYPTO_SW_ID`_ .

```
APFS_TYPE_FILE_EXTENT
```

A physical extent record for a file.

```
APFS_TYPE_FILE_EXTENT=8
```

The key is an instance of _`j_file_extent_key_t`_ and the value is an instance of _`j_file_extent_val_t`_ .


85

**File-System Constants** _`j_obj_types`_

## _`APFS_TYPE_DIR_REC`_

A directory entry.

```
APFS_TYPE_DIR_REC=9
```

The key is an instance of _`j_drec_key_t`_ and the value is an instance of _`j_drec_val_t`_ .

```
APFS_TYPE_DIR_STATS
```

Information about a directory.

```
APFS_TYPE_DIR_STATS=10
```

The key is an instance of _`j_dir_stats_key_t`_ and the value is an instance of _`j_drec_val_t`_ .

```
APFS_TYPE_SNAP_NAME
```

The name of a snapshot.

```
APFS_TYPE_SNAP_NAME=11
```

The key is an instance of _`j_snap_name_key_t`_ and the value is an instance of _`j_snap_name_val_t`_ .

```
APFS_TYPE_SIBLING_MAP
```

A mapping from a hard link to its target inode.

```
APFS_TYPE_SIBLING_MAP=12
```

The key is an instance of _`j_sibling_map_key_t`_ and the value is an instance of _`j_sibling_map_val_t`_ .

```
APFS_TYPE_FILE_INFO
```

Additional information about file data.

```
APFS_TYPE_FILE_INFO=13
```

The key is an instance of _`j_file_info_key_t`_ and the value is an instance of _`j_file_info_val_t`_ .

```
APFS_TYPE_MAX_VALID
```

The largest valid value for a file-system objectʼs type.

```
APFS_TYPE_MAX_VALID=13
```

```
APFS_TYPE_MAX
```

The largest value for a file-system objectʼs type.

```
APFS_TYPE_MAX=15
```


86

**File-System Constants** _`j_obj_kinds`_

## _`APFS_TYPE_INVALID`_

An invalid object type.

```
APFS_TYPE_INVALID=15
```

## _`j_obj_kinds`_

The kind of a file-system record.

```
typedefenum{
APFS_KIND_ANY=0,
APFS_KIND_NEW=1,
APFS_KIND_UPDATE=2,
APFS_KIND_DEAD=3,
APFS_KIND_UPDATE_REFCNT=4,
APFS_KIND_INVALID=255
}j_obj_kinds;
```

This value is stored in the kind bits of a _`j_phys_ext_val_t`_ structureʼs _`len_and_kind`_ field.

## _`APFS_KIND_ANY`_

A record of any kind.

```
APFS_KIND_ANY=0
```

This value isnʼt valid as the kind of a file-system record on disk. However, implementations of Apple File System can use it internally — for example, in search queries and in tests when iterating over objects.

## _`APFS_KIND_NEW`_

A new record.

```
APFS_KIND_NEW=1
```

This record adds data that isnʼt part of any snapshots.

## _`APFS_KIND_UPDATE`_

An updated record.

## _`APFS_KIND_UPDATE = 2`_

This record changes data thatʼs part of an existing snapshot.

## _`APFS_KIND_DEAD`_

A record thatʼs being deleted.

## _`APFS_KIND_DEAD = 3`_

This value isnʼt valid as the kind of a file-system record on disk. However, implementations of Apple File System can use it internally.


87

**File-System Constants** _`j_inode_flags`_

## _`APFS_KIND_UPDATE_REFCNT`_

An update to the reference count of a record.

```
APFS_KIND_UPDATE_REFCNT=4
```

This value isnʼt valid as the kind of a file-system record on disk. However, implementations of Apple File System can use it internally.

## _`APFS_KIND_INVALID`_

An invalid record kind.

```
APFS_KIND_INVALID=255
```

## _`j_inode_flags`_

The flags used by inodes.

```
typedefenum{
```

```
INODE_IS_APFS_PRIVATE=0x00000001,
INODE_MAINTAIN_DIR_STATS=0x00000002,
INODE_DIR_STATS_ORIGIN=0x00000004,
INODE_PROT_CLASS_EXPLICIT=0x00000008,
INODE_WAS_CLONED=0x00000010,
INODE_FLAG_UNUSED=0x00000020,
INODE_HAS_SECURITY_EA=0x00000040,
INODE_BEING_TRUNCATED=0x00000080,
INODE_HAS_FINDER_INFO=0x00000100,
INODE_IS_SPARSE=0x00000200,
INODE_WAS_EVER_CLONED=0x00000400,
INODE_ACTIVE_FILE_TRIMMED=0x00000800,
INODE_PINNED_TO_MAIN=0x00001000,
INODE_PINNED_TO_TIER2=0x00002000,
INODE_HAS_RSRC_FORK=0x00004000,
INODE_NO_RSRC_FORK=0x00008000,
INODE_ALLOCATION_SPILLEDOVER=0x00010000,
INODE_FAST_PROMOTE=0x00020000,
INODE_HAS_UNCOMPRESSED_SIZE=0x00040000,
INODE_IS_PURGEABLE=0x00080000,
INODE_WANTS_TO_BE_PURGEABLE=0x00100000,
INODE_IS_SYNC_ROOT=0x00200000,
INODE_SNAPSHOT_COW_EXEMPTION=0x00400000,
```

```
INODE_INHERITED_INTERNAL_FLAGS=(INODE_MAINTAIN_DIR_STATS\
|INODE_SNAPSHOT_COW_EXEMPTION),
```

```
INODE_CLONED_INTERNAL_FLAGS=(INODE_HAS_RSRC_FORK\
|INODE_NO_RSRC_FORK\
```


88

**File-System Constants** _`j_inode_flags`_

```
|INODE_HAS_FINDER_INFO\
|INODE_SNAPSHOT_COW_EXEMPTION),
```

```
}j_inode_flags;
```

```
#defineAPFS_VALID_INTERNAL_INODE_FLAGS(INODE_IS_APFS_PRIVATE\
```

```
|INODE_MAINTAIN_DIR_STATS\
```

```
|INODE_DIR_STATS_ORIGIN\
```

```
|INODE_PROT_CLASS_EXPLICIT\
|INODE_WAS_CLONED\
```

```
|INODE_HAS_SECURITY_EA\
```

```
|INODE_BEING_TRUNCATED\
|INODE_HAS_FINDER_INFO\
|INODE_IS_SPARSE\
```

```
|INODE_WAS_EVER_CLONED\
```

```
|INODE_ACTIVE_FILE_TRIMMED\
```

```
|INODE_PINNED_TO_MAIN\
```

```
|INODE_PINNED_TO_TIER2\
|INODE_HAS_RSRC_FORK\
|INODE_NO_RSRC_FORK\
|INODE_ALLOCATION_SPILLEDOVER\
|INODE_FAST_PROMOTE\
|INODE_HAS_UNCOMPRESSED_SIZE\
|INODE_IS_PURGEABLE\
```

```
|INODE_WANTS_TO_BE_PURGEABLE\
|INODE_IS_SYNC_ROOT\
|INODE_SNAPSHOT_COW_EXEMPTION)
```

```
#defineAPFS_INODE_PINNED_MASK(INODE_PINNED_TO_MAIN|INODE_PINNED_TO_TIER2)
```

## _`INODE_IS_APFS_PRIVATE`_

The inode is used internally by an implementation of Apple File System.

```
INODE_IS_APFS_PRIVATE=0x00000001
```

Inodes with this flag set arenʼt considered part of the volume. They canʼt be cloned, renamed, or deleted. Theyʼre ignored by operations like counting the number of files on disk, and theyʼre hidden from the user during operations like listing the files of a directory.

This flag isnʼt reserved by Apple; implementations of the Apple File System must set this flag on any inodes they create for their own record keeping. However, to prevent implementations from interfering with each other, an implementation modifies inodes with this flag only if the implementation created that inode.

Appleʼs implementation uses this flag for temporary files.

See also _`PRIV_DIR_INO_NUM`_ .

```
INODE_MAINTAIN_DIR_STATS
```

The inode tracks the size of all of its children.


89

**File-System Constants** _`j_inode_flags`_

## _`INODE_MAINTAIN_DIR_STATS = 0x00000002`_

This flag is only valid on a directory, and must also be set on the directoryʼs subdirectories.

When removing the _`INODE_MAINTAIN_DIR_STATS`_ flag from a directory, walk its subdirectories and remove it from any directories that inherited it from this directory. Directories that have the _`INODE_DIR_STATS_ORIGIN`_ flag set, and subdirectories of those directories, continue to have the _`INODE_MAINTAIN_DIR_STATS`_ flag set, because they donʼt inherit it from this directory.

## _`INODE_DIR_STATS_ORIGIN`_

The inode has the _`INODE_MAINTAIN_DIR_STATS`_ flag set explicitly, not due to inheritance.

```
INODE_DIR_STATS_ORIGIN=0x00000004
```

More than one directory in a hierarchy can have this flag set.

## _`INODE_PROT_CLASS_EXPLICIT`_

The inodeʼs data protection class was set explicitly when the inode was created.

```
INODE_PROT_CLASS_EXPLICIT=0x00000008
```

## _`INODE_WAS_CLONED`_

The inode was created by cloning another inode.

```
INODE_WAS_CLONED=0x00000010
```

## _`INODE_FLAG_UNUSED`_

Reserved.

## _`INODE_FLAG_UNUSED = 0x00000020`_

Leave this flag unset when you create a new inode, and preserve its value when you modify an existing inode.

## _`INODE_HAS_SECURITY_EA`_

The inode has an access control list.

```
INODE_HAS_SECURITY_EA=0x00000040
```

## _`INODE_BEING_TRUNCATED`_

The inode was truncated.

```
INODE_BEING_TRUNCATED=0x00000080
```

This flag is used as follows to allow the truncation operation to complete after a crash:

1. The system is asked to truncate an inode

2. This flag is set on the inode

3. The system starts truncating the file

4. A crash occurs


90

**File-System Constants** _`j_inode_flags`_

5. In the post-crash recovery process, this flag is detected

6. The system finishes truncating the inode

Note that after a crash, the truncation operation might not resume until the next time the inode is accessed.

## _`INODE_HAS_FINDER_INFO`_

The inode has a Finder info extended field.

```
INODE_HAS_FINDER_INFO=0x00000100
```

See also _`INO_EXT_TYPE_FINDER_INFO`_ .

## _`INODE_IS_SPARSE`_

The inode has a sparse byte count extended field.

```
INODE_IS_SPARSE=0x00000200
```

See also _`INO_EXT_TYPE_SPARSE_BYTES`_ .

## _`INODE_WAS_EVER_CLONED`_

The inode has been cloned at least once.

```
INODE_WAS_EVER_CLONED=0x00000400
```

If this flag is set, the blocks on disk that store this inode might also be in use with another inode. For example, when deleting this inode, you need to check reference counts before deallocating storage.

Versions of macOS prior to 10.13.3 had a known issue where this flag could be set incorrectly. Before reading this flag, confirm that the inodeʼs object identifier is larger than the value stored in the _`apfs_cloneinfo_id_epoch`_ field of _`apfs_superblock_t`_ . In addition, to ensure that the volume hasnʼt been modified by an older OS version, confirm that the value of the _`apfs_cloneinfo_xid`_ field and the _`apfs_modified_by`_ field of _`apfs_superblock_t`_ contain the same value.

## _`INODE_ACTIVE_FILE_TRIMMED`_

The inode is an overprovisioning file that has been trimmed.

```
INODE_ACTIVE_FILE_TRIMMED=0x00000800
```

This file type is used only on devices running iOS. By allocating space for the file, but never writing to that space, extra blocks are set aside for overprovisioning thatʼs performed by the underlying NAND storage.

## _`INODE_PINNED_TO_MAIN`_

The inodeʼs file content is always on the main storage device.

```
INODE_PINNED_TO_MAIN=0x00001000
```

This flag is only valid for Fusion systems. The main storage is a solid-state drive.


91

**File-System Constants** _`j_inode_flags`_

## _`INODE_PINNED_TO_TIER2`_

The inodeʼs file content is always on the secondary storage device.

## _`INODE_PINNED_TO_TIER2 = 0x00002000`_

This flag is only valid for Fusion systems. The secondary storage is a hard drive.

## _`INODE_HAS_RSRC_FORK`_

The inode has a resource fork.

```
INODE_HAS_RSRC_FORK=0x00004000
```

If this flag is set, _`INODE_NO_RSRC_FORK`_ must not be set. Itʼs also valid for neither flag to be set, which implicitly indicates that the inode doesnʼt have a resource fork.

## _`INODE_NO_RSRC_FORK`_

The inode doesnʼt have a resource fork.

## _`INODE_NO_RSRC_FORK = 0x00008000`_

If this flag is set, _`INODE_HAS_RSRC_FORK`_ must not be set. Itʼs also valid for neither flag to be set, which implicitly indicates that the inode doesnʼt have a resource fork.

## _`INODE_ALLOCATION_SPILLEDOVER`_

The inodeʼs file content has some space allocated outside of the preferred storage tier for that file.

```
INODE_ALLOCATION_SPILLEDOVER=0x00010000
```

See also _`APFS_FS_SPILLEDOVER`_ .

## _`INODE_FAST_PROMOTE`_

This inode is scheduled for promotion from slow storage to fast storage.

```
INODE_FAST_PROMOTE=0x00020000
```

The promotion between tiers will happen the first time this inode is read.

## _`INODE_HAS_UNCOMPRESSED_SIZE`_

This inode stores its uncompressed size in the inode.

```
INODE_HAS_UNCOMPRESSED_SIZE=0x00040000
```

The uncompressed size is stored in the _`uncompressed_size`_ field of _`j_inode_val_t`_ .

Prior to macOS 10.15 and iOS 13.1, this flag was ignored and Appleʼs implementation always treated the _`uncompressed_size`_ field as padding.


92

**File-System Constants** _`j_inode_flags`_

## _`INODE_IS_PURGEABLE`_

This inode will be deleted at the next purge.

## _`INODE_IS_PURGEABLE = 0x00080000`_

A purge is requested from user space by part of the operating system, and the process of deleting purgeable files is the responsibility of the operating system.

## _`INODE_WANTS_TO_BE_PURGEABLE`_

This inode should become purgeable when its link count drops to one.

```
INODE_WANTS_TO_BE_PURGEABLE=0x00100000
```

## _`INODE_IS_SYNC_ROOT`_

This inode is the root of a sync hierarchy for _`fileproviderd`_ .

```
INODE_IS_SYNC_ROOT=0x00200000
```

Donʼt add or remove this flag, but preserve the flag if it already exists.

To prevent data loss, Appleʼs implementation coordinates with _`fileproviderd`_ during operations such as renaming a file in a sync hierarchy, moving a file from inside a sync hierarchy out of that hierarchy, and moving a file from outside of a sync hierarchy into that hierarchy. Other implementations of the Apple File System should treat requests to perform these operations as errors.

## _`INODE_SNAPSHOT_COW_EXEMPTION`_

This inode is exempt from copy-on-write behavior if the data is part of a snapshot.

## _`INODE_SNAPSHOT_COW_EXEMPTION = 0x00400000`_

Donʼt add or remove this flag, but preserve the flag if it already exists.

The number of files with this flag is tracked by the _`APFS_COW_EXEMPT_COUNT_NAME`_ extended attribute.

## _`INODE_INHERITED_INTERNAL_FLAGS`_

A bit mask of the flags that are inherited by the files and subdirectories in a directory.

```
INODE_INHERITED_INTERNAL_FLAGS=(INODE_MAINTAIN_DIR_STATS\
```

```
|INODE_SNAPSHOT_COW_EXEMPTION)
```

## _`INODE_CLONED_INTERNAL_FLAGS`_

A bit mask of the flags that are preserved when cloning.

```
INODE_CLONED_INTERNAL_FLAGS=(INODE_HAS_RSRC_FORK
```

```
|INODE_NO_RSRC_FORK\
|INODE_HAS_FINDER_INFO\
```

```
|INODE_SNAPSHOT_COW_EXEMPTION)
```


93

**File-System Constants** _`j_xattr_flags`_

## _`APFS_VALID_INTERNAL_INODE_FLAGS`_

A bit mask of all valid flags.

```
#defineAPFS_VALID_INTERNAL_INODE_FLAGS(INODE_IS_APFS_PRIVATE\
```

```
|INODE_MAINTAIN_DIR_STATS\
```

```
|INODE_DIR_STATS_ORIGIN\
```

```
|INODE_PROT_CLASS_EXPLICIT\
```

```
|INODE_WAS_CLONED\
```

```
|INODE_HAS_SECURITY_EA\
```

```
|INODE_BEING_TRUNCATED\
|INODE_HAS_FINDER_INFO\
```

```
|INODE_IS_SPARSE\
```

```
|INODE_WAS_EVER_CLONED\
```

```
|INODE_ACTIVE_FILE_TRIMMED\
```

```
|INODE_PINNED_TO_MAIN\
```

```
|INODE_PINNED_TO_TIER2\
```

```
|INODE_HAS_RSRC_FORK\
```

```
|INODE_NO_RSRC_FORK\
|INODE_ALLOCATION_SPILLEDOVER\
|INODE_FAST_PROMOTE\
|INODE_HAS_UNCOMPRESSED_SIZE\
|INODE_IS_PURGEABLE\
|INODE_WANTS_TO_BE_PURGEABLE\
|INODE_IS_SYNC_ROOT\
```

```
|INODE_SNAPSHOT_COW_EXEMPTION)
```

```
APFS_INODE_PINNED_MASK
```

A bit mask of the flags that are related to pinning.

```
#defineAPFS_INODE_PINNED_MASK(INODE_PINNED_TO_MAIN|INODE_PINNED_TO_TIER2)
```

## _`j_xattr_flags`_

The flags used in an extended attribute record to provide additional information.

```
typedefenum{
XATTR_DATA_STREAM=0x00000001,
XATTR_DATA_EMBEDDED=0x00000002,
XATTR_FILE_SYSTEM_OWNED=0x00000004,
XATTR_RESERVED_8=0x00000008,
}j_xattr_flags;
```

```
XATTR_DATA_STREAM
```

The attribute data is stored in a data stream.

```
XATTR_DATA_STREAM=0x00000001
```

If this flag is set, _`XATTR_DATA_EMBEDDED`_ must not be set.


94

**File-System Constants** _`dir_rec_flags`_

## _`XATTR_DATA_EMBEDDED`_

The attribute data is stored directly in the record.

```
XATTR_DATA_EMBEDDED=0x00000002
```

If this flag is set, the size of the value be smaller than _`XATTR_MAX_EMBEDDED_SIZE`_ , and _`XATTR_DATA_STREAM`_ must not be set.

## _`XATTR_FILE_SYSTEM_OWNED`_

The extended attribute record is owned by the file system.

```
XATTR_FILE_SYSTEM_OWNED=0x00000004
```

For example, this flag is used on symbolic links. The links have an extended attribute whose name is _`SYMLINK_EA_ NAME`_ , and this flag is set on that attribute.

## _`XATTR_RESERVED_8`_

Reserved.

```
XATTR_RESERVED_8=0x00000008
```

Donʼt add this flag to an extended attribute record, but preserve the flag if it already exists.

## _`dir_rec_flags`_

The flags used by directory records.

```
typedefenum{
```

```
DREC_TYPE_MASK=0x000f,
RESERVED_10=0x0010
}dir_rec_flags;
```

```
DREC_TYPE_MASK
```

The bit mask used to access the type.

```
DREC_TYPE_MASK=0x000f
```

This bit mask is used with the _`flags`_ field of _`j_drec_val_t`_ .

```
RESERVED_10
```

Reserved.

```
RESERVED_10=0x0010
```

Donʼt set this flag. If you find a directory record with this flag set in production, file a bug against the Apple File System implementation.


95

**File-System Constants** Inode Numbers

## Inode Numbers

Inodes whose number is always the same.

```
#defineINVALID_INO_NUM0
#defineROOT_DIR_PARENT1
#defineROOT_DIR_INO_NUM2
#definePRIV_DIR_INO_NUM3
#defineSNAP_DIR_INO_NUM6
#definePURGEABLE_DIR_INO_NUM7
#defineMIN_USER_INO_NUM16
#defineUNIFIED_ID_SPACE_MARK0x0800000000000000ULL
```

If the _`APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE`_ flag is set on the volume, the system volume reserves each of the inode numbers listed above but with _`UNIFIED_ID_SPACE_MARK`_ added to them. For example, the inode number _`0x0800000000000002ULL`_ is equal to _`ROOT_DIR_INO_NUM + UNIFIED_ID_SPACE_MARK`_ , meaning this inode number is reserved for the system volumeʼs root directory.

```
INVALID_INO_NUM
```

An invalid inode number.

```
#defineINVALID_INO_NUM0
```

```
ROOT_DIR_PARENT
```

The inode number for the root directoryʼs parent.

```
#defineROOT_DIR_PARENT1
```

This is a sentinel value; thereʼs no inode on disk with this inode number.

```
ROOT_DIR_INO_NUM
```

The inode number for the root directory of the volume.

```
#defineROOT_DIR_INO_NUM2
```

```
PRIV_DIR_INO_NUM
```

The inode number for the private directory.

```
#definePRIV_DIR_INO_NUM3
```

The private directoryʼs filename is “private-dir”. When creating a new volume, you must create a directory with this name and inode number.

This directory isnʼt reserved by Apple; implementations of the Apple File System can use it to store their own recordkeeping information. However, to prevent implementations from interfering with each other, an implementation modifies files in the private directory only if the implementation created the files.


96

**File-System Constants** Extended Attributes Constants

## See also _`INODE_IS_APFS_PRIVATE`_ .

## _`SNAP_DIR_INO_NUM`_

The inode number for the directory where snapshot metadata is stored.

## _`#define SNAP_DIR_INO_NUM 6`_

Snapshot inodes are stored in the snapshot metedata tree.

## _`PURGEABLE_DIR_INO_NUM`_

The inode number used for storing references to purgeable files.

## _`#define PURGEABLE_DIR_INO_NUM 7`_

This inode number and the directory records that use it are reserved. Other implementations of the Apple File System must not modify them.

There isnʼt an actual directory with this inode number.

Purgeable files have the _`INODE_IS_PURGEABLE`_ flag set on the _`internal_flags`_ field of _`j_inode_val_t`_ .

## _`MIN_USER_INO_NUM`_

The smallest inode number available for user content.

## _`#define MIN_USER_INO_NUM 16`_

All inode numbers less than this value are reserved.

## _`UNIFIED_ID_SPACE_MARK`_

The smallest inode number used by the system volume in a volume group.

```
#defineUNIFIED_ID_SPACE_MARK0x0800000000000000ULL
```

For more information, see _`APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE`_ .

## Extended Attributes Constants

Constants used with extended attributes.

```
#defineXATTR_MAX_EMBEDDED_SIZE3804
#defineSYMLINK_EA_NAME”com.apple.fs.symlink”
#defineFIRMLINK_EA_NAME”com.apple.fs.firmlink”
#defineAPFS_COW_EXEMPT_COUNT_NAME”com.apple.fs.cow-exempt-file-count”
```

## _`XATTR_MAX_EMBEDDED_SIZE`_

The largest size, in bytes, of an extended attribute whose value is stored directly in the record.

```
#defineXATTR_MAX_EMBEDDED_SIZE3804
```

For information about embedded values, see _`j_xattr_val_t`_ .


97

**File-System Constants** File-System Object Constants

## _`SYMLINK_EA_NAME`_

The name of an extended attribute for a symbolic link whose value is the target file on the data volume.

```
#defineSYMLINK_EA_NAME”com.apple.fs.symlink”
```

## _`FIRMLINK_EA_NAME`_

The name of an extended attribute for a firm link whose value is the target file.

```
#defineFIRMLINK_EA_NAME”com.apple.fs.firmlink”
```

## _`APFS_COW_EXEMPT_COUNT_NAME`_

The number of files on the volume that donʼt use copy on write.

```
#defineAPFS_COW_EXEMPT_COUNT_NAME”com.apple.fs.cow-exempt-file-count”
```

Donʼt add this extended attribute or modify its value, but preserve the attribute if it already exists.

The inodes that are counted here have the _`INODE_SNAPSHOT_COW_EXEMPTION`_ flag set. This number is used by Time Machine when making snapshots.

## File-System Object Constants

_No overview available._

```
#defineOWNING_OBJ_ID_INVALID~0ULL
#defineOWNING_OBJ_ID_UNKNOWN~1ULL
#defineJOBJ_MAX_KEY_SIZE832
#defineJOBJ_MAX_VALUE_SIZE3808
#defineMIN_DOC_ID3
```

## _`MIN_DOC_ID`_

The smallest document identifier available for user content.

```
#defineMIN_DOC_ID3
```

All document identifiers less than this value are reserved.

## File Extent Constants

_No overview available._

```
#defineFEXT_CRYPTO_ID_IS_TWEAK0x01
```

## File Modes

The values used by the _`mode`_ field of _`j_inode_val_t`_ to indicate a fileʼs mode.


98

**File-System Constants** File Modes

```
typedefuint16_tmode_t;
#defineS_IFMT0170000
#defineS_IFIFO0010000
#defineS_IFCHR0020000
#defineS_IFDIR0040000
#defineS_IFBLK0060000
#defineS_IFREG0100000
#defineS_IFLNK0120000
#defineS_IFSOCK0140000
#defineS_IFWHT0160000
```

The names, values, and meanings of these constants are the same as the constants provided by _`<sys/stat.h>`_ . These values are the same as the values defined in Directory Entry File Types, except for a bit shift.

```
mode_t
```

A file mode.

```
typedefuint16_tmode_t;
```

```
S_IFMT
```

The bit mask used to access the file type.

```
#defineS_IFMT0170000
```

```
S_IFIFO
```

A named pipe.

```
#defineS_IFIFO0010000
```

```
S_IFCHR
```

A character-special file.

```
#defineS_IFCHR0020000
```

```
S_IFDIR
```

A directory.

```
#defineS_IFDIR0040000
```

```
S_IFBLK
```

A block-special file.

```
#defineS_IFBLK0060000
```


99

**File-System Constants** Directory Entry File Types

## _`S_IFREG`_

A regular file.

```
#defineS_IFREG0100000
```

```
S_IFLNK
```

A symbolic link.

```
#defineS_IFLNK0120000
```

```
S_IFSOCK
```

A socket.

```
#defineS_IFSOCK0140000
```

```
S_IFWHT
```

A whiteout.

```
#defineS_IFWHT0160000
```

## Directory Entry File Types

Values used by the _`flags`_ field of _`j_drec_val_t`_ to indicate a directory entryʼs type.

|_`#define `_|_`DT_UNKNOWN`_|_`0`_|
|---|---|---|
|_`#define `_|_`DT_FIFO`_|_`1`_|
|_`#define `_|_`DT_CHR`_|_`2`_|
|_`#define `_|_`DT_DIR`_|_`4`_|
|_`#define `_|_`DT_BLK`_|_`6`_|
|_`#define `_|_`DT_REG`_|_`8`_|
|_`#define `_|_`DT_LNK`_|_`10`_|
|_`#define `_|_`DT_SOCK`_|_`12`_|
|_`#define `_|_`DT_WHT`_|_`14`_|



These values are the same as the values defined in File Modes, except for a bit shift.

```
DT_UNKNOWN
```

An unknown directory entry.

```
#defineDT_UNKNOWN0
```

```
DT_FIFO
```

A named pipe

```
#defineDT_FIFO1
```


100

**File-System Constants** Directory Entry File Types

## _`DT_CHR`_

A character-special file.

```
#defineDT_CHR2
```

```
DT_DIR
```

A directory.

```
#defineDT_DIR4
```

```
DT_BLK
```

A block-special file.

```
#defineDT_BLK6
```

```
DT_REG
```

A regular file.

```
#defineDT_REG8
```

```
DT_LNK
```

A symbolic link.

```
#defineDT_LNK10
```

```
DT_SOCK
```

A socket.

```
#defineDT_SOCK12
```

```
DT_WHT
```

A whiteout.

```
#defineDT_WHT14
```


101
