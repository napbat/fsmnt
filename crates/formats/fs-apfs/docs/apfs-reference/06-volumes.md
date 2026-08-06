<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Volumes

A volume contains a file system, the files and metadata that make up that file system, and various supporting data structures like an object map.

## _`apfs_superblock_t`_

A volume superblock.

```
structapfs_superblock{
obj_phys_tapfs_o;
uint32_tapfs_magic;
uint32_tapfs_fs_index;
uint64_tapfs_features;
uint64_tapfs_readonly_compatible_features;
uint64_tapfs_incompatible_features;
uint64_tapfs_unmount_time;
uint64_tapfs_fs_reserve_block_count;
uint64_tapfs_fs_quota_block_count;
uint64_tapfs_fs_alloc_count;
wrapped_meta_crypto_state_tapfs_meta_crypto;
uint32_tapfs_root_tree_type;
uint32_tapfs_extentref_tree_type;
uint32_tapfs_snap_meta_tree_type;
oid_tapfs_omap_oid;
oid_tapfs_root_tree_oid;
oid_tapfs_extentref_tree_oid;
oid_tapfs_snap_meta_tree_oid;
xid_tapfs_revert_to_xid;
oid_tapfs_revert_to_sblock_oid;
uint64_tapfs_next_obj_id;
uint64_tapfs_num_files;
uint64_tapfs_num_directories;
uint64_tapfs_num_symlinks;
uint64_tapfs_num_other_fsobjects;
uint64_tapfs_num_snapshots;
```


51

**Volumes** _`apfs_superblock_t`_

```
uint64_tapfs_total_blocks_alloced;
uint64_tapfs_total_blocks_freed;
uuid_tapfs_vol_uuid;
uint64_tapfs_last_mod_time;
uint64_tapfs_fs_flags;
apfs_modified_by_tapfs_formatted_by;
apfs_modified_by_tapfs_modified_by[APFS_MAX_HIST];
uint8_tapfs_volname[APFS_VOLNAME_LEN];
uint32_tapfs_next_doc_id;
uint16_tapfs_role;
uint16_treserved;
xid_tapfs_root_to_xid;
oid_tapfs_er_state_oid;
uint64_tapfs_cloneinfo_id_epoch;
uint64_tapfs_cloneinfo_xid;
oid_tapfs_snap_meta_ext_oid;
uuid_tapfs_volume_group_id;
oid_tapfs_integrity_meta_oid;
oid_tapfs_fext_tree_oid;
uint32_tapfs_fext_tree_type;
uint32_treserved_type;
oid_treserved_oid;
};
#defineAPFS_MAGIC'BSPA'
#defineAPFS_MAX_HIST8
#defineAPFS_VOLNAME_LEN256
```

```
apfs_o
```

The objectʼs header.

```
obj_phys_tapfs_o;
```

```
apfs_magic
```

A number that can be used to verify that youʼre reading an instance of _`apfs_superblock_t`_ .


52

**Volumes** _`apfs_superblock_t`_

## _`uint32_t apfs_magic;`_

The value of this field is always _`APFS_MAGIC`_ .

## _`apfs_fs_index`_

The index of the object identifier for this volumeʼs file system in the containerʼs array of file systems.

## _`uint32_t apfs_fs_index`_

The containerʼs array is stored in the _`nx_fs_oid`_ field of _`nx_superblock_t`_ .

When a volume is being deleted, itʼs removed from the containerʼs array of volumes before _`apfs_superblock_t`_ object is destroyed. If you read this field of a volume thatʼs being deleted, the specified entry in the array might have already been reused for another volume.

## _`apfs_features`_

A bit field of the optional features being used by this volume.

## _`uint64_t apfs_features;`_

For the values used in this bit field, see Optional Volume Feature Flags.

If your implementation doesnʼt support an optional feature thatʼs in use, ignore that feature in this list and mount the volume as usual.

## _`apfs_readonly_compatible_features`_

A bit field of the read-only compatible features being used by this volume.

```
uint64_tapfs_readonly_compatible_features;
```

For the values used in this bit field, see Read-Only Compatible Volume Feature Flags.

If your implementation doesnʼt support a read-only compatible feature thatʼs in use, mount the volume as read-only.

## _`apfs_incompatible_features`_

A bit field of the backward-incompatible features being used by this volume.

```
uint64_tapfs_incompatible_features;
```

For the values used in this bit field, see Incompatible Volume Feature Flags.

If your implementation doesnʼt support a backward-incompatible feature thatʼs in use, it must not mount the volume.

## _`apfs_unmount_time`_

The time that this volume was last unmounted.

```
uint64_tapfs_unmount_time;
```

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds.


53

**Volumes** _`apfs_superblock_t`_

## _`apfs_fs_reserve_block_count`_

The number of blocks that have been reserved for this volume to allocate.

```
uint64_tapfs_fs_reserve_block_count;
```

```
apfs_fs_quota_block_count
```

The maximum number of blocks that this volume can allocate.

```
uint64_tapfs_fs_quota_block_count;
```

```
apfs_fs_alloc_count
```

The number of blocks currently allocated for this volumeʼs file system.

```
uint64_tapfs_fs_alloc_count;
```

```
apfs_meta_crypto
```

Information about the key used to encrypt metadata for this volume.

```
wrapped_meta_crypto_state_tapfs_meta_crypto;
```

On devices running macOS, the volume encryption key (VEK) is used to encrypt the metadata, as discussed in Accessing Encrypted Objects.

```
apfs_root_tree_type
```

The type of the root file-system tree.

```
uint32_tapfs_root_tree_type
```

The value is typically _`OBJ_VIRTUAL | OBJECT_TYPE_BTREE`_ , with a subtype of _`OBJECT_TYPE_FSTREE`_ . For possible values, see Object Types.

```
apfs_extentref_tree_type
```

The type of the extent-reference tree.

```
uint32_tapfs_extentref_tree_type
```

The value is typically _`OBJ_PHYSICAL | OBJECT_TYPE_BTREE`_ , with a subtype of _`OBJECT_TYPE_BLOCKREF`_ . For possible values, see Object Types.

```
apfs_snap_meta_tree_type
```

The type of the snapshot metadata tree.

```
uint32_tapfs_snap_meta_tree_type
```

The value is typically _`OBJ_PHYSICAL | OBJECT_TYPE_BTREE`_ , with a subtype of _`OBJECT_TYPE_BLOCKREF`_ . For possible values, see Object Types.


54

**Volumes** _`apfs_superblock_t`_

## _`apfs_omap_oid`_

The physical object identifier of the volumeʼs object map.

```
oid_tapfs_omap_oid;
```

```
apfs_root_tree_oid
```

The virtual object identifier of the root file-system tree.

```
oid_tapfs_root_tree_oid;
```

```
apfs_extentref_tree_oid
```

The physical object identifier of the extent-reference tree.

```
oid_tapfs_extentref_tree_oid;
```

When a snapshot is created, the current extent-reference tree is moved to the snapshot. A new, empty, extentreference tree is created and its object identifier becomes the new value of this field.

## _`apfs_snap_meta_tree_oid`_

The virtual object identifier of the snapshot metadata tree.

```
oid_tapfs_snap_meta_tree_oid;
```

## _`apfs_revert_to_xid`_

The transaction identifier of a snapshot that the volume will revert to.

```
xid_tapfs_revert_to_xid;
```

When mounting a volume, if the value of this field nonzero, revert to the specified snapshot by deleting all snapshots after the specified transaction identifier and deleting the current state, and then setting this field to zero.

## _`apfs_revert_to_sblock_oid`_

The physical object identifier of a volume superblock that the volume will revert to.

```
oid_tapfs_revert_to_sblock_oid;
```

When mounting a volume, if the _`apfs_revert_to_xid`_ field is nonzero, ignore the value of this field. Otherwise, revert to the specified volume superblock.

## _`apfs_next_obj_id`_

The next identifier that will be assigned to a file-system object in this volume.

```
uint64_tapfs_next_obj_id;
```


55

**Volumes** _`apfs_superblock_t`_

## _`apfs_num_files`_

The number of regular files in this volume.

```
uint64_tapfs_num_files;
```

```
apfs_num_directories
```

The number of directories in this volume.

```
uint64_tapfs_num_directories;
```

```
apfs_num_symlinks
```

The number of symbolic links in this volume.

```
uint64_tapfs_num_symlinks;
```

```
apfs_num_other_fsobjects
```

The number of other files in this volume.

```
uint64_tapfs_num_other_fsobjects;
```

The value of this field includes all files that arenʼt included in the _`apfs_num_symlinks`_ , _`apfs_num_directories`_ , or _`apfs_num_files`_ fields.

## _`apfs_num_snapshots`_

The number of snapshots in this volume.

```
uint64_tapfs_num_snapshots;
```

## _`apfs_total_blocks_alloced`_

The total number of blocks that have been allocated by this volume.

```
uint64_tapfs_total_blocks_alloced;
```

The value of this field increases when blocks are allocated, but isnʼt modified when theyʼre freed. If the volume doesnʼt contain any files, the value of this field matches _`apfs_total_blocks_freed`_ .

## _`apfs_total_blocks_freed`_

The total number of blocks that have been freed by this volume.

```
uint64_tapfs_total_blocks_freed;
```

The value of this field isnʼt modified when blocks are allocated, but increases when theyʼre freed. If the volume doesnʼt contain any files, the value of this field matches _`apfs_total_blocks_alloced`_ .


56

**Volumes** _`apfs_superblock_t`_

## _`apfs_vol_uuid`_

The universally unique identifier for this volume.

```
uuid_tapfs_vol_uuid;
```

## _`apfs_last_mod_time`_

The time that this volume was last modified.

```
uint64_tapfs_last_mod_time;
```

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds.

## _`apfs_fs_flags`_

The volumeʼs flags.

```
uint64_tapfs_fs_flags;
```

For the values used in this bit field, see Volume Flags.

## _`apfs_formatted_by`_

Information about the software that created this volume.

```
apfs_modified_by_tapfs_formatted_by;
```

This field is set only once, when the volume is created.

## _`apfs_modified_by`_

Information about the software that has modified this volume.

```
apfs_modified_by_tapfs_modified_by[APFS_MAX_HIST]
```

The newest element in this array is stored at index zero. To update this field when you modify a volume, move each element to the index thatʼs larger by one, and then write the new modification information. When you create a new volume, fill the arrayʼs memory with zeros.

If the implementationʼs information is already the last entry in this field, you can update the field as usual (creating a duplicate), or leave the fieldʼs value unmodified. Both behaviors are permitted.

## _`apfs_volname`_

The name of the volume, represented as a null-terminated UTF-8 string.

```
uint8_tapfs_volname[APFS_VOLNAME_LEN]
```

The _`APFS_INCOMPAT_NON_UTF8_FNAMES`_ flag has no effect on this fieldʼs value.


57

**Volumes** _`apfs_superblock_t`_

## _`apfs_next_doc_id`_

The next document identifier that will be assigned.

## _`uint32_t apfs_next_doc_id`_

A documentʼs identifier is stored in the _`INO_EXT_TYPE_DOCUMENT_ID`_ extended field of the inode.

After assigning a new document identifier, increment this field by one. Valid document identifiers are greater than _`MIN_DOC_ID`_ and less than _`UINT32_MAX - 1`_ . If a new document identifier isnʼt available, thatʼs an unrecoverable error. Identifiers arenʼt allowed to restart from one or to be reused.

## _`apfs_role`_

The role of this volume within the container.

```
uint16_tapfs_role
```

For possible values, see Volume Roles.

## _`reserved`_

Reserved.

```
uint16_treserved
```

Populate this field with zero when you create a new volume, and preserve its value when you modify an existing volume.

```
apfs_root_to_xid
```

The transaction identifier of the snapshot to root from, or zero to root normally.

```
xid_tapfs_root_to_xid;
```

```
apfs_er_state_oid
```

The current state of encryption or decryption for a drive thatʼs being encrypted or decrypted, or zero if no encryption change is in progress.

```
oid_tapfs_er_state_oid;
```

## _`apfs_cloneinfo_id_epoch`_

The largest object identifier used by this volume at the time _`INODE_WAS_EVER_CLONED`_ started storing valid information.

```
uint64_tapfs_cloneinfo_id_epoch;
```

If the value of this field is zero, all information stored using _`INODE_WAS_EVER_CLONED`_ is valid. For information about how to this identifier is used, see _`INODE_WAS_EVER_CLONED`_ .

This field was added to this data structure for macOS 10.13.3. Older implementations of Apple File System store zero in this field when initializing an instance of the structure, and they preserve the fieldʼs value when modifying the structure. Because zero is a valid value for this field, check the value of _`apfs_cloneinfo_xid`_ – if that field is also zero, the structure was created by an older implementation.


58

**Volumes** _`apfs_superblock_t`_

## _`apfs_cloneinfo_xid`_

A transaction identifier used with _`apfs_cloneinfo_id_epoch`_ .

## _`uint64_t apfs_cloneinfo_xid;`_

When unmounting a volume, the value of this field is set to the latest transaction identifier, the same as the _`apfs_modified_by`_ field. For information about how to this identifier is used, see _`INODE_WAS_EVER_CLONED`_ .

This field was added to this data structure for macOS 10.13.3. Older implementations of Apple File System store zero in this field when initializing an instance of the structure, and they preserve the fieldʼs value when modifying the structure.

## _`apfs_snap_meta_ext_oid`_

The virtual object identifier of the extended snapshot metadata object.

## _`oid_t apfs_snap_meta_ext_oid;`_

This field was added to this data structure for macOS 10.15. Older implementations of Apple File System store zero in this field when initializing an instance of the structure, and they preserve the fieldʼs value when modifying the structure.

## _`apfs_volume_group_id`_

The volume group the volume belongs to.

```
uuid_tapfs_volume_group_id;
```

If the volume doesnʼt belong to a volume group, the value of this field is zero and the _`APFS_FEATURE_VOLGRP_ SYSTEM_INO_SPACE`_ flag must not be set. Otherwise, the _`APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE`_ flag must be set and this field must have a nonzero value.

This field was added to this data structure for macOS 10.15. Older implementations of Apple File System store zero in this field when initializing an instance of the structure, and they preserve the fieldʼs value when modifying the structure.

## _`apfs_integrity_meta_oid`_

The virtual object identifier of the integrity metadata object.

## _`oid_t apfs_integrity_meta_oid;`_

If the value of this field is nonzero, the _`APFS_INCOMPAT_SEALED_VOLUME`_ flag must also be set.

This field was added to this data structure for macOS 11. Older implementations of Apple File System store zero in this field when initializing an instance of the structure, and they preserve the fieldʼs value when modifying the structure.

## _`apfs_fext_tree_oid`_

The virtual object identifier of the file extent tree.

## _`oid_t apfs_fext_tree_oid;`_

If the value of this field is nonzero, the _`APFS_INCOMPAT_SEALED_VOLUME`_ flag must also be set.

This field was added to this data structure for macOS 11. Older implementations of Apple File System store zero in this field when initializing an instance of the structure, and they preserve the fieldʼs value when modifying the structure.


59

**Volumes** _`apfs_modified_by_t`_

## _`apfs_fext_tree_type`_

The type of the file extent tree.

```
uint32_tapfs_fext_tree_type;
```

The value is typically _`OBJ_PHYSICAL | OBJECT_TYPE_BTREE`_ , with a subtype of _`OBJECT_TYPE_FEXT_TREE`_ . For possible values, see Object Types.

This field was added to this data structure for macOS 11. Older implementations of Apple File System store zero in this field when initializing an instance of the structure, and they preserve the fieldʼs value when modifying the structure.

## _`reserved_type`_

Reserved.

```
uint32_treserved_type;
```

```
reserved_oid
```

Reserved.

```
oid_treserved_oid;
```

```
APFS_MAGIC
```

The value of the _`apfs_magic`_ field.

```
#defineAPFS_MAGIC'BSPA'
```

This magic number was chosen because in hex dumps it appears as “APSB”, which is an abbreviated form of _APFS superblock_ .

```
APFS_MAX_HIST
```

The number of entries stored in the _`apfs_modified_by`_ field.

```
#defineAPFS_MAX_HIST8
```

```
APFS_VOLNAME_LEN
```

The maximum length of the volume name stored in the _`apfs_volname`_ field.

```
#defineAPFS_VOLNAME_LEN256
```

## _`apfs_modified_by_t`_

Information about a program that modified the volume.

```
structapfs_modified_by{
uint8_tid[APFS_MODIFIED_NAMELEN];
uint64_ttimestamp;
xid_tlast_xid;
};
```


60

**Volumes** Volume Flags

```
typedefstructapfs_modified_byapfs_modified_by_t;
```

```
#defineAPFS_MODIFIED_NAMELEN32
```

This structure is used by the _`apfs_modified_by`_ and _`apfs_formatted_by`_ fields of _`apfs_superblock_t`_ .

## _`id`_

A string that identifies the program and its version.

```
uint8_tid[APFS_MODIFIED_NAMELEN];
```

## _`timestamp`_

The time that the program last modified this volume.

```
uint64_ttimestamp;
```

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds.

## _`last_xid`_

The last transaction identifier thatʼs part of this programʼs modifications.

```
xid_tlast_xid;
```

## Volume Flags

The flags used to indicate volume status.

```
#defineAPFS_FS_UNENCRYPTED0x00000001LL
#defineAPFS_FS_RESERVED_20x00000002LL
#defineAPFS_FS_RESERVED_40x00000004LL
#defineAPFS_FS_ONEKEY0x00000008LL
#defineAPFS_FS_SPILLEDOVER0x00000010LL
#defineAPFS_FS_RUN_SPILLOVER_CLEANER0x00000020LL
#defineAPFS_FS_ALWAYS_CHECK_EXTENTREF0x00000040LL
#defineAPFS_FS_RESERVED_800x00000080LL
#defineAPFS_FS_RESERVED_1000x00000100LL
```

```
#defineAPFS_FS_FLAGS_VALID_MASK(APFS_FS_UNENCRYPTED\
```

```
|APFS_FS_RESERVED_2\
```

```
|APFS_FS_RESERVED_4\
|APFS_FS_ONEKEY\
|APFS_FS_SPILLEDOVER\
|APFS_FS_RUN_SPILLOVER_CLEANER\
```

```
|APFS_FS_ALWAYS_CHECK_EXTENTREF\
```

```
|APFS_FS_RESERVED_80\
|APFS_FS_RESERVED_100)
```

```
#defineAPFS_FS_CRYPTOFLAGS
```

```
(APFS_FS_UNENCRYPTED\
```


61

**Volumes** Volume Flags

```
|APFS_FS_ONEKEY)
```

## _`APFS_FS_UNENCRYPTED`_

The volume isnʼt encrypted.

```
#defineAPFS_FS_UNENCRYPTED0x00000001LL
```

```
APFS_FS_RESERVED_2
```

Reserved.

```
#defineAPFS_FS_RESERVED_20x00000002LL
```

Donʼt set this flag, but preserve it if itʼs already set.

```
APFS_FS_RESERVED_4
```

Reserved.

```
#defineAPFS_FS_RESERVED_40x00000004LL
```

Donʼt set this flag, but preserve it if itʼs already set.

## _`APFS_FS_ONEKEY`_

Files on the volume are all encrypted using the volume encryption key (VEK).

```
#defineAPFS_FS_ONEKEY0x00000008LL
```

This flag is used only on devices running macOS; devices running iOS always use per-file encryption keys. When this flag is set, several encryption-related data structures store different information, as discussed in Accessing Encrypted Objects.

## _`APFS_FS_SPILLEDOVER`_

The volume has run out of allocated space on the solid-state drive.

```
#defineAPFS_FS_SPILLEDOVER0x00000010LL
```

See also _`INODE_ALLOCATION_SPILLEDOVER`_ .

## _`APFS_FS_RUN_SPILLOVER_CLEANER`_

The volume has spilled over and the spillover cleaner must be run.

```
#defineAPFS_FS_RUN_SPILLOVER_CLEANER0x00000020LL
```

## _`APFS_FS_ALWAYS_CHECK_EXTENTREF`_

The volumeʼs extent reference tree is always consulted when deciding whether to overwrite an extent.

```
#defineAPFS_FS_ALWAYS_CHECK_EXTENTREF0x00000040LL
```


62

**Volumes** Volume Roles

## _`APFS_FS_RESERVED_80`_

## Reserved.

```
#defineAPFS_FS_RESERVED_800x00000080LL
```

```
APFS_FS_RESERVED_100
```

## Reserved.

```
#defineAPFS_FS_RESERVED_1000x00000100LL
```

```
APFS_FS_FLAGS_VALID_MASK
```

A bit mask of all volume flags.

```
#defineAPFS_FS_FLAGS_VALID_MASK(APFS_FS_UNENCRYPTED\
|APFS_FS_RESERVED_2\
|APFS_FS_RESERVED_4\
|APFS_FS_ONEKEY\
|APFS_FS_RUN_SPILLOVER_CLEANER\
|APFS_FS_ALWAYS_CHECK_EXTENTREF)
```

```
APFS_FS_CRYPTOFLAGS
```

A bit mask of all encryption-related volume flags.

```
#defineAPFS_FS_CRYPTOFLAGS(APFS_FS_UNENCRYPTED\
|APFS_FS_RESERVED_2\
|APFS_FS_ONEKEY)
```

## Volume Roles

The values used to indicate a volumeʼs roles.

```
#defineAPFS_VOL_ROLE_NONE0x0000
#defineAPFS_VOL_ROLE_SYSTEM0x0001
#defineAPFS_VOL_ROLE_USER0x0002
#defineAPFS_VOL_ROLE_RECOVERY0x0004
#defineAPFS_VOL_ROLE_VM0x0008
#defineAPFS_VOL_ROLE_PREBOOT0x0010
#defineAPFS_VOL_ROLE_INSTALLER0x0020
#defineAPFS_VOL_ROLE_DATA(1<<APFS_VOLUME_ENUM_SHIFT)
#defineAPFS_VOL_ROLE_BASEBAND(2<<APFS_VOLUME_ENUM_SHIFT)
#defineAPFS_VOL_ROLE_UPDATE(3<<APFS_VOLUME_ENUM_SHIFT)
#defineAPFS_VOL_ROLE_XART(4<<APFS_VOLUME_ENUM_SHIFT)
#defineAPFS_VOL_ROLE_HARDWARE(5<<APFS_VOLUME_ENUM_SHIFT)
#defineAPFS_VOL_ROLE_BACKUP(6<<APFS_VOLUME_ENUM_SHIFT)
#defineAPFS_VOL_ROLE_RESERVED_7(7<<APFS_VOLUME_ENUM_SHIFT)
```


63

**Volumes** Volume Roles

```
#defineAPFS_VOL_ROLE_RESERVED_8
#defineAPFS_VOL_ROLE_ENTERPRISE
#defineAPFS_VOL_ROLE_RESERVED_10
#defineAPFS_VOL_ROLE_PRELOGIN
```

```
(8<<APFS_VOLUME_ENUM_SHIFT)
(9<<APFS_VOLUME_ENUM_SHIFT)
(10<<APFS_VOLUME_ENUM_SHIFT)
(11<<APFS_VOLUME_ENUM_SHIFT)
```

```
#defineAPFS_VOLUME_ENUM_SHIFT6
```

These values are used by the _`apfs_role`_ field of _`apfs_superblock_t`_ . A volume has at most one role.

For historical reasons, the underlying values of these constants have two variations. The roles whose constants use only the six least significant bits and the _`APFS_VOL_ROLE_DATA`_ and _`APFS_VOL_ROLE_BASEBAND`_ roles are supported by all versions of macOS and iOS. The remaining roles that are stored using the ten most significant bits are supported only by devices running macOS 10.15, iOS 13, and later.

## _`APFS_VOL_ROLE_NONE`_

The volume has no defined role.

```
#defineAPFS_VOL_ROLE_NONE0x0000
```

A volume whose role doesnʼt have a constant defined doesnʼt have any flags set.

## _`APFS_VOL_ROLE_SYSTEM`_

The volume contains a root directory for the system.

```
#defineAPFS_VOL_ROLE_SYSTEM0x0001
```

The file system for the system volume that contains the running OS is normally mounted at _`/`_ . On devices running iOS and macOS 10.15 or later, the system volume is mounted read-only.

See also _`APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE`_ , which is used to mount the system and user data as a single user-visible volume.

## _`APFS_VOL_ROLE_USER`_

The volume contains usersʼ home directories.

```
#defineAPFS_VOL_ROLE_USER0x0002
```

## _`APFS_VOL_ROLE_RECOVERY`_

The volume contains a recovery system.

```
#defineAPFS_VOL_ROLE_RECOVERY0x0004
```

This is used the same way as a recovery partition on HFS-Plus.

## _`APFS_VOL_ROLE_VM`_

The volume is used as swap space for virtual memory.

```
#defineAPFS_VOL_ROLE_VM0x0008
```

The file system for a virtual-memory volume is mounted at _`/var/vm`_ .


64

**Volumes** Volume Roles

## _`APFS_VOL_ROLE_PREBOOT`_

The volume contains files needed to boot from an encrypted volume.

```
#defineAPFS_VOL_ROLE_PREBOOT0x0010
```

## _`APFS_VOL_ROLE_INSTALLER`_

The volume is used by the OS installer.

```
#defineAPFS_VOL_ROLE_INSTALLER0x0020
```

For example, the installer writes log files to this volume during the installation process.

## _`APFS_VOL_ROLE_DATA`_

The volume contains mutable data.

```
#defineAPFS_VOL_ROLE_DATA(1<<APFS_VOLUME_ENUM_SHIFT)
```

This role is used only on devices running iOS and macOS 10.15 or later. It contains both user data and mutable system data. Immutable system data is stored on the volume with the _`APFS_VOL_ROLE_SYSTEM`_ flag.

See also _`APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE`_ , which is used to mount the system and user data as a single user-visible volume.

## _`APFS_VOL_ROLE_BASEBAND`_

The volume is used by the radio firmware.

```
#defineAPFS_VOL_ROLE_BASEBAND(2<<APFS_VOLUME_ENUM_SHIFT)
```

This role is used only on devices running iOS.

## _`APFS_VOL_ROLE_UPDATE`_

The volume is used by the software update mechanism.

```
#defineAPFS_VOL_ROLE_UPDATE(3<<APFS_VOLUME_ENUM_SHIFT)
```

This role is used only on devices running iOS.

## _`APFS_VOL_ROLE_XART`_

The volume is used to manage OS access to secure user data.

```
#defineAPFS_VOL_ROLE_XART(4<<APFS_VOLUME_ENUM_SHIFT)
```

This role is used only on devices running iOS.

## _`APFS_VOL_ROLE_HARDWARE`_

The volume is used for firmware data.

```
#defineAPFS_VOL_ROLE_HARDWARE(5<<APFS_VOLUME_ENUM_SHIFT)
```


65

**Volumes** Volume Roles

This role is used only on devices running iOS.

## _`APFS_VOL_ROLE_BACKUP`_

The volume is used by Time Machine to store backups.

```
#defineAPFS_VOL_ROLE_BACKUP(6<<APFS_VOLUME_ENUM_SHIFT)
```

This role is used only on devices running macOS.

```
APFS_VOL_ROLE_RESERVED_7
```

## Reserved.

```
#defineAPFS_VOL_ROLE_SIDECAR(7<<APFS_VOLUME_ENUM_SHIFT)
```

```
APFS_VOL_ROLE_RESERVED_8
```

## Reserved.

```
#defineAPFS_VOL_ROLE_RESERVED_8(8<<APFS_VOLUME_ENUM_SHIFT)
```

## _`APFS_VOL_ROLE_ENTERPRISE`_

This volume is used to store enterprise-managed data.

```
#defineAPFS_VOL_ROLE_ENTERPRISE(9<<APFS_VOLUME_ENUM_SHIFT)
```

For more information, see Managing Devices & Corporate Data on iOS.

```
APFS_VOL_ROLE_RESERVED_10
```

## Reserved.

```
#defineAPFS_VOL_ROLE_RESERVED_10(10<<APFS_VOLUME_ENUM_SHIFT)
```

## _`APFS_VOL_ROLE_PRELOGIN`_

This volume is used to store system data used before login.

```
#defineAPFS_VOL_ROLE_PRELOGIN(11<<APFS_VOLUME_ENUM_SHIFT)
```

This role is used only on devices running macOS. The prelogin volume lets the system boot to the login screen, at which point the user can log in and the userʼs password can be used to mount encrypted volumes.

## _`APFS_VOLUME_ENUM_SHIFT`_

The bit shift used to separate the old and new enumeration cases.

```
#defineAPFS_VOLUME_ENUM_SHIFT6
```


66

**Volumes** Optional Volume Feature Flags

## Optional Volume Feature Flags

The flags used to describe optional features of an Apple File System volume.

```
#defineAPFS_FEATURE_DEFRAG_PRERELEASE0x00000001LL
#defineAPFS_FEATURE_HARDLINK_MAP_RECORDS0x00000002LL
#defineAPFS_FEATURE_DEFRAG0x00000004LL
#defineAPFS_FEATURE_STRICTATIME0x00000008LL
#defineAPFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE0x00000010LL
```

```
#defineAPFS_SUPPORTED_FEATURES_MASK(APFS_FEATURE_DEFRAG\
|APFS_FEATURE_DEFRAG_PRERELEASE\
|APFS_FEATURE_HARDLINK_MAP_RECORDS\
|APFS_FEATURE_STRICTATIME\
|APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE)
```

These flags are used by the _`apfs_features`_ field of _`apfs_superblock_t`_ .

```
APFS_FEATURE_DEFRAG_PRERELEASE
```

## Reserved.

```
#defineAPFS_FEATURE_DEFRAG_PRERELEASE0x00000001LL
```

## **Warning**

To avoid data corruption, this flag must not be set.

This flag enabled a prerelease version of the defragmentation system in macOS 10.13 versions. Itʼs ignored by macOS 10.13.6 and later.

```
APFS_FEATURE_HARDLINK_MAP_RECORDS
```

The volume has hardlink map records.

```
#defineAPFS_FEATURE_HARDLINK_MAP_RECORDS0x00000002LL
```

For details about hardlink map records, see Siblings.

## _`APFS_FEATURE_DEFRAG`_

The volume supports defragmentation.

```
#defineAPFS_FEATURE_DEFRAG0x00000004LL
```

This flag is ignored by versions before macOS 10.14.

## _`APFS_FEATURE_STRICTATIME`_

This volume updates file access times every time the file is read.

```
#defineAPFS_FEATURE_STRICTATIME0x00000008LL
```


67

**Volumes** Read-Only Compatible Volume Feature Flags

If this flag is set, the _`access_time`_ field of _`j_inode_val_t`_ is updated every time the file is read. Otherwise, that field is updated when the file is read, but only if its value is prior to the timestamp stored in the _`mod_time`_ field.

## _`APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE`_

This volume supports mounting a system and data volume as a single user-visible volume.

```
#defineAPFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE0x00000010LL
```

This feature is used by macOS 10.15 and later to combine a read-only system volume with its corresponding read-write user data volume. Both volumes have the same value for the _`apfs_volume_group_id`_ field of _`apfs_ superblock_t`_ , which indicates they form a volume group.

If this flag is set, inode numbers on those volumes are assigned as follows: The volume whose role is _`APFS_VOL_ ROLE_DATA`_ uses inode numbers less than _`UNIFIED_ID_SPACE_MARK`_ , and the volume whose role is _`APFS_VOL_ ROLE_SYSTEM`_ uses inode numbers _`UNIFIED_ID_SPACE_MARK`_ and larger. The first 16 inode numbers for both the system and data volume are reserved, as described in Inode Numbers.

## _`APFS_SUPPORTED_FEATURES_MASK`_

A bit mask of all the optional volume features.

```
#defineAPFS_SUPPORTED_FEATURES_MASK(APFS_FEATURE_DEFRAG\
```

```
|APFS_FEATURE_DEFRAG_PRERELEASE\
|APFS_FEATURE_HARDLINK_MAP_RECORDS\
|APFS_FEATURE_STRICTATIME\
|APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE)
```

## Read-Only Compatible Volume Feature Flags

The flags used to describe read-only compatible features of an Apple File System volume.

```
#defineAPFS_SUPPORTED_ROCOMPAT_MASK(0x0ULL)
```

These flags are used by the _`apfs_readonly_compatible_features`_ field of _`apfs_superblock_t`_ . There are currently none defined.

```
APFS_SUPPORTED_ROCOMPAT_MASK
```

A bit mask of all read-only compatible volume features.

```
#defineAPFS_SUPPORTED_ROCOMPAT_MASK(0x0ULL)
```

## Incompatible Volume Feature Flags

The flags used to describe backward-incompatible features of an Apple File System volume.

```
#defineAPFS_INCOMPAT_CASE_INSENSITIVE0x00000001LL
#defineAPFS_INCOMPAT_DATALESS_SNAPS0x00000002LL
#defineAPFS_INCOMPAT_ENC_ROLLED0x00000004LL
#defineAPFS_INCOMPAT_NORMALIZATION_INSENSITIVE0x00000008LL
#defineAPFS_INCOMPAT_INCOMPLETE_RESTORE0x00000010LL
#defineAPFS_INCOMPAT_SEALED_VOLUME0x00000020LL
```


68

**Volumes** Incompatible Volume Feature Flags

```
#defineAPFS_INCOMPAT_RESERVED_40
```

## _`0x00000040LL`_

```
#defineAPFS_SUPPORTED_INCOMPAT_MASK(APFS_INCOMPAT_CASE_INSENSITIVE\
|APFS_INCOMPAT_DATALESS_SNAPS\
|APFS_INCOMPAT_ENC_ROLLED\
|APFS_INCOMPAT_NORMALIZATION_INSENSITIVE\
|APFS_INCOMPAT_INCOMPLETE_RESTORE\
|APFS_INCOMPAT_SEALED_VOLUME\
|APFS_INCOMPAT_RESERVED_40)
```

These flags are used by the _`apfs_incompatible_features`_ field of _`apfs_superblock_t`_ .

```
APFS_INCOMPAT_CASE_INSENSITIVE
```

Filenames on this volume are case insensitive.

```
#defineAPFS_INCOMPAT_CASE_INSENSITIVE0x00000001LL
```

```
APFS_INCOMPAT_DATALESS_SNAPS
```

At least one snapshot with no data exists for this volume.

```
#defineAPFS_INCOMPAT_DATALESS_SNAPS0x00000002LL
```

```
APFS_INCOMPAT_ENC_ROLLED
```

This volumeʼs encryption has changed keys at least once.

```
#defineAPFS_INCOMPAT_ENC_ROLLED0x00000004LL
```

```
APFS_INCOMPAT_NORMALIZATION_INSENSITIVE
```

Filenames on this volume are normalization insensitive.

```
#defineAPFS_INCOMPAT_NORMALIZATION_INSENSITIVE0x00000008LL
```

Normalization insensitivity is part of hashing filenames, as described in the _`name_len_and_hash`_ field of _`j_drec_ hashed_key_t`_ .

```
APFS_INCOMPAT_INCOMPLETE_RESTORE
```

This volume is being restored, or a restore operation to this volume was uncleanly aborted.

```
#defineAPFS_INCOMPAT_INCOMPLETE_RESTORE0x00000010LL
```

```
APFS_INCOMPAT_SEALED_VOLUME
```

This volume canʼt be modified.

```
#defineAPFS_INCOMPAT_SEALED_VOLUME0x00000020LL
```

For more information, see Sealed Volumes.


69

**Volumes** Incompatible Volume Feature Flags

```
APFS_INCOMPAT_RESERVED_40
```

Reserved.

```
#defineAPFS_INCOMPAT_RESERVED_400x00000040LL
```

```
APFS_SUPPORTED_INCOMPAT_MASK
```

A bit mask of all the backward-incompatible volume features.

```
#defineAPFS_SUPPORTED_INCOMPAT_MASK(APFS_INCOMPAT_CASE_INSENSITIVE\
```

```
|APFS_INCOMPAT_DATALESS_SNAPS\
```

```
|APFS_INCOMPAT_ENC_ROLLED\
```

```
|APFS_INCOMPAT_NORMALIZATION_INSENSITIVE\
```

```
|APFS_INCOMPAT_INCOMPLETE_RESTORE)
```


70
