<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Container

The container includes several top-level objects that are shared by all of the containerʼs volumes:

- _Checkpoint description and data areas_ store ephemeral objects in a way that provides crash protection. At the end of each transaction, new state is saved by writing a checkpoint.

- _The space manager_ keeps track of available space within the container and is used to allocate and free blocks that store objects and file data.

- _The reaper_ manages the deletion of objects that are too large to be deleted in the time between transactions. It keeps track of the deletion state so these objects can be deleted across multiple transactions.

The container superblock describes the location of all of these objects.

Because a single container can have multiple volumes, configurations that would require multiple partitions under other file systems can usually share a single partition with Apple File System. For example, a drive can be configured with two bootable volumes — one with a shipping version of macOS and one with a beta version — as well as a user data volume. All three of these volumes share free space, meaning you donʼt have to decide ahead of time how to divide space between them.

## Mounting an Apple File System Partition

To mount the volumes of a partition thatʼs formatted using the Apple File System, do the following:

1. Read block zero of the partition. This block contains a copy of the container superblock (an instance of _`nx_superblock_t`_ ). It might be a copy of the latest version or an old version, depending on whether the drive was unmounted cleanly.

2. Use the block-zero copy of the container superblock to locate the checkpoint descriptor area by reading the _`nx_xp_desc_base`_ field.

3. Read the entries in the checkpoint descriptor area, which are instances of _`checkpoint_map_phys_t`_ or _`nx_superblock_t`_ .

4. Find the container superblock that has the largest transaction identifier and isnʼt malformed. For example, confirm that its magic number and checksum are valid. That superblock and its checkpoint-mapping blocks comprise the _latest valid checkpoint_ . The superblockʼs fields, like _`nx_xp_desc_blocks`_ and _`nx_data_len`_ , indicate which checkpoint-mapping blocks belong to that superblock.

## **Note**

The checkpoint description area is a ring buffer stored as an array. Walking backward from the latest valid superblock to read all of its checkpoint-mapping blocks sometimes requires wrapping around from the first block to the last block.

5. Read the ephemeral objects listed in the checkpoint from the checkpoint data area into memory. If any of the ephemeral objects is malformed, the checkpoint that contains that object is malformed; go back to the previous step and mount from an older checkpoint.


26

**Container** _`nx_superblock_t`_

The details of this step vary. For example, if youʼre mounting the partition read-only and performance isnʼt a consideration, you can skip this step and read from the checkpoint every time you need to access an ephemeral object.

6. Locate the container object map using the _`nx_omap_oid`_ field of the container superblock.

7. Read the list of volumes from the _`nx_fs_oid`_ field of the container superblock. If youʼre mounting only a particular volume, you can ignore the virtual object identifiers for the other volumes.

8. For each volume, look up the specified virtual object identifier in the container object map to locate the volume superblock (an instance of _`apfs_superblock_t`_ ). If youʼre mounting only a particular volume, you can skip this step for the other volumes.

9. For each volume, read the root file system treeʼs virtual object identifier from the _`apfs_root_tree_oid`_ field, and then look it up in the volume object map indicated by the _`apfs_omap_oid`_ field. If youʼre mounting only a particular volume, you can skip this step for the other volumes.

10. Walk the root file system tree as needed by your implementation to mount the file system.

## _`nx_superblock_t`_

A container superblock.

```
structnx_superblock{
obj_phys_tnx_o;
uint32_tnx_magic;
uint32_tnx_block_size;
uint64_tnx_block_count;
uint64_tnx_features;
uint64_tnx_readonly_compatible_features;
uint64_tnx_incompatible_features;
uuid_tnx_uuid;
oid_tnx_next_oid;
xid_tnx_next_xid;
uint32_tnx_xp_desc_blocks;
uint32_tnx_xp_data_blocks;
paddr_tnx_xp_desc_base;
paddr_tnx_xp_data_base;
uint32_tnx_xp_desc_next;
uint32_tnx_xp_data_next;
uint32_tnx_xp_desc_index;
uint32_tnx_xp_desc_len;
uint32_tnx_xp_data_index;
uint32_tnx_xp_data_len;
oid_tnx_spaceman_oid;
oid_tnx_omap_oid;
```


27

**Container** _`nx_superblock_t`_

```
oid_tnx_reaper_oid;
uint32_tnx_test_type;
uint32_tnx_max_file_systems;
oid_tnx_fs_oid[NX_MAX_FILE_SYSTEMS];
uint64_tnx_counters[NX_NUM_COUNTERS];
prange_tnx_blocked_out_prange;
oid_tnx_evict_mapping_tree_oid;
uint64_tnx_flags;
paddr_tnx_efi_jumpstart;
uuid_tnx_fusion_uuid;
prange_tnx_keylocker;
uint64_tnx_ephemeral_info[NX_EPH_INFO_COUNT];
oid_tnx_test_oid;
oid_tnx_fusion_mt_oid;
oid_tnx_fusion_wbc_oid;
prange_tnx_fusion_wbc;
uint64_tnx_newest_mounted_version;
prange_tnx_mkb_locker;
```

```
};
```

```
typedefstructnx_superblocknx_superblock_t;
```

```
#defineNX_MAGIC'BSXN'
#defineNX_MAX_FILE_SYSTEMS100
#defineNX_EPH_INFO_COUNT4
#defineNX_EPH_MIN_BLOCK_COUNT8
#defineNX_MAX_FILE_SYSTEM_EPH_STRUCTS4
#defineNX_TX_MIN_CHECKPOINT_COUNT4
#defineNX_EPH_INFO_VERSION_11
```

Note that all fields are 64-bit aligned.

```
nx_o
```

The objectʼs header.

```
obj_phys_tnx_o;
```

```
nx_magic
```

A number that can be used to verify that youʼre reading an instance of _`nx_superblock_t`_ .

```
uint32_tnx_magic;
```


28

**Container** _`nx_superblock_t`_

The value of this field is always _`NX_MAGIC`_ .

## _`nx_block_size`_

The logical block size used in the Apple File System container.

```
uint32_tnx_block_size;
```

This size is often the same as the block size used by the underlying storage device, but it can also be an integer multiple of the deviceʼs block size.

## _`nx_block_count`_

The total number of logical blocks available in the container.

```
uint64_tnx_block_count;
```

## _`nx_features`_

A bit field of the optional features being used by this container.

```
uint64_tnx_features;
```

For the values used in this bit field, see Optional Container Feature Flags.

If your implementation doesnʼt implement an optional feature thatʼs in use, ignore that feature in this list and mount the containerʼs volumes as usual.

## _`nx_readonly_compatible_features`_

A bit field of the read-only compatible features being used by this container.

```
uint64_tnx_readonly_compatible_features;
```

For the values used in this bit field, see Read-Only Compatible Container Feature Flags.

If your implementation doesnʼt implement a read-only compatible feature thatʼs in use, mount the containerʼs volumes as read-only.

## _`nx_incompatible_features`_

A bit field of the backward-incompatible features being used by this container.

```
uint64_tnx_incompatible_features;
```

For the values used in this bit field, see Incompatible Container Feature Flags.

If your implementation doesnʼt implement a read-only feature thatʼs in use, it must not mount the containerʼs volumes.

## _`nx_uuid`_

The universally unique identifier of this container.

```
uuid_tnx_uuid;
```


29

**Container** _`nx_superblock_t`_

## _`nx_next_oid`_

The next object identifier to be used for a new ephemeral or virtual object.

```
oid_tnx_next_oid;
```

## _`nx_next_xid`_

The next transaction to be used.

```
xid_tnx_next_xid;
```

## _`nx_xp_desc_blocks`_

The number of blocks used by the checkpoint descriptor area.

```
uint32_tnx_xp_desc_blocks;
```

The highest bit of this number is used as a flag, as discussed in _`nx_xp_desc_base`_ . Ignore that bit when accessing this field as a count.

## _`nx_xp_data_blocks`_

The number of blocks used by the checkpoint data area.

```
uint32_tnx_xp_data_blocks;
```

The highest bit of this number is used as a flag, as discussed in _`nx_xp_data_base`_ . Ignore that bit when accessing this field as a count.

## _`nx_xp_desc_base`_

Either the base address of the checkpoint descriptor area or the physical object identifier of a tree that contains the address information.

## _`paddr_t nx_xp_desc_base;`_

If the highest bit of _`nx_xp_desc_blocks`_ is zero, the checkpoint descriptor area is contiguous and this field contains the address of the first block. Otherwise, the checkpoint descriptor area isnʼt contiguous and this field contains the physical object identifier of a B-tree. The treeʼs keys are block offsets into the checkpoint descriptor area, and its values are instances of _`prange_t`_ that contain the fragmentʼs size and location.

## _`nx_xp_data_base`_

Either the base address of the checkpoint data area or the physical object identifier of a tree that contains the address information.

## _`paddr_t nx_xp_data_base;`_

If the highest bit of _`nx_xp_data_blocks`_ is zero, the checkpoint data area is contiguous and this field contains the address of the first block. Otherwise, the checkpoint data area isnʼt contiguous and this field contains the object identifier of a B-tree. The treeʼs keys are block offsets into the checkpoint data area, and its values are instances of _`prange_t`_ that contain the fragmentʼs size and location.


30

**Container** _`nx_superblock_t`_

## _`nx_xp_desc_next`_

The next index to use in the checkpoint descriptor area.

## _`uint32_t nx_xp_desc_next;`_

If the superblock is part of a checkpoint, this field must have a value. Otherwise, ignore the value of this field when reading, and use zero as the value when creating a new instance. For example, this field has no meaning for the copy of the superblock thatʼs stored in block zero.

## _`nx_xp_data_next`_

The next index to use in the checkpoint data area.

## _`uint32_t nx_xp_data_next;`_

If the superblock is part of a checkpoint, this field must have a value. Otherwise, ignore the value of this field when reading, and use zero as the value when creating a new instance. For example, this field has no meaning for the copy of the superblock thatʼs stored in block zero.

## _`nx_xp_desc_index`_

The index of the first valid item in the checkpoint descriptor area.

## _`uint32_t nx_xp_desc_index;`_

If the superblock is part of a checkpoint, this field must have a value. Otherwise, ignore the value of this field when reading, and use zero as the value when creating a new instance. For example, this field has no meaning for the copy of the superblock thatʼs stored in block zero.

## _`nx_xp_desc_len`_

The number of blocks in the checkpoint descriptor area used by the checkpoint that this superblock belongs to.

## _`uint32_t nx_xp_desc_len;`_

If the superblock is part of a checkpoint, this field must have a value. Otherwise, ignore the value of this field when reading, and use zero as the value when creating a new instance. For example, this field has no meaning for the copy of the superblock thatʼs stored in block zero.

## _`nx_xp_data_index`_

The index of the first valid item in the checkpoint data area.

## _`uint32_t nx_xp_data_index;`_

If the superblock is part of a checkpoint, this field must have a value. Otherwise, ignore the value of this field when reading, and use zero as the value when creating a new instance. For example, this field has no meaning for the copy of the superblock thatʼs stored in block zero.

## _`nx_xp_data_len`_

The number of blocks in the checkpoint data area used by the checkpoint that this superblock belongs to.

```
uint32_tnx_xp_data_len;
```


31

**Container** _`nx_superblock_t`_

If the superblock is part of a checkpoint, this field must have a value. Otherwise, ignore the value of this field when reading, and use zero as the value when creating a new instance. For example, this field has no meaning for the copy of the superblock thatʼs stored in block zero.

## _`nx_spaceman_oid`_

The ephemeral object identifier for the space manager.

```
oid_tnx_spaceman_oid;
```

## _`nx_omap_oid`_

The physical object identifier for the containerʼs object map.

```
oid_tnx_omap_oid;
```

## _`nx_reaper_oid`_

The ephemeral object identifier for the reaper.

```
oid_tnx_reaper_oid;
```

## _`nx_test_type`_

Reserved for testing.

```
uint32_tnx_test_type;
```

This field never has a value other than zero on disk. If you find another value in production, file a bug against the Apple File System implementation.

This field isnʼt reserved by Apple; non-Apple implementations of Apple File System can use it to store an object type during testing.

## _`nx_max_file_systems`_

The maximum number of volumes that can be stored in this container.

```
uint32_tnx_max_file_systems;
```

To calculate this value, divide the size of the container by 512 MiB and round up. For example, a container with 1.3 GiB of space can contain three volumes. This value must not be larger than the value of _`NX_MAX_FILE_SYSTEMS`_ .

## _`nx_fs_oid`_

An array of virtual object identifiers for volumes.

```
oid_tnx_fs_oid[NX_MAX_FILE_SYSTEMS];
```

The objectsʼ types are all _`OBJECT_TYPE_BTREE`_ and their subtypes are all _`OBJECT_TYPE_FSTREE`_ .


32

**Container** _`nx_superblock_t`_

## _`nx_counters`_

An array of counters that store information about the container.

## _`uint64_t nx_counters[NX_NUM_COUNTERS];`_

These counters are primarily intended to help during development and debugging of Apple File System implementations. For the meaning of these counters, see _`nx_counter_id_t`_ .

## _`nx_blocked_out_prange`_

The physical range of blocks where space will not be allocated.

```
prange_tnx_blocked_out_prange;
```

This field is used with _`nx_evict_mapping_tree_oid`_ while shrinking a partition. If nothing is currently blocked out, the value of _`nx_blocked_out_prange.pr_block_count`_ is zero and the value of _`nx_blocked_out_prange. pr_start_paddr`_ is ignored.

## _`nx_evict_mapping_tree_oid`_

The physical object identifier of a tree used to keep track of objects that must be moved out of blocked-out storage.

## _`oid_t nx_evict_mapping_tree_oid;`_

The keys in this tree are physical addresses of blocks that must be moved, and the values are instances of _`evict_mapping_val_t`_ that describe where the blocks are being moved to.

This identifier is valid only while shrinking a partition. First, the blocks to be removed from the partition are added to the _`nx_blocked_out_prange`_ field. Next, every object thatʼs stored in a blocked-out range is added to this tree. Finally, every object in this tree has space allocated and is moved into the new space. Because the space manager honors the blocked-out range, data is never moved from one blocked-out address to another address thatʼs also blocked out. After all data has been removed from the blocked-out range and this tree is empty, the partition shrinks and the block count of _`nx_blocked_out_prange`_ is set to zero, which clears the field.

## _`nx_flags`_

Other container flags.

```
uint64_tnx_flags;
```

For the values used in this bit field, see Container Flags.

## _`nx_efi_jumpstart`_

The physical object identifier of the object that contains EFI driver data extents.

## _`paddr_t nx_efi_jumpstart;`_

The object is an instance of _`nx_efi_jumpstart_t`_ .


33

**Container** _`nx_superblock_t`_

## _`nx_fusion_uuid`_

The universally unique identifier of the containerʼs Fusion set, or zero for non-Fusion containers.

## _`uuid_t nx_fusion_uuid;`_

The hard drive and the solid-state drive each have a partition, which combine to make a single container. Each partition has its own copy of the container superblock at block zero, and each copy has the same value for the low 127 bits of this field. The highest bit is one for the Fusion setʼs main device and zero for the second-tier device.

## _`nx_keylocker`_

The location of the containerʼs keybag.

## _`prange_t nx_keylocker;`_

The data at this location is an instance of _`kb_locker_t`_ .

## _`nx_ephemeral_info`_

An array of fields used in the management of ephemeral data.

```
uint64_tnx_ephemeral_info[NX_EPH_INFO_COUNT];
```

The first array entry records information about how the checkpoint data areaʼs size was chosen as follows:

```
nx_ephemeral_info[0]=(min_block_count<<32)
```

- _`| ((NX_MAX_FILE_SYSTEM_EPH_STRUCTS & 0xFFFF) << 16)`_

- _`| NX_EPH_INFO_VERSION_1;`_

The value of _`min_block_count`_ depends on the size of the container. If the container is larger than 128 MiB, it takes the value of _`NX_EPH_MIN_BLOCK_COUNT`_ . Otherwise, it takes the value of _`spaceman_phys_t.sm_fq[SFQ_MAIN] .sfq_tree_node_limit`_ from the space manager.

## _`nx_test_oid`_

Reserved for testing.

## _`oid_t nx_test_oid;`_

This field never has a value other than zero on disk. If you find another value in production, file a bug against the Apple File System implementation.

This field isnʼt reserved by Apple; non-Apple implementations of Apple File System can use it to store an object identifier during testing.

## _`nx_fusion_mt_oid`_

The physical object identifier of the Fusion middle tree (a B-tree mapping _`fusion_mt_key_t`_ to _`fusion_mt_val_t`_ ), or zero if for non-Fusion drives.

```
oid_tnx_fusion_mt_oid;
```


34

**Container** _`nx_superblock_t`_

## _`nx_fusion_wbc_oid`_

The ephemeral object identifier of the Fusion write-back cache state ( _`fusion_wbc_phys_t`_ ), or zero for non-Fusion drives.

```
oid_tnx_fusion_wbc_oid;
```

## _`nx_fusion_wbc`_

The blocks used for the Fusion write-back cache area, or zero for non-Fusion drives.

```
prange_tnx_fusion_wbc;
```

## _`nx_newest_mounted_version`_

## Reserved.

```
uint64_tnx_newest_mounted_version;
```

Appleʼs implementation uses this field to record the newest version of the software that ever mounted the container. Other implementations of the Apple file System must not modify this field.

This integer is understood as a fixed-point decimal number of the form _`aaaaaaa.bbb.ccc.ddd.eee`_ where _`a`_ is a major version number and _`b`_ , _`c`_ , _`d`_ , and _`e`_ are minor versions.

## _`nx_mkb_locker`_

Wrapped media key.

```
prange_tnx_mkb_locker;
```

## _`NX_MAGIC`_

The value of the _`nx_magic`_ field.

```
#defineNX_MAGIC'BSXN'
```

This magic number was chosen because in hex dumps it appears as “NXSB”, which is an abbreviated form of _NX superblock_ .

## _`NX_MAX_FILE_SYSTEMS`_

The maximum number of volumes that can be in a single container.

```
#defineNX_MAX_FILE_SYSTEMS100
```

## _`NX_EPH_INFO_COUNT`_

The length of the array in the _`nx_ephemeral_info`_ field.

```
#defineNX_EPH_INFO_COUNT4
```


35

**Container** Container Flags

## _`NX_EPH_MIN_BLOCK_COUNT`_

The default minimum size, in blocks, for structures that contain ephemeral data.

```
#defineNX_EPH_MIN_BLOCK_COUNT8
```

This value is used when choosing the size for a new containerʼs checkpoint data area, and the value used is recorded in the _`nx_ephemeral_info`_ field.

## _`NX_MAX_FILE_SYSTEM_EPH_STRUCTS`_

The number of structures that contain ephemeral data that a volume can have.

```
#defineNX_MAX_FILE_SYSTEM_EPH_STRUCTS4
```

This value is used when choosing the size for a new containerʼs checkpoint data area, and the value used is recorded in the _`nx_ephemeral_info`_ field.

## _`NX_TX_MIN_CHECKPOINT_COUNT`_

The minimum number of checkpoints that can fit in the checkpoint data area.

```
#defineNX_TX_MIN_CHECKPOINT_COUNT4
```

This value is used when choosing the size for a new containerʼs checkpoint data area.

## _`NX_EPH_INFO_VERSION_1`_

The version number for structures that contain ephemeral data.

```
#defineNX_EPH_INFO_VERSION_11
```

This value is recorded in the _`nx_ephemeral_info`_ field.

## Container Flags

The flags used for general information about a container.

```
#defineNX_RESERVED_10x00000001LL
#defineNX_RESERVED_20x00000002LL
#defineNX_CRYPTO_SW0x00000004LL
```

These flags are used by the _`nx_flags`_ field of _`nx_superblock_t`_ .

## _`NX_RESERVED_1`_

Reserved.

```
#defineNX_RESERVED_10x00000001LL
```

Donʼt set this flag, but preserve it if itʼs already set.


36

**Container** Optional Container Feature Flags

## _`NX_RESERVED_2`_

## Reserved.

## _`#define NX_RESERVED_2 0x00000002LL`_

Donʼt add this flag to a container. If this flag is set, preserve it when reading the container, and remove it when modifying the container.

## _`NX_CRYPTO_SW`_

The container uses software cryptography.

## _`#define NX_CRYPTO_SW 0x00000004LL`_

If this flag is set, the _`crypto_id`_ field on all instances of _`j_file_extent_val_t`_ has a value of _`CRYPTO_SW_ID`_ .

Note that a container that has no volumes never has this flag set, regardless of whether the container will use software cryptography for new volumes. If you are creating a new volume in this scenario, determine whether to use software or hardware cryptography by consulting the I/O Registry as discussed in IOKit Fundamentals.

## Optional Container Feature Flags

The flags used to describe optional features of an Apple File System container.

```
#defineNX_FEATURE_DEFRAG0x0000000000000001ULL
#defineNX_FEATURE_LCFD0x0000000000000002ULL
#defineNX_SUPPORTED_FEATURES_MASK(NX_FEATURE_DEFRAG|NX_FEATURE_LCFD)
```

These flags are used by the _`nx_features`_ field of _`nx_superblock_t`_ .

## _`NX_FEATURE_DEFRAG`_

The volumes in this container support defragmentation.

```
#defineNX_FEATURE_DEFRAG0x0000000000000001ULL
```

## _`NX_FEATURE_LCFD`_

This container is using low-capacity Fusion Drive mode.

```
#defineNX_FEATURE_LCFD0x0000000000000002ULL
```

Low-capacity Fusion Drive mode is enabled when the solid-state drive has a smaller capacity and so the cache must be smaller.

## _`NX_SUPPORTED_FEATURES_MASK`_

A bit mask of all the optional features.

```
#defineNX_SUPPORTED_FEATURES_MASK(NX_FEATURE_DEFRAG|NX_FEATURE_LCFD)
```


37

**Container** Read-Only Compatible Container Feature Flags

## Read-Only Compatible Container Feature Flags

The flags used to describe read-only compatible features of an Apple File System container.

```
#defineNX_SUPPORTED_ROCOMPAT_MASK(0x0ULL)
```

These flags are used by the _`nx_readonly_compatible_features`_ field of _`nx_superblock_t`_ . There are currently none defined.

## _`NX_SUPPORTED_ROCOMPAT_MASK`_

A bit mask of all read-only compatible features.

```
#defineNX_SUPPORTED_ROCOMPAT_MASK(0x0ULL)
```

## Incompatible Container Feature Flags

The flags used to describe backward-incompatible features of an Apple File System container.

```
#defineNX_INCOMPAT_VERSION10x0000000000000001ULL
#defineNX_INCOMPAT_VERSION20x0000000000000002ULL
#defineNX_INCOMPAT_FUSION0x0000000000000100ULL
#defineNX_SUPPORTED_INCOMPAT_MASK(NX_INCOMPAT_VERSION2|NX_INCOMPAT_FUSION)
```

These flags are used by the _`nx_incompatible_features`_ field of _`nx_superblock_t`_ .

## _`NX_INCOMPAT_VERSION1`_

The container uses version 1 of Apple File System, as implemented in macOS 10.12.

```
#defineNX_INCOMPAT_VERSION10x0000000000000001ULL
```

## **Important**

Version 1 of the Apple File System was a prerelease thatʼs incompatible with later versions. This document describes only version 2 and later.

## _`NX_INCOMPAT_VERSION2`_

The container uses version 2 of Apple File System, as implemented in macOS 10.13 and iOS 10.3.

```
#defineNX_INCOMPAT_VERSION20x0000000000000002ULL
```

## _`NX_INCOMPAT_FUSION`_

The container supports Fusion Drives.

```
#defineNX_INCOMPAT_FUSION0x0000000000000100ULL
```


38

**Container** Block and Container Sizes

## _`NX_SUPPORTED_INCOMPAT_MASK`_

A bit mask of all the backward-incompatible features.

```
#defineNX_SUPPORTED_INCOMPAT_MASK(NX_INCOMPAT_VERSION2|NX_INCOMPAT_FUSION)
```

## Block and Container Sizes

Constants used when choosing the size of a block or container.

The block size for a container is defined by the _`nx_block_size`_ field of _`nx_superblock_t`_ .

```
#defineNX_MINIMUM_BLOCK_SIZE4096
#defineNX_DEFAULT_BLOCK_SIZE4096
#defineNX_MAXIMUM_BLOCK_SIZE65536
```

```
#defineNX_MINIMUM_CONTAINER_SIZE1048576
```

## _`NX_MINIMUM_BLOCK_SIZE`_

The smallest supported size, in bytes, for a block.

```
#defineNX_MINIMUM_BLOCK_SIZE4096
```

If you try to define a block size thatʼs too small, some data structures wonʼt be able to fit in a single block.

## _`NX_DEFAULT_BLOCK_SIZE`_

The default size, in bytes, for a block.

```
#defineNX_DEFAULT_BLOCK_SIZE4096
```

```
NX_MAXIMUM_BLOCK_SIZE
```

The largest supported size, in bytes, for a block.

```
#defineNX_MAXIMUM_BLOCK_SIZE65536
```

If you try to define a block size thatʼs too large, parts of the block will be outside of the range of a 16-bit address.

```
NX_MINIMUM_CONTAINER_SIZE
```

The smallest supported size, in bytes, for a container.

```
#defineNX_MINIMUM_CONTAINER_SIZE1048576
```

This value is slightly less that the capacity of a floppy disk. For a container this size, statically allocated metadata takes up about a third of the available space.

## _`nx_counter_id_t`_

Indexes into a container superblockʼs array of counters.


39

**Container** _`checkpoint_mapping_t`_

```
typedefenum{
NX_CNTR_OBJ_CKSUM_SET=0,
NX_CNTR_OBJ_CKSUM_FAIL=1,
```

```
NX_NUM_COUNTERS=32
}nx_counter_id_t;
```

These values are used as indexes into the array stored in the _`nx_counters`_ field of _`nx_superblock_t`_ .

```
NX_CNTR_OBJ_CKSUM_SET
```

The number of times a checksum has been computed while writing objects to disk.

```
NX_CNTR_OBJ_CKSUM_SET=0
```

```
NX_CNTR_OBJ_CKSUM_FAIL
```

The number of times an objectʼs checksum was invalid when reading from disk.

```
NX_CNTR_OBJ_CKSUM_FAIL=1
```

```
NX_NUM_COUNTERS
```

The maximum number of counters.

```
NX_NUM_COUNTERS=32
```

## _`checkpoint_mapping_t`_

A mapping from an ephemeral object identifier to its physical address in the checkpoint data area.

```
structcheckpoint_mapping{
uint32_tcpm_type;
uint32_tcpm_subtype;
uint32_tcpm_size;
uint32_tcpm_pad;
oid_tcpm_fs_oid;
oid_tcpm_oid;
oid_tcpm_paddr;
```

```
};
```

```
typedefstructcheckpoint_mappingcheckpoint_mapping_t;
```

```
cpm_type
```

The objectʼs type.

```
uint32_tcpm_type;
```

An object type is a 32-bit value: The low 16 bits indicate the type using the values listed in Object Types, and the high 16 bits are flags using the values listed in Object Type Flags.

This field has the same meaning and behavior as the _`o_type`_ field of _`obj_phys_t`_ .


40

**Container** _`checkpoint_map_phys_t`_

## _`cpm_subtype`_

The objectʼs subtype.

```
uint32_tcpm_subtype;
```

One of the values listed in Object Types.

Subtypes indicate the type of data stored in a data structure such as a B-tree. For example, a leaf node in a B-tree that contains file-system records has a type of _`OBJECT_TYPE_BTREE_NODE`_ and a subtype of _`OBJECT_TYPE_FSTREE`_ .

This field has the same meaning and behavior as the _`o_subtype`_ field of _`obj_phys_t`_ .

## _`cpm_size`_

The size, in bytes, of the object.

```
uint32_tcpm_size;
```

## _`cpm_pad`_

Reserved.

```
uint32_tcpm_pad;
```

Populate this field with zero when you create a new mapping, and preserve its value when you modify an existing mapping.

This field is padding.

## _`cpm_fs_oid`_

The virtual object identifier of the volume that the object is associated with.

```
oid_tcpm_fs_oid;
```

```
cpm_oid
```

The ephemeral object identifier.

```
oid_tcpm_oid;
```

## _`cpm_paddr`_

The address in the checkpoint data area where the object is stored.

```
oid_tcpm_paddr;
```

## _`checkpoint_map_phys_t`_

A checkpoint-mapping block.

```
structcheckpoint_map_phys{
obj_phys_tcpm_o;
uint32_tcpm_flags;
```


41

**Container** Checkpoint Flags

```
uint32_tcpm_count;
checkpoint_mapping_tcpm_map[];
```

```
};
```

If a checkpoint needs to store more mappings than a single block can hold, the checkpoint has multiple checkpointmapping blocks stored contiguously in the checkpoint descriptor area. The last checkpoint-mapping block is marked with the _`CHECKPOINT_MAP_LAST`_ flag.

```
cpm_o
```

The objectʼs header.

```
obj_phys_tcpm_o;
```

```
cpm_flags
```

A bit field that contains additional information about the list of checkpoint mappings.

```
uint32_tcpm_flags;
```

For the values used in this bit field, see Checkpoint Flags.

```
cpm_count
```

The number of checkpoint mappings in the array.

```
uint32_tcpm_count;
```

```
cpm_map
```

The array of checkpoint mappings.

```
checkpoint_mapping_tcpm_map[];
```

## Checkpoint Flags

The flags used by a checkpoint-mapping block.

```
#defineCHECKPOINT_MAP_LAST0x00000001
```

```
CHECKPOINT_MAP_LAST
```

A flag marking the last checkpoint-mapping block in a given checkpoint.

```
#defineCHECKPOINT_MAP_LAST0x00000001
```

## _`evict_mapping_val_t`_

A range of physical addresses that data is being moved into.

```
structevict_mapping_val{
paddr_tdst_paddr;
uint64_tlen;
}__attribute__((packed));
```


42

**Container** _`evict_mapping_val_t`_

```
typedefstructevict_mapping_valevict_mapping_val_t;
```

This data type is used by the evict-mapping tree, which is accessed through the _`nx_evict_mapping_tree_oid`_ field of _`nx_superblock_t`_ .

```
dst_paddr
```

The address where the destination starts.

```
paddr_tdst_paddr;
```

```
len
```

The number of blocks being moved.

```
uint64_tlen;
```


43
