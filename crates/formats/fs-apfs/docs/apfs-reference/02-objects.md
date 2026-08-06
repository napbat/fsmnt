<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Objects

Depending on how theyʼre stored, objects have some differences, the most important of which is the way you use an object identifier to find an object. At the container level, there are three storage methods for objects:

- _Ephemeral objects_ are stored in memory for a mounted container, and are persisted across unmounts in a checkpoint. Ephemeral objects for a mounted partition can be modified in place while theyʼre in memory, but theyʼre always written back to disk as part of a new checkpoint. Theyʼre used for information thatʼs frequently updated because of the performance benefits of in-place, in-memory changes.

- _Physical objects_ are stored at a known block address on the disk, and are modified by writing the copy to a new location on disk. Because the object identifier for a physical object is its physical address, this copy-on-write behavior means that the modified copy has a different object identifier.

- _Virtual objects_ are stored on disk at a block address that you look up using an object map. Virtual objects are also copied when they are modified; however, both the original and the modified copy have the same object identifier. When you look up a virtual object in an object map, you use a transaction identifier, in addition to the object identifier, to specify the point in time that you want.

Regardless of their storage, objects on disk are never modified in place, and modified copies of an object are always written to a new location on disk. To access an object, you need to know its storage and its identifier. For virtual objects, you also need a transaction identifier. The storage for an object is almost always implicit from the context in which that identifier appears. For example, the object identifier for the space manager is stored in the _`nx_spaceman_oid`_ field of _`nx_superblock_t`_ , and the documentation for that field says that the space manager is always an ephemeral object.

Object identifiers are unique inside the entire container, within their storage method. For example, no two virtual objects can have the same identifier — even when stored in different object maps — because their storage methods are the same. However, a virtual object and a physical object _can_ have the same identifier because their storage methods are different. For information about determining the identifier for a new object, see _`oid_t`_ .

When writing a new object to disk, fill all unused space in the block with zeros. Future versions of Apple File System add new fields at the end of a structure; zeroing out the uninitialized bytes makes it possible to determine whether data has been stored in a field that was added later, such as the _`apfs_cloneinfo_xid`_ field of _`apfs_superblock_t`_ .

## _`obj_phys_t`_

A header used at the beginning of all objects.

```
structobj_phys{
uint8_to_cksum[MAX_CKSUM_SIZE];
oid_to_oid;
xid_to_xid;
uint32_to_type;
uint32_to_subtype;
```

```
};
typedefstructobj_physobj_phys_t;
```

```
#defineMAX_CKSUM_SIZE8
```


10

**Objects** Supporting Data Types

## _`o_cksum`_

The Fletcher 64 checksum of the object.

```
uint8_to_cksum[MAX_CKSUM_SIZE];
```

## _`o_oid`_

The objectʼs identifier.

```
oid_to_oid;
```

## _`o_xid`_

The identifier of the most recent transaction that this object was modified in.

```
xid_to_xid;
```

## _`o_type`_

The objectʼs type and flags.

```
uint32_to_type;
```

An object type is a 32-bit value: The low 16 bits indicate the type using the values listed in Object Types, and the high 16 bits are flags using the values listed in Object Type Flags.

## _`o_subtype`_

The objectʼs subtype.

```
uint32_to_subtype;
```

For the values used in this field, see Object Types.

Subtypes indicate the type of data stored in a data structure such as a B-tree. For example, a node in a B-tree that contains volume records has a type of _`OBJECT_TYPE_BTREE_NODE`_ and a subtype of _`OBJECT_TYPE_FS`_ .

## _`MAX_CKSUM_SIZE`_

The number of bytes used for an object checksum.

```
#defineMAX_CKSUM_SIZE8
```

## Supporting Data Types

Types used as unique identifiers within an object.

```
typedefuint64_toid_t;
typedefuint64_txid_t;
```


11

**Objects** Object Identifier Constants

## _`oid_t`_

An object identifier.

## _`typedef uint64_t oid_t;`_

Objects are identified by this number as follows:

- For a physical object, its identifier is the logical block address on disk where the object is stored.

- For an ephemeral object, its identifier is a number.

- For a virtual object, its identifier is a number.

For more information about physical, ephemeral, or virtual objects, see Objects.

To determine the identifier for a new physical object, find a free block using the space manager, and use that blockʼs address. To determine the identifier for a new ephemeral or virtual object, check the value of _`nx_superblock_t. nx_next_oid`_ . New ephemeral and virtual object identifiers must be monotonically increasing.

## **Note**

Although both ephemeral and virtual objects use _`nx_next_oid`_ field of _`nx_superblock_t`_ in Appleʼs implementation, this isnʼt guaranteed or required. Ephemeral and virtual objects are stored in different places, so itʼs valid to encounter (or create) an ephemeral object and a virtual object that have the same identifier.

## _`xid_t`_

A transaction identifier.

```
typedefuint64_txid_t;
```

Transactions are uniquely identified by a monotonically increasing number.

The number zero isnʼt a valid transaction identifier. Implementations of Apple File System can use it as a sentinel value in memory — for example, to refer to the current transaction — but must not let it appear on disk.

This data type is sufficiently large that you arenʼt expected to ever run out of transaction identifiers. For example, if you created 1,000,000 transactions per second, it would take more than 5,000 centuries to exhaust the available transaction identifiers.

If a new transaction identifier isnʼt available, thatʼs an unrecoverable error. Identifiers arenʼt allowed to restart from one or to be reused.

## Object Identifier Constants

Constants used for virtual objects that always have a given identifier.

```
#defineOID_NX_SUPERBLOCK1
#defineOID_INVALID0ULL
#defineOID_RESERVED_COUNT1024
```


12

**Objects** Object Type Masks

## _`OID_NX_SUPERBLOCK`_

The ephemeral object identifier for the container superblock.

## _`#define OID_NX_SUPERBLOCK 1`_

Although the container superblock is stored in memory like other ephemeral objects, it isnʼt saved on disk in the same area. For details, see Mounting an Apple File System Partition.

## _`OID_INVALID`_

An invalid object identifier.

```
#defineOID_INVALID0ULL
```

## _`OID_RESERVED_COUNT`_

The number of object identifiers that are reserved for objects with a fixed object identifier.

## _`#define OID_RESERVED_COUNT 1024`_

This range of identifiers is reserved for physical, virtual, and ephemeral objects.

Currently, the only object with a reserved identifier is the container superblock, as described in _`OID_NX_SUPERBLOCK`_ . All other object identifiers less than _`OID_RESERVED_COUNT`_ are reserved by Apple.

## Object Type Masks

Bit masks used to access specific portions of an object type.

```
#defineOBJECT_TYPE_MASK0x0000ffff
#defineOBJECT_TYPE_FLAGS_MASK0xffff0000
#defineOBJ_STORAGETYPE_MASK0xc0000000
#defineOBJECT_TYPE_FLAGS_DEFINED_MASK0xf8000000
```

## _`OBJECT_TYPE_MASK`_

The bit mask used to access the type.

```
#defineOBJECT_TYPE_MASK0x0000ffff
```

For the values that appear in this bit field, see Object Types.

## _`OBJECT_TYPE_FLAGS_MASK`_

The bit mask used to access the flags.

```
#defineOBJECT_TYPE_FLAGS_MASK0xffff0000
```

For the values that appear in this bit field, see Object Type Flags.


13

**Objects** Object Types

## _`OBJ_STORAGETYPE_MASK`_

The bit mask used to access the storage portion of the object type.

```
#defineOBJ_STORAGETYPE_MASK0xc0000000
```

For the values that appear in this bit field, see Object Type Flags.

```
OBJECT_TYPE_FLAGS_DEFINED_MASK
```

A bit mask of all bits for which flags are defined.

```
#defineOBJECT_TYPE_FLAGS_DEFINED_MASK0xf8000000
```

## Object Types

Values used as types and subtypes by the _`obj_phys_t`_ structure.

```
#defineOBJECT_TYPE_NX_SUPERBLOCK0x00000001
#defineOBJECT_TYPE_BTREE0x00000002
#defineOBJECT_TYPE_BTREE_NODE0x00000003
#defineOBJECT_TYPE_SPACEMAN0x00000005
#defineOBJECT_TYPE_SPACEMAN_CAB0x00000006
#defineOBJECT_TYPE_SPACEMAN_CIB0x00000007
#defineOBJECT_TYPE_SPACEMAN_BITMAP0x00000008
```

```
#defineOBJECT_TYPE_SPACEMAN0x00000005
#defineOBJECT_TYPE_SPACEMAN_CAB0x00000006
#defineOBJECT_TYPE_SPACEMAN_CIB0x00000007
#defineOBJECT_TYPE_SPACEMAN_BITMAP0x00000008
#defineOBJECT_TYPE_SPACEMAN_FREE_QUEUE0x00000009
```

```
#defineOBJECT_TYPE_EXTENT_LIST_TREE0x0000000a
#defineOBJECT_TYPE_OMAP0x0000000b
#defineOBJECT_TYPE_CHECKPOINT_MAP0x0000000c
#defineOBJECT_TYPE_FS0x0000000d
#defineOBJECT_TYPE_FSTREE0x0000000e
#defineOBJECT_TYPE_BLOCKREFTREE0x0000000f
#defineOBJECT_TYPE_SNAPMETATREE0x00000010
```

```
#defineOBJECT_TYPE_FS
#defineOBJECT_TYPE_FSTREE
#defineOBJECT_TYPE_BLOCKREFTREE
#defineOBJECT_TYPE_SNAPMETATREE
```

```
#defineOBJECT_TYPE_NX_REAPER0x00000011
#defineOBJECT_TYPE_NX_REAP_LIST0x00000012
#defineOBJECT_TYPE_OMAP_SNAPSHOT0x00000013
#defineOBJECT_TYPE_EFI_JUMPSTART0x00000014
#defineOBJECT_TYPE_FUSION_MIDDLE_TREE0x00000015
#defineOBJECT_TYPE_NX_FUSION_WBC0x00000016
#defineOBJECT_TYPE_NX_FUSION_WBC_LIST0x00000017
#defineOBJECT_TYPE_ER_STATE0x00000018
#defineOBJECT_TYPE_GBITMAP0x00000019
#defineOBJECT_TYPE_GBITMAP_TREE0x0000001a
#defineOBJECT_TYPE_GBITMAP_BLOCK0x0000001b
```


14

**Objects** Object Types

```
#defineOBJECT_TYPE_ER_RECOVERY_BLOCK0x0000001c
#defineOBJECT_TYPE_SNAP_META_EXT0x0000001d
#defineOBJECT_TYPE_INTEGRITY_META0x0000001e
#defineOBJECT_TYPE_FEXT_TREE0x0000001f
#defineOBJECT_TYPE_RESERVED_200x00000020
```

```
#defineOBJECT_TYPE_INVALID0x00000000
#defineOBJECT_TYPE_TEST0x000000ff
#defineOBJECT_TYPE_CONTAINER_KEYBAG'keys'
#defineOBJECT_TYPE_VOLUME_KEYBAG'recs'
#defineOBJECT_TYPE_MEDIA_KEYBAG'mkey'
```

The value of _`obj_phys_t.o_type & OBJECT_TYPE_MASK`_ is one of these constants.

```
OBJECT_TYPE_NX_SUPERBLOCK
```

A container superblock ( _`nx_superblock_t`_ ).

```
#defineOBJECT_TYPE_NX_SUPERBLOCK0x00000001
```

```
OBJECT_TYPE_BTREE
```

A B-tree root node ( _`btree_node_phys_t`_ ).

```
#defineOBJECT_TYPE_BTREE0x00000002
```

```
OBJECT_TYPE_BTREE_NODE
```

A B-tree node ( _`btree_node_phys_t`_ ).

```
#defineOBJECT_TYPE_BTREE_NODE0x00000003
```

```
OBJECT_TYPE_SPACEMAN
```

A space manager ( _`spaceman_phys_t`_ ).

```
#defineOBJECT_TYPE_SPACEMAN0x00000005
```

```
OBJECT_TYPE_SPACEMAN_CAB
```

A chunk-info address block ( _`cib_addr_block`_ ) used by the space manager.

```
#defineOBJECT_TYPE_SPACEMAN_CAB0x00000006
```

```
OBJECT_TYPE_SPACEMAN_CIB
```

A chunk-info block ( _`chunk_info_block`_ ) used by the space manager.

```
#defineOBJECT_TYPE_SPACEMAN_CIB0x00000007
```


15

**Objects** Object Types

## _`OBJECT_TYPE_SPACEMAN_BITMAP`_

A free-space bitmap used by the space manager.

```
#defineOBJECT_TYPE_SPACEMAN_BITMAP0x00000008
```

## _`OBJECT_TYPE_SPACEMAN_FREE_QUEUE`_

A free-space queue (a mapping from _`spaceman_free_queue_key_t`_ to _`spaceman_free_queue_t`_ ), used by the space manager.

```
#defineOBJECT_TYPE_SPACEMAN_FREE_QUEUE0x00000009
```

This type is used only as a subtype of a tree.

## _`OBJECT_TYPE_EXTENT_LIST_TREE`_

An extents-list tree (a mapping from _`paddr_t`_ to _`prange_t`_ ).

```
#defineOBJECT_TYPE_EXTENT_LIST_TREE0x0000000a
```

The keys are an offset into the logical start of the extent, and the value is the physical location where that data is stored.

This type is used only as a subtype of a tree.

## _`OBJECT_TYPE_OMAP`_

As a type, an object map ( _`omap_phys_t`_ ); as a subtype, a tree that stores the records of an object map (a mapping from _`omap_key_t`_ to _`omap_val_t`_ ).

```
#defineOBJECT_TYPE_OMAP0x0000000b
```

```
OBJECT_TYPE_CHECKPOINT_MAP
```

A checkpoint map ( _`checkpoint_map_phys_t`_ ).

```
#defineOBJECT_TYPE_CHECKPOINT_MAP0x0000000c
```

```
OBJECT_TYPE_FS
```

A volume ( _`apfs_superblock_t`_ ).

```
#defineOBJECT_TYPE_FS0x0000000d
```

```
OBJECT_TYPE_FSTREE
```

A tree containing file-system records.

```
#defineOBJECT_TYPE_FSTREE0x0000000e
```

This type is used only as a subtype of a tree.

The keys and values stored in the tree vary. Each key begins with _`j_key_t`_ , which contains a field that indicates the type of that key and its value.


16

**Objects** Object Types

## _`OBJECT_TYPE_BLOCKREFTREE`_

A tree containing extent references (a mapping from _`j_phys_ext_key_t`_ to _`j_phys_ext_val_t`_ ).

```
#defineOBJECT_TYPE_BLOCKREFTREE0x0000000f
```

This type is used only as a subtype of a tree.

## _`OBJECT_TYPE_SNAPMETATREE`_

A tree containing snapshot metadata for a volume (a mapping from _`j_snap_metadata_key_t`_ to _`j_snap_ metadata_val_t`_ ).

```
#defineOBJECT_TYPE_SNAPMETATREE0x00000010
```

This type is used only as a subtype of a tree.

## _`OBJECT_TYPE_NX_REAPER`_

A reaper ( _`nx_reaper_phys_t`_ ).

```
#defineOBJECT_TYPE_NX_REAPER0x00000011
```

```
OBJECT_TYPE_NX_REAP_LIST
```

A reaper list ( _`nx_reap_list_phys_t`_ ).

```
#defineOBJECT_TYPE_NX_REAP_LIST0x00000012
```

## _`OBJECT_TYPE_OMAP_SNAPSHOT`_

A tree containing information about snapshots of an object map (a mapping from _`xid_t`_ to _`omap_snapshot_t`_ ).

```
#defineOBJECT_TYPE_OMAP_SNAPSHOT0x00000013
```

This type is used only as a subtype of a tree.

## _`OBJECT_TYPE_EFI_JUMPSTART`_

EFI information used for booting ( _`nx_efi_jumpstart_t`_ ).

```
#defineOBJECT_TYPE_EFI_JUMPSTART0x00000014
```

## _`OBJECT_TYPE_FUSION_MIDDLE_TREE`_

A tree used for Fusion devices to track blocks from the hard drive that are cached on the solid-state drive (a mapping from _`fusion_mt_key_t`_ to _`fusion_mt_val_t`_ ).

```
#defineOBJECT_TYPE_FUSION_MIDDLE_TREE0x00000015
```

This type is used only as a subtype of a tree.


17

**Objects** Object Types

## _`OBJECT_TYPE_NX_FUSION_WBC`_

A write-back cache state ( _`fusion_wbc_phys_t`_ ) used for Fusion devices.

```
#defineOBJECT_TYPE_NX_FUSION_WBC0x00000016
```

```
OBJECT_TYPE_NX_FUSION_WBC_LIST
```

A write-back cache list ( _`fusion_wbc_list_phys_t`_ ) used for Fusion devices.

```
#defineOBJECT_TYPE_NX_FUSION_WBC_LIST0x00000017
```

## _`OBJECT_TYPE_ER_STATE`_

An encryption-rolling state ( _`er_state_phys_t`_ ).

```
#defineOBJECT_TYPE_ER_STATE0x00000018
```

## _`OBJECT_TYPE_GBITMAP`_

A general-purpose bitmap ( _`gbitmap_phys_t`_ ).

```
#defineOBJECT_TYPE_GBITMAP0x00000019
```

```
OBJECT_TYPE_GBITMAP_TREE
```

A B-tree of general-purpose bitmaps (a mapping from _`uint64_t`_ to _`uint64_t`_ ).

```
#defineOBJECT_TYPE_GBITMAP_TREE0x0000001a
```

This type is used only as a subtype of a tree.

```
OBJECT_TYPE_GBITMAP_BLOCK
```

A block containing a general-purpose bitmap ( _`gbitmap_block_phys_t`_ ).

```
#defineOBJECT_TYPE_GBITMAP_BLOCK0x0000001b
```

```
OBJECT_TYPE_ER_RECOVERY_BLOCK
```

Information that can be used to recover from a system crash if one occurs during the encryption rolling process ( _`er_recovery_block_phys_t`_ ).

```
#defineOBJECT_TYPE_ER_RECOVERY_BLOCK0x0000001c
```

```
OBJECT_TYPE_SNAP_META_EXT
```

Additional metadata about snapshots ( _`snap_meta_ext_obj_phys_t`_ .)

```
#defineOBJECT_TYPE_SNAP_META_EXT0x0000001d
```


18

**Objects** Object Types

## _`OBJECT_TYPE_INTEGRITY_META`_

An integrity metadata object ( _`integrity_meta_phys_t`_ ).

```
#defineOBJECT_TYPE_INTEGRITY_META0x0000001e
```

```
OBJECT_TYPE_FEXT_TREE
```

A B-tree of file extents (a mapping from _`fext_tree_key_t`_ to _`fext_tree_val_t`_ ).

```
#defineOBJECT_TYPE_FEXT_TREE0x0000001f
```

This type is used only as a subtype of a tree.

```
OBJECT_TYPE_RESERVED_20
```

Reserved.

```
#defineOBJECT_TYPE_RESERVED_200x00000020
```

```
OBJECT_TYPE_INVALID
```

As a type, an invalid object; as a subtype, an object with no subtype.

```
#defineOBJECT_TYPE_INVALID0x00000000
```

```
OBJECT_TYPE_TEST
```

Reserved for testing.

```
#defineOBJECT_TYPE_TEST0x000000ff
```

Donʼt create objects of this type on disk. If you find an object of this type in production, file a bug against the Apple File System implementation.

This type isnʼt reserved by Apple; non-Apple implementations of Apple File System can use it during testing.

```
OBJECT_TYPE_CONTAINER_KEYBAG
```

A containerʼs keybag ( _`media_keybag_t`_ ).

```
#defineOBJECT_TYPE_CONTAINER_KEYBAG'keys'
```

```
OBJECT_TYPE_VOLUME_KEYBAG
```

A volumeʼs keybag ( _`media_keybag_t`_ ).

```
#defineOBJECT_TYPE_VOLUME_KEYBAG'recs'
```

```
OBJECT_TYPE_MEDIA_KEYBAG
```

A media keybag ( _`media_keybag_t`_ ).

```
#defineOBJECT_TYPE_MEDIA_KEYBAG'mkey'
```


19

**Objects** Object Type Flags

## Object Type Flags

The flags used in the object type to provide additional information.

```
#defineOBJ_VIRTUAL0x00000000
#defineOBJ_EPHEMERAL0x80000000
#defineOBJ_PHYSICAL0x40000000
#defineOBJ_NOHEADER0x20000000
#defineOBJ_ENCRYPTED0x10000000
#defineOBJ_NONPERSISTENT0x08000000
```

The value of _`obj_phys_t.o_type & OBJECT_TYPE_FLAGS_MASK`_ uses these constants. The value of _`obj_ phys_t.o_type & OBJ_STORAGETYPE_MASK`_ uses only _`OBJ_VIRTUAL`_ , _`OBJ_EPHEMERAL`_ , and _`OBJ_PHYSICAL`_ .

The flags on an objectʼs type must indicate whether the object is virtual, ephemeral, or physical by setting either the _`OBJ_EPHEMERAL`_ or _`OBJ_PHYSICAL`_ flag, or setting neither flag. An object type that contains both flags is invalid.

The absence of both flags indicates a virtual object. The _`OBJ_VIRTUAL`_ constant is defined to allow code that tests for virtual objects to match code testing for physical or ephemeral objects, even though thereʼs no corresponding bit set in the objectʼs type. For example:

```
obj_phys_tobj=/*assumethisexists*/
if((obj.o_type&OBJ_STORAGETYPE_MASK)==OBJ_VIRTUAL){...}
elif((obj.o_type&OBJ_STORAGETYPE_MASK)==OBJ_EPHEMERAL){...}
elif((obj.o_type&OBJ_STORAGETYPE_MASK)==OBJ_PHYSICAL){...}
else{/*error*/}
```

## _`OBJ_VIRTUAL`_

A virtual object.

```
#defineOBJ_VIRTUAL0x00000000
```

```
OBJ_EPHEMERAL
```

An ephemeral object.

```
#defineOBJ_EPHEMERAL0x80000000
```

```
OBJ_PHYSICAL
```

A physical object.

```
#defineOBJ_PHYSICAL0x40000000
```

```
OBJ_NOHEADER
```

An object stored without an _`obj_phys_t`_ header.

```
#defineOBJ_NOHEADER0x20000000
```

This flag is used, for example, by the space managerʼs bitmap.


20

**Objects** Object Type Flags

## _`OBJ_ENCRYPTED`_

An encrypted object.

```
#defineOBJ_ENCRYPTED0x10000000
```

## _`OBJ_NONPERSISTENT`_

An ephemeral object that isnʼt persisted across unmounting.

## _`#define OBJ_NONPERSISTENT 0x08000000`_

Objects with this flag never appear on disk. If you find an object of this type in production, file a bug against the Apple File System implementation.

This flag isnʼt reserved by Apple; non-Apple implementations of Apple File System can mark their runtime-only data structures with _`OBJ_NONPERSISTENT | OBJ_EPHEMERAL`_ .


21
