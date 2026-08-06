<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Object Maps

An object map uses a B-tree to store a mapping from virtual object identifiers and transaction identifiers to the physical addresses where those objects are stored. The keys in the B-tree are instances of _`omap_key_t`_ and the values are instances of _`paddr_t`_ .

To access a virtual object using the object map, perform the following operations:

1. Determine which object map to use. Objects that are within a volume use that volumeʼs object map, and all other objects use the containerʼs object map.

2. Locate the object map for the volume by reading the _`apfs_omap_oid`_ field of _`apfs_superblock_t`_ or the _`nx_omap_oid`_ field of _`nx_superblock_t`_ .

3. Locate the B-tree for the object map by reading the _`om_tree_oid`_ field of _`omap_phys_t`_ .

4. Search the B-tree for a key whose object identifier is the same as the desired object identifier, and whose transaction identifier is less than or equal to the desired transaction identifier. If there are multiple keys that satisfy this test, use the key with the largest transaction identifier.

5. Using the table of contents entry, read the corresponding value for the key you found, which contains a physical address.

6. Read the object from disk at that address.

For example, assume the object mapʼs B-tree contains the following mappings:

```
OID588,XID2101->Address200
OID588,XID2202->Address300
OID588,XID2300->Address100
```

To access object 588 as of transaction 2300, you use the last entry — its object and transaction identifiers match exactly — and read physical address 100.

To access object 588 as of transaction 2290, you use the second entry. Thereʼs no entry with the transaction identifier 2290, and 2202 is the largest transaction identifier in the object map thatʼs still less than 2290. That entry tells you to read physical address 300.

## _`omap_phys_t`_

An object map.

```
structomap_phys{
obj_phys_tom_o;
uint32_tom_flags;
uint32_tom_snap_count;
uint32_tom_tree_type;
uint32_tom_snapshot_tree_type;
oid_tom_tree_oid;
oid_tom_snapshot_tree_oid;
xid_tom_most_recent_snap;
xid_tom_pending_revert_min;
```


44

**Object Maps** _`omap_phys_t`_

```
xid_tom_pending_revert_max;
```

## _`};`_

```
typedefstructomap_physomap_phys_t;
```

## _`om_o`_

The objectʼs header.

```
obj_phys_tom_o;
```

```
om_flags
```

The object mapʼs flags.

```
uint32_tom_flags;
```

For the values used in this bit field, see Object Map Flags.

```
om_tree_type
```

The type of tree being used for object mappings.

```
uint32_tom_tree_type;
```

```
om_tree_oid
```

The virtual object identifier of the tree being used for object mappings.

```
oid_tom_tree_oid;
```

```
om_snapshot_tree_oid
```

The virtual object identifier of the tree being used to hold snapshot information.

```
oid_tom_snapshot_tree_oid;
```

```
om_snapshot_tree_type
```

The type of tree being used for snapshots.

```
uint32_tom_snapshot_tree_type;
```

```
om_snap_count
```

The number of snapshots that this object map has.

```
uint32_tom_snap_count;
```

```
om_most_recent_snap
```

The transaction identifier of the most recent snapshot thatʼs stored in this object map.

```
xid_tom_most_recent_snap;
```


45

**Object Maps** _`omap_key_t`_

```
om_pending_revert_min
```

The smallest transaction identifier for an in-progress revert.

```
xid_tom_pending_revert_min;
```

```
om_pending_revert_max
```

The largest transaction identifier for an in-progress revert.

```
xid_tom_pending_revert_max;
```

## _`omap_key_t`_

A key used to access an entry in the object map.

```
structomap_key{
oid_tok_oid;
xid_tok_xid;
};
typedefstructomap_keyomap_key_t;
```

```
ok_oid
```

The object identifier.

```
oid_tok_oid;
```

```
ok_xid
```

The transaction identifier.

```
xid_tok_xid;
```

```
omap_val_t
```

A value in the object map.

```
structomap_val{
uint32_tov_flags;
uint32_tov_size;
paddr_tov_paddr;
};
typedefstructomap_valomap_val_t;
```

```
ov_flags
```

A bit field of flags.

```
uint32_tov_flags;
```

For the values used in this bit field, see Object Map Value Flags.


46

**Object Maps** _`omap_snapshot_t`_

## _`ov_size`_

The size, in bytes, of the object.

```
uint32_tov_size;
```

This value must be a multiple of the containerʼs logical block size. If the object is smaller than one logical block, the value of this field is the size of one logical block.

## _`ov_paddr`_

The address of the object.

```
paddr_tov_paddr;
```

## _`omap_snapshot_t`_

Information about a snapshot of an object map.

```
structomap_snapshot{
```

```
uint32_toms_flags;
uint32_toms_pad;
oid_toms_oid;
};
typedefstructomap_snapshotomap_snapshot_t;
```

When accessing or storing a snapshot in the snapshot tree, use the transaction identifier as the key. This structure is the value stored in a snapshot tree.

## _`oms_flags`_

The snapshotʼs flags.

```
uint32_toms_flags;
```

For the values used in this bit field, see Snapshot Flags.

## _`oms_pad`_

Reserved.

```
uint32_toms_pad;
```

Populate this field with zero when you create a new snapshot, and preserve its value when you modify an existing snapshot.

This field is padding.

## _`oms_oid`_

Reserved.

```
oid_toms_oid;
```


47

**Object Maps** Object Map Value Flags

Populate this field with zero when you create a new snapshot, and preserve its value when you modify an existing snapshot.

## Object Map Value Flags

The flags used by entries in the object map.

```
#defineOMAP_VAL_DELETED0x00000001
#defineOMAP_VAL_SAVED0x00000002
#defineOMAP_VAL_ENCRYPTED0x00000004
#defineOMAP_VAL_NOHEADER0x00000008
#defineOMAP_VAL_CRYPTO_GENERATION0x00000010
```

## _`OMAP_VAL_DELETED`_

The object has been deleted, and this mapping is a placeholder.

```
#defineOMAP_VAL_DELETED0x00000001
```

## _`OMAP_VAL_SAVED`_

This object mapping shouldnʼt be replaced when the object is updated.

## _`#define OMAP_VAL_SAVED 0x00000002`_

This flag is used only on mappings in an object map thatʼs manually managed. In the current Apple implementation, itʼs never used.

See also the _`OMAP_MANUALLY_MANAGED`_ flag.

```
OMAP_VAL_ENCRYPTED
```

The object is encrypted.

```
#defineOMAP_VAL_ENCRYPTED0x00000004
```

```
OMAP_VAL_NOHEADER
```

The object is stored without an _`obj_phys_t`_ header.

```
#defineOMAP_VAL_NOHEADER0x00000008
```

```
OMAP_VAL_CRYPTO_GENERATION
```

A one-bit flag that tracks encryption configuration.

```
#defineOMAP_VAL_CRYPTO_GENERATION0x00000010
```

During the transition from an old encryption configuration to a new one, not all objects have been reencrypted using the new configuration. When the encryption configuration is changed, the object mapʼs flag is toggled. After an object is reencrypted, the objectʼs flag is also toggled.

If this flag doesnʼt match the flag on the object map, the encryption configuration has changed, but the object hasnʼt been reencrypted yet. Use the previous encryption configuration to decrypt the object.


48

**Object Maps** Snapshot Flags

See also _`OMAP_CRYPTO_GENERATION`_ , which is used by the _`omap_phys_t`_ field of _`om_flags`_ .

## Snapshot Flags

The flags used to describe the state of a snapshot.

```
#defineOMAP_SNAPSHOT_DELETED0x00000001
#defineOMAP_SNAPSHOT_REVERTED0x00000002
```

```
OMAP_SNAPSHOT_DELETED
```

The snapshot has been deleted.

```
#defineOMAP_SNAPSHOT_DELETED0x00000001
```

## _`OMAP_SNAPSHOT_REVERTED`_

The snapshot has been deleted as part of a revert.

```
#defineOMAP_SNAPSHOT_REVERTED0x00000002
```

## Object Map Flags

The flags used by object maps.

```
#defineOMAP_MANUALLY_MANAGED0x00000001
#defineOMAP_ENCRYPTING0x00000002
#defineOMAP_DECRYPTING0x00000004
#defineOMAP_KEYROLLING0x00000008
#defineOMAP_CRYPTO_GENERATION0x00000010
```

```
#defineOMAP_VALID_FLAGS0x0000001f
```

```
OMAP_MANUALLY_MANAGED
```

The object map doesnʼt support snapshots.

```
#defineOMAP_MANUALLY_MANAGED0x00000001
```

This flag must be set on the containerʼs object map and is invalid on a volumeʼs object map.

```
OMAP_ENCRYPTING
```

A transition is in progress from unencrypted storage to encrypted storage.

```
#defineOMAP_ENCRYPTING0x00000002
```

## _`OMAP_DECRYPTING`_

A transition is in progress from encrypted storage to unencrypted storage.

```
#defineOMAP_DECRYPTING0x00000004
```


49

**Object Maps** Object Map Constants

## _`OMAP_KEYROLLING`_

A transition is in progress from encrypted storage using an old key to encrypted storage using a new key.

```
#defineOMAP_KEYROLLING0x00000008
```

```
OMAP_CRYPTO_GENERATION
```

A one-bit flag that tracks encryption configuration.

```
#defineOMAP_CRYPTO_GENERATION0x00000010
```

For information about how this flag is used to track the old and new encryption configuration, see _`OMAP_VAL_ CRYPTO_GENERATION`_ , which is used by the _`ov_flags`_ field of _`omap_val_t`_ .

## _`OMAP_VALID_FLAGS`_

A bit mask of all valid object map flags.

```
#defineOMAP_VALID_FLAGS0x0000001f
```

## Object Map Constants

Constants that specify size constraints of an object map.

```
#defineOMAP_MAX_SNAP_COUNTUINT32_MAX
```

```
OMAP_MAX_SNAP_COUNT
```

The maximum number of snapshots that can be stored in an object map.

```
#defineOMAP_MAX_SNAP_COUNTUINT32_MAX
```

## Object Map Reaper Phases

Phases used by the reaper when deleting objects that are stored in an object map.

```
#defineOMAP_REAP_PHASE_MAP_TREE1
#defineOMAP_REAP_PHASE_SNAPSHOT_TREE2
```

```
OMAP_REAP_PHASE_MAP_TREE
```

The reaper is deleting entries from the object mapping tree.

```
#defineOMAP_REAP_PHASE_MAP_TREE1
```

```
OMAP_REAP_PHASE_SNAPSHOT_TREE
```

The reaper is deleting entries from the snapshot tree.

```
#defineOMAP_REAP_PHASE_SNAPSHOT_TREE2
```


50
