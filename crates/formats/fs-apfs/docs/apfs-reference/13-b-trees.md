<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## B-Trees

The B-trees used in Apple File System are implemented using the _`btree_node_phys_t`_ structure to represent a node. The same structure is used for all nodes in a tree. Within a node, storage is divided into several areas:

- Information about the node

- The table of contents, which lists the location of keys and values

- Storage for the keys

- Storage for the values

- Information about the entire tree

The figure below shows the storage areas of a typical root node.

**==> picture [469 x 52] intentionally omitted <==**

The instance of _`btree_node_phys_t`_ stores information about this B-tree node, like its flags and the location of its keys, and is always located at the beginning of the block. For a root node, an instance of _`btree_info_t`_ is located at the end of the block, and contains information like the sizes of keys and values, the total number of keys in the tree, and the number of nodes in the tree. Nonroot nodes omit _`btree_info_t`_ . The rest of the block (the _`btn_data`_ field of _`btree_node_phys_t`_ ) is organized dynamically.

Compared to other B-tree implementations, this data structure has some unique characteristics. Traversal is always done from the root node because nodes donʼt have parent or sibling pointers. All values are stored in leaf nodes, which makes these B+ trees, and the values in nonleaf nodes are object identifiers of child nodes. The keys, values, or both can be of variable size; if the keys and values of a node are both fixed in size, some optimizations for the table of contents are possible.

## **Keys and Values**

The keys and values are stored starting at opposite ends of the B-tree nodeʼs storage area, with free space thatʼs available for new keys or values in the available portion of the storage area between them. The key and value areas grow toward each other into their shared free space. Free space within the key area and within the value area is organized using a free list. For example, free space appears outside the shared free space when an entry is removed from a B-tree. The figure below shows free space for keys and values in a typical nonroot node.

**==> picture [469 x 109] intentionally omitted <==**

The locations of keys and values are stored as offsets, which uses less on-disk space than storing the full location. The offset to a key is counted from the beginning of the key area to the beginning of the key. The offset to a value is counted from the end of the value area to the beginning of the value.


122

**B-Trees** _`btree_node_phys_t`_

Keys and value are normally aligned to eight-byte boundaries when stored. The length recorded for a key or value in the table of contents omits any padding needed for alignment. If the _`BTREE_KV_NONALIGNED`_ flag is set, keys and values are stored without padding.

If the _`BTREE_ALLOW_GHOSTS`_ flag is set on the B-tree, the tree can contain keys that have no value.

## **Table of Contents**

The table of contents stores the location of each key and value that form a key-value pair.

If the _`BTNODE_FIXED_KV_SIZE`_ flag is set, the table of contents stores only the offsets for keys and values. Otherwise, it stores both their offsets and lengths.

Free space within the table of contents is located at the end. If thereʼs no free space remaining, but a new entry is needed, the table of contents area must be expanded. The entire key area is shifted to make space available, using some of the shared free space for key space, and some space from the beginning of the key space for the table of contents. Because the offset to a key is counted relative to the beginning of the key area, moving the entire key area doesnʼt invalidate any of these offsets. Likewise, when the table of contents has too much unused space, it shrinks, and the key area is shifted into the space from the table of contents. Appleʼs implementation uses _`BTREE_TOC_ENTRY_INCREMENT`_ and _`BTREE_TOC_ENTRY_MAX_UNUSED`_ to determine when to expand or shrink the table of contents.

## **Note**

When the _`BTNODE_FIXED_KV_SIZE`_ flag is set, Appleʼs implementation allocates enough space for the table of contents to avoid the need to expand it later. This is possible because the maximum number of entries is known, as well as the size of an entry. However, if the _`BTREE_ALLOW_GHOSTS`_ flag is also set, the table of contents might still need to expand.

## **Key Comparison**

The entries in the table of contents are sorted by key. The comparison function used for sorting depends on the keyʼs type. Object map B-trees are sorted by object identifier and then by transaction identifier. Free queue B-trees are sorted by transaction identifier and then by physical address. File-system records are sorted according to the rules listed in File-System Objects.

## _`btree_node_phys_t`_

A B-tree node.

```
structbtree_node_phys{
obj_phys_tbtn_o;
uint16_tbtn_flags;
uint16_tbtn_level;
uint32_tbtn_nkeys;
nloc_tbtn_table_space;
nloc_tbtn_free_space;
nloc_tbtn_key_free_list;
nloc_tbtn_val_free_list;
uint64_tbtn_data[];
```


123

**B-Trees** _`btree_node_phys_t`_

## _`};`_

## _`typedef struct btree_node_phys btree_node_phys_t;`_

The locations of the key and value areas arenʼt stored explicitly. The key area begins after the end of the table of contents and ends before the start of the shared free space. The value area begins after the end of shared free space and ends at the end of the B-tree node (for nonroot nodes) or before the instance of _`btree_info_t`_ thatʼs at the end of a root node.

## _`btn_o`_

The objectʼs header.

```
obj_phys_tbtn_o;
```

## _`btn_flags`_

The B-tree nodeʼs flags.

```
uint16_tbtn_flags;
```

For the values used in this bit field, see B-Tree Node Flags.

## _`btn_level`_

The number of child levels below this node.

## _`uint16_t btn_level;`_

For example, the value of this field is zero for a leaf node and one for the immediate parent of a leaf node. Likewise, the height of a tree is one plus the value of this field on the treeʼs root node.

## _`btn_nkeys`_

The number of keys stored in this node.

```
uint32_tbtn_nkeys;
```

## _`btn_table_space`_

The location of the table of contents.

## _`nloc_t btn_table_space;`_

The offset for the table of contents is counted from the beginning of the nodeʼs _`btn_data`_ field to the beginning of the table of contents.

If the _`BTNODE_FIXED_KV_SIZE`_ flag is set, the table of contents is an array of instances of _`kvoff_t`_ ; otherwise, itʼs an array of instances of _`kvloc_t`_ .

## _`btn_free_space`_

The location of the shared free space for keys and values.

```
nloc_tbtn_free_space;
```


124

**B-Trees** _`btree_info_fixed_t`_

The locationʼs offset is counted from the beginning of the key area to the beginning of the free space.

## _`btn_key_free_list`_

A linked list that tracks free key space.

```
nloc_tbtn_key_free_list;
```

The offset from the beginning of the key area to the first available space for a key is stored in the _`off`_ field, and the total amount of free key space is stored in the _`len`_ field. Each free space stores an instance of _`nloc_t`_ whose _`len`_ field indicates the size of that free space and whose _`off`_ field contains the location of the next free space.

## _`btn_val_free_list`_

A linked list that tracks free value space.

```
nloc_tbtn_val_free_list;
```

The offset from the end of the value area to the first available space for a value is stored in the _`off`_ field, and the total amount of free value space is stored in the _`len`_ field. Each free space stores an instance of _`nloc_t`_ whose _`len`_ field indicates the size of that free space and whose _`off`_ field contains the location of the next free space.

## _`btn_data`_

The nodeʼs storage area.

```
uint64_tbtn_data[];
```

This area contains the table of contents, keys, free space, and values. A root node also has as an instance of _`btree_info_t`_ at the end of its storage area. For more information, see B-trees.

## _`btree_info_fixed_t`_

Static information about a B-tree.

```
structbtree_info_fixed{
uint32_tbt_flags;
uint32_tbt_node_size;
uint32_tbt_key_size;
uint32_tbt_val_size;
};
typedefstructbtree_info_fixedbtree_info_fixed_t;
```

This information doesnʼt change over time as the B-tree is modified. Itʼs stored separately from the rest of the information in _`btree_info_t`_ , which does change, to enable this information to be cached more easily.

## _`bt_flags`_

The B-treeʼs flags.

```
uint32_tbt_flags;
```

For the values used in this bit field, see B-Tree Flags.


125

**B-Trees** _`btree_info_t`_

## _`bt_node_size`_

The on-disk size, in bytes, of a node in this B-tree.

```
uint32_tbt_node_size;
```

Leaf nodes, nonleaf nodes, and the root node are all the same size.

## _`bt_key_size`_

The size of a key, or zero if the keys have variable size.

```
uint32_tbt_key_size;
```

If this field has a value of zero, the _`btn_flags`_ field of instances of _`btree_node_phys_t`_ in this tree must not include _`BTNODE_FIXED_KV_SIZE`_ .

## _`bt_val_size`_

The size of a value, or zero if the values have variable size.

```
uint32_tbt_val_size;
```

If this field has a value of zero, the _`btn_flags`_ field of instances of _`btree_node_phys_t`_ for leaf nodes in this tree must not include _`BTNODE_FIXED_KV_SIZE`_ . Nonleaf nodes in a tree with variable-size values include _`BTNODE_FIXED_KV_SIZE`_ , because the values stored in those nodes are the object identifiers of their child nodes, and object identifiers have a fixed size.

## _`btree_info_t`_

Information about a B-tree.

```
structbtree_info{
```

```
btree_info_fixed_tbt_fixed;
uint32_tbt_longest_key;
uint32_tbt_longest_val;
uint64_tbt_key_count;
uint64_tbt_node_count;
};
typedefstructbtree_infobtree_info_t;
```

This information appears only in a root node, stored at the end of the node.

```
btree_info_fixed_t
```

Information about the B-tree that doesnʼt change over time.

```
btree_info_fixed_tbt_fixed;
```

## _`bt_longest_key`_

The length, in bytes, of the longest key that has ever been stored in the B-tree.

```
uint32_tbt_longest_key;
```


126

**B-Trees** _`btn_index_node_val_t`_

```
bt_longest_val
```

The length, in bytes, of the longest value that has ever been stored in the B-tree.

```
uint32_tbt_longest_val;
```

```
bt_key_count
```

The number of keys stored in the B-tree.

```
uint64_tbt_key_count;
```

```
bt_node_count
```

The number of nodes stored in the B-tree.

```
uint64_tbt_node_count;
```

## _`btn_index_node_val_t`_

The value used by hashed B-trees for nonleaf nodes.

```
structbtn_index_node_val{
oid_tbinv_child_oid;
uint8_tbinv_child_hash[BTREE_NODE_HASH_SIZE_MAX];
};
typedefstructbtn_index_node_valbtn_index_node_val_t;
```

```
#defineBTREE_NODE_HASH_SIZE_MAX64
```

For nonhashed B-trees, instead of using this structure, the values are instances of _`oid_t`_ . Because this structureʼs _`oid_t`_ field comes first, code thatʼs expecting only the object identifier of the child node as the B-tree value is still able to read the hashed B-tree by ignoring the hashes.

```
binv_child_oid
```

The object identifier of the child node.

```
oid_tbinv_child_oid;
```

```
binv_child_hash
```

The hash of the child node.

```
uint8_tbinv_child_hash[BTREE_NODE_HASH_SIZE_MAX];
```

The hash algorithm used by this tree determines the length of the hash. See the _`im_hash_type`_ field of _`integrity_ meta_phys_t`_ , and the _`hash_size`_ field of _`j_file_data_hash_val_t`_ .

To compute the hash, use the entire child node object as the input for the hash algorithm specified for this tree. If the output from that hash algorithm is smaller than the _`BTREE_NODE_HASH_SIZE_MAX`_ bytes, treat the remaining bytes as padding — set them to zero when you create a new node, and preserve their value when you modify an existing node.


127

**B-Trees** _`nloc_t`_

## _`BTREE_NODE_HASH_SIZE_MAX`_

The maximum length of a hash that can be stored in this structure.

```
#defineBTREE_NODE_HASH_SIZE_MAX64
```

This value is the same as _`APFS_HASH_MAX_SIZE`_ .

## _`nloc_t`_

A location within a B-tree node.

```
structnloc{
uint16_toff;
uint16_tlen;
};
typedefstructnlocnloc_t;
#defineBTOFF_INVALID0xffff
```

## _`off`_

The offset, in bytes.

```
uint16_toff;
```

Depending on the data type that contains this location, the offset is either implicitly positive or negative, and is counted starting at different points in the B-tree node.

```
len
```

The length, in bytes.

```
uint16_tlen;
```

```
BTOFF_INVALID
```

An invalid offset.

```
#defineBTOFF_INVALID0xffff
```

This value is stored in the _`off`_ field of _`nloc_t`_ to indicate that thereʼs no offset. For example, the last entry in a free list has no entry after it, so it uses this value for its _`off`_ field.

## _`kvloc_t`_

The location, within a B-tree node, of a key and value.

```
structkvloc{
nloc_tk;
nloc_tv;
};
typedefstructkvlockvloc_t;
```


128

**B-Trees** _`kvoff_t`_

The B-tree nodeʼs table of contents uses this structure when the keys and values are not both fixed in size.

```
nloc_t
```

The location of the key.

```
nloc_tk;
```

```
nloc_t
```

The location of the value.

```
nloc_tv;
```

## _`kvoff_t`_

The location, within a B-tree node, of a fixed-size key and value.

```
structkvoff{
uint16_tk;
uint16_tv;
};
typedefstructkvoffkvoff_t;
```

The B-tree nodeʼs table of contents uses this structure when the keys and values are both fixed in size. The meaning of the offsets stored in this structureʼs _`k`_ and _`v`_ fields is the same as the meaning of the _`off`_ field in an instance of _`nloc_t`_ . This structure doesnʼt have a field thatʼs equivalent to the _`len`_ field of _`nloc_t`_ — the key and value lengths are always the same, and omitting them from the table of contents saves space.

## _`k`_

The offset of the key.

```
uint16_tk;
```

```
v
```

The offset of the value.

```
uint16_tv;
```

## B-Tree Flags

The flags used to describe configuration options for a B-tree.

```
#defineBTREE_UINT64_KEYS0x00000001
#defineBTREE_SEQUENTIAL_INSERT0x00000002
#defineBTREE_ALLOW_GHOSTS0x00000004
#defineBTREE_EPHEMERAL0x00000008
#defineBTREE_PHYSICAL0x00000010
#defineBTREE_NONPERSISTENT0x00000020
#defineBTREE_KV_NONALIGNED0x00000040
#defineBTREE_HASHED0x00000080
```


129

**B-Trees** B-Tree Flags

## _`#define BTREE_NOHEADER`_

## _`0x00000100`_

## _`BTREE_UINT64_KEYS`_

Code that works with the B-tree should enable optimizations to make comparison of keys fast.

## _`#define BTREE_UINT64_KEYS 0x00000001`_

This is a hint used by Appleʼs implementation.

## _`BTREE_SEQUENTIAL_INSERT`_

Code that works with the B-tree should enable optimizations to keep the B-tree compact during sequential insertion of entries.

## _`#define BTREE_SEQUENTIAL_INSERT 0x00000002`_

This is a hint used by Appleʼs implementation.

Normally, nodes are split in half when they become almost full. With this flag set, a new node is added to provide the needed space, instead of splitting a node thatʼs almost full. This yields a tree with nodes that are almost full instead of nodes that are about half full.

## _`BTREE_ALLOW_GHOSTS`_

The table of contents is allowed to contain keys that have no corresponding value.

## _`#define BTREE_ALLOW_GHOSTS 0x00000004`_

In the table of contents, a ghost is indicated by a value whose location offset is _`BTOFF_INVALID`_ .

The meaning of a ghost depends on context — it can indicate a key that has been deleted and should be ignored, or a key whose value is implicit from context. For example, in the space managerʼs free queue, a ghost indicates a free extent thatʼs one block long.

Using ghosts to store an implicit value allows more entries to be stored in some circumstances because no space in the value area is used by the ghost.

## _`BTREE_EPHEMERAL`_

The nodes in the B-tree use ephemeral object identifiers to link to child nodes.

## _`#define BTREE_EPHEMERAL 0x00000008`_

If this flag is set, _`BTREE_PHYSICAL`_ must not be set. If neither flag is set, nodes in the B-tree use virtual object identifiers to link to their child nodes.

## _`BTREE_PHYSICAL`_

The nodes in the B-tree use physical object identifiers to link to child nodes.

## _`#define BTREE_PHYSICAL 0x00000010`_

If this flag is set, _`BTREE_EPHEMERAL`_ must not be set. If neither flag is set, nodes in the B-tree use virtual object identifiers to link to their child nodes.


130

**B-Trees** B-Tree Table of Contents Constants

## _`BTREE_NONPERSISTENT`_

The B-tree isnʼt persisted across unmounting.

## _`#define BTREE_NONPERSISTENT 0x00000020`_

This flag is valid only when _`BTREE_EPHEMERAL`_ is also set, and only on in-memory B-trees.

## _`BTREE_KV_NONALIGNED`_

The keys and values in the B-tree arenʼt required to be aligned to eight-byte boundaries.

## _`#define BTREE_KV_NONALIGNED 0x00000040`_

Aligning to eight-byte boundaries avoids unaligned reads on 64-bit platforms, which improves performance, but wastes space on disk for structures whose size isnʼt a multiple of eight bytes.

## _`BTREE_HASHED`_

The nonleaf nodes of this B-tree store a hash of their child nodes.

## _`#define BTREE_HASHED 0x00000080`_

If this flag is set, all nodes of this B-tree have the _`BTNODE_HASHED`_ flag set.

The hash is stored in the _`binv_child_hash`_ field of _`btn_index_node_val_t`_ .

## _`BTREE_NOHEADER`_

The nodes of this B-tree are stored without object headers.

```
#defineBTREE_NOHEADER0x00000100
```

If this flag is set, all nodes of this B-tree have the _`BTNODE_NOHEADER`_ flag set.

## B-Tree Table of Contents Constants

Constants used in managing the size of the table of contents in a B-tree node.

```
#defineBTREE_TOC_ENTRY_INCREMENT8
#defineBTREE_TOC_ENTRY_MAX_UNUSED(2*BTREE_TOC_ENTRY_INCREMENT)
```

These values are used by Appleʼs implementation; other implementations can choose different values. If you donʼt use these values, profile your implementation to determine the performance impact of your chosen values.

## _`BTREE_TOC_ENTRY_INCREMENT`_

The number of entries that are added or removed when changing the size of the table of contents.

```
#defineBTREE_TOC_ENTRY_INCREMENT8
```

## _`BTREE_TOC_ENTRY_MAX_UNUSED`_

The maximum allowed number of unused entries in the table of contents.

```
#defineBTREE_TOC_ENTRY_MAX_UNUSED(2*BTREE_TOC_ENTRY_INCREMENT)
```


131

**B-Trees** B-Tree Node Flags

## B-Tree Node Flags

The flags used with a B-tree node.

```
#defineBTNODE_ROOT0x0001
#defineBTNODE_LEAF0x0002
#defineBTNODE_FIXED_KV_SIZE0x0004
#defineBTNODE_HASHED0x0008
#defineBTNODE_NOHEADER0x0010
#defineBTNODE_CHECK_KOFF_INVAL0x8000
```

## _`BTNODE_ROOT`_

The B-tree node is a root node.

## _`#define BTNODE_ROOT 0x0001`_

If this flag is set, the nodeʼs object type is _`OBJECT_TYPE_BTREE`_ . If this is the treeʼs only node, both _`BTNODE_ROOT`_ and _`BTNODE_LEAF`_ are set. Otherwise, the _`BTNODE_LEAF`_ flag must not be set.

## _`BTNODE_LEAF`_

The B-tree node is a leaf node.

## _`#define BTNODE_LEAF 0x0002`_

If this is the treeʼs only node, the node objectʼs type is _`OBJECT_TYPE_BTREE`_ , and both _`BTNODE_ROOT`_ and _`BTNODE_LEAF`_ are set. Otherwise, the nodeʼs object type is _`OBJECT_TYPE_BTREE_NODE`_ , and the _`BTNODE_ROOT`_ flag must not be set.

## _`BTNODE_FIXED_KV_SIZE`_

The B-tree node has keys and values of a fixed size, and the table of contents omits their lengths.

## _`#define BTNODE_FIXED_KV_SIZE 0x0004`_

If the keys and values both have a fixed size, this flag must be set.

Within the same B-tree, itʼs valid to have a mix of nodes that have this flag set and nodes that donʼt. For example, consider a B-tree with fixed-sized keys and variable-sized values. Leaf nodes in that tree donʼt have this flag set because of the variable-sized values. However, nonleaf nodes in in the same tree _do_ have this flag set. The values stored in nonleaf nodes are object identifiers, which _are_ fixed-sized values; therefore, this flag can be applied to nonleaf nodes of any tree with fixed-size keys.

## _`BTNODE_HASHED`_

The B-tree node contains child hashes.

## _`#define BTNODE_HASHED 0x0008`_

This flag is valid only on B-trees that have the _`BTREE_HASHED`_ flag. You can this flag on a leaf node, for consistency with the nonleaf nodes in the same tree, but it doesnʼt mean anything there and is ignored.


132

**B-Trees** B-Tree Node Constants

If this flag isnʼt set, the _`binv_child_hash`_ field of _`btn_index_node_val_t`_ is unused.

## _`BTNODE_NOHEADER`_

The B-tree node is stored without an object header.

```
#defineBTNODE_NOHEADER0x0010
```

This flag is valid only on B-trees that have the _`BTREE_NOHEADER`_ flag.

If this flag is set, the _`btn_o`_ field of this instance of _`btree_node_phys_t`_ is always zero.

## _`BTNODE_CHECK_KOFF_INVAL`_

The B-tree node is in a transient state.

```
#defineBTNODE_CHECK_KOFF_INVAL0x8000
```

Objects with this flag never appear on disk. If you find an object of this type in production, file a bug against the Apple File System implementation.

This flag isnʼt reserved by Apple; non-Apple implementations of Apple File System can set it on B-tree nodes in memory.

## B-Tree Node Constants

Constants used to determine the size of a B-tree node.

```
#defineBTREE_NODE_SIZE_DEFAULT4096
#defineBTREE_NODE_MIN_ENTRY_COUNT4
```

A node is almost always one logical block in size. Smaller nodes waste space, and larger nodes can experience allocation issues when space is fragmented. For example, a five-block node requires five adjacent blocks to all be free, but on a fragmented disk such a large free space might not exist.

## _`BTREE_NODE_SIZE_DEFAULT`_

The default size, in bytes, of a B-tree node.

```
#defineBTREE_NODE_SIZE_DEFAULT4096
```

## _`BTREE_NODE_MIN_ENTRY_COUNT`_

The minimum number of entries that must be able to fit in a nonleaf B-tree node.

```
#defineBTREE_NODE_MIN_ENTRY_COUNT4
```

To satisfy this requirement, reduce the size of the keys stored in the node. The maximum key size is computed as follows:

```
uint32_tbtree_key_max_size(uint32_tnodesize){
```

```
uint32_tdataspace,esize,count,kvspace;
```

```
dataspace=nodesize-offsetof(btree_node_phys_t,btn_data)
```

- _`sizeof(btree_info_t);`_


133

**B-Trees** B-Tree Node Constants

```
esize=sizeof(kvloc_t);
count=BTREE_TOC_ENTRY_INCREMENT;
kvspace=dataspace-(count*esize);
return((kvspace/BTREE_NODE_MIN_ENTRY_COUNT)-sizeof(oid_t));
```

## _`}`_

## **Note**

This requirement comes from logic in Appleʼs implementation that performs proactive splitting of B-tree nodes.


134
