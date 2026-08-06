<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Snapshot Metadata

Snapshots let you get a stable, read-only copy of the filesystem at a given point in time — for example, while updating a backup of the entire drive. Snapshots are designed to be fast and inexpensive to create; however, deleting a snapshot involves more work.

## _`j_snap_metadata_key_t`_

The key half of a record containing metadata about a snapshot.

```
structj_snap_metadata_key{
j_key_thdr;
}__attribute__((packed));
typedefstructj_snap_metadata_keyj_snap_metadata_key_t;
```

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the snapshotʼs transaction identifier. The type in the header is always _`APFS_TYPE_SNAP_METADATA`_ .

## _`j_snap_metadata_val_t`_

The value half of a record containing metadata about a snapshot.

```
structj_snap_metadata_val{
oid_textentref_tree_oid;
oid_tsblock_oid;
uint64_tcreate_time;
uint64_tchange_time;
uint64_tinum;
uint32_textentref_tree_type;
uint32_tflags;
uint16_tname_len;
uint8_tname[0];
}__attribute__((packed));
typedefstructj_snap_metadata_valj_snap_metadata_val_t;
```

```
extentref_tree_oid
```

The physical object identifier of the B-tree that stores extents information.

```
oid_textentref_tree_oid;
```

```
sblock_oid
```

The physical object identifier of the volume superblock.


117

**Snapshot Metadata** _`j_snap_metadata_val_t`_

## _`oid_t sblock_oid;`_

## _`create_time`_

The time that this snapshot was created.

```
uint64_tcreate_time;
```

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds.

## _`change_time`_

The time that this snapshot was last modified.

## _`uint64_t change_time;`_

This timestamp is represented as the number of nanoseconds since January 1, 1970 at 0�00 UTC, disregarding leap seconds.

## _`inum`_

_No overview available._

```
uint64_tinum;
```

## _`extentref_tree_type`_

The type of the B-tree that stores extents information.

```
uint32_textentref_tree_type;
```

## _`flags`_

A bit field that contains additional information about a snapshot metadata record.

```
uint32_tflags;
```

For the values used in this bit field, see _`snap_meta_flags`_ .

## _`name_len`_

The length of the snapshotʼs name, including the final null character (U+0000).

```
uint16_tname_len;
```

## _`name`_

The snapshotʼs name, represented as a null-terminated UTF-8 string.

```
uint8_tname[0];
```


118

**Snapshot Metadata** _`j_snap_name_key_t`_

## _`j_snap_name_key_t`_

The key half of a snapshot name record.

```
structj_snap_name_key{
j_key_thdr;
uint16_tname_len;
uint8_tname[0];
}__attribute__((packed));
typedefstructj_snap_name_keyj_snap_name_key_t;
```

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is always _`~0ULL`_ . The type in the header is always _`APFS_TYPE_SNAP_NAME`_ .

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

## _`j_snap_name_val_t`_

The value half of a snapshot name record.

```
structj_snap_name_val{
xid_tsnap_xid;
}__attribute__((packed));
typedefstructj_snap_name_valj_snap_name_val_t;
```

```
snap_xid
```

The last transaction identifier included in the snapshot.

```
xid_tsnap_xid;
```

## _`snap_meta_flags`_

_No overview available._

```
typedefenum{
SNAP_META_PENDING_DATALESS=0x00000001,
SNAP_META_MERGE_IN_PROGRESS=0x00000002,
```


119

**Snapshot Metadata** _`snap_meta_ext_obj_phys_t`_

```
}snap_meta_flags;
```

## _`snap_meta_ext_obj_phys_t`_

Additional metadata about snapshots.

```
structsnap_meta_ext_obj_phys{
obj_phys_tsmeop_o;
snap_meta_ext_tsmeop_sme;
}
typedefstructsnap_meta_ext_obj_phys_t;
```

```
smeop_o
```

_No overview available._

```
obj_phys_tsmeop_o;
```

```
smeop_sme
```

_No overview available._

```
snap_meta_ext_tsmeop_sme;
```

## _`snap_meta_ext_t`_

_No overview available._

```
typedefstructsnap_meta_ext{
uint32_tsme_version;
uint32_tsme_flags;
xid_tsme_snap_xid;
uuid_tsme_uuid;
uint64_tsme_token;
```

```
}__attribute__((packed))
typedefstructsnap_meta_extsnap_meta_ext_t;
```

```
sme_version
```

The version of this structure.

```
uint32_tsme_version;
```

```
sme_flags
```

```
uint32_tsme_flags;
```


120

**Snapshot Metadata** _`snap_meta_ext_t`_

```
sme_snap_xid
```

The snapshotʼs transaction identifier.

```
xid_tsme_snap_xid;
```

```
sme_uuid
```

The snapshotʼs UUID.

```
uuid_tsme_uuid;
```

```
sme_token
```

Opaque metadata.

```
uint64_tsme_token;
```


121
