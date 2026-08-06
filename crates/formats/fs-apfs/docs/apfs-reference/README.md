# Apple File System Reference (2020-06-22)

The official **Apple File System Reference** (Apple Inc., revision 2020-06-22),
split from `Apple-File-System-Reference.pdf` into one Markdown file per chapter.
Converted from PDF with `pymupdf4llm`.

This is the only on-disk format specification Apple publishes. It is authoritative
for structure layouts but incomplete in places (some behavior is described only as
"reserved" or left to the implementation); cross-check against the community
sources listed in [`../references.md`](../references.md) when a field is unclear.

> **Conversion note:** C declarations inside fenced code blocks lost inter-token
> spacing during PDF extraction (e.g. `typedefint64_tpaddr_t;`). Field names and
> prose are intact; the original PDF is kept alongside for verification.

## Files

| File | What to find here |
|------|-------------------|
| `00-introduction.md` | **Layered design** — container layer vs. file-system layer, the `nx_`/`j_` prefixes, physical/ephemeral/virtual objects, checkpoints, copy-on-write, crash protection |
| `01-general-purpose-types.md` | `paddr_t` (physical block address), `prange_t` (physical range), `uuid_t` |
| `02-objects.md` | **`obj_phys_t`** common object header (`o_cksum`, `o_oid`, `o_xid`, `o_type`, `o_subtype`), `oid_t`, `xid_t`, OID constants, object type masks, **all object types**, object type flags (`OBJ_VIRTUAL`/`OBJ_PHYSICAL`/`OBJ_EPHEMERAL`, `OBJ_ENCRYPTED`) |
| `03-efi-jumpstart.md` | Booting from an APFS partition, **`nx_efi_jumpstart_t`**, `APFS_GPT_PARTITION_UUID` and other partition UUIDs |
| `04-container.md` | **`nx_superblock_t`** (container superblock, magic `NXSB`), container flags, container feature flags (optional / read-only compatible / incompatible), block & container sizes, **`checkpoint_map_phys_t`**, `checkpoint_mapping_t`, checkpoint flags, `evict_mapping_val_t` |
| `05-object-maps.md` | **`omap_phys_t`** object map, `omap_key_t`/`omap_val_t`, `omap_snapshot_t`, object map value flags, snapshot flags, object map flags & constants, reaper phases |
| `06-volumes.md` | **`apfs_superblock_t`** (volume superblock, magic `APSB`), `apfs_modified_by_t`, volume flags, **volume roles**, volume feature flags (optional / read-only compatible / incompatible) |
| `07-file-system-objects.md` | **`j_key_t`** file-system record header, `j_inode_key_t`/`j_inode_val_t`, `j_drec_key_t`/`j_drec_hashed_key_t`/`j_drec_val_t` (directory entries), `j_dir_stats_*`, `j_xattr_key_t`/`j_xattr_val_t` |
| `08-file-system-constants.md` | `j_obj_types`, `j_obj_kinds`, **`j_inode_flags`**, `j_xattr_flags`, `dir_rec_flags`, reserved inode numbers, extended-attribute constants, file-extent constants, file modes, directory-entry file types |
| `09-data-streams.md` | **File extents** — `j_phys_ext_key_t`/`j_phys_ext_val_t`, `j_file_extent_key_t`/`j_file_extent_val_t`, `j_dstream_id_*`, `j_xattr_dstream_t`, **`j_dstream_t`** |
| `10-extended-fields.md` | **`xf_blob_t`**, `x_field_t`, extended-field types (inode and directory-record), extended-field flags |
| `11-siblings.md` | **Hard links** — `j_sibling_key_t`/`j_sibling_val_t`, `j_sibling_map_key_t`/`j_sibling_map_val_t` |
| `12-snapshot-metadata.md` | `j_snap_metadata_key_t`/`j_snap_metadata_val_t`, `j_snap_name_key_t`/`j_snap_name_val_t`, `snap_meta_flags`, `snap_meta_ext_t` |
| `13-b-trees.md` | **`btree_node_phys_t`** B-tree node, `btree_info_fixed_t`/`btree_info_t`, `btn_index_node_val_t`, `nloc_t`/`kvloc_t`/`kvoff_t`, B-tree flags, table-of-contents constants, node flags & constants |
| `14-encryption.md` | Accessing encrypted objects, `j_crypto_key_t`/`j_crypto_val_t`, `wrapped_crypto_state_t`, `wrapped_meta_crypto_state_t`, encryption types, **protection classes**, encryption identifiers, **keybag** (`kb_locker_t`, `keybag_entry_t`, `media_keybag_t`, keybag tags) |
| `15-sealed-volumes.md` | **`integrity_meta_phys_t`**, integrity metadata version constants & flags, `apfs_hash_type_t`, `fext_tree_*`, `j_file_info_*`, `j_file_data_hash_val_t` |
| `16-space-manager.md` | **`spaceman_phys_t`**, `chunk_info_t`/`chunk_info_block`, `spaceman_free_queue_*`, `spaceman_device_t`, allocation zones, internal-pool bitmap |
| `17-reaper.md` | **`nx_reaper_phys_t`** (deferred deletion), `nx_reap_list_phys_t`/`nx_reap_list_entry_t`, volume reaper states, reaper flags, `omap_reap_state_t`, `apfs_reap_state_t` |
| `18-encryption-rolling.md` | **`er_state_phys_t`** (encryption rolling), `er_phase_t`, `er_recovery_block_phys_t`, `gbitmap_phys_t`, ER checksum block sizes, ER flags & constants |
| `19-fusion.md` | **Fusion drives** — `fusion_wbc_phys_t` write-back cache, `fusion_wbc_list_*`, address markers, `fusion_mt_key_t`/`fusion_mt_val_t` middle tree |
| `20-symbol-index.md` | Alphabetical symbol index and the spec's own revision history |

## Quick Lookup

| Question | File |
|----------|------|
| Container vs. file-system layer? | `00-introduction.md` |
| What is an object map / virtual object? | `00-introduction.md`, `05-object-maps.md` |
| Common object header layout? | `02-objects.md` |
| How is the Fletcher checksum stored? | `02-objects.md` (`o_cksum`) |
| Container superblock fields? | `04-container.md` |
| How to find the latest checkpoint? | `04-container.md` |
| Volume superblock fields and roles? | `06-volumes.md` |
| Inode record layout? | `07-file-system-objects.md`, `08-file-system-constants.md` |
| Directory entry / hashed directory entry? | `07-file-system-objects.md` |
| Where is file content mapped? | `09-data-streams.md` |
| Extended fields (timestamps, sparse, etc.)? | `10-extended-fields.md` |
| Hard link siblings? | `11-siblings.md` |
| Snapshot records? | `12-snapshot-metadata.md` |
| B-tree node and key/value layout? | `13-b-trees.md` |
| Protection classes and keybag? | `14-encryption.md` |
| Sealed volume / integrity (hashed files)? | `15-sealed-volumes.md` |
| Free space and allocation tracking? | `16-space-manager.md` |
| Deferred deletion (reaper)? | `17-reaper.md` |
| Fusion (SSD + HDD) drives? | `19-fusion.md` |
