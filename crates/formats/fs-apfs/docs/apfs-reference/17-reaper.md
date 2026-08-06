<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Reaper

The reaper is a mechanism that allows large objects to be deleted over a period spanning multiple transactions. Thereʼs exactly one instance of this structure in a container.

## _`nx_reaper_phys_t`_

_No overview available._

```
structnx_reaper_phys{
obj_phys_tnr_o;
uint64_tnr_next_reap_id;
uint64_tnr_completed_id;
oid_tnr_head;
oid_tnr_tail;
uint32_tnr_flags;
uint32_tnr_rlcount;
uint32_tnr_type;
uint32_tnr_size;
oid_tnr_fs_oid;
oid_tnr_oid;
xid_tnr_xid;
uint32_tnr_nrle_flags;
uint32_tnr_state_buffer_size;
uint8_tnr_state_buffer[];
};
typedefstructnx_reaper_physnx_reaper_phys_t;
```

## _`nx_reap_list_phys_t`_

_No overview available._

```
structnx_reap_list_phys{
obj_phys_tnrl_o;
oid_tnrl_next;
uint32_tnrl_flags;
uint32_tnrl_max;
uint32_tnrl_count;
uint32_tnrl_first;
uint32_tnrl_last;
uint32_tnrl_free;
nx_reap_list_entry_tnrl_entries[];
};
typedefstructnx_reap_list_physnx_reap_list_phys_t;
```

## _`nx_reap_list_entry_t`_

_No overview available._

> 2020-06-22 | Copyright © 2020 Apple Inc. All Rights Reserved.

164

**Reaper** Volume Reaper States

```
structnx_reap_list_entry{
```

```
uint32_tnrle_next;
uint32_tnrle_flags;
uint32_tnrle_type;
uint32_tnrle_size;
oid_tnrle_fs_oid;
oid_tnrle_oid;
xid_tnrle_xid;
```

```
};
typedefstructnx_reap_list_entrynx_reap_list_entry_t;
```

## Volume Reaper States

_No overview available._

```
enum{
APFS_REAP_PHASE_START=0,
APFS_REAP_PHASE_SNAPSHOTS=1,
APFS_REAP_PHASE_ACTIVE_FS=2,
APFS_REAP_PHASE_DESTROY_OMAP=3,
APFS_REAP_PHASE_DONE=4
```

```
};
```

## Reaper Flags

The flags used for general information about a reaper.

```
#defineNR_BHM_FLAG0x00000001
#defineNR_CONTINUE0x00000002
```

These flags are used by the _`nr_flags`_ field of _`nx_reaper_phys_t`_ .

```
NR_BHM_FLAG
```

Reserved.

```
#defineNR_BHM_FLAG0x00000001
```

This flag must always be set.

```
NR_CONTINUE
```

The current object is being reaped.

```
#defineNR_CONTINUE0x00000002
```

## Reaper List Entry Flags

_No overview available._

```
#defineNRLE_VALID0x00000001
#defineNRLE_REAP_ID_RECORD0x00000002
```


165

**Reaper** Reaper List Flags

```
#defineNRLE_CALL0x00000004
#defineNRLE_COMPLETION0x00000008
#defineNRLE_CLEANUP0x00000010
```

## Reaper List Flags

_No overview available._

_`#define NRL_INDEX_INVALID 0xffffffff omap_reap_state_t`_ State used when reaping an object map. _`struct omap_reap_state { uint32_t omr_phase; omap_key_t omr_ok; }; typedef struct omap_reap_state omap_reap_state_t;`_

The reaper uses the state thatʼs stored in this structure to resume after an interruption.

```
omr_phase
```

The current reaping phase.

```
uint32_tomr_phase;
```

For the values used in this field, see Object Map Reaper Phases.

```
omr_ok
```

The key of the most recently freed entry in the object map.

```
omap_key_tomr_ok;
```

This field allows the reaper to resume after the last entry it processed.

## _`omap_cleanup_state_t`_

State used when reaping to clean up deleted snapshots.

```
structomap_cleanup_state{
uint32_tomc_cleaning;
uint32_tomc_omsflags;
xid_tomc_sxidprev;
xid_tomc_sxidstart;
xid_tomc_sxidend;
xid_tomc_sxidnext;
omap_key_tomc_curkey;
```

```
};
```

```
typedefstructomap_cleanup_stateomap_cleanup_state_t;
```


166

**Reaper** _`apfs_reap_state_t`_

## _`omc_cleaning`_

A flag that indicates whether the structure has valid data in it.

## _`uint32_t omc_cleaning;`_

If the value of this field is zero, the structure has been allocated and zeroed, but doesnʼt yet contain valid data. Otherwise, the structure is valid.

## _`omc_omsflags`_

The flags for the snapshot being deleted.

```
uint32_tomc_omsflags;
```

The value for this field is the same as the value of the snapshotʼs _`omap_snapshot_t.oms_flags`_ field.

## _`omc_sxidprev`_

The transaction identifier of the snapshot prior to the snapshots being deleted.

```
xid_tomc_sxidprev;
```

## _`omc_sxidstart`_

The transaction identifier of the first snapshot being deleted.

```
xid_tomc_sxidstart;
```

## _`omc_sxidend`_

The transaction identifier of the last snapshot being deleted.

```
xid_tomc_sxidend;
```

## _`omc_sxidnext`_

The transaction identifier of the snapshot after the snapshots being deleted.

```
xid_tomc_sxidnext;
```

## _`omc_curkey`_

The key of the next object mapping to consider for deletion.

```
omap_key_tomc_curkey;
```

## _`apfs_reap_state_t`_

_No overview available._

```
structapfs_reap_state{
uint64_tlast_pbn;
xid_tcur_snap_xid;
uint32_tphase;
```


167

**Reaper** _`apfs_reap_state_t`_

```
}__attribute__((packed));
```

```
typedefstructapfs_reap_stateapfs_reap_state_t;
```


168
