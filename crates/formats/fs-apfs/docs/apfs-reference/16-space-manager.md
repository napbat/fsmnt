<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Space Manager

The space manager allocates and frees blocks where objects and file data can be stored. Thereʼs exactly one instance of this structure in a container.

## _`chunk_info_t`_

_No overview available._

```
structchunk_info{
uint64_tci_xid;
uint64_tci_addr;
uint32_tci_block_count;
uint32_tci_free_count;
paddr_tci_bitmap_addr;
};
typedefstructchunk_infochunk_info_t;
```

## _`chunk_info_block`_

A block that contains an array of chunk-info structures.

```
structchunk_info_block{
obj_phys_tcib_o;
uint32_tcib_index;
uint32_tcib_chunk_info_count;
chunk_info_tcib_chunk_info[];
};
typedefstructchunk_info_blockchunk_info_block_t;
```

_No overview available._

## _`cib_addr_block`_

A block that contains an array of chunk-info block addresses.

```
structcib_addr_block{
obj_phys_tcab_o;
uint32_tcab_index;
uint32_tcab_cib_count;
paddr_tcab_cib_addr[];
};
typedefstructcib_addr_blockcib_addr_block_t;
```

_No overview available._

## _`spaceman_free_queue_entry_t`_

_No overview available._


159

**Space Manager** _`spaceman_free_queue_key_t`_

```
structspaceman_free_queue_entry{
spaceman_free_queue_key_tsfqe_key;
spaceman_free_queue_val_tsfqe_count;
};
typedefstructspaceman_free_queue_entryspaceman_free_queue_entry_t;
typedefuint64_tspaceman_free_queue_val_t;
```

## _`spaceman_free_queue_key_t`_

_No overview available._

```
structspaceman_free_queue_key{
xid_tsfqk_xid;
paddr_tsfqk_paddr;
};
typedefstructspaceman_free_queue_keyspaceman_free_queue_key_t;
```

## _`spaceman_free_queue_t`_

_No overview available._

```
structspaceman_free_queue{
uint64_tsfq_count;
oid_tsfq_tree_oid;
xid_tsfq_oldest_xid;
uint16_tsfq_tree_node_limit;
uint16_tsfq_pad16;
uint32_tsfq_pad32;
uint64_tsfq_reserved;
};
typedefstructspaceman_free_queuespaceman_free_queue_t;
```

```
spaceman_device_t
```

_No overview available._

```
structspaceman_device{
uint64_tsm_block_count;
uint64_tsm_chunk_count;
uint32_tsm_cib_count;
uint32_tsm_cab_count;
uint64_tsm_free_count;
uint32_tsm_addr_offset;
uint32_tsm_reserved;
uint64_tsm_reserved2;
};
typedefstructspaceman_devicespaceman_device_t;
```


160

**Space Manager** _`spaceman_allocation_zone_boundaries_t`_

## _`spaceman_allocation_zone_boundaries_t`_

## _No overview available._

```
structspaceman_allocation_zone_boundaries{
uint64_tsaz_zone_start;
uint64_tsaz_zone_end;
```

```
};
typedefstructspaceman_allocation_zone_boundaries
spaceman_allocation_zone_boundaries_t;
```

## _`spaceman_allocation_zone_info_phys_t`_

_No overview available._

```
structspaceman_allocation_zone_info_phys{
spaceman_allocation_zone_boundaries_tsaz_current_boundaries;
spaceman_allocation_zone_boundaries_t
saz_previous_boundaries[SM_ALLOCZONE_NUM_PREVIOUS_BOUNDARIES];
uint16_tsaz_zone_id;
uint16_tsaz_previous_boundary_index;
uint32_tsaz_reserved;
```

```
};
```

```
typedefstructspaceman_allocation_zone_info_phys
spaceman_allocation_zone_info_phys_t;
```

```
#defineSM_ALLOCZONE_INVALID_END_BOUNDARY0
#defineSM_ALLOCZONE_NUM_PREVIOUS_BOUNDARIES7
```

## _`spaceman_datazone_info_phys_t`_

_No overview available._

```
structspaceman_datazone_info_phys{
spaceman_allocation_zone_info_phys_t
sdz_allocation_zones[SD_COUNT][SM_DATAZONE_ALLOCZONE_COUNT];
};
typedefstructspaceman_datazone_info_physspaceman_datazone_info_phys_t;
#defineSM_DATAZONE_ALLOCZONE_COUNT8
```

## _`spaceman_phys_t`_

_No overview available._

```
structspaceman_phys{
obj_phys_tsm_o;
uint32_tsm_block_size;
uint32_tsm_blocks_per_chunk;
uint32_tsm_chunks_per_cib;
```


161

**Space Manager** _`sfq`_

```
uint32_tsm_cibs_per_cab;
spaceman_device_tsm_dev[SD_COUNT];
uint32_tsm_flags;
uint32_tsm_ip_bm_tx_multiplier;
uint64_tsm_ip_block_count;
uint32_tsm_ip_bm_size_in_blocks;
uint32_tsm_ip_bm_block_count;
paddr_tsm_ip_bm_base;
paddr_tsm_ip_base;
uint64_tsm_fs_reserve_block_count;
uint64_tsm_fs_reserve_alloc_count;
spaceman_free_queue_tsm_fq[SFQ_COUNT];
uint16_tsm_ip_bm_free_head;
uint16_tsm_ip_bm_free_tail;
uint32_tsm_ip_bm_xid_offset;
uint32_tsm_ip_bitmap_offset;
uint32_tsm_ip_bm_free_next_offset;
uint32_tsm_version;
uint32_tsm_struct_size;
spaceman_datazone_info_phys_tsm_datazone;
};
typedefstructspaceman_physspaceman_phys_t;
```

```
#defineSM_FLAG_VERSIONED0x00000001
```

## _`sfq`_

_No overview available._

```
enumsfq{
SFQ_IP=0,
SFQ_MAIN=1,
SFQ_TIER2=2,
SFQ_COUNT=3
};
```

## _`smdev`_

_No overview available._

```
enumsmdev{
SD_MAIN=0,
SD_TIER2=1,
SD_COUNT=2
};
```

## Chunk Info Block Constants

_No overview available._


162

**Space Manager** Internal-Pool Bitmap

```
#defineCI_COUNT_MASK0x000fffff
#defineCI_COUNT_RESERVED_MASK0xfff00000
```

Internal-Pool Bitmap

_No overview available._

```
#defineSPACEMAN_IP_BM_TX_MULTIPLIER16
#defineSPACEMAN_IP_BM_INDEX_INVALID0xffff
#defineSPACEMAN_IP_BM_BLOCK_COUNT_MAX0xfffe
```


163
