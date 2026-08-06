<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Encryption Rolling

_No overview available._

```
er_state_phys_t
```

_No overview available._

```
structer_state_phys{
```

```
er_state_phys_header_tersb_header;
uint64_tersb_flags;
uint64_tersb_snap_xid;
uint64_tersb_current_fext_obj_id;
uint64_tersb_file_offset;
uint64_tersb_progress;
uint64_tersb_total_blk_to_encrypt;
oid_tersb_blockmap_oid;
uint64_tersb_tidemark_obj_id;
uint64_tersb_recovery_extents_count;
oid_tersb_recovery_list_oid;
uint64_tersb_recovery_length;
```

```
};
```

```
typedefstructer_state_physer_state_phys_t;
```

```
structer_state_phys_v1{
```

```
er_state_phys_header_tersb_header;
uint64_tersb_flags;
uint64_tersb_snap_xid;
uint64_tersb_current_fext_obj_id;
uint64_tersb_file_offset;
uint64_tersb_fext_pbn;
uint64_tersb_paddr;
uint64_tersb_progress;
uint64_tersb_total_blk_to_encrypt;
uint64_tersb_blockmap_oid;
uint32_tersb_checksum_count;
uint32_tersb_reserved;
uint64_tersb_fext_cid;
uint8_tersb_checksum[0];
```

```
};
```

```
typedefstructer_state_physer_state_phys_v1_t;
```

```
structer_state_phys_header{
```

```
obj_phys_tersb_o;
uint32_tersb_magic;
uint32_tersb_version;
};
```


169

**Encryption Rolling** _`er_phase_t`_

```
typedefstructer_state_phys_headerer_state_phys_header_t;
```

## _`er_phase_t`_

_No overview available._

```
enumer_phase_enum{
ER_PHASE_OMAP_ROLL=1,
ER_PHASE_DATA_ROLL=2,
ER_PHASE_SNAP_ROLL=3,
};
typedefenumer_phase_enumer_phase_t;
```

```
er_recovery_block_phys_t
```

_No overview available._

```
structer_recovery_block_phys{
obj_phys_terb_o;
uint64_terb_offset;
oid_terb_next_oid;
uint8_terb_data[0];
};
typedefstructer_recovery_block_physer_recovery_block_phys_t;
gbitmap_block_phys_t
```

_No overview available._

_`struct gbitmap_block_phys { obj_phys_t bmb_o; uint64_t bmb_field[0]; }; typedef struct gbitmap_block_phys gbitmap_block_phys_t; gbitmap_phys_t` No overview available._ _`struct gbitmap_phys { obj_phys_t bm_o; oid_t bm_tree_oid; uint64_t bm_bit_count; uint64_t bm_flags; }; typedef struct gbitmap_phys gbitmap_phys_t;`_

Encryption-Rolling Checksum Block Sizes

_No overview available._


170

**Encryption Rolling** Encryption Rolling Flags

```
enum{
ER_512B_BLOCKSIZE=0,
ER_2KiB_BLOCKSIZE=1,
ER_4KiB_BLOCKSIZE=2,
ER_8KiB_BLOCKSIZE=3,
ER_16KiB_BLOCKSIZE=4,
ER_32KiB_BLOCKSIZE=5,
ER_64KiB_BLOCKSIZE=6,
};
```

## Encryption Rolling Flags

_No overview available._

```
#defineERSB_FLAG_ENCRYPTING0x00000001
#defineERSB_FLAG_DECRYPTING0x00000002
#defineERSB_FLAG_KEYROLLING0x00000004
#defineERSB_FLAG_PAUSED0x00000008
#defineERSB_FLAG_FAILED0x00000010
#defineERSB_FLAG_CID_IS_TWEAK0x00000020
#defineERSB_FLAG_FREE_10x00000040
#defineERSB_FLAG_FREE_20x00000080
```

```
#defineERSB_FLAG_CM_BLOCK_SIZE_MASK0x00000F00
#defineERSB_FLAG_CM_BLOCK_SIZE_SHIFT8
```

```
#defineERSB_FLAG_ER_PHASE_MASK0x00003000
#defineERSB_FLAG_ER_PHASE_SHIFT12
#defineERSB_FLAG_FROM_ONEKEY0x00004000
```

## Encryption-Rolling Constants

_No overview available._

```
#defineER_CHECKSUM_LENGTH8
#defineER_MAGIC'FLAB'
#defineER_VERSION1
```

```
#defineER_MAX_CHECKSUM_COUNT_SHIFT16
#defineER_CUR_CHECKSUM_COUNT_MASK0x0000FFFF
```


171
