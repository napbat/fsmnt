<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Fusion

_No overview available._

## _`fusion_wbc_phys_t`_

_No overview available._

```
typedefstruct{
obj_phys_tfwp_objHdr;
uint64_tfwp_version;
oid_tfwp_listHeadOid;
oid_tfwp_listTailOid;
uint64_tfwp_stableHeadOffset;
uint64_tfwp_stableTailOffset;
uint32_tfwp_listBlocksCount;
uint32_tfwp_reserved;
uint64_tfwp_usedByRC;
prange_tfwp_rcStash;
}fusion_wbc_phys_t;
```

## _`fusion_wbc_list_entry_t`_

_No overview available._

```
typedefstruct{
paddr_tfwle_wbcLba;
paddr_tfwle_targetLba;
uint64_tfwle_length;
}fusion_wbc_list_entry_t;
```

## _`fusion_wbc_list_phys_t`_

_No overview available._

```
typedefstruct{
obj_phys_tfwlp_objHdr;
uint64_tfwlp_version;
uint64_tfwlp_tailOffset;
uint32_tfwlp_indexBegin;
uint32_tfwlp_indexEnd;
uint32_tfwlp_indexMax;
uint32_tfwlp_reserved;
fusion_wbc_list_entry_tfwlp_listEntries[];
}fusion_wbc_list_phys_t;
```

This mapping keeps track of data from the hard drive thatʼs cached on the solid-state drive. For _read_ caching, the same data is stored on both the hard drive and the solid-state drive. For _write_ caching, the data is stored on the solid-


172

**Fusion** Address Markers

state drive, but space for the data has been allocated on the hard drive, and the data will eventually be copied to that space.

## Address Markers

_No overview available._

```
#defineFUSION_TIER2_DEVICE_BYTE_ADDR0x4000000000000000ULL
```

```
#defineFUSION_TIER2_DEVICE_BLOCK_ADDR(_blksize)\
```

```
(FUSION_TIER2_DEVICE_BYTE_ADDR>>__builtin_ctzl(_blksize))
```

```
#defineFUSION_BLKNO(_fusion_tier2,_blkno,_blksize)\
((_fusion_tier2)\
?(FUSION_TIER2_DEVICE_BLOCK_ADDR(_blksize)|(_blkno))\
:(_blkno))
```

```
fusion_mt_key_t
```

_No overview available._

_`typedef paddr_t fusion_mt_key_t; fusion_mt_val_t` No overview available._ _`typedef struct { paddr_t fmv_lba; uint32_t fmv_length; uint32_t fmv_flags; } fusion_mt_val_t;`_

## Fusion Middle-Tree Flags

_No overview available._

```
#defineFUSION_MT_DIRTY(1<<0)
#defineFUSION_MT_TENANT(1<<1)
#defineFUSION_MT_ALLFLAGS(FUSION_MT_DIRTY|FUSION_MT_TENANT)
```


173
