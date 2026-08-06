<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## EFI Jumpstart

A partition formatted using the Apple File System contains an embedded EFI driver thatʼs used to boot a machine from that partition.

## Booting from an Apple File System Partition

You can locate the EFI driver by reading a few data structures, starting at a known physical address on disk. You donʼt need any support for reading or mounting Apple File System to locate the EFI driver. This design intentionally simplifies the steps needed to boot, which means the code needed to boot a piece of hardware or virtualization software can likewise be simpler. To boot using the embedded EFI driver, do the following:

1. Read physical block zero from the partition. This block contains a copy of the container superblock, which is an instance of _`nx_superblock_t`_ .

2. Read the _`nx_o`_ field of the superblock, which is an instance of _`obj_phys_t`_ . Then read the _`o_cksum`_ field of the _`nx_o`_ field of the superblock, which contains the Fletcher 64 checksum of the object. Verify that the checksum is correct.

3. Read the _`nx_magic`_ field of the superblock. Verify that the fieldʼs value is _`NX_MAGIC`_ (the four-character code _`'BSXN'`_ ).

4. Read the _`nx_efi_jumpstart`_ field of the superblock. This field contains the physical block address (also referred to as the physical object identifier) for the EFI jumpstart information, which is an instance of _`nx_efi_jumpstart_t`_ .

5. Read the _`nej_magic`_ field of the EFI jumpstart information. Verify that the fieldʼs value is _`NX_EFI_JUMP START_MAGIC`_ (the four-character code _`'RDSJ'`_ ).

6. Read the _`nej_o`_ field of the EFI jumpstart information, which is an instance of _`obj_phys_t`_ . Then read the _`o_cksum`_ field of the _`nej_o`_ field of the jumpstart information, which contains the Fletcher 64 checksum of the object. Verify that the checksum is correct.

7. Read the _`nej_version`_ field of the EFI jumpstart information. This field contains the EFI jumpstart version number. Verify that the fieldʼs value is _`NX_EFI_JUMPSTART_VERSION`_ (the number one).

8. Read the _`nej_efi_file_len`_ field of the jumpstart information. This field contains the length, in bytes, of the embedded EFI driver. Allocate a contiguous block of memory of at least that size, which youʼll later use to store the EFI driver.

9. Read the _`nej_num_extents`_ field of the jumpstart information, and then read that number of _`prange_t`_ records from the _`nej_rec_extents`_ field.

10. Read each extent of the EFI driver into memory, contiguously, in the order theyʼre listed.

11. Load the EFI driver and start executing it.

## **Implementation Outline**

The code listing below shows one way to boot using the embedded EFI driver, assuming the functions listed at the beginning are defined.

```
nx_superblock_t*read_superblock(intaddress){
```


22

**EFI Jumpstart** Booting from an Apple File System Partition

```
//Readthegivenphysicalblockfromdisk
//andreturnitscontentsasapointertoannx_superblock_t.
}
```

```
nx_efi_jumpstart_t*read_jumpstart(intaddress){
//Readthegivenphysicalblockfromdisk
//andreturnitscontentsasapointertoannx_efi_jumpstart_t.
}
```

```
void*read_block(intaddress){
//Readthegivenphysicalblockfromdisk
//andreturnapointertoitscontents.
}
```

```
uint8_t*fletcher64_checksum(void*object){
//CalculateandreturnaFletcher64checksum.
}
```

```
voidassert_arrays_equal(intlength,uint8_t*x,uint8_t*y){
//Assertthatthegivenarrayscontainthesamedata.
}
```

```
voidload_and_execute(void*address){
//LoadtheEFIdriveratthespecifiedaddress
//andthenstartexecutingit.
```

```
}
```

```
intmain(){
nx_superblock_t*superblock=read_superblock(0);
assert(superblock->nx_o.o_cksum==fletcher64_checksum(&superblock));
assert(superblock->nx_magic=='BSXN');
```

```
paddr_tjumpstart_address=superblock->nx_efi_jumpstart;
nx_efi_jumpstart_t*jumpstart=read_jumpstart(jumpstart_address);
```

```
uint8_t*checksum=fletcher64_checksum(&jumpstart);
assert_arrays_equal(MAX_CKSUM_SIZE,jumpstart->nej_o.o_cksum,checksum);
assert(jumpstart->nej_version==1);
```

```
void*efi_driver=malloc(jumpstart->nej_efi_file_len);
void*efi_driver_cursor=efi_driver;
```

```
for(inti=0;i<jumpstart->nej_num_extents;i++){
prange_tefi_extent_address=jumpstart->nej_rec_extents[i];
for(intj=0;j<efi_extent_address.pr_block_count;j++){
void*efi_block=read_block(efi_extent_address.pr_start_paddr+j);
memcpy(efi_driver_cursor,efi_block,superblock->nx_block_size);
efi_driver_cursor+=superblock->nx_block_size;
```


23

**EFI Jumpstart** _`nx_efi_jumpstart_t`_

```
}
}
load_and_execute(efi_driver);
return0;
}
```

## _`nx_efi_jumpstart_t`_

Information about the embedded EFI driver thatʼs used to boot from an Apple File System partition.

```
structnx_efi_jumpstart{
obj_phys_tnej_o;
uint32_tnej_magic;
uint32_tnej_version;
uint32_tnej_efi_file_len;
uint32_tnej_num_extents;
uint64_tnej_reserved[16];
prange_tnej_rec_extents[];
};
typedefstructnx_efi_jumpstartnx_efi_jumpstart_t;
#defineNX_EFI_JUMPSTART_MAGIC'RDSJ'
#defineNX_EFI_JUMPSTART_VERSION1
```

```
nej_o
```

The objectʼs header.

```
obj_phys_tnej_o;
```

```
nej_magic
```

A number that can be used to verify that youʼre reading an instance of _`nx_efi_jumpstart_t`_ .

```
uint32_tnej_magic;
```

The value of this field is always _`NX_EFI_JUMPSTART_MAGIC`_ .

```
nej_version
```

The version of this data structure.

```
uint32_tnej_version;
```

The value of this field is always _`NX_EFI_JUMPSTART_VERSION`_ .

```
nej_efi_file_len
```

The size, in bytes, of the embedded EFI driver.

```
uint32_tnej_efi_file_len;
```


24

**EFI Jumpstart** Partition UUIDs

## _`nej_num_extents`_

The number of extents in the array.

```
uint32_tnej_num_extents;
```

```
nej_reserved
```

Reserved.

```
uint64_tnej_reserved[16];
```

Populate this field with zero when you create a new instance, and preserve its value when you modify an existing instance.

## _`nej_rec_extents`_

The locations where the EFI driver is stored.

```
prange_tnej_rec_extents[];
```

## _`NX_EFI_JUMPSTART_MAGIC`_

The value of the _`nej_magic`_ field.

```
#defineNX_EFI_JUMPSTART_MAGIC'RDSJ'
```

This magic number was chosen because in hex dumps it appears as “JSDR”, which is an abbreviated form of _jumpstart driver record_ .

## _`NX_EFI_JUMPSTART_VERSION`_

The version number for the EFI jumpstart.

```
#defineNX_EFI_JUMPSTART_VERSION1
```

## Partition UUIDs

Partition types used in GUID partition table entries.

```
#defineAPFS_GPT_PARTITION_UUID”7C3457EF-0000-11AA-AA11-00306543ECAC”
```

## _`APFS_GPT_PARTITION_UUID`_

The partition type for a partition that contains an Apple File System container.

```
#defineAPFS_GPT_PARTITION_UUID”7C3457EF-0000-11AA-AA11-00306543ECAC”
```


25
