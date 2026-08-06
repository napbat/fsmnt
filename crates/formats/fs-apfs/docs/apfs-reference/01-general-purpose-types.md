<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## General-Purpose Types

Basic types that are used in a variety of contexts, and arenʼt associated with any particular functionality.

## _`paddr_t`_

A physical address of an on-disk block.

```
typedefint64_tpaddr_t;
```

Negative numbers arenʼt valid addresses. This value is modeled as a signed integer to match IOKit.

## _`prange_t`_

A range of physical addresses.

```
structprange{
paddr_tpr_start_paddr;
uint64_tpr_block_count;
};
typedefstructprangeprange_t;
```

```
pr_start_paddr
```

The first block in the range.

```
paddr_tpr_start_paddr;
```

```
pr_block_count
```

The number of blocks in the range.

```
uint64_tpr_block_count;
```

```
uuid_t
```

A universally unique identifier.

```
typedefunsignedcharuuid_t[16];
```


9
