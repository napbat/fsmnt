<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## Siblings

Hard links that all refer to the same inode are called _siblings_ . Each sibling has its own identifier thatʼs used instead of the shared inode number when siblings need to be distinguished. For example, some Carbon APIs in macOS use sibling identifiers.

The sibling whose identifier is the lowest number is called the _primary link_ . The other siblings copy various properties of the primary link, as discussed in _`j_inode_val_t`_ .

You use sibling links and sibling maps to convert between sibling identifiers and inode numbers. Sibling-link records let you find all the hard links whose target is a given inode. Sibling-map records let you find the target inode of a given hard link.

## _`j_sibling_key_t`_

The key half of a sibling-link record.

```
structj_sibling_key{
j_key_thdr;
uint64_tsibling_id;
}__attribute__((packed));
typedefstructj_sibling_keyj_sibling_key_t;
```

## _`hdr`_

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the file-system objectʼs identifier, that is, its inode number. The type in the header is always _`APFS_TYPE_SIBLING_LINK`_ .

## _`sibling_id`_

The siblingʼs unique identifier.

```
uint64_tsibling_id;
```

This value matches the object identifier for the sibling map record ( _`j_sibling_key_t`_ ).

## _`j_sibling_val_t`_

The value half of a sibling-link record.

```
structj_sibling_val{
uint64_tparent_id;
uint16_tname_len;
uint8_tname[0];
}__attribute__((packed));
typedefstructj_sibling_valj_sibling_val_t;
```


115

**Siblings** _`j_sibling_map_key_t`_

## _`parent_id`_

The object identifier for the inode thatʼs the parent directory.

```
uint64_tparent_id;
```

```
name_len
```

The length of the name, including the final null character (U+0000).

```
uint16_tname_len;
```

## _`name`_

The name, represented as a null-terminated UTF-8 string.

```
uint8_tname[0];
```

## _`j_sibling_map_key_t`_

The key half of a sibling-map record.

```
structj_sibling_map_key{
j_key_thdr;
}__attribute__((packed));
typedefstructj_sibling_map_keyj_sibling_map_key_t;
```

```
hdr
```

The recordʼs header.

```
j_key_thdr;
```

The object identifier in the header is the siblingʼs unique identifier, which matches the _`sibling_id`_ field of _`j_sibling_key_t`_ . The type in the header is always _`APFS_TYPE_SIBLING_MAP`_ .

## _`j_sibling_map_val_t`_

The value half of a sibling-map record.

```
structj_sibling_map_val{
uint64_tfile_id;
}__attribute__((packed));
typedefstructj_sibling_map_valj_sibling_map_val_t;
```

## _`file_id`_

The inode number of the underlying file.

```
uint64_tfile_id;
```


116
