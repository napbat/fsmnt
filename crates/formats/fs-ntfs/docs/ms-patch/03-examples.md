# 3 Structure Examples

The **LZXD** bitstream is to be interpreted as a sequence of aligned 16-bit integers stored in the order
least significant byte to most significant byte (little-endian words).

The only exception is the uncompressed data bytes stored in the uncompressed block interpreted as a
sequence of bytes. The following example is a sample encoding sequence of a simple 3-byte text input
"abc" encoded with a **Block Type** field value of 3 (uncompressed block).

| Bits to decode | Value of decoded bits | Interpretation |
|---|---|---|
| 16 | 0x0014 | Chunk size: 20 bytes |
| 1 | 0 | E8 translation: disabled |
| 3 | 3 (binary 011) | **Block Type**: uncompressed |
| 24 | 0x000003 | **Block Size**: 3 bytes |
| 4 | binary 0000 | Padding to word-align following |
| 4 bytes | 0x00000001 (little-endian DWORD [MS-DTYP]) | R0: 1 |
| 4 bytes | 0x00000001 (little-endian DWORD) | R1: 1 |
| 4 bytes | 0x00000001 (little-endian DWORD) | R2: 1 |
| 3 bytes | 0x61, 0x62, 0x63 | Uncompressed bytes: "abc" |
| 1 byte | 0x00 | Padding to restore word alignment |

Raw hexadecimal compressed byte sequence of the encoded fields:

```
14 00 00 30 30 00 01 00 00 00 01 00 00 00 01 00 00 00 61 62 63 00
```
