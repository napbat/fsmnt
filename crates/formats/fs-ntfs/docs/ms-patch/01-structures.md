# 2 Structures

**LZXD** compressed data consists of a header that indicates the file translation size, followed by a
sequence of compressed blocks. A stream of uncompressed input can be output as multiple
compressed LZXD blocks to improve compression, because each compressed block contains its own
statistical tree structures.

A block can be one of the following types:

- Uncompressed block, as specified in section 2.3.2.1.
- Verbatim block, as specified in section 2.3.2.2.
- Aligned offset, as specified in section 2.3.2.3.

In this document, ranges are specified using interval notation. A range in parenthesis "()" does not
include the upper and lower endpoints. A range in brackets "[]" does include the upper and lower
endpoints.

## 2.1 Concepts

### 2.1.1 Bitstream

An **LZXD** bitstream is encoded as a sequence of aligned 16-bit (or 2-byte) integers stored in the least-
significant-byte to most-significant-byte order, also known as byte-swapped, or **little-endian**, words.
Given an input byte stream in hex `1A, 2B, 3C, 4D, 5E, 6F, …`, the output byte stream MUST be
byte-swapped in 16-bit words.

### 2.1.2 Window Size

The sliding window size MUST be a power of 2, from 2^17 (128 KB) up to 2^25 (32 MB). The window
size is not stored in the compressed data stream and MUST be specified to the decoder before decoding
begins. The window size SHOULD be the smallest power of two between 2^17 and 2^25 that is greater
than or equal to the sum of the size of the reference data rounded up to a multiple of 32,768 and the
size of the subject data.

### 2.1.3 Reference Data

For delta compression, the reference data is a sequence of bytes given to the compressor before
compressing the subject data. The exact same reference data sequence MUST be given to the
decompressor before decompression. The reference data sequence is treated as logically prepended to
the subject data sequence being compressed or decompressed. During decompression, match offsets
are negative displacements from the "current position" in the output stream, up to the specified
window size. When match offset values exceed the number of bytes already emitted in the
uncompressed output stream, they are pointing into the reference data that is logically prepended to
the subject data.

Example: the reference data is 10 bytes long and consists of the sequence "ABCDEFGHIJ". The
data to be compressed (subject data) is also 10 bytes long and consists of "abcDEFabce". A valid
encoded sequence would consist of the following tokens:

```
'a', 'b', 'c', (match offset -10, length 3), (match offset -6, length 3), 'e'
```

The first match offset exceeds the amount of subject data already in the window, pointing instead into
the reference data portion. The second match offset does not exceed the amount of subject data in
the window and instead refers to a portion of the subject data previously compressed or
decompressed.

### 2.1.4 Repeated Offsets

**LZXD** compression extends the conventional LZ77 sliding window algorithm format, as specified in
[UASDC], in several ways, one of which is in the use of repeated offset codes. Three match offset
codes, named the repeated offset codes, are reserved to indicate that the current match offset is the
same as that of one of the three previous matches, which is not itself a repeated offset.

The three special offset codes are encoded as offset values 0, 1, and 2 (encoding an offset of 0
means "use the most recent nonrepeated match offset"; an offset of 1 means "use the second most
recent nonrepeated match offset"; and so on). All remaining encoded offset values are displaced by
real offset +2, as shown in the following table, which prevents matches at offsets WINDOW_SIZE,
WINDOW_SIZE-1, and WINDOW_SIZE-2.

| Encoded offset | Real offset |
|---|---|
| 0 | Most recent real match offset |
| 1 | Second most recent match offset |
| 2 | Third most recent match offset |
| 3 | 1 (closest allowable) |
| 4 | 2 |
| 5 | 3 |
| 6 | 4 |
| 7 | 5 |
| 8 | 6 |
| 500 | 498 |
| X+2 | X |
| WINDOW_SIZE-1 (maximum possible) | WINDOW_SIZE-3 |

The three most recent real match offsets are kept in a list:

- Let R0 be defined as the most recent real offset.
- Let R1 be defined as the second most recent offset.
- Let R2 be defined as the third most recent offset.

The list is managed similarly to a least recently used queue, with the exception of the cases when R1
or R2 is output. In these cases, R1 or R2 is simply swapped with R0, which requires fewer operations
than a least recently used queue would.

The initial state of R0, R1, R2 is (1, 1, 1).

| Match offset X where... | Operation |
|---|---|
| X≠R0 and X≠R1 and X≠R2 | R2←R1, R1←R0, R0←X |
| X = R0 | None |
| X = R1 | swap R0↔R1 |
| X = R2 | swap R0↔R2 |

### 2.1.5 Match Lengths

The minimum match length (number of bytes) encoded by **LZXD** is 2 bytes, and the maximum match
length is 32,768 bytes. However, no match of any length can span a modulo 32-KB boundary in the
uncompressed stream. Match-length encoding is combined with match-position encoding as described
in section 2.6. Match length can be larger than the repeated offset, which means the matched
substrings can overlap.

### 2.1.6 Position Slot

The window size determines the number of window subdivisions, or position slots, as shown in the
following table.

| Window size | Position slots required |
|---|---|
| 128 KB | 34 |
| 256 KB | 36 |
| 512 KB | 38 |
| 1 MB | 42 |
| 2 MB | 50 |
| 4 MB | 66 |
| 8 MB | 98 |
| 16 MB | 162 |
| 32 MB | 290 |

## 2.2 Header

### 2.2.1 Chunk Size

The **LZXD** compressor emits chunks of compressed data. A chunk represents exactly 32 KB of
uncompressed data until the last chunk in the stream, which can represent less than 32 KB. To
ensure that an exact number of input bytes represent an exact number of output bytes for each
chunk, after each 32 KB of uncompressed data is represented in the output compressed bitstream, the
output bitstream is padded with up to 15 bits of zeros to realign the bitstream on a 16-bit boundary
(even byte boundary) for the next 32 KB of data. This results in a compressed chunk of a byte-aligned
size. The compressed chunk could be smaller than 32 KB or larger than 32 KB if the data is
incompressible when the chunk is not the last one.

The LZXD engine encodes a compressed, chunk-size prefix field preceding each compressed chunk in
the compressed byte stream. The compressed, chunk-size prefix field is a byte aligned, little-endian,
16-bit field. The chunk prefix chain could be followed in the compressed stream without
decompressing any data. The next chunk prefix is at a location computed by the absolute byte offset
location of this chunk prefix plus 2 (for the size of the chunk-size prefix field) plus the current chunk
size.

### 2.2.2 E8 Call Translation

E8 call translation is an optional feature that can be used when the data to compress contains x86
instruction sequences. E8 translation operates as a preprocessing stage before compressing each
chunk, and the compressed stream header contains a bit that indicates whether the decoder shall
reverse the translation as a postprocessing step after decompressing each chunk.

The x86 instruction beginning with a byte value of 0xE8 is followed by a 32-bit, little-endian relative
displacement to the call target. When E8 call translation is enabled, the following preprocessing steps
are performed on the uncompressed input before compression (assuming little-endian byte ordering):

Let `chunk_offset` refer to the total number of uncompressed bytes preceding this chunk.

Let `E8_file_size` refer to the caller-specified value given to the compressor or decoded from the header
of the compressed stream during decompression.

**E8 translation (compression preprocessing):**

```c
if ((chunk_offset < 0x40000000) && (chunk_size > 10))
    for (i = 0; i < (chunk_size - 10); i++)
        if (chunk_byte[i] == 0xE8)
            long current_pointer = chunk_offset + i;
            long displacement =
                chunk_byte[i+1]       |
                chunk_byte[i+2] << 8  |
                chunk_byte[i+3] << 16 |
                chunk_byte[i+4] << 24;
            long target = current_pointer + displacement;
            if ((target >= 0) && (target < E8_file_size + current_pointer))
                if (target >= E8_file_size)
                    target = displacement - E8_file_size;
                endif
                chunk_byte[i+1] = (byte)(target);
                chunk_byte[i+2] = (byte)(target >> 8);
                chunk_byte[i+3] = (byte)(target >> 16);
                chunk_byte[i+4] = (byte)(target >> 24);
            endif
            i += 4;
        endif
    endfor
endif
```

**E8 translation reversal (decompression postprocessing):**

```c
long value =
    chunk_byte[i+1]       |
    chunk_byte[i+2] << 8  |
    chunk_byte[i+3] << 16 |
    chunk_byte[i+4] << 24;

if ((value >= -current_pointer) && (value < E8_file_size))
    if (value >= 0)
        displacement = value - current_pointer;
    else
        displacement = value + E8_file_size;
    endif
    chunk_byte[i+1] = (byte)(displacement);
    chunk_byte[i+2] = (byte)(displacement >> 8);
    chunk_byte[i+3] = (byte)(displacement >> 16);
    chunk_byte[i+4] = (byte)(displacement >> 24);
endif
```

The first bit in the first chunk in the **LZXD** bitstream (following the 2-byte, chunk-size prefix described
in section 2.2.1) indicates the presence or absence of two 16-bit fields immediately following the
single bit. If the bit is set, E8 translation is enabled for all the following chunks in the stream using the
32-bit value derived from the two 16-bit fields as the E8_file_size provided to the compressor when E8
translation was enabled. Note that E8_file_size is completely independent of the length of the
uncompressed data. E8 call translation is disabled after the 32,768th chunk (after 1 GB of
uncompressed data).

| Field | Comments | Size |
|---|---|---|
| E8 translation | 0-disabled, 1-enabled | 1 bit |
| Translation size high word | Only present if enabled | 0 or 16 bits |
| Translation size low word | Only present if enabled | 0 or 16 bits |

## 2.3 Block

### 2.3.1 Block Header

An **LZXD** block represents a sequence of compressed data that is encoded with the same set of
Huffman trees, or a sequence of uncompressed data. There can be one or more LZXD blocks in a
compressed stream, each with its own set of Huffman trees. Blocks do not have to start or end on a
chunk boundary; blocks can span multiple chunks, or a single chunk can contain multiple blocks. The
number of chunks is related to the size of the data being compressed, while the number of blocks is
related to how well the data is compressed. The **Block Type** field, as specified in section 2.3.1.1,
indicates which type of block follows, and the **Block Size** field, as specified in section 2.3.1.2,
indicates the number of uncompressed bytes represented by the block. Following the generic block
header is a type-specific header that describes the remainder of the block.

| Field | Comments | Size |
|---|---|---|
| **Block Type** | See valid values in section 2.3.1.1 | 3 bits |
| **Block Size** most significant bit | Block size is the high 8 bits of 24 | 8 bits |
| **Block Size** byte 2 | Block size is the middle 8 bits of 24 | 8 bits |
| **Block Size** least significant bit | Block size is the low 8 bits of 24 | 8 bits |

#### 2.3.1.1 Block Type Field

Each block of compressed data begins with a 3-bit **Block Type** field, followed by the **Block Size** field,
as specified in section 2.3.1.2, and then type-specific block data, as specified in section 2.3.2. Of the
eight possible values, only three are valid values for the **Block Type** field.

| Bits | Value | Meaning |
|---|---|---|
| 001 | 1 | Verbatim block |
| 010 | 2 | Aligned offset block |
| 011 | 3 | Uncompressed block |
| other | 0, 4-7 | Not valid |

#### 2.3.1.2 Block Size Field

The **Block Size** field indicates the number of uncompressed bytes that are represented by the block.
The maximum value for the **Block Size** field is 2^24-1 (16 MB-1, or 0x00FFFFFF). The **Block Size**
field is encoded in the bitstream as three 8-bit fields comprising a 24-bit value, most significant to
least significant, immediately following the value of the **Block Type** field.

### 2.3.2 Block Data

#### 2.3.2.1 Uncompressed Block

Following the generic block header, an uncompressed block begins with 1 to 16 bits of zero padding
to align the bit buffer on a 16-bit boundary. At this point, the bitstream ends and a byte stream
begins. Following the zero padding, new 32-bit values for R0, R1, and R2 are output in little-endian
form, followed by the uncompressed data bytes themselves. Finally, if the uncompressed data length
is odd, one extra byte of zero padding is encoded to realign the following bitstream.

| Field | Comments | Size |
|---|---|---|
| Padding to align following field on 16-bit boundary | Bits have a value of zero | Variable, [1..16] bits |

Then, the following fields are encoded directly in the byte stream, not in the bitstream of byte-swapped 16-bit words:

| Field | Comments | Size |
|---|---|---|
| R0 | Least significant to most significant byte (little-endian DWORD [MS-DTYP]) | 4 bytes |
| R1 | Least significant to most significant byte (little-endian DWORD) | 4 bytes |
| R2 | Least significant to most significant byte (little-endian DWORD) | 4 bytes |
| Uncompressed raw data bytes | Can use the direct memcpy function, as specified in [IEEE1003.1] | [2^24 - 1] bytes |
| Padding to realign bitstream | Only if uncompressed size is odd | 0 or 1 byte |

Then the bitstream of byte-swapped 16-bit integers resumes for the next **Block Type** field (if there
are subsequent blocks).

The decoded R0, R1, and R2 values are used as initial repeated offset values to decode the
subsequent compressed block if present.

#### 2.3.2.2 Verbatim Block

The fields of a verbatim block that follow the generic block header are listed in the following table.

| Entry | Comments | Size |
|---|---|---|
| Pretree for first 256 elements of main tree | 20 elements, 4 bits each | 80 bits |
| Path lengths of first 256 elements of main tree | Encoded using pretree | Variable |
| Pretree for remainder of main tree | 20 elements, 4 bits each | 80 bits |
| Path lengths of remaining elements of main tree | Encoded using pretree | Variable |
| Pretree for length tree | 20 elements, 4 bits each | 80 bits |
| Path lengths of elements in length tree | Encoded using pretree | Variable |
| Token sequence (matches and literals) | Specified in section 2.6 | Variable |

#### 2.3.2.3 Aligned Offset Block

An aligned offset block is identical to the verbatim block except for the presence of the aligned offset
tree preceding the other trees.

| Entry | Comments | Size |
|---|---|---|
| Aligned offset tree | 8 elements, 3 bits each | 24 bits |
| Pretree for first 256 elements of main tree | 20 elements, 4 bits each | 80 bits |
| Path lengths of first 256 elements of main tree | Encoded using pretree | Variable |
| Pretree for remainder of main tree | 20 elements, 4 bits each | 80 bits |
| Path lengths of remaining elements of main tree | Encoded using pretree | Variable |
| Pretree for length tree | 20 elements, 4 bits each | 80 bits |
| Path lengths of elements in length tree | Encoded using pretree | Variable |
| Token sequence (matches and literals) | Specified in section 2.6 | Variable |

## 2.4 Huffman Trees

**LZXD** compression uses canonical Huffman tree structures to represent elements. Huffman trees, as
specified in [Cormen], are well known in data compression and are not described here. Because an
LZXD decoder uses only the path lengths of the Huffman tree to reconstruct the identical tree, the
following constraints are made on the tree structure.

For any two elements with the same path length, the lower-numbered element MUST be farther left on
the tree than the higher-numbered element. An alternative way of stating this constraint is that lower-
numbered elements MUST have lower path traversal values; for example, 0010 (left-left-right-left) is
lower than 0011 (left-left-right-right).

For each level, starting at the deepest level of the tree and then moving upward, leaf nodes MUST
start as far left as possible. An alternative way of stating this constraint is that if any tree node has
children, all tree nodes to the right of it with the same path length MUST also have children.

A non-empty Huffman tree MUST contain at least two elements. In the case where all but one tree
element has zero frequency, the resulting tree MUST minimally consist of two Huffman codes, "0" and
"1".

LZXD compression uses several Huffman tree structures. The main tree comprises 256 elements that
correspond to all possible 8-bit characters, plus 8 * **NUM_POSITION_SLOTS** elements that
correspond to matches. The **NUM_POSITION_SLOTS** elements refer to the position slots required,
as specified in section 2.1.6. The value of the **NUM_POSITION_SLOTS** elements depends on the
specified window size as described in section 2.1.6. The length tree comprises 249 elements. Other
trees, such as the aligned offset tree (comprising 8 elements), and the pretrees (comprising 20
elements each), have a smaller role.

## 2.5 Encoding the Trees and Pretrees

Because all trees used in **LZXD** compression are created in the form of a canonical Huffman tree, the
path length of each element in the tree is sufficient to reconstruct the original tree. The main tree
and the length tree are each encoded using the method described here. However, the main tree is
encoded in two components as if it were two separate trees, the first tree corresponding to the first
256 tree elements (uncompressed symbols), and the second tree corresponding to the remaining
elements (matches).

Because trees are output several times during compression of large amounts of data (multiple blocks),
LZXD optimizes compression by encoding only the delta path lengths between the current and
previous trees. In the case of the very first such tree, the delta is calculated against a tree in which all
elements have a zero path length.

Each tree element can have a path length of [0, 16], where a zero path length indicates that the
element has a zero frequency and is not present in the tree. Tree elements are output in sequential
order starting with the first element. Elements can be encoded in one of two ways: if several
consecutive elements have the same path length, run-length encoding is employed; otherwise, the
element is output by encoding the difference between the current path length and the previous path
length of the tree, mod 17. To represent a canonical Huffman tree, specify the path lengths of each of
the elements in the tree. The following table specifies how to interpret a code.

| Code | Operation |
|---|---|
| 0 to 16 | `Len[x] = (prev_len[x] - code + 17) mod 17` |
| 17 | `Zeros = getbits(4)`, `Len[x] = 0` for next `(4 + Zeros)` elements |
| 18 | `Zeros = getbits(5)`, `Len[x] = 0` for next `(20 + Zeros)` elements |
| 19 | `Same = getbits(1)`, decode new code, `Value = (prev_len[x] - code + 17) mod 17`, `Len[x] = Value` for next `(4 + Same)` elements |

Codes 17, 18, and 19 are used to represent consecutive elements that have the same path length.
`Zeros`, `Same`, and `Value` are variables created for the purpose of this sample code, and `getbits(n)` is a
function that fetches the next n bits from the bitstream. "Decode new code" is used to parse the next
code from the bitstream, which has a value range of [0, 16].

Each of the 17 possible values of `(len[x] - prev_len[x]) mod 17`, plus three additional codes used for
run-length encoding, are not output directly as 5-bit numbers but are instead encoded via a Huffman
tree called the pretree. The pretree is generated dynamically according to the frequencies of the 20
allowable tree codes. The structure of the pretree is encoded in a total of 80 bits by using 4 bits to
output the path length of each of the 20 pretree elements. A zero path length indicates a
zero-frequency element.

| Code | Operation |
|---|---|
| Length of tree code 0 | 4 bits |
| Length of tree code 1 | 4 bits |
| Length of tree code 2 | 4 bits |
| ... | ... |
| Length of tree code 18 | 4 bits |
| Length of tree code 19 | 4 bits |

The "real" tree is then encoded using the pretree Huffman codes.
