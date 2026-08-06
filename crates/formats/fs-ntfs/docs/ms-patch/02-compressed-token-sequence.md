# 2.6 Compressed Token Sequence

The compressed token sequence (bitstream) contains the Huffman-encoded matches and literals using
the Huffman trees specified in the block header. Decompression continues until the number of
decompressed bytes corresponds exactly to the number of uncompressed bytes indicated in the block
header.

The representation of an unmatched literal character in the output is simply the appropriate element
index [0..255] from the main Huffman tree.

The representation of a match in the output involves several transformations. At the top are the match
length [2..257] and the match offset [0..WINDOW_SIZE-3]. The match offset and match length are
split into subcomponents and encoded separately. For matches of length [258..32768], the token
indicates match length 257, and then the additional value of the **Extra Length** field is encoded in the
bitstream following the other match subcomponent fields.

## 2.6.1 Converting Match Offset into Formatted Offset Values

The match offset, range [1..WINDOW_SIZE-3], is converted into a formatted offset by determining
whether the offset can be encoded as a repeated offset, as shown in the following pseudocode. It is
acceptable not to encode a match as a repeated offset even if it is possible to do so.

```
if offset == R0 then
    formatted offset ← 0
else if offset == R1 then
    formatted offset ← 1
else if offset == R2 then
    formatted offset ← 2
else
    formatted offset ← offset + 2
endif
```

## 2.6.2 Converting Formatted Offset into Position Slot and Position Footer Values

The formatted offset is subdivided into a position slot and a position footer. The position slot defines
the most significant bits of the formatted offset in the form of a base position. The position footer
defines the remaining least significant bits of the formatted offset. The number of bits dedicated to
the position footer grows as the formatted offset becomes larger, meaning that each position slot
addresses a larger and larger range.

The number of position slots available depends on the window size. The number of bits of position
footer for each position slot is fixed and is shown in the following table.

| Position slot | Base position | Footer bits | Range (formatted offset) |
|---|---|---|---|
| 0 (R0) | 0 | 0 | 0 |
| 1 (R1) | 1 | 0 | 1 |
| 2 (R2) | 2 | 0 | 2 |
| 3 (offset 1) | 3 | 0 | 3 |
| 4 (offset 2..3) | 4 | 1 | 4-5 |
| 5 (offset 4..5) | 6 | 1 | 6-7 |
| 6 (offset 6..9) | 8 | 2 | 8-11 |
| 7 | 12 | 2 | 12-15 |
| 8 | 16 | 3 | 16-23 |
| 9 | 24 | 3 | 24-31 |
| 10 | 32 | 4 | 32-47 |
| 11 | 48 | 4 | 48-63 |
| 12 | 64 | 5 | 64-95 |
| 13 | 96 | 5 | 96-127 |
| 14 | 128 | 6 | 128-191 |
| 15 | 192 | 6 | 192-255 |
| 16 | 256 | 7 | 256-383 |
| 17 | 384 | 7 | 384-511 |
| 18 | 512 | 8 | 512-767 |
| 19 | 768 | 8 | 768-1023 |
| 20 | 1024 | 9 | 1024-1535 |
| 21 | 1536 | 9 | 1536-2047 |
| 22 | 2048 | 10 | 2048-3071 |
| 23 | 3072 | 10 | 3072-4095 |
| 24 | 4096 | 11 | 4096-6143 |
| 25 | 6144 | 11 | 6144-8191 |
| 26 | 8192 | 12 | 8192-12287 |
| 27 | 12288 | 12 | 12288-16383 |
| 28 | 16384 | 13 | 16384-24575 |
| 29 | 24576 | 13 | 24576-32767 |
| 30 | 32768 | 14 | 32768-49151 |
| 31 | 49152 | 14 | 49152-65535 |
| 32 | 65536 | 15 | 65536-98303 |
| 33 | 98304 | 15 | 98304-131071 |
| 34 | 131072 | 16 | 131072-196607 |
| 35 | 196608 | 16 | 196608-262143 |
| 36 | 262144 | 17 | 262144-393215 |
| 37 | 393216 | 17 | 393216-524287 |
| 38 | 524288 | 17 | 524288-655359 |
| 39 | 655360 | 17 | 655360-786431 |
| 40 | 786432 | 17 | 786432-917503 |
| 41 | 917504 | 17 | 917504-1048575 |
| 42 | 1048576 | 17 | 1048576-1179647 |
| ...etc.. | ...etc.. | 17 (all) | ...etc.. |
| 288 | 33292288 | 17 | 33292288-33423359 |
| 289 | 33423360 | 17 | 33423360-33554431 |

The following pseudocode demonstrates how to determine the position slot and the position footer.

```
position_slot ← calculate the position_slot from the formatted_offset
position_footer_bits ← determine the number of footer bits from the position slot value
if position_footer_bits > 0
    position_footer ← formatted_offset & ((2^position_footer_bits) - 1)
else
    position_footer ← null
endif
```

## 2.6.3 Converting Position Footer into Verbatim Bits or Aligned Offset Bits

The position footer can be further subdivided into verbatim bits and aligned offset bits if the current
value of the **Block Type** field is 010 (aligned offset), as specified in section 2.3.1.1. If the current
block is not an aligned offset block, there are no aligned offset bits, and the verbatim bits are the
position footer.

If aligned offsets are used, the lower 3 bits of the position footer are the aligned offset bits, while the
remaining portion of the position footer is the verbatim bits. In the case where fewer than 3 bits are in
the position footer (formatted offset is <= 15), it is not possible to take the "lower 3 bits
of the position footer", and therefore, there are no aligned offset bits and the verbatim bits and the
position footer are the same.

In situations where it is determined that there is a relatively larger number of position footers with
identical lower 3 bits, the aligned offset block could be used to reduce the number of bits required to
represent the position footer component in the match encoding.

The verbatim block could be used when the lower 3 bits of the position footer are relatively evenly
distributed.

```
if block_type is aligned_offset_block then
    if formatted_offset <= 15 then
        verbatim_bits ← position_footer
        aligned_offset ← null
    else
        aligned_offset ← position_footer
        verbatim_bits ← position_footer >> 3
    endif
else
    verbatim_bits ← position_footer
    aligned_offset ← null
endif
```

## 2.6.4 Converting Match Length into Length Header and Length Footer Values

The match length is converted into a length header and a length footer. The length header can have
one of eight possible values, with a range of [0, 7], indicating a match of length 2, 3, 4, 5, 6, 7, 8, or
a length greater than 8. If the match length is 8 or less, there is no length footer. Otherwise, the
value of the length footer is equal to the match length minus 9.

```
if match_length <= 8
    length_header ← match_length - 2
    length_footer ← null
else
    length_header ← 7
    length_footer ← match_length - 9
endif
```

| Match length | Length header | Length footer value |
|---|---|---|
| 2 | 0 | None |
| 3 | 1 | None |
| 4 | 2 | None |
| 5 | 3 | None |
| 6 | 4 | None |
| 7 | 5 | None |
| 8 | 6 | None |
| 9 | 7 | 0 |
| 10 | 7 | 1 |
| … | 7 | … |
| n | 7 | n-9 |

## 2.6.5 Converting Length Header and Position Slot into Length/Position Header Values

The length/position header is the stage that correlates the match position with the match length
(using only the most significant bits) and is created by combining the length header and the position
slot, as follows:

```
len_pos_header ← (position_slot << 3) + length_header
```

This operation creates a unique value for every combination of match length 2, 3, 4, 5, 6, 7, 8 with
every possible position slot. The remaining match lengths greater than 8 are all lumped together and,
as a group, are correlated with every possible position slot.

## 2.6.6 Extra Length Field

If the match length is 257 or larger, the encoded match length token value is 257, and an encoded
**Extra Length** field follows the other match encoding components, as specified in section 2.6.7, in the
bitstream.

| Prefix (in binary) | Number of bits to decode | Base value to add to decoded value |
|---|---|---|
| 0 | 8 | 257 |
| 10 | 10 | 257 + 256 |
| 110 | 12 | 257 + 256 + 1024 |
| 111 | 15 | 257 |

If the encoded match length token is equal to 257, it indicates the length of the match is >= 257. If
this is the case, the **Extra Length** field is after the other match encoding components in the
bitstream. If the prefix of the **Extra Length** field is 0, the match length is the decoded value of the
next 8 bits plus 257. If the prefix is 10, the match length is the decoded value of the next 10 bits plus
257 plus 256. If the prefix is 110, the match length is the decoded value of the next 12 bits plus 257
plus 256 plus 1024. If the prefix is 111, the match length is the decoded value of the next 15 bits plus
257.

## 2.6.7 Encoding a Match

The match is finally output as part of the compressed bitstream in up to five components, in the
following order:

1. Main tree element at index `(len_pos_header + 256)`.
2. If `length_footer != null`, the output length tree element is `length_footer`.
3. If `verbatim_bits != null`, the output is `verbatim_bits`.
4. If `aligned_offset_bits != null`, the output element is `aligned_offset` from the aligned offset tree.
5. If the match length is 257 or larger, the output consists of the prefix and value of the **Extra
   Length** field (section 2.6.6).

## 2.6.8 Encoding a Literal

A literal byte that is not part of a match is encoded simply as a main tree element index with a range
of [0, 255] corresponding to the value of the literal byte.

## 2.7 Decoding Matches and Literals (Aligned and Verbatim Blocks)

Decoding is performed by first decoding an element from the main tree and then, if the item is a
match, determining which additional components are required to decode to reconstruct the match.

```c
main_element = main_tree.decode_element()

/* Check if it is a literal character. */
if (main_element < 256)

    /* It is a literal, so copy the literal to output. */
    window[curpos] ← (byte) main_element
    curpos ← curpos + 1

/* Decode the match. For a match, there are two components, offset and length. */
else

    length_header ← (main_element - 256) & 7

    /* Length of the footer. */
    if (length_header == 7)
        match_length ← length_tree.decode_element() + 7 + 2
    else
        /* no length footer */
        match_length ← length_header + 2
    endif

    /* Decoding a match length (if a match length < 257). */
    position_slot ← (main_element - 256) >> 3

    /* Check for repeated offsets (positions 0,1,2). */
    if (position_slot == 0)
        match_offset ← R0
    else if (position_slot == 1)
        match_offset ← R1
        swap(R0 ↔ R1)
    else if (position_slot == 2)
        match_offset ← R2
        swap(R0 ↔ R2)
    /* Not a repeated offset. */
    else
        offset_bits ← footer_bits[position_slot]

        if (block_type == aligned_offset_block)
            /* This means there are some aligned bits. */
            if (offset_bits > 3)
                verbatim_bits ← (readbits(offset_bits - 3)) << 3
                aligned_bits ← aligned_offset_tree.decode_element()
            else
                /* 0, 1, or 2 verbatim bits */
                verbatim_bits ← readbits(offset_bits)
                aligned_bits ← 0
            endif

            formatted_offset ← base_position[position_slot]
                + verbatim_bits + aligned_bits

        else
            /* Block_type is a verbatim_block. */
            verbatim_bits ← readbits(offset_bits)
            formatted_offset ← base_position[position_slot] + verbatim_bits
        endif

        /* Decoding a match offset. */
        match_offset ← formatted_offset - 2

        /* Update repeated offset least recently used queue. */
        R2 ← R1
        R1 ← R0
        R0 ← match_offset

    endif

    /* Check for extra length. */
    if (match_length == 257)
        if (readbits(1) != 0)
            if (readbits(1) != 0)
                if (readbits(1) != 0)
                    extra_len = readbits(15)
                else
                    extra_len = readbits(12) + 1024 + 256
                endif
            else
                extra_len = readbits(10) + 256
            endif
        else
            extra_len = readbits(8)
        endif

        /* Get the match length (if match length >= 257). */
        match_length ← 257 + extra_len
    endif

    /* Get match length and offset. Perform copy and paste work. */
    for (i = 0; i < match_length; i++)
        window[curpos + i] ← window[curpos + i - match_offset]
    endfor

    curpos ← curpos + match_length

endif
```
