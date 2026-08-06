# MS-PATCH Reference (v14.1, August 2025)

Split from `[MS-PATCH].pdf` — Microsoft LZX DELTA Compression and Decompression specification.
Use this index to find the right file for a given topic.

## Files

| File | What to find here |
|------|-------------------|
| `00-introduction.md` | **Glossary** (LZXD, LZX, encoding, little-endian, path length, stream), normative/informative references, spec overview, relationship to OAB/Exchange protocols, applicability |
| `01-structures.md` | **Core data structures**: concepts (bitstream, window size, reference data, repeated offsets R0/R1/R2, match lengths, position slots), header (chunk size, E8 call translation with pseudocode), block types (uncompressed/verbatim/aligned offset) with field layouts, Huffman trees (main tree, length tree, aligned offset tree, pretrees), tree/pretree encoding with delta path lengths and run-length codes |
| `02-compressed-token-sequence.md` | **Token encoding/decoding**: match offset → formatted offset conversion, position slot/footer table (all 290 slots), verbatim vs aligned offset bits, match length → length header/footer, length/position header combining, Extra Length field (prefix codes for lengths ≥257), match encoding order (5 components), literal encoding, **full decoding pseudocode** for aligned and verbatim blocks |
| `03-examples.md` | Worked example: encoding "abc" as an uncompressed block with raw hex bytes |
| `04-security.md` | Security considerations (none) |
| `05-product-behavior.md` | Applicable Microsoft products (Exchange Server, Outlook versions) |

## Quick Lookup

| Question | File |
|----------|------|
| What is LZXD? How does delta compression work? | `00-introduction.md` |
| Window size constraints? Position slot count? | `01-structures.md` § 2.1.2, 2.1.6 |
| How do repeated offsets (R0/R1/R2) work? | `01-structures.md` § 2.1.4 |
| E8 call translation preprocessing? | `01-structures.md` § 2.2.2 |
| Block type values (verbatim/aligned/uncompressed)? | `01-structures.md` § 2.3.1.1 |
| Verbatim vs aligned offset block layout? | `01-structures.md` § 2.3.2.2, 2.3.2.3 |
| Huffman tree constraints? Main/length tree sizes? | `01-structures.md` § 2.4 |
| Pretree encoding (delta path lengths, codes 17-19)? | `01-structures.md` § 2.5 |
| Position slot → base position → footer bits table? | `02-compressed-token-sequence.md` § 2.6.2 |
| How to encode/decode a match? | `02-compressed-token-sequence.md` § 2.6.7, 2.7 |
| Extra length field for matches ≥257? | `02-compressed-token-sequence.md` § 2.6.6 |
| Full decompression pseudocode? | `02-compressed-token-sequence.md` § 2.7 |
| Worked encoding example with hex bytes? | `03-examples.md` |
