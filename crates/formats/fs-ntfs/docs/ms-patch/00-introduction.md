# 1 Introduction

LZX DELTA Compression and Decompression enables one set of data to be compressed within the
context of a reference set of data that is supplied to both the compressor and the decompressor.

Sections 1.7 and 2 of this specification are normative. All other sections and examples in this
specification are informative.

## 1.1 Glossary

- **encoding**: A process that specifies a Content-Transfer-Encoding for transforming character data
  from one form to another.

- **Lempel-Ziv Extended (LZX)**: An LZ77-based compression engine, as described in [UASDC], that
  is a universal lossless data compression algorithm. It performs no analysis on the data.

- **Lempel-Ziv Extended Delta (LZXD)**: A derivative of the Lempel-Ziv Extended (LZX) format with
  some modifications to facilitate efficient delta compression. Delta compression is a technique in
  which one set of data can be compressed within the context of a reference set of data that is
  supplied both to the compressor and decompressor. Delta compression is commonly used to
  encode updates to similar existing data sets so that the size of compressed data can be
  significantly reduced relative to ordinary non-delta compression techniques. Expanding a delta-
  compressed set of data requires that the exact same reference data be provided during
  decompression.

- **little-endian**: Multiple-byte values that are byte-ordered with the least significant byte stored in
  the memory location with the lowest address.

- **offline address book (OAB)**: A collection of address lists that are stored in a format that a client
  can save and use locally.

- **padding**: Bytes that are inserted in a data stream to maintain alignment of the protocol requests
  on natural boundaries.

- **path length**: The number of edges in the canonical Huffman tree between the top of the tree and
  the element.

- **stream**: A flow of data from one host to another host, or the data that flows between two hosts.

- **MAY, SHOULD, MUST, SHOULD NOT, MUST NOT**: These terms (in all caps) are used as defined
  in [RFC2119]. All statements of optional behavior use either MAY, SHOULD, or SHOULD NOT.

## 1.2 References

### 1.2.1 Normative References

- [Cormen] Cormen, T., Leiserson, C., Rivest, R., and Stein, C., "Introduction to Algorithms", 3rd
  edition, Massachusetts Institute of Technology, 2009, ISBN: 978-0-262-03384-8.

- [IEEE1003.1] The Open Group, "IEEE Std 1003.1, 2004 Edition", 2004,
  http://www.unix.org/version3/ieee_std.html

- [MS-DTYP] Microsoft Corporation, "Windows Data Types".

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC
  2119, March 1997, https://www.rfc-editor.org/info/rfc2119

- [UASDC] Ziv, J. and Lempel, A., "A Universal Algorithm for Sequential Data Compression", May 1977,
  http://www.cs.duke.edu/courses/spring03/cps296.5/papers/ziv_lempel_1977_universal_algorithm.pdf

### 1.2.2 Informative References

- [MS-OXOAB] Microsoft Corporation, "Offline Address Book (OAB) File Format and Schema".

- [MS-OXPROTO] Microsoft Corporation, "Exchange Server Protocols System Overview".

## 1.3 Overview

**LZXD** compression provides a mechanism for both the compressor and the decompressor to refer to
a common reference set of data. It relaxes the constraint that the match offset be constrained to less
than the current position in the output stream, allowing the match offset to refer to the logically
prepended reference data. This relaxed constraint effectively enables the compressed data stream to
encode "matches" both from the reference data and from the uncompressed data stream.

## 1.4 Relationship to Protocols and Other Structures

**LZXD** (D for Delta) is an **LZX** variant that is modified to facilitate efficient delta compression.

LZX is a compressor that is based on the Lempel-Ziv 1977 (LZ77) sliding window data compression
algorithm, as described in [UASDC], that uses static Huffman encoding and a sliding window of
selectable size. Data symbols are encoded either as an uncompressed symbol or as a logical (offset,
length) pair indicating that length symbols shall be copied from a displacement of offset symbols from
the current position in the output stream. The value of the offset is constrained to be less than the
current position in the output stream, up to the size of the sliding window.

The LZXD compression format is used by [MS-OXOAB] to compress data in the **offline address book
(OAB)**.

For conceptual background information and overviews of the relationships and interactions between
this and other protocols, see [MS-OXPROTO].

## 1.5 Applicability Statement

**LZXD** compression is commonly used to encode updates to similar existing data sets so that the size
of compressed data can be significantly reduced relative to ordinary compression techniques that do
not use the delta between a common reference set of data. One use for this compression format is the
compression data in **OAB** version 4 Differential Patch or Compressed OAB Template files.

## 1.6 Versioning and Localization

None.

## 1.7 Vendor-Extensible Fields

None.
