//! Shared canonical Huffman table decoder for XPRESS Huffman and LZX.
//!
//! Builds a table-based decoder from an array of per-symbol code
//! lengths. Codes up to `TABLE_BITS` in length use a direct lookup
//! table; longer codes fall back to a linked overflow table.

use alloc::vec;
use alloc::vec::Vec;

use crate::bitstream::BitReader;
use crate::{Error, Result};

/// Maximum code length supported (LZX uses up to 16, XPRESS Huffman
/// up to 15). 16 covers both.
const MAX_CODE_LEN: usize = 16;

/// Sentinel value meaning "no symbol" in an overflow node.
const NO_SYMBOL: u16 = u16::MAX;

/// Entry in the direct lookup table (codes <= `TABLE_BITS`).
#[derive(Clone, Copy, Debug)]
struct TableEntry {
    /// Decoded symbol index.
    symbol: u16,
    /// Actual code length in bits (so the caller knows how many bits
    /// to consume). Zero means this slot points to the overflow table
    /// via `symbol` as an index.
    code_len: u8,
}

/// Node in the overflow tree for codes longer than `TABLE_BITS`.
#[derive(Clone, Copy, Debug)]
struct OverflowNode {
    /// Decoded symbol, or `NO_SYMBOL` if this is an internal node.
    symbol: u16,
    /// Index of child for bit 0 (left). `u32::MAX` = no child.
    child0: u32,
    /// Index of child for bit 1 (right). `u32::MAX` = no child.
    child1: u32,
}

/// Decoding table built from canonical Huffman code lengths.
///
/// Uses direct table lookup for short codes and a tree walk for
/// codes exceeding the table width.
#[allow(
    dead_code,
    reason = "used by xpress-huffman and lzx when those features are enabled"
)]
#[derive(Debug)]
pub(crate) struct HuffmanTable {
    /// Direct lookup table of size `2^table_bits`.
    table: Vec<TableEntry>,
    /// Overflow nodes for codes longer than `table_bits`.
    overflow: Vec<OverflowNode>,
    /// Number of bits used for the direct lookup table.
    table_bits: u32,
}

#[allow(
    dead_code,
    reason = "used by xpress-huffman and lzx when those features are enabled"
)]
impl HuffmanTable {
    /// Build a decoding table from per-symbol code lengths.
    ///
    /// `lengths[i]` is the Huffman code length for symbol `i`. A
    /// length of zero means the symbol does not appear. `max_bits`
    /// controls the direct-table width (e.g. 11 for XPRESS Huffman).
    pub fn from_code_lengths(lengths: &[u8], max_bits: u32) -> Result<Self> {
        let table_bits = max_bits.min(MAX_CODE_LEN as u32);

        validate_lengths(lengths)?;
        let counts = count_per_length(lengths);
        validate_code_space(&counts)?;

        let codes = assign_canonical_codes(lengths, &counts);
        let (table, overflow) = build_tables(&codes, table_bits)?;

        Ok(Self {
            table,
            overflow,
            table_bits,
        })
    }

    /// Decode one symbol from the bitstream.
    ///
    /// Reads bits from `reader`, performs a table lookup, and
    /// consumes the appropriate number of bits.
    pub fn decode_symbol(&self, reader: &mut BitReader<'_>) -> Result<u16> {
        reader.ensure_bits(self.table_bits)?;
        let index = reader.peek_bits(self.table_bits) as usize;
        let entry = self.table[index];

        if entry.code_len > 0 {
            reader.consume_bits(u32::from(entry.code_len));
            return Ok(entry.symbol);
        }

        self.decode_overflow(reader, u32::from(entry.symbol))
    }

    /// Walk the overflow tree for codes longer than `table_bits`.
    fn decode_overflow(&self, reader: &mut BitReader<'_>, root_index: u32) -> Result<u16> {
        reader.consume_bits(self.table_bits);
        let mut node_idx = root_index as usize;

        for _ in self.table_bits..MAX_CODE_LEN as u32 {
            reader.ensure_bits(1)?;
            let bit = reader.peek_bits(1);
            reader.consume_bits(1);

            let node = self.overflow[node_idx];
            let child = if bit == 0 { node.child0 } else { node.child1 };
            if child == u32::MAX {
                return Err(Error::InvalidHuffmanTable {
                    reason: "incomplete tree traversal",
                });
            }
            let next = &self.overflow[child as usize];
            if next.symbol != NO_SYMBOL {
                return Ok(next.symbol);
            }
            node_idx = child as usize;
        }

        Err(Error::InvalidHuffmanTable {
            reason: "code exceeds maximum length",
        })
    }

    /// Decode one symbol from a raw bit buffer without using BitReader.
    ///
    /// `next_bits` contains bits MSB-aligned in a `u32` (the top
    /// `table_bits` are used for the direct lookup). Returns
    /// `Ok((symbol, code_length))` so the caller can shift the buffer.
    ///
    /// Used by the XPRESS Huffman deficit-based decode loop where the
    /// caller manages its own bit buffer and byte position to correctly
    /// handle interleaved extension bytes.
    pub fn decode_symbol_from_bits(&self, next_bits: u32) -> Result<(u16, u32)> {
        let index = (next_bits >> (32 - self.table_bits)) as usize;
        let entry = self.table[index];

        if entry.code_len > 0 {
            return Ok((entry.symbol, u32::from(entry.code_len)));
        }

        // Overflow: walk the tree using bits beyond table_bits.
        let mut node_idx = entry.symbol as usize;
        let mut bits_used = self.table_bits;

        for _ in self.table_bits..MAX_CODE_LEN as u32 {
            let bit = (next_bits >> (31 - bits_used)) & 1;
            bits_used += 1;

            let node = self.overflow[node_idx];
            let child = if bit == 0 { node.child0 } else { node.child1 };
            if child == u32::MAX {
                return Err(Error::InvalidHuffmanTable {
                    reason: "incomplete tree traversal",
                });
            }
            let next = &self.overflow[child as usize];
            if next.symbol != NO_SYMBOL {
                return Ok((next.symbol, bits_used));
            }
            node_idx = child as usize;
        }

        Err(Error::InvalidHuffmanTable {
            reason: "code exceeds maximum length",
        })
    }
}

/// Reject tables with no symbols at all.
pub(crate) fn validate_lengths(lengths: &[u8]) -> Result<()> {
    let non_zero = lengths.iter().filter(|&&l| l > 0).count();
    if non_zero == 0 {
        return Err(Error::InvalidHuffmanTable {
            reason: "all code lengths are zero",
        });
    }
    Ok(())
}

/// Count how many symbols exist at each code length (1..=MAX_CODE_LEN).
///
/// `counts[0]` is always 0 -- symbols with length 0 are excluded.
pub(crate) fn count_per_length(lengths: &[u8]) -> [u32; MAX_CODE_LEN + 1] {
    let mut counts = [0u32; MAX_CODE_LEN + 1];
    for &len in lengths {
        let idx = usize::from(len);
        if idx > 0 && idx <= MAX_CODE_LEN {
            counts[idx] += 1;
        }
    }
    counts
}

/// Check that the code lengths do not oversubscribe the code space.
///
/// For a single-symbol tree we allow it (Kraft sum = 0.5 < 1.0).
pub(crate) fn validate_code_space(counts: &[u32; MAX_CODE_LEN + 1]) -> Result<()> {
    // Kraft inequality: sum(count[i] * 2^(max - i)) <= 2^max
    // We use max = MAX_CODE_LEN and work in integer units.
    let max = MAX_CODE_LEN as u32;
    let mut kraft: u64 = 0;

    for (len, &count) in counts.iter().enumerate().skip(1) {
        if len > MAX_CODE_LEN {
            break;
        }
        kraft += u64::from(count) << (max - len as u32);
    }

    let capacity = 1u64 << max;
    if kraft > capacity {
        return Err(Error::InvalidHuffmanTable {
            reason: "oversubscribed code space",
        });
    }
    Ok(())
}

/// Assign canonical codes to each symbol based on code lengths.
///
/// Returns a vector of `(code, length)` per symbol index. Symbols
/// with length 0 get code 0 (unused).
pub(crate) fn assign_canonical_codes(
    lengths: &[u8],
    counts: &[u32; MAX_CODE_LEN + 1],
) -> Vec<(u32, u8)> {
    let mut next_code = [0u32; MAX_CODE_LEN + 1];
    let mut code: u32 = 0;
    for bits in 1..=MAX_CODE_LEN {
        code = (code + counts[bits - 1]) << 1;
        next_code[bits] = code;
    }

    let mut codes = vec![(0u32, 0u8); lengths.len()];
    for (sym, &len) in lengths.iter().enumerate() {
        let l = usize::from(len);
        if l > 0 && l <= MAX_CODE_LEN {
            codes[sym] = (next_code[l], len);
            next_code[l] += 1;
        }
    }
    codes
}

/// Build canonical Huffman code lengths from symbol frequency counts.
///
/// Given `freqs[i]` = frequency of symbol `i`, computes the optimal
/// code length for each symbol, limited to at most `max_bits` bits.
/// Symbols with zero frequency get code length 0.
///
/// Uses a standard Huffman tree construction via `BinaryHeap`, then
/// limits code lengths using Kraft-based redistribution.
#[allow(
    dead_code,
    reason = "used by compress-xpress-huffman and compress-lzx when those features are enabled"
)]
pub(crate) fn build_code_lengths(freqs: &[u32], max_bits: u8) -> Result<Vec<u8>> {
    use alloc::collections::BinaryHeap;
    use core::cmp::Reverse;

    let num_symbols = freqs.len();
    let non_zero: Vec<(usize, u32)> = freqs
        .iter()
        .enumerate()
        .filter(|(_, f)| **f > 0)
        .map(|(i, f)| (i, *f))
        .collect();

    if non_zero.is_empty() {
        return Ok(vec![0u8; num_symbols]);
    }

    if non_zero.len() == 1 {
        let mut lengths = vec![0u8; num_symbols];
        lengths[non_zero[0].0] = 1;
        // Add a dummy second symbol at codelen 1 to form a complete
        // Huffman tree (Kraft sum = 1.0). Without this, decoders
        // like wimlib reject the incomplete code.
        let real_sym = non_zero[0].0;
        let dummy = if real_sym == 0 { 1 } else { 0 };
        lengths[dummy] = 1;
        return Ok(lengths);
    }

    // Build Huffman tree using a min-heap of (frequency, node_id).
    // Internal nodes are assigned IDs starting from num_symbols.
    let mut parent = vec![u32::MAX; 2 * num_symbols];
    let mut heap: BinaryHeap<Reverse<(u64, u32)>> = BinaryHeap::new();

    for &(sym, freq) in &non_zero {
        heap.push(Reverse((u64::from(freq), sym as u32)));
    }

    let mut next_internal = num_symbols as u32;
    while heap.len() > 1 {
        let Reverse((f1, n1)) = heap.pop().expect("heap underflow");
        let Reverse((f2, n2)) = heap.pop().expect("heap underflow");
        let internal = next_internal;
        next_internal += 1;
        parent[n1 as usize] = internal;
        parent[n2 as usize] = internal;
        if (next_internal as usize) > parent.len() {
            parent.resize(next_internal as usize + 1, u32::MAX);
        }
        heap.push(Reverse((f1 + f2, internal)));
    }

    // Compute depths from the tree.
    let mut lengths = vec![0u8; num_symbols];
    for (sym, _) in &non_zero {
        let mut depth = 0u8;
        let mut node = *sym as u32;
        while parent[node as usize] != u32::MAX {
            depth += 1;
            node = parent[node as usize];
        }
        lengths[*sym] = depth;
    }

    // Limit code lengths to max_bits using Kraft-based redistribution.
    limit_code_lengths(&mut lengths, max_bits);

    Ok(lengths)
}

/// Limit code lengths to `max_bits` using package-merge-style
/// redistribution: push overlong codes down to `max_bits`, then
/// fix the Kraft inequality by shortening the shortest codes.
fn limit_code_lengths(lengths: &mut [u8], max_bits: u8) {
    let max = max_bits as u32;

    // Check if any code exceeds max_bits.
    let overlong = lengths.iter().any(|l| *l > max_bits);
    if !overlong {
        return;
    }

    // Clamp all codes to max_bits.
    for len in lengths.iter_mut() {
        if *len > max_bits {
            *len = max_bits;
        }
    }

    // Fix Kraft inequality: sum(2^(max - len_i)) must equal 2^max.
    // After clamping, we may have oversubscribed (kraft_sum > capacity).
    // We need to increase some code lengths to reduce the sum.
    loop {
        let capacity = 1u64 << max;
        let kraft_sum: u64 = lengths
            .iter()
            .filter(|l| **l > 0)
            .map(|l| 1u64 << (max - u32::from(*l)))
            .sum();

        if kraft_sum <= capacity {
            break;
        }

        // Find the shortest code (lowest length > 0) and increase it.
        let excess = kraft_sum - capacity;
        let min_len = lengths
            .iter()
            .filter(|l| **l > 0)
            .copied()
            .min()
            .expect("at least one non-zero length");

        // Cost of lengthening a symbol from min_len to min_len+1:
        // reduces kraft sum by 2^(max - min_len) - 2^(max - min_len - 1)
        // = 2^(max - min_len - 1)
        let reduction_per = 1u64 << (max - u32::from(min_len) - 1);
        let needed = excess.div_ceil(reduction_per) as usize;

        let mut count = 0;
        for len in lengths.iter_mut() {
            if count >= needed {
                break;
            }
            if *len == min_len {
                *len = min_len + 1;
                count += 1;
            }
        }
    }
}

/// Build the direct lookup table and overflow tree.
fn build_tables(
    codes: &[(u32, u8)],
    table_bits: u32,
) -> Result<(Vec<TableEntry>, Vec<OverflowNode>)> {
    let table_size = 1usize << table_bits;
    let mut table = vec![
        TableEntry {
            symbol: NO_SYMBOL,
            code_len: 0,
        };
        table_size
    ];
    let mut overflow: Vec<OverflowNode> = Vec::new();

    for (sym, &(code, len)) in codes.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let sym = sym as u16;
        if u32::from(len) <= table_bits {
            fill_short_code(&mut table, sym, code, len, table_bits);
        } else {
            insert_long_code(&mut table, &mut overflow, sym, code, len, table_bits)?;
        }
    }

    fill_undersubscribed_entries(&mut table, &overflow);

    Ok((table, overflow))
}

/// Fill empty direct-table entries left by undersubscribed trees.
///
/// When a tree uses less than the full code space (e.g. a single
/// symbol), some table entries remain uninitialized. Those entries
/// have `code_len == 0` but do not point to overflow nodes. We
/// fill them with the first valid entry so that any peek value
/// produces a valid decode.
fn fill_undersubscribed_entries(table: &mut [TableEntry], _overflow: &[OverflowNode]) {
    let Some(fill) = table.iter().find(|e| e.code_len > 0).copied() else {
        return;
    };
    for entry in table.iter_mut() {
        if entry.code_len == 0 && entry.symbol == NO_SYMBOL {
            *entry = fill;
        }
    }
}

/// Fill table entries for a code that fits within the direct table.
///
/// A code of length `len < table_bits` maps to multiple table
/// entries (all suffixes).
fn fill_short_code(table: &mut [TableEntry], symbol: u16, code: u32, len: u8, table_bits: u32) {
    let pad_bits = table_bits - u32::from(len);
    let base = code << pad_bits;
    let count = 1u32 << pad_bits;
    for i in 0..count {
        let idx = (base | i) as usize;
        table[idx] = TableEntry {
            symbol,
            code_len: len,
        };
    }
}

/// Insert a long code (> `table_bits`) into the overflow tree.
///
/// The top `table_bits` of the code index into the direct table;
/// that entry points to the overflow tree root. Remaining bits walk
/// the tree to a leaf.
fn insert_long_code(
    table: &mut [TableEntry],
    overflow: &mut Vec<OverflowNode>,
    symbol: u16,
    code: u32,
    len: u8,
    table_bits: u32,
) -> Result<()> {
    let prefix = code >> (u32::from(len) - table_bits);
    let entry = &mut table[prefix as usize];

    let root_idx = if entry.code_len == 0 && entry.symbol == NO_SYMBOL {
        if overflow.len() >= usize::from(NO_SYMBOL) {
            return Err(Error::InvalidHuffmanTable {
                reason: "overflow table exceeds u16 index space",
            });
        }
        let idx = overflow.len() as u16;
        overflow.push(OverflowNode {
            symbol: NO_SYMBOL,
            child0: u32::MAX,
            child1: u32::MAX,
        });
        entry.symbol = idx;
        entry.code_len = 0; // marks overflow pointer
        u32::from(idx)
    } else {
        u32::from(entry.symbol)
    };

    let extra_bits = u32::from(len) - table_bits;
    let mut node_idx = root_idx as usize;

    for bit_pos in (0..extra_bits).rev() {
        let bit = (code >> bit_pos) & 1;
        let node = overflow[node_idx];
        let child = if bit == 0 { node.child0 } else { node.child1 };

        if child == u32::MAX {
            let new_idx = overflow.len() as u32;
            overflow.push(OverflowNode {
                symbol: NO_SYMBOL,
                child0: u32::MAX,
                child1: u32::MAX,
            });
            if bit == 0 {
                overflow[node_idx].child0 = new_idx;
            } else {
                overflow[node_idx].child1 = new_idx;
            }
            node_idx = new_idx as usize;
        } else {
            node_idx = child as usize;
        }
    }

    overflow[node_idx].symbol = symbol;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    /// Helper: encode `symbols` using the given code lengths into a
    /// byte buffer suitable for `BitReader` (16-bit LE words,
    /// MSB-first bits). Returns the encoded bytes.
    fn encode_symbols(lengths: &[u8], symbols: &[u16]) -> Vec<u8> {
        let counts = count_per_length(lengths);
        let codes = assign_canonical_codes(lengths, &counts);

        let mut bits: Vec<u8> = Vec::new();
        let mut accum: u32 = 0;
        let mut accum_bits: u32 = 0;

        for &sym in symbols {
            let (code, len) = codes[sym as usize];
            accum = (accum << u32::from(len)) | code;
            accum_bits += u32::from(len);

            while accum_bits >= 16 {
                accum_bits -= 16;
                let word = (accum >> accum_bits) as u16;
                let le = word.to_le_bytes();
                bits.push(le[0]);
                bits.push(le[1]);
                accum &= (1u32 << accum_bits) - 1;
            }
        }

        // Flush remaining bits, padded with zeros.
        if accum_bits > 0 {
            let word = (accum << (16 - accum_bits)) as u16;
            let le = word.to_le_bytes();
            bits.push(le[0]);
            bits.push(le[1]);
        }

        bits
    }

    #[test]
    fn uniform_distribution() {
        // 8 symbols, each with code length 3 (2^3 = 8, perfect fit).
        let lengths = [3u8; 8];
        let table = HuffmanTable::from_code_lengths(&lengths, 11).expect("valid uniform tree");

        let symbols: Vec<u16> = (0..8).collect();
        let encoded = encode_symbols(&lengths, &symbols);
        let mut reader = BitReader::new(&encoded);

        for expected in 0u16..8 {
            let decoded = table.decode_symbol(&mut reader).expect("decode failed");
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn single_symbol_tree() {
        // Only symbol 0 has a non-zero length.
        let mut lengths = [0u8; 4];
        lengths[0] = 1;

        let table =
            HuffmanTable::from_code_lengths(&lengths, 11).expect("valid single-symbol tree");

        // Encode symbol 0 three times (code = 0, length = 1).
        let encoded = encode_symbols(&lengths, &[0, 0, 0]);
        let mut reader = BitReader::new(&encoded);

        for _ in 0..3 {
            let sym = table.decode_symbol(&mut reader).expect("decode failed");
            assert_eq!(sym, 0);
        }
    }

    #[test]
    fn skewed_distribution() {
        // Symbol 0: length 1 (most frequent)
        // Symbol 1: length 2
        // Symbol 2: length 3
        // Symbol 3: length 3
        // Kraft: 1/2 + 1/4 + 1/8 + 1/8 = 1.0 (valid)
        let lengths = [1u8, 2, 3, 3];
        let table = HuffmanTable::from_code_lengths(&lengths, 11).expect("valid skewed tree");

        let symbols = [0u16, 1, 2, 3, 0, 3, 2, 1, 0];
        let encoded = encode_symbols(&lengths, &symbols);
        let mut reader = BitReader::new(&encoded);

        for &expected in &symbols {
            let decoded = table.decode_symbol(&mut reader).expect("decode failed");
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn max_depth_tree() {
        // Build a tree where the maximum depth is 15 bits.
        // Symbols 0..14 get lengths 1..15 won't work because
        // Kraft = sum(2^(-i)) for i=1..15 < 1.0 and that's fine.
        // Instead, build a minimal tree that actually reaches depth
        // 15. Use lengths that sum to exactly 1.0 under Kraft.
        //
        // Simple approach: a degenerate left-skewed tree.
        // Symbol 0: len 1, symbol 1: len 2, ..., symbol 13: len 14,
        // symbol 14: len 15, symbol 15: len 15.
        let mut lengths = [0u8; 16];
        for i in 0u8..14 {
            lengths[i as usize] = i + 1;
        }
        lengths[14] = 15;
        lengths[15] = 15;

        let table = HuffmanTable::from_code_lengths(&lengths, 11).expect("valid max-depth tree");

        // Decode the two deepest symbols.
        let symbols = [14u16, 15, 0, 1];
        let encoded = encode_symbols(&lengths, &symbols);
        let mut reader = BitReader::new(&encoded);

        for &expected in &symbols {
            let decoded = table.decode_symbol(&mut reader).expect("decode failed");
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn max_depth_all_long_codes_decoded() {
        // Regression: multiple long codes sharing the same table prefix
        // must all be decodable. Previously the sentinel check used
        // symbol==0, which collided with overflow root index 0.
        let mut lengths = [0u8; 16];
        for i in 0u8..14 {
            lengths[i as usize] = i + 1;
        }
        lengths[14] = 15;
        lengths[15] = 15;

        let table = HuffmanTable::from_code_lengths(&lengths, 11).expect("valid tree");

        // Decode ALL symbols including the long codes (11-15).
        let symbols: Vec<u16> = (0..16).collect();
        let encoded = encode_symbols(&lengths, &symbols);
        let mut reader = BitReader::new(&encoded);

        for expected in 0u16..16 {
            let decoded = table
                .decode_symbol(&mut reader)
                .unwrap_or_else(|e| panic!("failed to decode symbol {expected}: {e}"));
            assert_eq!(decoded, expected, "mismatch at symbol {expected}");
        }
    }

    #[test]
    fn invalid_tree_oversubscribed() {
        // Two symbols each with length 1 → codes 0 and 1 → Kraft =
        // 0.5 + 0.5 = 1.0. That's valid.
        // Three symbols with length 1 → Kraft = 1.5 → oversubscribed.
        let lengths = [1u8, 1, 1];
        let result = HuffmanTable::from_code_lengths(&lengths, 11);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("oversubscribed"),
            "expected oversubscribed error, got: {msg}"
        );
    }

    #[test]
    fn invalid_tree_all_zero_lengths() {
        let lengths = [0u8; 16];
        let result = HuffmanTable::from_code_lengths(&lengths, 11);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("zero"), "expected all-zero error, got: {msg}");
    }

    #[test]
    fn decode_known_sequence() {
        // 4 symbols with known canonical codes:
        //   sym 0: len 2 -> code 00
        //   sym 1: len 2 -> code 01
        //   sym 2: len 2 -> code 10
        //   sym 3: len 2 -> code 11
        let lengths = [2u8, 2, 2, 2];
        let table = HuffmanTable::from_code_lengths(&lengths, 11).expect("valid tree");

        // Manually build bitstream: symbols [3, 0, 2, 1]
        // codes: 11, 00, 10, 01 = 1100_1001 as 8 bits.
        // BitReader loads 16-bit LE words MSB-first, so place
        // these 8 bits at the top of a 16-bit word:
        // 1100_1001_0000_0000 = 0xC900, LE bytes: [0x00, 0xC9].
        // Pad with an extra word so ensure_bits(11) can refill
        // when fewer than 11 bits remain in the accumulator.
        let data = [0x00u8, 0xC9, 0x00, 0x00];
        let mut reader = BitReader::new(&data);

        let expected = [3u16, 0, 2, 1];
        for &exp in &expected {
            let sym = table.decode_symbol(&mut reader).expect("decode failed");
            assert_eq!(sym, exp);
        }
    }

    // -- build_code_lengths tests -----------------------------------------

    #[test]
    fn build_uniform_distribution() {
        // 8 symbols, equal frequency → all should get length 3.
        let freqs = [10u32; 8];
        let lengths = build_code_lengths(&freqs, 15).expect("build failed");
        for &l in &lengths {
            assert_eq!(l, 3);
        }
        // Verify decodable
        HuffmanTable::from_code_lengths(&lengths, 11).expect("valid table");
    }

    #[test]
    fn build_power_of_two_skew() {
        // Frequencies that form a natural Huffman tree.
        let freqs = [8u32, 4, 2, 1, 1, 0, 0, 0];
        let lengths = build_code_lengths(&freqs, 15).expect("build failed");
        assert_eq!(lengths[0], 1); // most frequent
        assert_eq!(lengths[1], 2);
        assert_eq!(lengths[2], 3);
        assert_eq!(lengths[3], 4);
        assert_eq!(lengths[4], 4);
        assert_eq!(lengths[5], 0); // zero freq
        HuffmanTable::from_code_lengths(&lengths, 11).expect("valid table");
    }

    #[test]
    fn build_single_symbol() {
        let freqs = [0u32, 0, 0, 100, 0];
        let lengths = build_code_lengths(&freqs, 15).expect("build failed");
        // The real symbol gets codelen 1.
        assert_eq!(lengths[3], 1);
        // A dummy symbol (the first available, index 0) also gets
        // codelen 1 to form a complete Huffman tree.
        assert_eq!(lengths[0], 1);
        // All other symbols are still 0.
        for (i, &l) in lengths.iter().enumerate() {
            if i != 0 && i != 3 {
                assert_eq!(l, 0, "symbol {i} should be 0");
            }
        }
        // Verify decodable.
        HuffmanTable::from_code_lengths(&lengths, 11).expect("valid table");
    }

    #[test]
    fn build_all_zero_frequencies() {
        let freqs = [0u32; 16];
        let lengths = build_code_lengths(&freqs, 15).expect("build failed");
        assert!(lengths.iter().all(|&l| l == 0));
    }

    #[test]
    fn build_max_bits_constraint() {
        // Many symbols with wildly varying frequencies → natural tree
        // would be deep. Constrain to 4 bits max.
        let mut freqs = [0u32; 32];
        freqs[0] = 100_000;
        freqs[1] = 1;
        freqs[2] = 1;
        freqs[3] = 1;
        freqs[4] = 1;
        freqs[5] = 1;
        freqs[6] = 1;
        freqs[7] = 1;
        let lengths = build_code_lengths(&freqs, 4).expect("build failed");
        for &l in &lengths {
            assert!(l <= 4, "code length {l} exceeds max_bits 4");
        }
        // Verify Kraft inequality holds
        let counts = count_per_length(&lengths);
        validate_code_space(&counts).expect("valid code space");
    }

    #[test]
    fn build_roundtrip_with_huffman_table() {
        // Build lengths, create a HuffmanTable, encode, and decode.
        let freqs = [50u32, 30, 20, 10, 5, 3, 2, 1];
        let lengths = build_code_lengths(&freqs, 15).expect("build failed");
        let table = HuffmanTable::from_code_lengths(&lengths, 11).expect("valid table");

        let symbols: Vec<u16> = (0..8).collect();
        let encoded = encode_symbols(&lengths, &symbols);
        let mut reader = BitReader::new(&encoded);

        for expected in 0u16..8 {
            let decoded = table
                .decode_symbol(&mut reader)
                .unwrap_or_else(|e| panic!("failed to decode symbol {expected}: {e}"));
            assert_eq!(decoded, expected);
        }
    }
}
