//! Fixed-storage canonical decoding for small Huffman alphabets.

use crate::bitstream::BitReader;
use crate::{Error, Result};

use super::{MAX_CODE_LEN, count_per_length, validate_code_space, validate_lengths};

/// Fixed-storage canonical decoder for small alphabets such as LZX pre-trees.
///
/// It trades a short cold-path scan over possible code lengths for avoiding a
/// heap-backed direct table. `SYMBOLS` is the maximum alphabet size.
pub(crate) struct SmallHuffmanTable<const SYMBOLS: usize> {
    counts: [u16; MAX_CODE_LEN + 1],
    first_code: [u32; MAX_CODE_LEN + 1],
    first_symbol: [u16; MAX_CODE_LEN + 1],
    symbols: [u16; SYMBOLS],
    fallback: Option<(u16, u8)>,
}

impl<const SYMBOLS: usize> SmallHuffmanTable<SYMBOLS> {
    /// Create an empty table ready to be rebuilt in place.
    pub(crate) const fn new() -> Self {
        Self {
            counts: [0; MAX_CODE_LEN + 1],
            first_code: [0; MAX_CODE_LEN + 1],
            first_symbol: [0; MAX_CODE_LEN + 1],
            symbols: [0; SYMBOLS],
            fallback: None,
        }
    }

    /// Rebuild from code lengths without allocating.
    pub(crate) fn rebuild(&mut self, lengths: &[u8]) -> Result<()> {
        if lengths.len() > SYMBOLS {
            return Err(Error::InvalidHuffmanTable {
                reason: "small Huffman alphabet exceeds fixed capacity",
            });
        }
        validate_lengths(lengths)?;
        let counts = count_per_length(lengths);
        validate_code_space(&counts)?;

        self.counts.fill(0);
        self.first_code.fill(0);
        self.first_symbol.fill(0);
        self.symbols.fill(0);
        self.fallback = None;

        let mut code = 0_u32;
        let mut symbol_offset = 0_u16;
        for length in 1..=MAX_CODE_LEN {
            code = (code + counts[length - 1]) << 1;
            self.first_code[length] = code;
            self.first_symbol[length] = symbol_offset;
            self.counts[length] = u16::try_from(counts[length])
                .expect("a small Huffman table has at most u16::MAX symbols");
            symbol_offset = symbol_offset.saturating_add(self.counts[length]);
        }

        let mut positions = self.first_symbol;
        for (symbol, &length) in lengths.iter().enumerate() {
            let index = usize::from(length);
            if index == 0 || index > MAX_CODE_LEN {
                continue;
            }
            let symbol =
                u16::try_from(symbol).expect("a small Huffman table has at most u16::MAX symbols");
            self.fallback.get_or_insert((symbol, length));
            let position = usize::from(positions[index]);
            self.symbols[position] = symbol;
            positions[index] += 1;
        }
        Ok(())
    }

    /// Decode one symbol through canonical range lookup.
    pub(crate) fn decode_symbol(&self, reader: &mut BitReader<'_>) -> Result<u16> {
        for length in 1..=MAX_CODE_LEN {
            let count = u32::from(self.counts[length]);
            if count == 0 {
                continue;
            }
            let bit_count =
                u32::try_from(length).expect("Huffman code lengths are at most 16 bits");
            reader.ensure_bits(bit_count)?;
            let code = reader.peek_bits(bit_count);
            let Some(offset) = code.checked_sub(self.first_code[length]) else {
                continue;
            };
            if offset >= count {
                continue;
            }
            let symbol_index = usize::from(self.first_symbol[length])
                + usize::try_from(offset).expect("the symbol offset is at most u16::MAX");
            reader.consume_bits(bit_count);
            return Ok(self.symbols[symbol_index]);
        }

        let (symbol, length) = self.fallback.ok_or(Error::InvalidHuffmanTable {
            reason: "small Huffman table has no fallback symbol",
        })?;
        reader.ensure_bits(u32::from(length))?;
        reader.consume_bits(u32::from(length));
        Ok(symbol)
    }
}

impl<const SYMBOLS: usize> Default for SmallHuffmanTable<SYMBOLS> {
    fn default() -> Self {
        Self::new()
    }
}
