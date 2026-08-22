use alloc::format;

use super::{
    Error, MAX_OVERFLOW, MAX_ROOT_SIZE, NUM_POSITION_SLOTS, PackedEntry, Result, canonical_codes,
    count_per_length, validate_code_space, validate_lengths,
};

/// Decode table with flat subtables for overflow codes.
///
/// Root table: `2^table_bits` entries (direct lookup).
/// Overflow: flat subtables indexed by remaining bits after root lookup.
/// Worst-case decode = exactly 2 array lookups (no loops, no tree walk).
pub(super) struct LzxDecodeTable {
    /// Root direct-lookup table.
    direct: [PackedEntry; MAX_ROOT_SIZE],
    /// Flat subtables for codes longer than `table_bits`.
    overflow: [PackedEntry; MAX_OVERFLOW],
    /// Number of overflow entries allocated.
    overflow_len: u16,
    /// Root table bits for this instance.
    table_bits: u32,
    /// Per-root-slot subtable bit width. Only entries where
    /// `direct[i] & 0xF == 0` are meaningful. Stored separately
    /// to keep `PackedEntry` at 16 bits.
    subtable_bits_map: [u8; MAX_ROOT_SIZE],
}

impl LzxDecodeTable {
    /// Build a decode table from code lengths with the given root table width.
    pub(super) fn build(lengths: &[u8], table_bits: u32) -> Result<Self> {
        debug_assert!((1..=11).contains(&table_bits));
        validate_lengths(lengths)?;
        let counts = count_per_length(lengths);
        validate_code_space(&counts)?;
        let root_size = 1usize << table_bits;

        let mut tbl = Self {
            direct: [0u16; MAX_ROOT_SIZE],
            overflow: [0u16; MAX_OVERFLOW],
            overflow_len: 0,
            table_bits,
            subtable_bits_map: [0u8; MAX_ROOT_SIZE],
        };

        // First pass: determine which root prefixes need subtables
        // and how many extra bits each needs.
        let mut max_extra_per_prefix = [0u8; MAX_ROOT_SIZE];
        for (_, code, len) in canonical_codes(lengths, &counts) {
            let len_u32 = u32::from(len);
            if len_u32 > table_bits {
                let prefix = (code >> (len_u32 - table_bits)) as usize;
                let extra = u8::try_from(len_u32 - table_bits)
                    .expect("LZX code lengths are at most 16 bits");
                if extra > max_extra_per_prefix[prefix] {
                    max_extra_per_prefix[prefix] = extra;
                }
            }
        }

        // Allocate subtables for each prefix that needs one.
        // subtable_offset[prefix] = starting index in overflow[].
        let mut subtable_offset = [0u16; MAX_ROOT_SIZE];
        for prefix in 0..root_size {
            let extra = max_extra_per_prefix[prefix];
            if extra > 0 {
                let sub_size = 1usize << extra;
                let offset = tbl.overflow_len as usize;
                if offset + sub_size > MAX_OVERFLOW {
                    return Err(Error::InvalidHuffmanTable {
                        reason: "LZX overflow table exceeds capacity",
                    });
                }
                let offset = u16::try_from(offset)
                    .expect("the LZX overflow table is bounded below u16::MAX");
                subtable_offset[prefix] = offset;
                tbl.direct[prefix] = offset << 4; // code_len=0 → subtable
                tbl.subtable_bits_map[prefix] = extra;
                tbl.overflow_len +=
                    u16::try_from(sub_size).expect("an LZX subtable has at most 2^16 entries");
            }
        }

        // Second pass: populate direct table and subtables.
        // Track first valid direct entry for filling unused slots.
        let mut first_direct_entry: Option<PackedEntry> = None;

        for (sym, code, len) in canonical_codes(lengths, &counts) {
            let sym =
                u16::try_from(sym).expect("an LZX decode table has fewer than u16::MAX symbols");
            let len_u32 = u32::from(len);

            if len_u32 <= table_bits {
                // Short code: fill all suffix positions in root table.
                let pad = table_bits - len_u32;
                let base = (code << pad) as usize;
                let count = 1usize << pad;
                let entry = (sym << 4) | u16::from(len);
                if first_direct_entry.is_none() {
                    first_direct_entry = Some(entry);
                }
                // Fill entries. For short codes (large pad), this is
                // the hot path during table build.
                let dest = &mut tbl.direct[base..base + count];
                dest.fill(entry);
            } else {
                // Long code: insert into the flat subtable.
                let prefix = (code >> (len_u32 - table_bits)) as usize;
                let sub_bits = u32::from(max_extra_per_prefix[prefix]);
                let offset = subtable_offset[prefix] as usize;

                // Suffix within the subtable, padded to subtable width.
                let suffix_bits = len_u32 - table_bits;
                let suffix = code & ((1 << suffix_bits) - 1);
                let pad = sub_bits - suffix_bits;
                let sub_base = (suffix << pad) as usize;
                let sub_count = 1usize << pad;
                let entry = (sym << 4) | u16::from(len);

                let dest = &mut tbl.overflow[offset + sub_base..offset + sub_base + sub_count];
                dest.fill(entry);
            }
        }

        // Fill unused root entries with a valid entry (avoids
        // undefined behavior on malformed but parseable streams).
        if let Some(fill) = first_direct_entry {
            for (slot, &extra) in tbl.direct[..root_size]
                .iter_mut()
                .zip(&max_extra_per_prefix[..root_size])
            {
                if *slot == 0 && extra == 0 {
                    *slot = fill;
                }
            }
        }

        Ok(tbl)
    }

    /// Decode one symbol from the top bits of `next_bits`.
    /// Returns `(symbol, code_len)`.
    ///
    /// Worst case: exactly 2 array lookups (root + subtable).
    #[inline]
    pub(super) fn decode(&self, next_bits: u32) -> (u16, u32) {
        let index = (next_bits >> (32 - self.table_bits)) as usize;
        // SAFETY: index = next_bits >> (32 - table_bits).
        // For table_bits <= 11, index < 2048 = MAX_ROOT_SIZE.
        let entry = unsafe { *self.direct.get_unchecked(index) };
        let code_len = u32::from(entry & 0xF);
        if code_len != 0 {
            return (entry >> 4, code_len);
        }
        // Subtable lookup: one more indexed load, no loop.
        self.decode_subtable(next_bits, index, entry)
    }

    #[inline]
    fn decode_subtable(
        &self,
        next_bits: u32,
        root_index: usize,
        root_entry: PackedEntry,
    ) -> (u16, u32) {
        let sub_offset = (root_entry >> 4) as usize;
        // SAFETY: subtable_bits_map has MAX_ROOT_SIZE entries,
        // root_index < MAX_ROOT_SIZE (checked by caller).
        let sub_bits = u32::from(unsafe { *self.subtable_bits_map.get_unchecked(root_index) });
        // Extract the next `sub_bits` after the root bits.
        let sub_index = ((next_bits << self.table_bits) >> (32 - sub_bits)) as usize;
        // SAFETY: sub_offset + sub_index < overflow_len (guaranteed by build).
        let sub_entry = unsafe { *self.overflow.get_unchecked(sub_offset + sub_index) };
        (sub_entry >> 4, u32::from(sub_entry & 0xF))
    }
}

// ---------------------------------------------------------------------------
// Cold error constructors
// ---------------------------------------------------------------------------

#[cold]
#[inline(never)]
pub(super) fn err_invalid_data(offset: usize, detail: &str) -> Error {
    Error::InvalidData {
        offset,
        reason: alloc::string::String::from(detail),
    }
}

#[cold]
#[inline(never)]
pub(super) fn err_output_too_small(needed: usize, available: usize) -> Error {
    Error::OutputTooSmall {
        expected: needed,
        actual: available,
    }
}

#[cold]
#[inline(never)]
pub(super) fn err_input_truncated(offset: usize, expected: usize, actual: usize) -> Error {
    Error::InputTruncated {
        offset,
        expected,
        actual,
    }
}

#[cold]
#[inline(never)]
pub(super) fn err_match_offset_exceeds(
    offset: usize,
    match_offset: usize,
    out_pos: usize,
) -> Error {
    Error::InvalidData {
        offset,
        reason: format!(
            "LZX match offset {match_offset} exceeds \
             output position {out_pos}",
        ),
    }
}

#[cold]
#[inline(never)]
pub(super) fn err_position_slot_exceeds(offset: usize, slot: usize) -> Error {
    Error::InvalidData {
        offset,
        reason: format!(
            "LZX position slot {slot} exceeds maximum {}",
            NUM_POSITION_SLOTS - 1,
        ),
    }
}

#[cold]
#[inline(never)]
pub(super) fn err_offset_below_minimum(offset: usize, raw: u32) -> Error {
    Error::InvalidData {
        offset,
        reason: format!("LZX computed offset {raw} below minimum"),
    }
}
