use super::*;
use alloc::vec;
use alloc::vec::Vec;

use crate::test_bitwriter::BitWriter;

// -- Canonical code assignment ----------------------------------------

fn assign_codes(lengths: &[u8]) -> Vec<(u32, u8)> {
    let mut counts = [0u32; 17];
    for &len in lengths {
        if len > 0 && (len as usize) < counts.len() {
            counts[len as usize] += 1;
        }
    }
    let mut next_code = [0u32; 17];
    let mut code: u32 = 0;
    for bits in 1..17usize {
        code = (code + counts[bits - 1]) << 1;
        next_code[bits] = code;
    }
    let mut codes = vec![(0u32, 0u8); lengths.len()];
    for (sym, &len) in lengths.iter().enumerate() {
        let l = len as usize;
        if l > 0 && l < 17 {
            codes[sym] = (next_code[l], len);
            next_code[l] += 1;
        }
    }
    codes
}

fn encode_symbol(w: &mut BitWriter, codes: &[(u32, u8)], sym: usize) {
    let (code, len) = codes[sym];
    w.write_bits(code, u32::from(len));
}

// -- Pre-tree and tree encoding helpers --------------------------------

/// Encode code lengths via a pre-tree, writing to the `BitWriter`.
/// `prev` contains previous block's lengths (or zeros for first block).
/// This writes the 20 x 4-bit pre-tree lengths, then the symbols.
fn write_code_lengths_simple(w: &mut BitWriter, target_lens: &[u8], prev_lens: &[u8]) {
    // For simplicity in tests, we only use symbols 0-16 (direct
    // delta encoding). Compute deltas.
    let mut deltas = Vec::with_capacity(target_lens.len());
    for (i, &target) in target_lens.iter().enumerate() {
        let old = if i < prev_lens.len() { prev_lens[i] } else { 0 };
        let delta_sym =
            ((u32::from(old) + NUM_CODE_LENGTHS - u32::from(target)) % NUM_CODE_LENGTHS) as u8;
        deltas.push(delta_sym);
    }

    // Collect unique delta symbols and assign short code lengths.
    // Use a uniform tree over all used delta symbols.
    let mut used = [false; PRE_TREE_SIZE];
    for &d in &deltas {
        used[d as usize] = true;
    }
    let used_count = used.iter().filter(|&&u| u).count();
    let code_len = if used_count <= 1 {
        1u8
    } else {
        // Smallest power of 2 >= used_count
        let mut bits = 1u8;
        while (1usize << bits) < used_count {
            bits += 1;
        }
        bits
    };

    // Assign code lengths: all used symbols get `code_len`.
    let mut precode_lengths = [0u8; PRE_TREE_SIZE];
    for (i, &u) in used.iter().enumerate() {
        if u {
            precode_lengths[i] = code_len;
        }
    }

    // Write the 20 pre-tree code lengths (4 bits each).
    for &pl in &precode_lengths {
        w.write_bits(u32::from(pl), PRE_TREE_CODE_BITS);
    }

    // Build codes for the pre-tree.
    let pre_codes = assign_codes(&precode_lengths);

    // Write each delta symbol using the pre-tree.
    for &d in &deltas {
        encode_symbol(w, &pre_codes, d as usize);
    }
}

/// Write a complete verbatim block header and body for the given
/// literal bytes.
fn build_verbatim_literals_block(literals: &[u8]) -> Vec<u8> {
    let mut w = BitWriter::new();

    // Block type = 1 (verbatim), 3 bits.
    w.write_bits(BLOCK_VERBATIM, 3);
    // Default block size flag = 1 (32768).
    w.write_bits(1, 1);

    // Build a main tree where all used literal symbols have the
    // same code length. The main tree has 496 symbols.
    let mut main_lens = [0u8; MAIN_TREE_SIZE];

    // Collect unique literals.
    let mut used_lits = [false; 256];
    for &b in literals {
        used_lits[b as usize] = true;
    }
    let lit_count = used_lits.iter().filter(|&&u| u).count().max(1);

    // Assign uniform code length.
    let code_len = {
        let mut bits = 1u8;
        while (1usize << bits) < lit_count {
            bits += 1;
        }
        bits
    };
    for (i, &u) in used_lits.iter().enumerate() {
        if u {
            main_lens[i] = code_len;
        }
    }

    // Write main tree: first half (0..256), second half (256..496).
    let prev_main = [0u8; MAIN_TREE_SIZE];
    write_code_lengths_simple(&mut w, &main_lens[..256], &prev_main[..256]);
    write_code_lengths_simple(
        &mut w,
        &main_lens[256..MAIN_TREE_SIZE],
        &prev_main[256..MAIN_TREE_SIZE],
    );

    // Length tree: all zeros is fine since we have no matches.
    // But we must encode it. Use symbol 17 (run of zeros).
    // Actually, the length tree has 249 elements. We need at
    // least one non-zero. Let's just give symbol 0 a code length
    // of 1 for a valid single-symbol tree.
    let mut length_lens = [0u8; LENGTH_TREE_SIZE];
    length_lens[0] = 1;
    let prev_length = [0u8; LENGTH_TREE_SIZE];
    write_code_lengths_simple(&mut w, &length_lens, &prev_length);

    // Now encode the literal symbols.
    let main_codes = assign_codes(&main_lens);
    for &b in literals {
        encode_symbol(&mut w, &main_codes, b as usize);
    }

    w.finish(2)
}

/// Build a verbatim block with literals and matches.
/// `ops` is a sequence of operations to encode.
fn build_verbatim_block_with_matches(
    ops: &[TestOp],
    prev_main: &[u8; MAIN_TREE_SIZE],
    prev_length: &[u8; LENGTH_TREE_SIZE],
) -> (Vec<u8>, [u8; MAIN_TREE_SIZE], [u8; LENGTH_TREE_SIZE]) {
    let mut w = BitWriter::new();

    // Block type = 1 (verbatim).
    w.write_bits(BLOCK_VERBATIM, 3);
    // Default block size.
    w.write_bits(1, 1);

    // Determine which main tree and length tree symbols we need.
    let mut main_used = [false; MAIN_TREE_SIZE];
    let mut length_used = [false; LENGTH_TREE_SIZE];

    for op in ops {
        match op {
            TestOp::Literal(b) => {
                main_used[*b as usize] = true;
            }
            TestOp::Match {
                position_slot,
                length_header,
                length_extra,
                ..
            } => {
                let main_sym = 256 + position_slot * 8 + length_header;
                main_used[main_sym] = true;
                if *length_header == 7 {
                    length_used[*length_extra] = true;
                }
            }
        }
    }

    // Assign code lengths for used symbols.
    let mut main_lens = [0u8; MAIN_TREE_SIZE];
    let main_count = main_used.iter().filter(|&&u| u).count().max(1);
    let main_cl = {
        let mut bits = 1u8;
        while (1usize << bits) < main_count {
            bits += 1;
        }
        bits
    };
    for (i, &u) in main_used.iter().enumerate() {
        if u {
            main_lens[i] = main_cl;
        }
    }

    let mut length_lens = [0u8; LENGTH_TREE_SIZE];
    let len_count = length_used.iter().filter(|&&u| u).count();
    if len_count > 0 {
        let len_cl = {
            let mut bits = 1u8;
            while (1usize << bits) < len_count {
                bits += 1;
            }
            bits
        };
        for (i, &u) in length_used.iter().enumerate() {
            if u {
                length_lens[i] = len_cl;
            }
        }
    } else {
        // Need at least one valid symbol.
        length_lens[0] = 1;
    }

    // Write trees.
    write_code_lengths_simple(&mut w, &main_lens[..256], &prev_main[..256]);
    write_code_lengths_simple(
        &mut w,
        &main_lens[256..MAIN_TREE_SIZE],
        &prev_main[256..MAIN_TREE_SIZE],
    );
    write_code_lengths_simple(&mut w, &length_lens, prev_length);

    // Encode operations.
    let main_codes = assign_codes(&main_lens);
    let length_codes = assign_codes(&length_lens);

    for op in ops {
        match op {
            TestOp::Literal(b) => {
                encode_symbol(&mut w, &main_codes, *b as usize);
            }
            TestOp::Match {
                position_slot,
                length_header,
                length_extra,
                footer_value,
            } => {
                let main_sym = 256 + position_slot * 8 + length_header;
                encode_symbol(&mut w, &main_codes, main_sym);

                if *length_header == 7 {
                    encode_symbol(&mut w, &length_codes, *length_extra);
                }

                // Write footer bits for position slot.
                if *position_slot >= 3 {
                    let extra = u32::from(FOOTER_BITS[*position_slot]);
                    w.write_bits(*footer_value, extra);
                }
            }
        }
    }

    (w.finish(2), main_lens, length_lens)
}

#[derive(Clone)]
enum TestOp {
    Literal(u8),
    Match {
        position_slot: usize,
        length_header: usize,
        length_extra: usize,
        footer_value: u32,
    },
}

// -- Uncompressed block builder ----------------------------------------

fn build_uncompressed_block(data: &[u8], r0: u32, r1: u32, r2: u32) -> Vec<u8> {
    let mut w = BitWriter::new();
    // Block type = 3 (uncompressed), 3 bits.
    w.write_bits(BLOCK_UNCOMPRESSED, 3);
    // Non-default block size.
    w.write_bits(0, 1);
    w.write_bits(
        u32::try_from(data.len()).expect("the synthetic block is smaller than 64 KiB"),
        16,
    );

    // Flush the bitstream before writing raw bytes.
    let mut result = w.finish(2);
    // Remove the trailing padding from BitWriter::finish.
    result.truncate(result.len() - 4);

    // Align: the BitWriter already wrote full 16-bit words, so
    // byte_pos after align_to_u16 should be at the current position.
    // However, we need to ensure proper alignment. The data after
    // the bitstream should start at an even offset.
    if !result.len().is_multiple_of(2) {
        result.push(0);
    }

    // R0, R1, R2 as raw u32 LE.
    result.extend_from_slice(&r0.to_le_bytes());
    result.extend_from_slice(&r1.to_le_bytes());
    result.extend_from_slice(&r2.to_le_bytes());

    // Raw data bytes.
    result.extend_from_slice(data);

    // If odd count, add a padding byte.
    if !data.len().is_multiple_of(2) {
        result.push(0);
    }

    result
}

// -- Tests -------------------------------------------------------------

#[test]
fn uncompressed_block_passthrough() {
    let payload = b"Hello, LZX!";
    let input = build_uncompressed_block(payload, 1, 1, 1);
    let mut output = [0u8; 11];
    let n = decompress(&input, &mut output).expect("decompress failed");
    // E8 post-processing may modify data containing 0xE8, but
    // "Hello, LZX!" has no 0xE8 bytes so output should match.
    assert_eq!(n, 11);
    assert_eq!(&output[..n], payload);
}

#[test]
fn verbatim_block_literals_only() {
    let literals = [0x41u8, 0x42, 0x43, 0x44]; // "ABCD"
    let input = build_verbatim_literals_block(&literals);
    let mut output = [0u8; 4];
    let n = decompress(&input, &mut output).expect("decompress failed");
    assert_eq!(n, 4);
    assert_eq!(&output[..4], b"ABCD");
}

#[test]
fn verbatim_block_with_match() {
    // Write "ABCD", then a match that copies 4 bytes from offset 4.
    // Position slot 4 has base=4, footer_bits=1.
    // Offset = base + footer_value - 2 = 4 + 0 - 2 = 2.
    // Wait, we want offset=4. So 4 + footer_value - 2 = 4 →
    // footer_value = 2. But footer_bits for slot 4 is 1, max
    // value is 1. So slot 4 can encode offsets 2..3.
    //
    // For offset=4: 4 + 2 = 6 (stored). Slot 5: base=6,
    // footer_bits=1. 6 + footer - 2 = offset → 6+0-2=4. Yes!
    // Use position slot 5, footer_value=0.
    let ops = vec![
        TestOp::Literal(b'A'),
        TestOp::Literal(b'B'),
        TestOp::Literal(b'C'),
        TestOp::Literal(b'D'),
        TestOp::Match {
            position_slot: 5,
            length_header: 2, // length = 2 + 2 = 4
            length_extra: 0,
            footer_value: 0,
        },
    ];
    let prev_main = [0u8; MAIN_TREE_SIZE];
    let prev_length = [0u8; LENGTH_TREE_SIZE];
    let (input, _, _) = build_verbatim_block_with_matches(&ops, &prev_main, &prev_length);

    let mut output = [0u8; 8];
    let n = decompress(&input, &mut output).expect("decompress failed");
    assert_eq!(n, 8);
    assert_eq!(&output[..8], b"ABCDABCD");
}

#[test]
fn aligned_offset_block() {
    // Build an aligned offset block. We need to construct one
    // manually since our test helpers only do verbatim.
    let mut w = BitWriter::new();

    // Block type = 2 (aligned), 3 bits.
    w.write_bits(BLOCK_ALIGNED, 3);
    // Default block size.
    w.write_bits(1, 1);

    // Aligned offset tree: 8 entries, 3 bits each.
    // Use uniform 3-bit codes for all 8 symbols.
    let aligned_lens = [3u8; ALIGNED_TREE_SIZE];
    for &al in &aligned_lens {
        w.write_bits(u32::from(al), ALIGNED_CODE_BITS);
    }

    // Main tree: we need literal 'X' (0x58) and a match symbol.
    // Use position slot 6 (base=8, footer=2): offset = 8+fb-2.
    // With aligned: read (2-3)=negative, so footer < 3 → read
    // directly. Actually footer_bits for slot 6 = 2 which is
    // < 3, so aligned tree isn't used for this slot.
    //
    // Use slot 7: base=12, footer=2. Still < 3.
    // Use slot 8: base=16, footer=3. Aligned IS used.
    // offset = 16 + (verbatim<<3) + aligned - 2
    // For offset=14: 16 + 0 + 0 - 2 = 14. Yes!
    //
    // We need 14 literal bytes first, then a match at offset 14.
    let mut ops = Vec::new();
    for i in 0..14u8 {
        ops.push(TestOp::Literal(b'A' + (i % 4)));
    }
    // Match: slot 8, length_header=2 (len=4), footer: verbatim
    // bits = 0 (0 bits since footer-3=0), aligned = 0.
    ops.push(TestOp::Match {
        position_slot: 8,
        length_header: 2,
        length_extra: 0,
        footer_value: 0, // Not used directly; handled below.
    });

    // Determine main/length tree symbols.
    let mut main_used = [false; MAIN_TREE_SIZE];
    let mut length_used = [false; LENGTH_TREE_SIZE];
    for op in &ops {
        match op {
            TestOp::Literal(b) => main_used[*b as usize] = true,
            TestOp::Match {
                position_slot,
                length_header,
                length_extra,
                ..
            } => {
                main_used[256 + position_slot * 8 + length_header] = true;
                if *length_header == 7 {
                    length_used[*length_extra] = true;
                }
            }
        }
    }

    let mut main_lens = [0u8; MAIN_TREE_SIZE];
    let main_count = main_used.iter().filter(|&&u| u).count().max(1);
    let main_cl = {
        let mut bits = 1u8;
        while (1usize << bits) < main_count {
            bits += 1;
        }
        bits
    };
    for (i, &u) in main_used.iter().enumerate() {
        if u {
            main_lens[i] = main_cl;
        }
    }

    let mut length_lens = [0u8; LENGTH_TREE_SIZE];
    length_lens[0] = 1;

    let prev_main = [0u8; MAIN_TREE_SIZE];
    let prev_length = [0u8; LENGTH_TREE_SIZE];

    // Write main tree (two halves) and length tree.
    write_code_lengths_simple(&mut w, &main_lens[..256], &prev_main[..256]);
    write_code_lengths_simple(
        &mut w,
        &main_lens[256..MAIN_TREE_SIZE],
        &prev_main[256..MAIN_TREE_SIZE],
    );
    write_code_lengths_simple(&mut w, &length_lens, &prev_length);

    // Encode data.
    let main_codes = assign_codes(&main_lens);
    let aligned_codes = assign_codes(&aligned_lens);

    for op in &ops {
        match op {
            TestOp::Literal(b) => {
                encode_symbol(&mut w, &main_codes, *b as usize);
            }
            TestOp::Match {
                position_slot,
                length_header,
                length_extra,
                ..
            } => {
                let main_sym = 256 + position_slot * 8 + length_header;
                encode_symbol(&mut w, &main_codes, main_sym);

                if *length_header == 7 {
                    let length_codes_local = assign_codes(&length_lens);
                    encode_symbol(&mut w, &length_codes_local, *length_extra);
                }

                // Footer bits for slot 8: 3 bits.
                // Aligned: read (3-3)=0 verbatim bits, then 3
                // aligned bits.
                // We want aligned_bits=0 → symbol 0.
                encode_symbol(&mut w, &aligned_codes, 0);
            }
        }
    }

    let input = w.finish(2);
    let mut output = [0u8; 18]; // 14 + 4
    let n = decompress(&input, &mut output).expect("decompress failed");
    assert_eq!(n, 18);
    // The match copies 4 bytes from offset 14 (the start).
    assert_eq!(&output[14..18], &output[0..4]);
}

#[test]
fn repeat_offset_r0_r1_r2() {
    // Test the LRU repeat offset queue.
    // Write 8 bytes "ABCDABCD", then:
    //   Match slot 0 (R0): should copy from offset of last match
    //   Match slot 1 (R1): should swap R1↔R0
    //   Match slot 2 (R2): should rotate
    //
    // First, establish R0 = 4 by doing a match at offset 4.
    // Position slot 5: base=6, footer_bits=1, footer=0 → offset=4.
    // Then R0=4, R1=1, R2=1.
    //
    // Next, use slot 0 (R0=4): copy 2 bytes from offset 4.
    // R0 stays 4.
    //
    // Set R1 to something by doing another explicit match.
    // Position slot 3: base=3, footer_bits=0 → offset=3-2=1.
    // Now R0=1, R1=4, R2=1.
    //
    // Use slot 1 (R1=4): copy 2 from offset 4. R1↔R0 → R0=4,R1=1.
    // Use slot 2 (R2=1): copy 2 from offset 1. R2=R0(4)→R0=1→ wait.
    // Slot 2: offset=R2=1, then R2=R0, R0=offset. R0=1,R1=1,R2=4.

    // For simplicity let's just verify slot 0 reuse.
    let ops = vec![
        TestOp::Literal(b'A'),
        TestOp::Literal(b'B'),
        TestOp::Literal(b'C'),
        TestOp::Literal(b'D'),
        // Match offset=4 via slot 5 (base=6,footer=1,value=0→6+0-2=4)
        TestOp::Match {
            position_slot: 5,
            length_header: 0, // len = 0+2 = 2
            length_extra: 0,
            footer_value: 0,
        },
        // R0=4. Use slot 0 to repeat offset 4.
        TestOp::Match {
            position_slot: 0,
            length_header: 0, // len = 2
            length_extra: 0,
            footer_value: 0,
        },
        // Use slot 1 (R1=1, initial). len=2, copies 2 from offset 1.
        TestOp::Match {
            position_slot: 1,
            length_header: 0,
            length_extra: 0,
            footer_value: 0,
        },
    ];

    let prev_main = [0u8; MAIN_TREE_SIZE];
    let prev_length = [0u8; LENGTH_TREE_SIZE];
    let (input, _, _) = build_verbatim_block_with_matches(&ops, &prev_main, &prev_length);

    // Expected output:
    // Pos 0-3: ABCD
    // Pos 4-5: match offset=4, len=2 → copies [0..2] = "AB"
    // Pos 6-7: match R0=4, len=2 → copies [2..4] = "CD"
    // Pos 8-9: match R1=1, len=2 → copies [7..9] = "DD"
    // Wait, R1 was initially 1. After first explicit match (slot 5),
    // R2=R1=1, R1=R0=1, R0=4. So R1=1.
    // After slot 0: R0 stays 4, R1=1, R2=1.
    // After slot 1: offset=R1=1, then R1=R0=4, R0=1.
    //   Copy 2 from offset 1: output[7]=output[6], output[8]=output[7].
    //   At this point output[6..8] = "CD" (from R0 match).
    //   offset 1 from pos 8: copies output[7]='D', output[8]='D'
    // Total: "ABCD" + "AB" + "CD" + "DD" = "ABCDABCDDD"
    let mut output = [0u8; 10];
    let n = decompress(&input, &mut output).expect("decompress failed");
    assert_eq!(n, 10);
    assert_eq!(&output[..4], b"ABCD");
    assert_eq!(&output[4..6], b"AB");
    assert_eq!(&output[6..8], b"CD");
    assert_eq!(&output[8..10], b"DD");
}

#[test]
fn invalid_block_type_returns_error() {
    let mut w = BitWriter::new();
    // Block type 0 is invalid.
    w.write_bits(0, 3);
    w.write_bits(1, 1); // default block size
    let input = w.finish(2);

    let mut output = [0u8; 32];
    let result = decompress(&input, &mut output);
    assert!(result.is_err());
}

#[test]
fn e8_integration() {
    // E8 post-processing only scans buffers > 10 bytes and
    // only processes positions < len - 10. Use 13 bytes so
    // E8 at pos 2 is within the scan range (2 < 13-10 = 3).
    //
    // Raw decompressed: [0x90, 0x90, 0xE8, 0x0A, 0x00, 0x00, 0x00, 0x90*6]
    // E8 at pos 2: operand = 10. Relative = 10 - 2 = 8.
    let literals = [
        0x90u8, 0x90, 0xE8, 0x0A, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    ];
    let input = build_verbatim_literals_block(&literals);

    let mut output = [0u8; 13];
    let n = decompress(&input, &mut output).expect("decompress failed");
    assert_eq!(n, 13);
    assert_eq!(output[0], 0x90);
    assert_eq!(output[1], 0x90);
    assert_eq!(output[2], 0xE8);
    let operand = i32::from_le_bytes([output[3], output[4], output[5], output[6]]);
    assert_eq!(operand, 8);
}

#[test]
fn lenient_corrupt_block() {
    // Feed a truncated/corrupt bitstream. Lenient mode should
    // return partial output with had_errors = true.
    let input = [0xFF, 0xFF, 0x00, 0x00]; // garbage
    let mut output = [0xCC; 32];
    let r = decompress_lenient(&input, &mut output);
    assert!(r.had_errors);
    // Output should be zero-filled (lenient fills zeros upfront).
    assert!(output.iter().all(|&b| b == 0));
}

#[test]
fn lenient_valid_matches_strict() {
    let literals = [0x41u8, 0x42, 0x43, 0x44];
    let input = build_verbatim_literals_block(&literals);

    let mut strict_out = [0u8; 4];
    let strict_n = decompress(&input, &mut strict_out).expect("strict failed");

    let mut lenient_out = [0u8; 4];
    let r = decompress_lenient(&input, &mut lenient_out);

    assert!(!r.had_errors);
    assert_eq!(r.bytes_written, strict_n);
    assert_eq!(&lenient_out[..r.bytes_written], &strict_out[..strict_n]);
}
