use super::*;
use crate::lzx_cab::WindowSize;
use crate::test_bitwriter::BitWriter;

/// Build a CAB LZX stream header (E8 disabled).
fn write_header_no_e8(w: &mut BitWriter) {
    w.write_bits(0, 1); // E8 disabled
}

/// Build a CAB LZX stream header (E8 enabled with given `file_size`).
fn write_header_with_e8(w: &mut BitWriter, file_size: i32) {
    w.write_bits(1, 1); // E8 enabled
    let fs = u32::try_from(file_size).expect("test file sizes are nonnegative");
    w.write_bits(fs >> 16, 16); // high 16 bits
    w.write_bits(fs & 0xFFFF, 16); // low 16 bits
}

/// Write a 4-symbol pretree: sym 0→00, 16→01, 17→10, 18→11.
fn write_pretree_4sym(w: &mut BitWriter) {
    let mut lens = [0u8; 20];
    lens[0] = 2;
    lens[16] = 2;
    lens[17] = 2;
    lens[18] = 2;
    for &pl in &lens {
        w.write_bits(u32::from(pl), 4);
    }
}

/// Write a 3-symbol pretree: sym 0→0, 17→10, 18→11.
fn write_pretree_3sym(w: &mut BitWriter) {
    let mut lens = [0u8; 20];
    lens[0] = 1;
    lens[17] = 2;
    lens[18] = 2;
    for &pl in &lens {
        w.write_bits(u32::from(pl), 4);
    }
}

/// Encode a run of `count` zeros. Pretree: 0→00, 17→10, 18→11.
fn encode_zero_run_4sym(w: &mut BitWriter, mut count: usize) {
    while count >= 20 {
        let run = count.min(51);
        w.write_bits(0b11, 2); // sym 18
        w.write_bits(
            u32::try_from(run - 20).expect("the synthetic long run uses five bits"),
            5,
        );
        count -= run;
    }
    if count >= 4 {
        w.write_bits(0b10, 2); // sym 17
        w.write_bits(
            u32::try_from(count - 4).expect("the synthetic short run uses four bits"),
            4,
        );
        count = 0;
    }
    for _ in 0..count {
        w.write_bits(0b00, 2); // sym 0 (delta 0 = keep previous = 0)
    }
}

/// Encode zeros with 3-symbol pretree (0→0, 17→10, 18→11).
fn encode_zero_run_3sym(w: &mut BitWriter, mut count: usize) {
    while count >= 20 {
        let run = count.min(51);
        w.write_bits(0b11, 2);
        w.write_bits(
            u32::try_from(run - 20).expect("the synthetic long run uses five bits"),
            5,
        );
        count -= run;
    }
    if count >= 4 {
        w.write_bits(0b10, 2);
        w.write_bits(
            u32::try_from(count - 4).expect("the synthetic short run uses four bits"),
            4,
        );
        count = 0;
    }
    for _ in 0..count {
        w.write_bits(0, 1);
    }
}

// -- Uncompressed block tests ------------------------------------------

#[test]
fn uncompressed_block_abc() {
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_UNCOMPRESSED, 3);
    w.write_bits(3, 24); // block size = 3

    let mut data = w.into_data();
    // Align to 16-bit boundary (writer should already be aligned).
    if !data.len().is_multiple_of(2) {
        data.push(0);
    }
    // R0, R1, R2 as raw u32 LE.
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    // Raw bytes.
    data.extend_from_slice(b"abc");
    data.push(0); // padding for odd count

    let mut output = [0u8; 3];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("uncompressed abc");
    assert_eq!(n, 3);
    assert_eq!(&output, b"abc");
}

#[test]
fn uncompressed_block_all_window_sizes() {
    for &ws in &[
        WindowSize::KB32,
        WindowSize::KB64,
        WindowSize::KB128,
        WindowSize::KB256,
        WindowSize::KB512,
        WindowSize::MB1,
        WindowSize::MB2,
    ] {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_UNCOMPRESSED, 3);
        w.write_bits(5, 24);

        let mut data = w.into_data();
        if !data.len().is_multiple_of(2) {
            data.push(0);
        }
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"HELLO");
        data.push(0);

        let mut output = [0u8; 5];
        let n = decompress(&data, &mut output, ws)
            .unwrap_or_else(|e| panic!("failed with {ws:?}: {e}"));
        assert_eq!(n, 5);
        assert_eq!(&output, b"HELLO");
    }
}

// -- Verbatim block tests ----------------------------------------------

#[test]
fn verbatim_literals_only() {
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(2, 24); // block size = 2

    // KB32 → 30 position slots → main tree = 256 + 240 = 496
    // Main tree first half (256 elements): A=1, B=1, rest=0.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 65); // skip to 'A' (0x41)
    w.write_bits(0b01, 2); // delta 16 for A
    w.write_bits(0b01, 2); // delta 16 for B
    encode_zero_run_4sym(&mut w, 193);

    // Main tree second half (240 elements): all zero.
    write_pretree_3sym(&mut w);
    encode_zero_run_3sym(&mut w, 240);

    // Length tree (249 elements): syms 0,1 get len=1.
    write_pretree_4sym(&mut w);
    w.write_bits(0b01, 2); // delta 16 for sym 0
    w.write_bits(0b01, 2); // delta 16 for sym 1
    encode_zero_run_4sym(&mut w, 247);

    // Tokens: A(code 0), B(code 1).
    w.write_bits(0, 1);
    w.write_bits(1, 1);

    let data = w.into_data();

    let mut output = [0u8; 2];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("verbatim literals");
    assert_eq!(n, 2);
    assert_eq!(&output, b"AB");
}

#[test]
fn verbatim_with_match() {
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(6, 24); // block size = 6 ("AAAAAA")

    // We'll encode: literal 'A', then match(offset=1, len=5).
    // offset=1 → formatted=3 → slot 3 (base=3, footer=0).
    // Match symbol = 256 + 3*8 + 3 = 283 (length_header=3 → len=5).
    // In the second half of main tree, index = 283 - 256 = 27.

    // Main first half (256): only A(0x41)=1.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 65);
    w.write_bits(0b01, 2); // delta 16 for 'A'
    encode_zero_run_4sym(&mut w, 190);

    // Main second half (240): only index 27=1.
    // 240 = 27 zeros + 1 non-zero + 212 zeros
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 27);
    w.write_bits(0b01, 2); // delta 16 for match sym
    encode_zero_run_4sym(&mut w, 212);

    // Length tree: syms 0,1 get len=1.
    write_pretree_4sym(&mut w);
    w.write_bits(0b01, 2);
    w.write_bits(0b01, 2);
    encode_zero_run_4sym(&mut w, 247);

    // Tokens: literal A (code 0), match 283 (code 1).
    w.write_bits(0, 1); // 'A'
    w.write_bits(1, 1); // match (slot=3, footer_bits=0, no footer needed)

    let data = w.into_data();

    let mut output = [0u8; 6];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("verbatim with match");
    assert_eq!(n, 6);
    assert_eq!(&output, b"AAAAAA");
}

// -- Aligned offset block test -----------------------------------------

#[test]
fn aligned_offset_block() {
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_ALIGNED, 3);
    w.write_bits(6, 24);

    // Aligned offset tree: 8 elements, 3 bits each.
    // Give syms 0,1 len=1 for a valid tree.
    let aligned_lens: [u8; 8] = [1, 1, 0, 0, 0, 0, 0, 0];
    for &al in &aligned_lens {
        w.write_bits(u32::from(al), 3);
    }

    // Same trees as verbatim_with_match test.
    // Main first half: A=1.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 65);
    w.write_bits(0b01, 2);
    encode_zero_run_4sym(&mut w, 190);

    // Main second half: index 27 (sym 283)=1.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 27);
    w.write_bits(0b01, 2);
    encode_zero_run_4sym(&mut w, 212);

    // Length tree.
    write_pretree_4sym(&mut w);
    w.write_bits(0b01, 2);
    w.write_bits(0b01, 2);
    encode_zero_run_4sym(&mut w, 247);

    // Tokens: literal A, match (slot 3, no footer).
    w.write_bits(0, 1);
    w.write_bits(1, 1);

    let data = w.into_data();

    let mut output = [0u8; 6];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("aligned offset block");
    assert_eq!(n, 6);
    assert_eq!(&output, b"AAAAAA");
}

// -- Multi-block with inter-block tree carry-over ----------------------

/// Encode N copies of pretree symbol 0 (delta=0, preserves
/// previous code length). Pretree must have sym 0 at `code_len=1`.
fn encode_delta_zero_run(w: &mut BitWriter, count: usize) {
    for _ in 0..count {
        w.write_bits(0, 1); // sym 0 = delta 0
    }
}

/// Write pretree with sym 0 at 1 bit (for delta-0 encoding).
fn write_pretree_delta_zero(w: &mut BitWriter) {
    let mut lens = [0u8; 20];
    lens[0] = 1;
    for &pl in &lens {
        w.write_bits(u32::from(pl), 4);
    }
}

#[test]
fn multi_block_tree_carry_over() {
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);

    // Block 1: verbatim, 2 bytes "AB".
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(2, 24);

    // KB32 → main tree size = 496, second half = 240.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 65);
    w.write_bits(0b01, 2); // A
    w.write_bits(0b01, 2); // B
    encode_zero_run_4sym(&mut w, 193);

    write_pretree_3sym(&mut w);
    encode_zero_run_3sym(&mut w, 240);

    write_pretree_4sym(&mut w);
    w.write_bits(0b01, 2);
    w.write_bits(0b01, 2);
    encode_zero_run_4sym(&mut w, 247);

    w.write_bits(0, 1); // A
    w.write_bits(1, 1); // B

    // Block 2: verbatim, 2 bytes "AB" — reuses trees from block 1.
    // Send delta=0 for every position to preserve previous trees.
    // (Cannot use zero-run syms 17/18 — those SET lengths to 0,
    // overwriting the non-zero entries from block 1.)
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(2, 24);

    // Main first half: 256 delta-0 symbols.
    write_pretree_delta_zero(&mut w);
    encode_delta_zero_run(&mut w, 256);

    // Main second half: 240 delta-0 symbols.
    write_pretree_delta_zero(&mut w);
    encode_delta_zero_run(&mut w, 240);

    // Length tree: 249 delta-0 symbols.
    write_pretree_delta_zero(&mut w);
    encode_delta_zero_run(&mut w, 249);

    // Same tokens as block 1.
    w.write_bits(0, 1); // A
    w.write_bits(1, 1); // B

    let data = w.into_data();

    let mut output = [0u8; 4];
    let n =
        decompress(&data, &mut output, WindowSize::KB32).expect("multi-block tree carry-over");
    assert_eq!(n, 4);
    assert_eq!(&output, b"ABAB");
}

// -- Repeat offset tests -----------------------------------------------

#[test]
fn repeat_offset_r0() {
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(8, 24); // "ABCDABCD"

    // Need: literals A,B,C,D + match(slot 5, len 2) + match(slot 0, len 2)
    // slot 5: base=6, footer=1, footer_val=0 → offset = 6+0-2 = 4
    // slot 0: R0 = 4, len 2

    // Main tree syms needed: A(65), B(66), C(67), D(68),
    //   match_slot5_lh0 = 256+5*8+0 = 296 (second half index 40),
    //   match_slot0_lh0 = 256+0*8+0 = 256 (second half index 0)
    // All get code_len = 3 (6 symbols → need 3 bits).

    // Build main first half: A,B,C,D get len 3.
    let mut main_first = [0u8; 256];
    main_first[65] = 3;
    main_first[66] = 3;
    main_first[67] = 3;
    main_first[68] = 3;

    // Build main second half (240): index 0 and 40 get len 3.
    let second_half_size = 240;
    let mut main_second = [0u8; 240];
    main_second[0] = 3;
    main_second[40] = 3;

    // Write main first half via pretree.
    write_simple_pretree_and_deltas(&mut w, &main_first, &[0u8; 256]);
    write_simple_pretree_and_deltas(&mut w, &main_second, &[0u8; 240]);

    // Length tree: sym 0 = 1 (we don't actually use it).
    let mut length_lens = [0u8; 249];
    length_lens[0] = 1;
    write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

    // Compute canonical codes for full main tree.
    let mut full_main = [0u8; 496];
    full_main[..256].copy_from_slice(&main_first);
    full_main[256..496].copy_from_slice(&main_second[..second_half_size]);

    let main_codes = assign_test_codes(&full_main);

    // Encode: A, B, C, D, match(slot5,lh0), match(slot0,lh0)
    encode_sym(&mut w, &main_codes, 65); // A
    encode_sym(&mut w, &main_codes, 66); // B
    encode_sym(&mut w, &main_codes, 67); // C
    encode_sym(&mut w, &main_codes, 68); // D
    encode_sym(&mut w, &main_codes, 296); // match slot 5
    w.write_bits(0, 1); // footer bit for slot 5
    encode_sym(&mut w, &main_codes, 256); // match slot 0 (R0)

    let data = w.into_data();

    let mut output = [0u8; 8];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("repeat offset r0");
    assert_eq!(n, 8);
    assert_eq!(&output, b"ABCDABCD");
}

#[test]
fn repeat_offset_r1_swap() {
    // After an explicit match sets R0=4, R1=1 (initial),
    // use slot 1 which swaps R0↔R1. R0 becomes 1.
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(8, 24);

    // Syms: A(65), B(66), C(67), D(68)
    //   match_slot5_lh0(296): offset=4
    //   match_slot1_lh0(264): R1 swap → offset=1
    let mut main_lens = [0u8; 496];
    main_lens[65] = 3;
    main_lens[66] = 3;
    main_lens[67] = 3;
    main_lens[68] = 3;
    main_lens[264] = 3; // slot 1, lh 0
    main_lens[296] = 3; // slot 5, lh 0

    write_simple_pretree_and_deltas(&mut w, &main_lens[..256], &[0u8; 256]);
    write_simple_pretree_and_deltas(&mut w, &main_lens[256..496], &[0u8; 240]);

    let mut length_lens = [0u8; 249];
    length_lens[0] = 1;
    write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

    let main_codes = assign_test_codes(&main_lens);

    encode_sym(&mut w, &main_codes, 65); // A
    encode_sym(&mut w, &main_codes, 66); // B
    encode_sym(&mut w, &main_codes, 67); // C
    encode_sym(&mut w, &main_codes, 68); // D
    encode_sym(&mut w, &main_codes, 296); // match slot5 → offset=4
    w.write_bits(0, 1); // footer for slot 5
    // Now R0=4, R1=1
    encode_sym(&mut w, &main_codes, 264); // match slot1 → R1=1, swap R0↔R1
    // R0=1, R1=4. Copy 2 bytes from offset 1.

    let data = w.into_data();
    let mut output = [0u8; 8];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("repeat offset r1");
    assert_eq!(n, 8);
    // Pos 0-3: ABCD, 4-5: AB (offset=4), 6-7: BB (offset=1 from pos 5='B')
    assert_eq!(&output[..4], b"ABCD");
    assert_eq!(&output[4..6], b"AB");
    assert_eq!(&output[6..8], b"BB");
}

#[test]
fn repeat_offset_r2_rotate() {
    // Use slot 2 which takes R2 and rotates: R2=R0, R0=old_R2.
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(10, 24);

    // We need:
    //   4 literals (ABCD)
    //   match slot5 (offset=4, len=2) → R0=4
    //   match slot3 (offset=1, len=2) → R0=1, R1=4, R2=1
    //   match slot2 (R2=1, len=2) → R0=1, R2=old_R0=1
    let mut main_lens = [0u8; 496];
    main_lens[65] = 4; // A
    main_lens[66] = 4; // B
    main_lens[67] = 4; // C
    main_lens[68] = 4; // D
    main_lens[256] = 4; // slot 0, lh 0
    main_lens[272] = 4; // slot 2, lh 0
    main_lens[280] = 4; // slot 3, lh 0
    main_lens[296] = 4; // slot 5, lh 0

    write_simple_pretree_and_deltas(&mut w, &main_lens[..256], &[0u8; 256]);
    write_simple_pretree_and_deltas(&mut w, &main_lens[256..496], &[0u8; 240]);

    let mut length_lens = [0u8; 249];
    length_lens[0] = 1;
    write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

    let main_codes = assign_test_codes(&main_lens);

    encode_sym(&mut w, &main_codes, 65); // A
    encode_sym(&mut w, &main_codes, 66); // B
    encode_sym(&mut w, &main_codes, 67); // C
    encode_sym(&mut w, &main_codes, 68); // D
    encode_sym(&mut w, &main_codes, 296); // slot 5 → offset=4
    w.write_bits(0, 1); // footer
    // R0=4, R1=1, R2=1
    encode_sym(&mut w, &main_codes, 280); // slot 3 → offset=1
    // R0=1, R1=4, R2=1
    encode_sym(&mut w, &main_codes, 272); // slot 2 → R2=1, R0=1, R2=old_R0=1
    // Copy 2 from offset=1 (R2)

    let data = w.into_data();
    let mut output = [0u8; 10];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("repeat offset r2");
    assert_eq!(n, 10);
    assert_eq!(&output[..4], b"ABCD");
    // pos 4-5: offset=4, len=2 → copies ABCD[0..2] = AB
    assert_eq!(&output[4..6], b"AB");
    // pos 6-7: offset=1, len=2 → copies from pos 5,6 = BB
    assert_eq!(&output[6..8], b"BB");
    // pos 8-9: R2=1, offset=1, len=2 → copies from pos 7,8 = BB
    assert_eq!(&output[8..10], b"BB");
}

#[test]
fn length_tree_lookup() {
    // Test length_header == 7 which triggers length tree decode.
    // Match with length_header=7, length_extra=0 → len = 7+0+2 = 9.
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(10, 24); // 1 literal + 9 match = 10

    // We need: literal 'A' and match(slot 3, lh 7, len_extra 0).
    // slot 3 → offset=1, length=9: repeat 'A' 9 times.
    // Match sym = 256 + 3*8 + 7 = 287. Second half index = 31.
    let mut main_lens = [0u8; 496];
    main_lens[65] = 1; // A
    main_lens[287] = 1; // match slot3 lh7

    write_simple_pretree_and_deltas(&mut w, &main_lens[..256], &[0u8; 256]);
    write_simple_pretree_and_deltas(&mut w, &main_lens[256..496], &[0u8; 240]);

    // Length tree: only sym 0 = 1.
    let mut length_lens = [0u8; 249];
    length_lens[0] = 1;
    write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

    let main_codes = assign_test_codes(&main_lens);
    let length_codes = assign_test_codes(&length_lens);

    encode_sym(&mut w, &main_codes, 65); // 'A'
    encode_sym(&mut w, &main_codes, 287); // match slot3 lh7
    encode_sym(&mut w, &length_codes, 0); // length extra = 0

    let data = w.into_data();
    let mut output = [0u8; 10];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("length tree lookup");
    assert_eq!(n, 10);
    assert_eq!(&output, b"AAAAAAAAAA");
}

#[test]
fn aligned_block_with_large_footer() {
    // Test aligned block with position slot 8 (footer_bits=3).
    // In aligned mode, 3 footer bits = 0 verbatim + 3 aligned.
    // slot 8: base=16, footer=3. offset = 16 + aligned - 2.
    // With aligned_sym=0: offset = 16 + 0 - 2 = 14.
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_ALIGNED, 3);
    w.write_bits(18, 24); // 14 literals + 4 match = 18

    // Aligned tree: uniform 3-bit codes for all 8 symbols.
    for _ in 0..8 {
        w.write_bits(3, 3);
    }

    // Main tree: 14 unique literals (A-N) + match sym.
    // match(slot 8, lh 2) = 256 + 8*8 + 2 = 322. Second half idx = 66.
    let mut main_lens = [0u8; 496];
    for i in 0..14usize {
        main_lens[65 + i] = 5; // A through N
    }
    main_lens[322] = 5; // match sym

    write_simple_pretree_and_deltas(&mut w, &main_lens[..256], &[0u8; 256]);
    write_simple_pretree_and_deltas(&mut w, &main_lens[256..496], &[0u8; 240]);

    let mut length_lens = [0u8; 249];
    length_lens[0] = 1;
    write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

    let main_codes = assign_test_codes(&main_lens);
    let aligned_lens_arr = [3u8; 8];
    let aligned_codes = assign_test_codes(&aligned_lens_arr);

    // 14 literals: A B C D E F G H I J K L M N
    for i in 0..14usize {
        encode_sym(&mut w, &main_codes, 65 + i);
    }
    // Match: slot 8, lh 2 → len=4. Footer=3 bits.
    // Aligned mode: 0 verbatim bits (3-3=0), then 3 aligned bits.
    encode_sym(&mut w, &main_codes, 322);
    encode_sym(&mut w, &aligned_codes, 0); // aligned_sym=0 → offset=14

    let data = w.into_data();
    let mut output = [0u8; 18];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("aligned large footer");
    assert_eq!(n, 18);
    // Match at offset 14 copies the first 4 bytes.
    assert_eq!(&output[14..18], &output[0..4]);
}

// -- E8 post-processing test -------------------------------------------

#[test]
fn e8_integration() {
    // Build a stream with E8 enabled, then an uncompressed block
    // containing an E8 instruction.
    let mut w = BitWriter::new();
    write_header_with_e8(&mut w, 12_000_000);
    w.write_bits(BLOCK_UNCOMPRESSED, 3);
    w.write_bits(13, 24);

    let mut data = w.into_data();
    if !data.len().is_multiple_of(2) {
        data.push(0);
    }
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    // Raw: 0x90 0x90 0xE8 <absolute addr> 0x90*6
    // E8 at pos 2: operand = 0x0A (absolute). After undo: relative = 10 - 2 = 8.
    data.extend_from_slice(&[
        0x90, 0x90, 0xE8, 0x0A, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    ]);
    data.push(0); // padding for odd count

    let mut output = [0u8; 13];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("e8 integration");
    assert_eq!(n, 13);
    assert_eq!(output[2], 0xE8);
    let operand = i32::from_le_bytes([output[3], output[4], output[5], output[6]]);
    assert_eq!(operand, 8);
}

// -- Error handling tests ----------------------------------------------

#[test]
fn invalid_block_type_returns_error() {
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(0, 3); // block type 0 = invalid
    w.write_bits(1, 24);
    let data = w.into_data();

    let mut output = [0u8; 1];
    assert!(decompress(&data, &mut output, WindowSize::KB32).is_err());
}

#[test]
fn truncated_input_returns_error() {
    let data = [0u8; 1]; // too short for header + block
    let mut output = [0u8; 10];
    assert!(decompress(&data, &mut output, WindowSize::KB32).is_err());
}

#[test]
fn lenient_on_valid_matches_strict() {
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_UNCOMPRESSED, 3);
    w.write_bits(3, 24);

    let mut data = w.into_data();
    if !data.len().is_multiple_of(2) {
        data.push(0);
    }
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(b"xyz");
    data.push(0);

    let mut strict_out = [0u8; 3];
    let strict_n = decompress(&data, &mut strict_out, WindowSize::KB32).expect("strict");

    let mut lenient_out = [0u8; 3];
    let lenient_r = decompress_lenient(&data, &mut lenient_out, WindowSize::KB32);

    assert_eq!(strict_n, lenient_r.bytes_written);
    assert!(!lenient_r.had_errors);
    assert_eq!(strict_out, lenient_out);
}

#[test]
fn lenient_corrupt_returns_partial() {
    let data = [0xFF, 0xFF, 0x00, 0x00]; // garbage
    let mut output = [0xCC; 32];
    let r = decompress_lenient(&data, &mut output, WindowSize::KB32);
    assert!(r.had_errors);
    assert!(output.iter().all(|&b| b == 0));
}

#[test]
fn empty_output_succeeds() {
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    let data = w.into_data();

    let mut output = [0u8; 0];
    let n = decompress(&data, &mut output, WindowSize::KB32).expect("empty output");
    assert_eq!(n, 0);
}

// -- 64 KB window test -------------------------------------------------

#[test]
fn verbatim_64kb_window() {
    // KB64 → 32 position slots → main tree = 256 + 256 = 512,
    // second half = 256.
    let mut w = BitWriter::new();
    write_header_no_e8(&mut w);
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(2, 24);

    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 65);
    w.write_bits(0b01, 2); // A
    w.write_bits(0b01, 2); // B
    encode_zero_run_4sym(&mut w, 193);

    // Second half is 256 elements for 64KB window.
    write_pretree_3sym(&mut w);
    encode_zero_run_3sym(&mut w, 256);

    write_pretree_4sym(&mut w);
    w.write_bits(0b01, 2);
    w.write_bits(0b01, 2);
    encode_zero_run_4sym(&mut w, 247);

    w.write_bits(0, 1); // A
    w.write_bits(1, 1); // B

    let data = w.into_data();

    let mut output = [0u8; 2];
    let n = decompress(&data, &mut output, WindowSize::KB64).expect("verbatim 64kb");
    assert_eq!(n, 2);
    assert_eq!(&output, b"AB");
}

// -- Test helpers ------------------------------------------------------

/// Write a pretree and encoded deltas for an arbitrary target
/// code-length array against a previous array.
fn write_simple_pretree_and_deltas(w: &mut BitWriter, target: &[u8], prev: &[u8]) {
    // Compute delta symbols.
    let mut deltas = alloc::vec::Vec::with_capacity(target.len());
    for (i, &t) in target.iter().enumerate() {
        let old = if i < prev.len() { prev[i] } else { 0 };
        let d = ((u32::from(old) + NUM_CODE_LENGTHS - u32::from(t)) % NUM_CODE_LENGTHS) as u8;
        deltas.push(d);
    }

    // Collect unique delta symbols.
    let mut used = [false; 20];
    for &d in &deltas {
        used[d as usize] = true;
    }
    let used_count = used.iter().filter(|&&u| u).count();
    let code_len = if used_count <= 1 {
        1u8
    } else {
        let mut bits = 1u8;
        while (1usize << bits) < used_count {
            bits += 1;
        }
        bits
    };

    let mut pre_lens = [0u8; 20];
    for (i, &u) in used.iter().enumerate() {
        if u {
            pre_lens[i] = code_len;
        }
    }

    // Write 20 pre-tree code lengths.
    for &pl in &pre_lens {
        w.write_bits(u32::from(pl), 4);
    }

    // Build codes for the pretree.
    let pre_codes = assign_test_codes(&pre_lens);

    // Write each delta.
    for &d in &deltas {
        encode_sym(w, &pre_codes, d as usize);
    }
}

/// Assign canonical codes for test encoding.
fn assign_test_codes(lengths: &[u8]) -> alloc::vec::Vec<(u32, u8)> {
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
    let mut codes = alloc::vec![(0u32, 0u8); lengths.len()];
    for (sym, &len) in lengths.iter().enumerate() {
        let l = len as usize;
        if l > 0 && l < 17 {
            codes[sym] = (next_code[l], len);
            next_code[l] += 1;
        }
    }
    codes
}

fn encode_sym(w: &mut BitWriter, codes: &[(u32, u8)], sym: usize) {
    let (code, len) = codes[sym];
    w.write_bits(code, u32::from(len));
}
