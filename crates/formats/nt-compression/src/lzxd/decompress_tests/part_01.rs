use super::*;
use crate::lzxd::WindowSize;

/// MS-PATCH spec § 3 example: "abc" encoded as an uncompressed
/// block. Raw hex (including 2-byte chunk-size prefix):
/// 14 00 00 30 30 00 01 00 00 00 01 00 00 00 01 00 00 00 61 62 63 00
#[test]
fn spec_abc_uncompressed() {
    let input: &[u8] = &[
        0x14, 0x00, // chunk size: 20 bytes
        0x00, 0x30, 0x30, 0x00, // E8=0, block_type=3(uncompressed), block_size=3
        0x01, 0x00, 0x00, 0x00, // R0 = 1
        0x01, 0x00, 0x00, 0x00, // R1 = 1
        0x01, 0x00, 0x00, 0x00, // R2 = 1
        0x61, 0x62, 0x63, // "abc"
        0x00, // padding (odd count)
    ];
    let mut output = [0u8; 3];
    let n = decompress(input, &mut output, WindowSize::KB128, &[]).expect("spec abc example");
    assert_eq!(n, 3);
    assert_eq!(&output, b"abc");
}

/// Same as above but without the chunk-size prefix (testing the
/// internal chunk data parsing via the Lonami/lzxd convention).
/// We still need the prefix since our API expects it.
#[test]
fn spec_abc_with_32kb_window() {
    let input: &[u8] = &[
        0x14, 0x00, 0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x00,
    ];
    let mut output = [0u8; 3];
    // WindowSize shouldn't matter for an uncompressed block.
    let n =
        decompress(input, &mut output, WindowSize::MB32, &[]).expect("abc with 32MB window");
    assert_eq!(n, 3);
    assert_eq!(&output, b"abc");
}

#[test]
fn lenient_on_valid_matches_strict() {
    let input: &[u8] = &[
        0x14, 0x00, 0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x00,
    ];
    let mut strict_out = [0u8; 3];
    let strict_n = decompress(input, &mut strict_out, WindowSize::KB128, &[]).expect("strict");

    let mut lenient_out = [0u8; 3];
    let lenient_r = decompress_lenient(input, &mut lenient_out, WindowSize::KB128, &[]);

    assert_eq!(strict_n, lenient_r.bytes_written);
    assert!(!lenient_r.had_errors);
    assert_eq!(strict_out, lenient_out);
}

#[test]
fn truncated_input_returns_error() {
    let input: &[u8] = &[0x14]; // only 1 byte, needs 2 for chunk size
    let mut output = [0u8; 3];
    assert!(decompress(input, &mut output, WindowSize::KB128, &[]).is_err());
}

#[test]
fn invalid_block_type_returns_error() {
    // Block type = 0 (invalid).
    let input: &[u8] = &[
        0x14, 0x00, // chunk size
        0x00, 0x00, 0x30, 0x00, // E8=0, block_type=0(invalid), block_size=3
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let mut output = [0u8; 3];
    assert!(decompress(input, &mut output, WindowSize::KB128, &[]).is_err());
}

#[test]
fn extra_length_decode() {
    // Test the extra length prefix decoder in isolation.
    use crate::bitstream::BitReader;

    // Prefix 0: 8-bit value = 42 → extra_len = 42
    let mut w = crate::test_bitwriter::BitWriter::new();
    w.write_bits(0, 1); // prefix bit 0
    w.write_bits(42, 8);
    w.flush();
    let data = w.data();
    let mut r = BitReader::new(data);
    assert_eq!(decode_extra_length(&mut r).expect("p0"), 42);

    // Prefix 10: 10-bit value = 100 → extra_len = 100 + 256 = 356
    let mut w = crate::test_bitwriter::BitWriter::new();
    w.write_bits(1, 1); // prefix bit 1
    w.write_bits(0, 1); // prefix bit 0
    w.write_bits(100, 10);
    w.flush();
    let data = w.data();
    let mut r = BitReader::new(data);
    assert_eq!(decode_extra_length(&mut r).expect("p10"), 356);

    // Prefix 110: 12-bit value = 500 → extra_len = 500 + 1280 = 1780
    let mut w = crate::test_bitwriter::BitWriter::new();
    w.write_bits(0b110, 3);
    w.write_bits(500, 12);
    w.flush();
    let data = w.data();
    let mut r = BitReader::new(data);
    assert_eq!(decode_extra_length(&mut r).expect("p110"), 1780);

    // Prefix 111: 15-bit value = 1000 → extra_len = 1000
    let mut w = crate::test_bitwriter::BitWriter::new();
    w.write_bits(0b111, 3);
    w.write_bits(1000, 15);
    w.flush();
    let data = w.data();
    let mut r = BitReader::new(data);
    assert_eq!(decode_extra_length(&mut r).expect("p111"), 1000);
}

#[test]
fn uncompressed_block_with_reference_data() {
    // Reference data = "HELLO", output should be "WORLD".
    // Just an uncompressed block — reference data isn't used
    // by uncompressed blocks, but verify it doesn't break.
    let input: &[u8] = &[
        0x18, 0x00, // chunk size: 24 bytes
        0x00, 0x30, 0x50, 0x00, // E8=0, block_type=3, block_size=5
        0x01, 0x00, 0x00, 0x00, // R0 = 1
        0x01, 0x00, 0x00, 0x00, // R1 = 1
        0x01, 0x00, 0x00, 0x00, // R2 = 1
        b'W', b'O', b'R', b'L', b'D', // "WORLD"
        0x00, // padding
        0x00, 0x00, // extra padding to fill chunk size
    ];
    let mut output = [0u8; 5];
    let n = decompress(input, &mut output, WindowSize::KB128, b"HELLO")
        .expect("uncompressed with ref");
    assert_eq!(n, 5);
    assert_eq!(&output, b"WORLD");
}

#[test]
fn copy_within_output_non_overlapping() {
    let mut buf = [0u8; 20];
    buf[0..5].copy_from_slice(b"HELLO");
    copy_within_output(&mut buf, 10, 10, 5);
    assert_eq!(&buf[10..15], b"HELLO");
}

#[test]
fn copy_within_output_overlapping() {
    // offset=1, length=5: repeats last byte 5 times.
    let mut buf = [0u8; 10];
    buf[0] = b'A';
    copy_within_output(&mut buf, 1, 1, 5);
    assert_eq!(&buf[1..6], b"AAAAA");
}

#[test]
fn window_size_does_not_affect_uncompressed() {
    // The spec abc example should work with any window size.
    let input: &[u8] = &[
        0x14, 0x00, 0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x00,
    ];
    for &ws in &[
        WindowSize::KB128,
        WindowSize::KB256,
        WindowSize::KB512,
        WindowSize::MB1,
        WindowSize::MB2,
        WindowSize::MB4,
        WindowSize::MB8,
        WindowSize::MB16,
        WindowSize::MB32,
    ] {
        let mut output = [0u8; 3];
        let n = decompress(input, &mut output, ws, &[])
            .unwrap_or_else(|e| panic!("failed with {ws:?}: {e}"));
        assert_eq!(n, 3);
        assert_eq!(&output, b"abc");
    }
}

/// Construct a synthetic verbatim block to test compressed data
/// decompression with only literal bytes.
#[test]
fn synthetic_verbatim_literals_only() {
    use crate::test_bitwriter::BitWriter;

    // Encode "AB" using a verbatim block.
    // KB128 → 34 position slots → main tree = 256 + 272 = 528
    let mut w = BitWriter::new();
    w.write_raw_bytes(&[0x00, 0x00]); // chunk size placeholder
    w.write_bits(0, 1); // E8 disabled
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(2, 24); // block size = 2

    // Main tree first half (256 elements): A=1, B=1, rest=0.
    // Deltas: 65 zeros, code 16, code 16, 193 zeros.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 65);
    w.write_bits(0b01, 2); // delta 16 for A
    w.write_bits(0b01, 2); // delta 16 for B
    encode_zero_run_4sym(&mut w, 193);

    // Main tree second half (272 elements): all zero.
    write_pretree_3sym(&mut w);
    encode_zero_run_3sym(&mut w, 272);

    // Length tree (249 elements): syms 0,1 get len=1 (minimal valid).
    // Deltas: code 16, code 16, 247 zeros.
    write_pretree_4sym(&mut w);
    w.write_bits(0b01, 2); // delta 16 for sym 0
    w.write_bits(0b01, 2); // delta 16 for sym 1
    encode_zero_run_4sym(&mut w, 247);

    // Tokens: A(code 0), B(code 1).
    w.write_bits(0, 1);
    w.write_bits(1, 1);

    let mut data = w.into_data();
    patch_chunk_size(&mut data);

    let mut output = [0u8; 2];
    let n = decompress(&data, &mut output, WindowSize::KB128, &[]).expect("synthetic verbatim");
    assert_eq!(n, 2);
    assert_eq!(&output, b"AB");
}

/// Test reference data matches: match offset exceeds output position.
#[test]
fn reference_data_match() {
    use crate::test_bitwriter::BitWriter;

    // Ref="ABCDE", output: match(offset=5,len=3) + literal 'X' → "ABCX".
    // offset=5 → formatted=7 → slot 5 (base=6, footer=1), footer_val=1.
    // Match symbol = 256 + 5*8 + 1 = 297 (index 41 in second half).
    let mut w = BitWriter::new();
    w.write_raw_bytes(&[0x00, 0x00]);
    w.write_bits(0, 1); // E8 disabled
    w.write_bits(BLOCK_VERBATIM, 3);
    w.write_bits(4, 24);

    // Main first half: X(0x58)=1, rest=0. 88 zeros, code 16, 167 zeros.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 88);
    w.write_bits(0b01, 2); // delta 16 for X
    encode_zero_run_4sym(&mut w, 167);

    // Main second half: index 41=1, rest=0. 41 zeros, code 16, 230 zeros.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 41);
    w.write_bits(0b01, 2); // delta 16 for match sym
    encode_zero_run_4sym(&mut w, 230);

    // Length tree: syms 0,1 get len=1.
    write_pretree_4sym(&mut w);
    w.write_bits(0b01, 2);
    w.write_bits(0b01, 2);
    encode_zero_run_4sym(&mut w, 247);

    // Tokens: match(code 1) + footer(1) + literal X(code 0).
    w.write_bits(1, 1);
    w.write_bits(1, 1);
    w.write_bits(0, 1);

    let mut data = w.into_data();
    patch_chunk_size(&mut data);

    let mut output = [0u8; 4];
    let n = decompress(&data, &mut output, WindowSize::KB128, b"ABCDE")
        .expect("reference data match");
    assert_eq!(n, 4);
    assert_eq!(&output, b"ABCX");
}

/// Test aligned offset block: match with offset requiring aligned bits.
#[test]
fn synthetic_aligned_offset_block() {
    use crate::test_bitwriter::BitWriter;

    // Encode "AAAAAA" using an aligned offset block.
    // 1 literal 'A', then match(offset=1, length=5) to repeat it.
    //
    // offset=1 → formatted_offset=3 → slot 3 (base=3, footer=0).
    // Match symbol = 256 + 3*8 + 3 = 283 (length_header=3 → len=5).
    // Slot 3 has 0 footer bits, so no aligned/verbatim bits needed.
    let mut w = BitWriter::new();
    w.write_raw_bytes(&[0x00, 0x00]); // chunk size placeholder
    w.write_bits(0, 1); // E8 disabled

    // Block type = aligned offset (2), size = 6.
    w.write_bits(BLOCK_ALIGNED, 3);
    w.write_bits(6, 24);

    // Aligned offset tree: 8 elements, 3 bits each.
    // Give syms 0,1 len=1 for a valid tree (others=0).
    let aligned_lens: [u8; 8] = [1, 1, 0, 0, 0, 0, 0, 0];
    for &al in &aligned_lens {
        w.write_bits(u32::from(al), 3);
    }

    // Main tree first half (256 elements): A(0x41)=1, rest=0.
    // But we need 2 symbols for valid tree. Add sym 283 in second half.
    // First half: 65 zeros, code 16, 190 zeros.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 65);
    w.write_bits(0b01, 2); // delta 16 for 'A'
    encode_zero_run_4sym(&mut w, 190);

    // Main tree second half (272 elements): index 27 (sym 283)=1.
    // 27 zeros, code 16, 244 zeros.
    write_pretree_4sym(&mut w);
    encode_zero_run_4sym(&mut w, 27);
    w.write_bits(0b01, 2); // delta 16 for match sym
    encode_zero_run_4sym(&mut w, 244);

    // Length tree: syms 0,1 get len=1.
    write_pretree_4sym(&mut w);
    w.write_bits(0b01, 2);
    w.write_bits(0b01, 2);
    encode_zero_run_4sym(&mut w, 247);

    // Tokens: literal A (code 0), match 283 (code 1).
    // Main tree: A=0x41(code 0, len 1), sym283(code 1, len 1).
    w.write_bits(0, 1); // 'A'
    w.write_bits(1, 1); // match (slot=3, no footer bits needed)

    let mut data = w.into_data();
    patch_chunk_size(&mut data);

    let mut output = [0u8; 6];
    let n =
        decompress(&data, &mut output, WindowSize::KB128, &[]).expect("aligned offset block");
    assert_eq!(n, 6);
    assert_eq!(&output, b"AAAAAA");
}

// -- Test helpers for building synthetic LZXD bitstreams ---------------

/// Write 4-symbol pretree: sym 0→00, 16→01, 17→10, 18→11.
fn write_pretree_4sym(w: &mut crate::test_bitwriter::BitWriter) {
    let mut lens = [0u8; 20];
    lens[0] = 2;
    lens[16] = 2;
    lens[17] = 2;
    lens[18] = 2;
    for &pl in &lens {
        w.write_bits(u32::from(pl), 4);
    }
}

/// Write 3-symbol pretree: sym 0→0, 17→10, 18→11.
fn write_pretree_3sym(w: &mut crate::test_bitwriter::BitWriter) {
    let mut lens = [0u8; 20];
    lens[0] = 1;
    lens[17] = 2;
    lens[18] = 2;
    for &pl in &lens {
        w.write_bits(u32::from(pl), 4);
    }
}

/// Encode a run of `count` zeros. Pretree: 0→00, 17→10, 18→11.
fn encode_zero_run_4sym(w: &mut crate::test_bitwriter::BitWriter, mut count: usize) {
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
        w.write_bits(0b00, 2);
    }
}

/// Encode zeros with 3-symbol pretree (0→0, 17→10, 18→11).
fn encode_zero_run_3sym(w: &mut crate::test_bitwriter::BitWriter, mut count: usize) {
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

fn patch_chunk_size(data: &mut [u8]) {
    let size =
        u16::try_from(data.len() - 2).expect("the synthetic chunk is smaller than 64 KiB");
    data[0] = (size & 0xFF) as u8;
    data[1] = (size >> 8) as u8;
}
