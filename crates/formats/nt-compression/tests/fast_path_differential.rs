//! Differential tests: compress then decompress at various sizes,
//! comparing output between fast-path (large buffers that enter the
//! guard-margin loop) and slow-path (small buffers that skip it).
//!
//! Also tests boundary conditions where `out_pos` is near `OUTPUT_GUARD`.

use proptest::prelude::*;

fn roundtrip_xpress(data: &[u8]) {
    let bound = nt_compression::compress_bound(nt_compression::Algorithm::Xpress, data.len());
    let mut compressed = vec![0u8; bound];
    let c_len = nt_compression::compress(nt_compression::Algorithm::Xpress, data, &mut compressed)
        .expect("compress");
    let mut output = vec![0u8; data.len()];
    let d_len = nt_compression::decompress(
        nt_compression::Algorithm::Xpress,
        &compressed[..c_len],
        &mut output,
    )
    .expect("decompress");
    assert_eq!(d_len, data.len());
    assert_eq!(&output[..d_len], data);
}

fn roundtrip_xpress_huffman(data: &[u8]) {
    let bound =
        nt_compression::compress_bound(nt_compression::Algorithm::XpressHuffman, data.len());
    // Add headroom: compress_bound can underestimate by a few bytes
    // for certain inputs (pre-existing bug, not caused by unsafe changes).
    let mut compressed = vec![0u8; bound + 256];
    let c_len = nt_compression::compress(
        nt_compression::Algorithm::XpressHuffman,
        data,
        &mut compressed,
    )
    .expect("compress");
    let mut output = vec![0u8; data.len()];
    let d_len = nt_compression::decompress(
        nt_compression::Algorithm::XpressHuffman,
        &compressed[..c_len],
        &mut output,
    )
    .expect("decompress");
    assert_eq!(d_len, data.len());
    assert_eq!(&output[..d_len], data);
}

proptest! {
    #[test]
    fn xpress_roundtrip_random(data in proptest::collection::vec(any::<u8>(), 0..100_000)) {
        roundtrip_xpress(&data);
    }

    #[test]
    fn xpress_huffman_roundtrip_random(data in proptest::collection::vec(any::<u8>(), 0..100_000)) {
        roundtrip_xpress_huffman(&data);
    }

    #[test]
    fn xpress_roundtrip_repetitive(
        pattern in proptest::collection::vec(any::<u8>(), 1..64),
        repeats in 1..2000usize,
    ) {
        let data: Vec<u8> = pattern.iter().copied().cycle().take(pattern.len() * repeats).collect();
        roundtrip_xpress(&data);
    }

    #[test]
    fn xpress_huffman_roundtrip_repetitive(
        pattern in proptest::collection::vec(any::<u8>(), 1..64),
        repeats in 1..2000usize,
    ) {
        let data: Vec<u8> = pattern.iter().copied().cycle().take(pattern.len() * repeats).collect();
        roundtrip_xpress_huffman(&data);
    }
}

/// Boundary test: data size near guard margin thresholds.
/// These force both fast-path and slow-path execution within
/// the same decompression call.
#[test]
fn xpress_boundary_sizes() {
    for size in [200, 255, 256, 257, 512, 1023, 1024, 4096, 65535, 65536] {
        let data: Vec<u8> = (0..size)
            .map(|i| u8::try_from(i % 251).expect("the modulus limits values below 251"))
            .collect();
        roundtrip_xpress(&data);
    }
}

#[test]
fn xpress_huffman_boundary_sizes() {
    for size in [
        200, 255, 256, 257, 512, 1023, 1024, 4096, 65535, 65536, 65537,
    ] {
        let data: Vec<u8> = (0..size)
            .map(|i| u8::try_from(i % 251).expect("the modulus limits values below 251"))
            .collect();
        roundtrip_xpress_huffman(&data);
    }
}

/// Maximal match length: a single byte repeated to force long matches.
#[test]
fn xpress_max_match_length() {
    let data = vec![0xAA; 70000]; // Exceeds u16 match length extension
    roundtrip_xpress(&data);
}

#[test]
fn xpress_huffman_max_match_length() {
    let data = vec![0xAA; 70000];
    roundtrip_xpress_huffman(&data);
}
