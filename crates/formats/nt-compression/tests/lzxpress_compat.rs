// Cross-compatibility tests using test vectors from MagnetForensics/rust-lzxpress.
//
// Copyright (c) MagnetForensics — MIT License.
// <https://github.com/MagnetForensics/rust-lzxpress>
//
// OSS-Fuzz crash reproducers are sourced from the same repository.
// LZNT1 "Beethoven" vector and binary fixtures are independently authored.

extern crate alloc;

// ===================================================================
// XPRESS Plain tests
// ===================================================================

#[cfg(feature = "xpress")]
mod xpress {
    use alloc::vec;
    use nt_compression::xpress;

    // ---------------------------------------------------------------
    // Test vectors (from rust-lzxpress)
    // ---------------------------------------------------------------

    // Vector 1: "this is a test. and this is a test too"
    // Compressed by Samba's XPRESS implementation.
    const PLAIN_1: &[u8] = b"this is a test. and this is a test too";
    #[rustfmt::skip]
    const COMPRESSED_1: &[u8] = &[
        0x00, 0x20, 0x00, 0x04, 0x74, 0x68, 0x69, 0x73, 0x20, 0x10, 0x00, 0x61, 0x20, 0x74, 0x65, 0x73,
        0x74, 0x2E, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x9F, 0x00, 0x04, 0x20, 0x74, 0x6F, 0x6F,
    ];

    // Vector 2: "abcdefghijklmnopqrstuvwxyz" (MS-XCA spec example).
    const PLAIN_2: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    #[rustfmt::skip]
    const COMPRESSED_2: &[u8] = &[
        0x3f, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
        0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
    ];

    // Vector 3: b"abc" repeated 100 times (300 bytes).
    const PLAIN_3: &[u8] = &{
        let mut buf = [0u8; 300];
        let mut i = 0;
        while i < 300 {
            buf[i] = b'a';
            buf[i + 1] = b'b';
            buf[i + 2] = b'c';
            i += 3;
        }
        buf
    };
    #[rustfmt::skip]
    const COMPRESSED_3: &[u8] = &[
        0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01,
    ];

    // OSS-Fuzz crash reproducers (XPRESS Plain malformed data).
    // From Samba OSS-Fuzz bug 20083 — must return Err, not panic.
    #[rustfmt::skip]
    const OSSFUZZ_20083: &[u8] = &[
        0x02, 0x00, 0x03, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x09, 0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20,
        0x09, 0x00, 0x00, 0x00, 0x20, 0x20, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    #[rustfmt::skip]
    const OSSFUZZ_5698056963227648: &[u8] = &[
        0x02, 0x00, 0x03, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x01, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x20, 0x00, 0x00,
        0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xff, 0xff,
        0xff, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x3a, 0x00, 0x00,
        0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x7e, 0x7e, 0x7e, 0x7e, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0x20, 0x20,
    ];

    // ---------------------------------------------------------------
    // Decompression tests
    // ---------------------------------------------------------------

    #[test]
    fn decompress_vector_1() {
        let mut output = vec![0u8; PLAIN_1.len()];
        let n = xpress::decompress(COMPRESSED_1, &mut output).expect("decompress vector 1");
        assert_eq!(n, PLAIN_1.len());
        assert_eq!(&output[..n], PLAIN_1);
    }

    #[test]
    fn decompress_vector_2() {
        let mut output = vec![0u8; PLAIN_2.len()];
        let n = xpress::decompress(COMPRESSED_2, &mut output).expect("decompress vector 2");
        assert_eq!(n, PLAIN_2.len());
        assert_eq!(&output[..n], PLAIN_2);
    }

    #[test]
    fn decompress_vector_3() {
        let mut output = vec![0u8; PLAIN_3.len()];
        let n = xpress::decompress(COMPRESSED_3, &mut output).expect("decompress vector 3");
        assert_eq!(n, PLAIN_3.len());
        assert_eq!(&output[..n], PLAIN_3);
    }

    #[test]
    fn ossfuzz_20083_returns_error() {
        let mut output = vec![0u8; 65536];
        let result = xpress::decompress(OSSFUZZ_20083, &mut output);
        assert!(result.is_err(), "OSS-Fuzz 20083 should return an error");
    }

    #[test]
    fn ossfuzz_5698056963227648_returns_error() {
        let mut output = vec![0u8; 65536];
        let result = xpress::decompress(OSSFUZZ_5698056963227648, &mut output);
        assert!(
            result.is_err(),
            "OSS-Fuzz 5698056963227648 should return an error"
        );
    }

    // ---------------------------------------------------------------
    // Compression roundtrip tests
    // ---------------------------------------------------------------

    #[cfg(feature = "compress-xpress")]
    #[test]
    fn compress_roundtrip_vector_1() {
        let bound = xpress::compress_bound(PLAIN_1.len());
        let mut compressed = vec![0u8; bound];
        let c_len = xpress::compress(PLAIN_1, &mut compressed).expect("compress vector 1");

        let mut decompressed = vec![0u8; PLAIN_1.len()];
        let d_len = xpress::decompress(&compressed[..c_len], &mut decompressed)
            .expect("decompress roundtrip vector 1");
        assert_eq!(d_len, PLAIN_1.len());
        assert_eq!(&decompressed[..d_len], PLAIN_1);
    }

    #[cfg(feature = "compress-xpress")]
    #[test]
    fn compress_roundtrip_vector_2() {
        let bound = xpress::compress_bound(PLAIN_2.len());
        let mut compressed = vec![0u8; bound];
        let c_len = xpress::compress(PLAIN_2, &mut compressed).expect("compress vector 2");

        let mut decompressed = vec![0u8; PLAIN_2.len()];
        let d_len = xpress::decompress(&compressed[..c_len], &mut decompressed)
            .expect("decompress roundtrip vector 2");
        assert_eq!(d_len, PLAIN_2.len());
        assert_eq!(&decompressed[..d_len], PLAIN_2);
    }

    #[cfg(feature = "compress-xpress")]
    #[test]
    fn compress_roundtrip_vector_3() {
        let bound = xpress::compress_bound(PLAIN_3.len());
        let mut compressed = vec![0u8; bound];
        let c_len = xpress::compress(PLAIN_3, &mut compressed).expect("compress vector 3");

        let mut decompressed = vec![0u8; PLAIN_3.len()];
        let d_len = xpress::decompress(&compressed[..c_len], &mut decompressed)
            .expect("decompress roundtrip vector 3");
        assert_eq!(d_len, PLAIN_3.len());
        assert_eq!(&decompressed[..d_len], PLAIN_3);
    }
}

// ===================================================================
// LZNT1 tests
// ===================================================================

#[cfg(feature = "lznt1")]
mod lznt1 {
    use alloc::vec;
    use nt_compression::lznt1;

    // ---------------------------------------------------------------
    // Test vectors
    // ---------------------------------------------------------------

    // Beethoven's Ode to Joy, LZNT1-compressed by Samba.
    const BEETHOVEN_PLAIN: &[u8] = b"F# F# G A A G F# E D D E F# F# E E \
F# F# G A A G F# E D D E F# E D D \
E E F# D E F# G F# D E F# G F# E D E A \
F# F# G A A G F# E D D E F# E D D\0";
    #[rustfmt::skip]
    const BEETHOVEN_COMPRESSED: &[u8] = &[
        0x38, 0xb0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20, 0x47, 0x20, 0x41, 0x00, 0x10, 0xa2, 0x47, 0x01,
        0xa0, 0x45, 0x20, 0x44, 0x00, 0x08, 0x45, 0x01, 0x50, 0x79, 0x00, 0xc0, 0x45, 0x20, 0x05, 0x24,
        0x13, 0x88, 0x05, 0xb4, 0x02, 0x4a, 0x44, 0xef, 0x03, 0x58, 0x02, 0x8c, 0x09, 0x16, 0x01, 0x48,
        0x45, 0x00, 0xbe, 0x00, 0x9e, 0x00, 0x04, 0x01, 0x18, 0x90, 0x00,
    ];

    // 1 MiB real-world LZNT1 block from rust-lzxpress test suite.
    const BLOCK1_COMPRESSED: &[u8] = include_bytes!("fixtures/lznt1_block1_compressed.bin");
    const BLOCK1_UNCOMPRESSED: &[u8] = include_bytes!("fixtures/lznt1_block1_uncompressed.bin");

    // ---------------------------------------------------------------
    // Decompression tests
    // ---------------------------------------------------------------

    #[test]
    fn decompress_beethoven() {
        let mut output = vec![0u8; BEETHOVEN_PLAIN.len()];
        let n = lznt1::decompress(BEETHOVEN_COMPRESSED, &mut output).expect("decompress beethoven");
        assert_eq!(n, BEETHOVEN_PLAIN.len());
        assert_eq!(&output[..n], BEETHOVEN_PLAIN);
    }

    #[test]
    fn decompress_block1() {
        let mut output = vec![0u8; BLOCK1_UNCOMPRESSED.len()];
        let n = lznt1::decompress(BLOCK1_COMPRESSED, &mut output).expect("decompress block1");
        assert_eq!(n, BLOCK1_UNCOMPRESSED.len());
        assert_eq!(&output[..n], BLOCK1_UNCOMPRESSED);
    }

    // ---------------------------------------------------------------
    // Compression roundtrip tests
    // ---------------------------------------------------------------

    #[cfg(feature = "compress-lznt1")]
    #[test]
    fn compress_roundtrip_beethoven() {
        let bound = lznt1::compress_bound(BEETHOVEN_PLAIN.len());
        let mut compressed = vec![0u8; bound];
        let c_len = lznt1::compress(BEETHOVEN_PLAIN, &mut compressed).expect("compress beethoven");

        let mut decompressed = vec![0u8; BEETHOVEN_PLAIN.len()];
        let d_len = lznt1::decompress(&compressed[..c_len], &mut decompressed)
            .expect("decompress roundtrip beethoven");
        assert_eq!(d_len, BEETHOVEN_PLAIN.len());
        assert_eq!(&decompressed[..d_len], BEETHOVEN_PLAIN);
    }

    #[cfg(feature = "compress-lznt1")]
    #[test]
    fn compress_roundtrip_block1() {
        let bound = lznt1::compress_bound(BLOCK1_UNCOMPRESSED.len());
        let mut compressed = vec![0u8; bound];
        let c_len = lznt1::compress(BLOCK1_UNCOMPRESSED, &mut compressed).expect("compress block1");

        let mut decompressed = vec![0u8; BLOCK1_UNCOMPRESSED.len()];
        let d_len = lznt1::decompress(&compressed[..c_len], &mut decompressed)
            .expect("decompress roundtrip block1");
        assert_eq!(d_len, BLOCK1_UNCOMPRESSED.len());
        assert_eq!(&decompressed[..d_len], BLOCK1_UNCOMPRESSED);
    }
}
