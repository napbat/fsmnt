//! LZX WIM compression compatibility tests.
//!
//! Windows RTL does not expose an LZX compression/decompression API,
//! so we verify roundtrip correctness with known test vectors and
//! various data patterns.

extern crate alloc;

#[allow(unused_imports)]
use alloc::vec;

/// Test that our compressor and decompressor agree on diverse inputs.
#[cfg(all(feature = "compress-lzx", feature = "lzx"))]
mod roundtrip {
    use super::*;
    use nt_compression::lzx;

    fn roundtrip(name: &str, input: &[u8]) {
        assert!(
            input.len() <= 32768,
            "{name}: LZX WIM chunks must be <= 32KB"
        );

        let bound = lzx::compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = lzx::compress(input, &mut compressed)
            .unwrap_or_else(|e| panic!("{name}: compress failed: {e}"));

        let mut decompressed = vec![0u8; input.len()];
        let d_len = lzx::decompress(&compressed[..c_len], &mut decompressed)
            .unwrap_or_else(|e| panic!("{name}: decompress failed: {e}"));

        assert_eq!(d_len, input.len(), "{name}: length mismatch");
        assert_eq!(&decompressed[..d_len], input, "{name}: data mismatch");
    }

    #[test]
    fn empty() {
        roundtrip("empty", &[]);
    }

    #[test]
    fn all_zeros_small() {
        roundtrip("zeros_100", &[0u8; 100]);
    }

    #[test]
    fn all_zeros_full_chunk() {
        roundtrip("zeros_32k", &vec![0u8; 32768]);
    }

    #[test]
    fn sequential_bytes() {
        let data: vec::Vec<u8> = (0..1000)
            .map(|i| u8::try_from(i % 256).expect("the modulus limits values to one byte"))
            .collect();
        roundtrip("sequential_1k", &data);
    }

    #[test]
    fn repetitive_pattern() {
        let data: vec::Vec<u8> = (0..8000).map(|i| b"ABCDEFGHIJ"[i % 10]).collect();
        roundtrip("repetitive_8k", &data);
    }

    #[test]
    fn mixed_data() {
        let mut data = vec![0u8; 16384];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = if i < 4096 {
                u8::try_from(i % 64).expect("the modulus limits values below 64")
            } else if i < 8192 {
                0
            } else {
                u8::try_from((i * 7 + 13) % 251).expect("the modulus limits values below 251")
            };
        }
        roundtrip("mixed_16k", &data);
    }

    #[test]
    fn full_chunk_varied() {
        let mut data = vec![0u8; 32768];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = u8::try_from(i % 251).expect("the modulus limits values below 251");
        }
        // Add repetitive regions to exercise match finding.
        let patch: vec::Vec<u8> = data[1000..2000].to_vec();
        data[15000..16000].copy_from_slice(&patch);
        let patch2: vec::Vec<u8> = data[5000..6000].to_vec();
        data[25000..26000].copy_from_slice(&patch2);
        roundtrip("full_chunk_varied", &data);
    }

    #[test]
    fn e8_like_data() {
        // Data containing 0xE8 bytes to exercise E8 preprocessing.
        let mut data = vec![0u8; 4096];
        for i in (0..data.len()).step_by(100) {
            data[i] = 0xE8;
            if i + 4 < data.len() {
                let val = u32::try_from(i)
                    .expect("the compatibility vector is 4096 bytes")
                    .to_le_bytes();
                data[i + 1] = val[0];
                data[i + 2] = val[1];
                data[i + 3] = val[2];
                data[i + 4] = val[3];
            }
        }
        roundtrip("e8_like_4k", &data);
    }

    #[test]
    fn single_byte() {
        roundtrip("single_byte", &[0x42]);
    }

    #[test]
    fn two_bytes() {
        roundtrip("two_bytes", &[0x42, 0x43]);
    }

    #[test]
    fn near_max_chunk() {
        let data: vec::Vec<u8> = (0..32767)
            .map(|i| u8::try_from(i % 251).expect("the modulus limits values below 251"))
            .collect();
        roundtrip("near_max_32767", &data);
    }
}
