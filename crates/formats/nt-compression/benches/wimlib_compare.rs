//! Side-by-side benchmarks: our implementation vs wimlib.
//!
//! Covers LZX WIM and XPRESS Huffman (wimlib provides LZX, XPRESS,
//! LZMS — RTL does not). Skips gracefully when wimlib is not installed.

mod wimlib_ffi;

use wimlib_ffi::*;

fn main() {
    if Wimlib::load().is_none() {
        eprintln!("wimlib not available — skipping wimlib_compare benchmarks");
    }
    divan::main();
}

#[cfg(all(feature = "compress-lzx", feature = "lzx"))]
mod lzx_wim {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;
    use divan::counter::BytesCount;

    use crate::wimlib_ffi::*;

    const LZX_WIM_BLOCK_SIZE: usize = 32_768;
    const SIZES: &[usize] = &[4_096, 16_384, 32_768];

    fn mixed(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = if i < n / 2 {
                (i % 64) as u8
            } else {
                ((i * 7 + 13) % 251) as u8
            };
        }
        buf
    }

    // -----------------------------------------------------------
    // LZX WIM compress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod lzx_wim_compress {
        use super::*;

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let mut compressor = nt_compression::lzx::Compressor::new();
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| vec![0u8; nt_compression::lzx::compress_bound(len)])
                .bench_local_refs(|out| compressor.compress(&input, out).unwrap());
        }

        #[divan::bench(args = SIZES)]
        fn wimlib(bencher: divan::Bencher<'_, '_>, len: usize) {
            let Some(lib) = Wimlib::load() else {
                eprintln!("wimlib not available — skipping");
                return;
            };
            let compressor =
                WimlibCompressor::new(&lib, WimlibCompressionType::Lzx, LZX_WIM_BLOCK_SIZE)
                    .expect("create wimlib LZX compressor");
            let input = mixed(len);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| vec![0u8; LZX_WIM_BLOCK_SIZE])
                .bench_local_refs(|out| compressor.compress(&input, out));
        }
    }

    // -----------------------------------------------------------
    // LZX WIM decompress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod lzx_wim_decompress {
        use super::*;

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let mut buf = vec![0u8; nt_compression::lzx::compress_bound(len)];
            let n = nt_compression::lzx::compress(&input, &mut buf).expect("pre-compress");
            buf.truncate(n);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| vec![0u8; len])
                .bench_local_refs(|out| nt_compression::lzx::decompress(&buf, out).unwrap());
        }

        #[divan::bench(args = SIZES)]
        fn wimlib(bencher: divan::Bencher<'_, '_>, len: usize) {
            let Some(lib) = Wimlib::load() else {
                eprintln!("wimlib not available — skipping");
                return;
            };
            let compressor =
                WimlibCompressor::new(&lib, WimlibCompressionType::Lzx, LZX_WIM_BLOCK_SIZE)
                    .expect("create wimlib LZX compressor");
            let decompressor =
                WimlibDecompressor::new(&lib, WimlibCompressionType::Lzx, LZX_WIM_BLOCK_SIZE)
                    .expect("create wimlib LZX decompressor");
            let input = mixed(len);
            let mut compressed = vec![0u8; LZX_WIM_BLOCK_SIZE];
            let c_len = compressor.compress(&input, &mut compressed);
            assert!(c_len > 0, "wimlib failed to compress bench data");
            compressed.truncate(c_len);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| vec![0u8; len])
                .bench_local_refs(|out| {
                    decompressor
                        .decompress(&compressed, out)
                        .expect("wimlib decompress")
                });
        }
    }
}

#[cfg(all(feature = "compress-xpress-huffman", feature = "xpress-huffman"))]
mod xpress_huffman {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;
    use divan::counter::BytesCount;

    use crate::wimlib_ffi::*;

    const XPRESS_HUFF_BLOCK_SIZE: usize = 65_536;
    const SIZES: &[usize] = &[4_096, 16_384, 65_536];

    fn mixed(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = if i < n / 2 {
                (i % 64) as u8
            } else {
                ((i * 7 + 13) % 251) as u8
            };
        }
        buf
    }

    // -----------------------------------------------------------
    // XPRESS Huffman compress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod xpress_huff_compress {
        use super::*;

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let mut compressor = nt_compression::xpress_huffman::Compressor::new();
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| vec![0u8; nt_compression::xpress_huffman::compress_bound(len)])
                .bench_local_refs(|out| compressor.compress(&input, out).unwrap());
        }

        #[divan::bench(args = SIZES)]
        fn wimlib(bencher: divan::Bencher<'_, '_>, len: usize) {
            let Some(lib) = Wimlib::load() else {
                eprintln!("wimlib not available — skipping");
                return;
            };
            let compressor =
                WimlibCompressor::new(&lib, WimlibCompressionType::Xpress, XPRESS_HUFF_BLOCK_SIZE)
                    .expect("create wimlib XPRESS compressor");
            let input = mixed(len);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| vec![0u8; XPRESS_HUFF_BLOCK_SIZE])
                .bench_local_refs(|out| compressor.compress(&input, out));
        }
    }

    // -----------------------------------------------------------
    // XPRESS Huffman decompress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod xpress_huff_decompress {
        use super::*;

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let bound = nt_compression::xpress_huffman::compress_bound(len);
            let mut buf = vec![0u8; bound];
            let n =
                nt_compression::xpress_huffman::compress(&input, &mut buf).expect("pre-compress");
            buf.truncate(n);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| vec![0u8; len])
                .bench_local_refs(|out| {
                    nt_compression::xpress_huffman::decompress(&buf, out).unwrap()
                });
        }

        #[divan::bench(args = SIZES)]
        fn wimlib(bencher: divan::Bencher<'_, '_>, len: usize) {
            let Some(lib) = Wimlib::load() else {
                eprintln!("wimlib not available — skipping");
                return;
            };
            let compressor =
                WimlibCompressor::new(&lib, WimlibCompressionType::Xpress, XPRESS_HUFF_BLOCK_SIZE)
                    .expect("create wimlib XPRESS compressor");
            let decompressor = WimlibDecompressor::new(
                &lib,
                WimlibCompressionType::Xpress,
                XPRESS_HUFF_BLOCK_SIZE,
            )
            .expect("create wimlib XPRESS decompressor");
            let input = mixed(len);
            let mut compressed = vec![0u8; XPRESS_HUFF_BLOCK_SIZE];
            let c_len = compressor.compress(&input, &mut compressed);
            assert!(c_len > 0, "wimlib failed to compress bench data");
            compressed.truncate(c_len);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| vec![0u8; len])
                .bench_local_refs(|out| {
                    decompressor
                        .decompress(&compressed, out)
                        .expect("wimlib decompress")
                });
        }
    }
}
