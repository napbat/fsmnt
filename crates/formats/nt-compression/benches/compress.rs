//! Compression throughput benchmarks for all four algorithms.

mod bench_data;

use bench_data::{mixed, random_ish, zeros};
use divan::counter::BytesCount;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

// ---------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------

const SIZES: &[usize] = &[4_096, 32_768, 65_536, 262_144];
const LZX_SIZES: &[usize] = &[4_096, 32_768];

// ---------------------------------------------------------------
// LZNT1
// ---------------------------------------------------------------

#[divan::bench_group]
mod lznt1 {
    use super::{BytesCount, SIZES, mixed, random_ish, zeros};

    #[divan::bench(args = SIZES)]
    fn compress_zeros(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = zeros(len);
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::lznt1::compress_bound(len)])
            .bench_local_refs(|out| nt_compression::lznt1::compress(&input, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn compress_mixed(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = mixed(len);
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::lznt1::compress_bound(len)])
            .bench_local_refs(|out| nt_compression::lznt1::compress(&input, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn compress_random_ish(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = random_ish(len);
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::lznt1::compress_bound(len)])
            .bench_local_refs(|out| nt_compression::lznt1::compress(&input, out).unwrap());
    }
}

// ---------------------------------------------------------------
// XPRESS
// ---------------------------------------------------------------

#[divan::bench_group]
mod xpress {
    use super::{BytesCount, SIZES, mixed, random_ish, zeros};

    #[divan::bench(args = SIZES)]
    fn compress_zeros(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = zeros(len);
        let mut compressor = nt_compression::xpress::Compressor::new();
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::xpress::compress_bound(len)])
            .bench_local_refs(|out| compressor.compress(&input, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn compress_mixed(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = mixed(len);
        let mut compressor = nt_compression::xpress::Compressor::new();
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::xpress::compress_bound(len)])
            .bench_local_refs(|out| compressor.compress(&input, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn compress_random_ish(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = random_ish(len);
        let mut compressor = nt_compression::xpress::Compressor::new();
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::xpress::compress_bound(len)])
            .bench_local_refs(|out| compressor.compress(&input, out).unwrap());
    }
}

// ---------------------------------------------------------------
// XPRESS Huffman
// ---------------------------------------------------------------

#[divan::bench_group]
mod xpress_huffman {
    use super::{BytesCount, SIZES, mixed, random_ish, zeros};

    #[divan::bench(args = SIZES)]
    fn compress_zeros(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = zeros(len);
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::xpress_huffman::compress_bound(len)])
            .bench_local_refs(|out| nt_compression::xpress_huffman::compress(&input, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn compress_mixed(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = mixed(len);
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::xpress_huffman::compress_bound(len)])
            .bench_local_refs(|out| nt_compression::xpress_huffman::compress(&input, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn compress_random_ish(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = random_ish(len);
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::xpress_huffman::compress_bound(len)])
            .bench_local_refs(|out| nt_compression::xpress_huffman::compress(&input, out).unwrap());
    }
}

// ---------------------------------------------------------------
// LZX (max 32 KB)
// ---------------------------------------------------------------

#[divan::bench_group]
mod lzx {
    use super::{BytesCount, LZX_SIZES, mixed, random_ish, zeros};

    #[divan::bench(args = LZX_SIZES)]
    fn compress_zeros(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = zeros(len);
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::lzx::compress_bound(len)])
            .bench_local_refs(|out| nt_compression::lzx::compress(&input, out).unwrap());
    }

    #[divan::bench(args = LZX_SIZES)]
    fn compress_mixed(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = mixed(len);
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::lzx::compress_bound(len)])
            .bench_local_refs(|out| nt_compression::lzx::compress(&input, out).unwrap());
    }

    #[divan::bench(args = LZX_SIZES)]
    fn compress_random_ish(bencher: divan::Bencher<'_, '_>, len: usize) {
        let input = random_ish(len);
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; nt_compression::lzx::compress_bound(len)])
            .bench_local_refs(|out| nt_compression::lzx::compress(&input, out).unwrap());
    }
}
