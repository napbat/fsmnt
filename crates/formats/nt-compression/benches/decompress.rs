//! Decompression throughput benchmarks for all four algorithms.

mod bench_data;

use bench_data::{mixed, random_ish, zeros};
use divan::counter::BytesCount;

fn main() {
    divan::main();
}

/// Pre-compress data and return (`compressed_bytes`, `original_len`).
fn precompressed<F>(
    data: &[u8],
    bound_fn: F,
    compress_fn: fn(&[u8], &mut [u8]) -> nt_compression::Result<usize>,
) -> Vec<u8>
where
    F: FnOnce(usize) -> usize,
{
    let mut buf = vec![0u8; bound_fn(data.len())];
    let n = compress_fn(data, &mut buf).expect("pre-compress failed");
    buf.truncate(n);
    buf
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
    use super::{BytesCount, SIZES, mixed, precompressed, random_ish, zeros};

    #[divan::bench(args = SIZES)]
    fn decompress_zeros(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &zeros(len),
            nt_compression::lznt1::compress_bound,
            nt_compression::lznt1::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| nt_compression::lznt1::decompress(&compressed, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn decompress_mixed(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &mixed(len),
            nt_compression::lznt1::compress_bound,
            nt_compression::lznt1::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| nt_compression::lznt1::decompress(&compressed, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn decompress_random_ish(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &random_ish(len),
            nt_compression::lznt1::compress_bound,
            nt_compression::lznt1::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| nt_compression::lznt1::decompress(&compressed, out).unwrap());
    }
}

// ---------------------------------------------------------------
// XPRESS
// ---------------------------------------------------------------

#[divan::bench_group]
mod xpress {
    use super::{BytesCount, SIZES, mixed, precompressed, random_ish, zeros};

    #[divan::bench(args = SIZES)]
    fn decompress_zeros(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &zeros(len),
            nt_compression::xpress::compress_bound,
            nt_compression::xpress::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| nt_compression::xpress::decompress(&compressed, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn decompress_mixed(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &mixed(len),
            nt_compression::xpress::compress_bound,
            nt_compression::xpress::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| nt_compression::xpress::decompress(&compressed, out).unwrap());
    }

    #[divan::bench(args = SIZES)]
    fn decompress_random_ish(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &random_ish(len),
            nt_compression::xpress::compress_bound,
            nt_compression::xpress::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| nt_compression::xpress::decompress(&compressed, out).unwrap());
    }
}

// ---------------------------------------------------------------
// XPRESS Huffman
// ---------------------------------------------------------------

#[divan::bench_group]
mod xpress_huffman {
    use super::{BytesCount, SIZES, mixed, precompressed, random_ish, zeros};

    #[divan::bench(args = SIZES)]
    fn decompress_zeros(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &zeros(len),
            nt_compression::xpress_huffman::compress_bound,
            nt_compression::xpress_huffman::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| {
                nt_compression::xpress_huffman::decompress(&compressed, out).unwrap()
            });
    }

    #[divan::bench(args = SIZES)]
    fn decompress_mixed(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &mixed(len),
            nt_compression::xpress_huffman::compress_bound,
            nt_compression::xpress_huffman::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| {
                nt_compression::xpress_huffman::decompress(&compressed, out).unwrap()
            });
    }

    #[divan::bench(args = SIZES)]
    fn decompress_random_ish(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &random_ish(len),
            nt_compression::xpress_huffman::compress_bound,
            nt_compression::xpress_huffman::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| {
                nt_compression::xpress_huffman::decompress(&compressed, out).unwrap()
            });
    }
}

// ---------------------------------------------------------------
// LZX (max 32 KB)
// ---------------------------------------------------------------

#[divan::bench_group]
mod lzx {
    use super::{BytesCount, LZX_SIZES, mixed, precompressed, random_ish, zeros};

    #[divan::bench(args = LZX_SIZES)]
    fn decompress_zeros(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &zeros(len),
            nt_compression::lzx::compress_bound,
            nt_compression::lzx::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| nt_compression::lzx::decompress(&compressed, out).unwrap());
    }

    #[divan::bench(args = LZX_SIZES)]
    fn decompress_mixed(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &mixed(len),
            nt_compression::lzx::compress_bound,
            nt_compression::lzx::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| nt_compression::lzx::decompress(&compressed, out).unwrap());
    }

    #[divan::bench(args = LZX_SIZES)]
    fn decompress_random_ish(bencher: divan::Bencher<'_, '_>, len: usize) {
        let compressed = precompressed(
            &random_ish(len),
            nt_compression::lzx::compress_bound,
            nt_compression::lzx::compress,
        );
        bencher
            .counter(BytesCount::new(len))
            .with_inputs(|| vec![0u8; len])
            .bench_local_refs(|out| nt_compression::lzx::decompress(&compressed, out).unwrap());
    }
}
