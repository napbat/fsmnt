//! Side-by-side benchmarks: our implementation vs Windows RTL (`ntdll.dll`).
//!
//! Covers LZNT1, XPRESS, and XPRESS Huffman (LZX is not available
//! through the RTL API). On non-Windows platforms the binary compiles
//! but registers no benchmarks.

fn main() {
    divan::main();
}

#[cfg(target_os = "windows")]
mod rtl_ffi;

#[cfg(target_os = "windows")]
mod benches {
    extern crate alloc;

    use alloc::vec::Vec;
    use divan::counter::BytesCount;

    use crate::rtl_ffi::{
        COMPRESSION_FORMAT_LZNT1, COMPRESSION_FORMAT_XPRESS, COMPRESSION_FORMAT_XPRESS_HUFF,
        RtlDecompressBufferEx, STATUS_SUCCESS, rtl_compress, rtl_workspace,
    };

    fn mixed(n: usize) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; n];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = if i < n / 2 {
                u8::try_from(i % 64).expect("the modulus limits values below 64")
            } else {
                u8::try_from((i * 7 + 13) % 251).expect("the modulus limits values below 251")
            };
        }
        buf
    }

    const SIZES: &[usize] = &[4_096, 32_768, 65_536, 262_144];

    // -----------------------------------------------------------
    // LZNT1 compress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod lznt1_compress {
        use super::{
            BytesCount, COMPRESSION_FORMAT_LZNT1, SIZES, alloc, mixed, rtl_compress, rtl_workspace,
        };

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| {
                    alloc::vec![
                        0u8;
                        nt_compression::lznt1::compress_bound(len)
                    ]
                })
                .bench_local_refs(|out| nt_compression::lznt1::compress(&input, out).unwrap());
        }

        #[divan::bench(args = SIZES)]
        fn rtl(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let (mut ws, _) = rtl_workspace(COMPRESSION_FORMAT_LZNT1);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| ())
                .bench_local_values(|()| rtl_compress(COMPRESSION_FORMAT_LZNT1, &input, &mut ws));
        }
    }

    // -----------------------------------------------------------
    // LZNT1 decompress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod lznt1_decompress {
        use super::{
            BytesCount, COMPRESSION_FORMAT_LZNT1, RtlDecompressBufferEx, SIZES, STATUS_SUCCESS,
            alloc, mixed, rtl_compress, rtl_workspace,
        };

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let mut buf = alloc::vec![
                0u8;
                nt_compression::lznt1::compress_bound(len)
            ];
            let n = nt_compression::lznt1::compress(&input, &mut buf).expect("pre-compress");
            buf.truncate(n);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| alloc::vec![0u8; len])
                .bench_local_refs(|out| nt_compression::lznt1::decompress(&buf, out).unwrap());
        }

        #[divan::bench(args = SIZES)]
        fn rtl(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let (mut c_ws, mut d_ws) = rtl_workspace(COMPRESSION_FORMAT_LZNT1);
            let compressed = rtl_compress(COMPRESSION_FORMAT_LZNT1, &input, &mut c_ws);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| alloc::vec![0u8; len])
                .bench_local_refs(|out| {
                    let mut final_size: u32 = 0;
                    let status = unsafe {
                        RtlDecompressBufferEx(
                            COMPRESSION_FORMAT_LZNT1,
                            out.as_mut_ptr(),
                            u32::try_from(out.len())
                                .expect("benchmark buffers are smaller than 4 GiB"),
                            compressed.as_ptr(),
                            u32::try_from(compressed.len())
                                .expect("benchmark buffers are smaller than 4 GiB"),
                            &raw mut final_size,
                            d_ws.as_mut_ptr(),
                        )
                    };
                    assert_eq!(status, STATUS_SUCCESS);
                    final_size as usize
                });
        }
    }

    // -----------------------------------------------------------
    // XPRESS compress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod xpress_compress {
        use super::{
            BytesCount, COMPRESSION_FORMAT_XPRESS, SIZES, alloc, mixed, rtl_compress, rtl_workspace,
        };

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| {
                    alloc::vec![
                        0u8;
                        nt_compression::xpress::compress_bound(len)
                    ]
                })
                .bench_local_refs(|out| nt_compression::xpress::compress(&input, out).unwrap());
        }

        #[divan::bench(args = SIZES)]
        fn rtl(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let (mut ws, _) = rtl_workspace(COMPRESSION_FORMAT_XPRESS);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| ())
                .bench_local_values(|()| rtl_compress(COMPRESSION_FORMAT_XPRESS, &input, &mut ws));
        }
    }

    // -----------------------------------------------------------
    // XPRESS decompress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod xpress_decompress {
        use super::{
            BytesCount, COMPRESSION_FORMAT_XPRESS, RtlDecompressBufferEx, SIZES, STATUS_SUCCESS,
            alloc, mixed, rtl_compress, rtl_workspace,
        };

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let mut buf = alloc::vec![
                0u8;
                nt_compression::xpress::compress_bound(len)
            ];
            let n = nt_compression::xpress::compress(&input, &mut buf).expect("pre-compress");
            buf.truncate(n);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| alloc::vec![0u8; len])
                .bench_local_refs(|out| nt_compression::xpress::decompress(&buf, out).unwrap());
        }

        #[divan::bench(args = SIZES)]
        fn rtl(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let (mut c_ws, mut d_ws) = rtl_workspace(COMPRESSION_FORMAT_XPRESS);
            let compressed = rtl_compress(COMPRESSION_FORMAT_XPRESS, &input, &mut c_ws);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| alloc::vec![0u8; len])
                .bench_local_refs(|out| {
                    let mut final_size: u32 = 0;
                    let status = unsafe {
                        RtlDecompressBufferEx(
                            COMPRESSION_FORMAT_XPRESS,
                            out.as_mut_ptr(),
                            u32::try_from(out.len())
                                .expect("benchmark buffers are smaller than 4 GiB"),
                            compressed.as_ptr(),
                            u32::try_from(compressed.len())
                                .expect("benchmark buffers are smaller than 4 GiB"),
                            &raw mut final_size,
                            d_ws.as_mut_ptr(),
                        )
                    };
                    assert_eq!(status, STATUS_SUCCESS);
                    final_size as usize
                });
        }
    }

    // -----------------------------------------------------------
    // XPRESS Huffman compress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod xpress_huffman_compress {
        use super::{
            BytesCount, COMPRESSION_FORMAT_XPRESS_HUFF, SIZES, alloc, mixed, rtl_compress,
            rtl_workspace,
        };

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| {
                    alloc::vec![
                        0u8;
                        nt_compression::xpress_huffman::compress_bound(len)
                    ]
                })
                .bench_local_refs(|out| {
                    nt_compression::xpress_huffman::compress(&input, out).unwrap()
                });
        }

        #[divan::bench(args = SIZES)]
        fn rtl(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let (mut ws, _) = rtl_workspace(COMPRESSION_FORMAT_XPRESS_HUFF);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| ())
                .bench_local_values(|()| {
                    rtl_compress(COMPRESSION_FORMAT_XPRESS_HUFF, &input, &mut ws)
                });
        }
    }

    // -----------------------------------------------------------
    // XPRESS Huffman decompress
    // -----------------------------------------------------------

    #[divan::bench_group]
    mod xpress_huffman_decompress {
        use super::{
            BytesCount, COMPRESSION_FORMAT_XPRESS_HUFF, RtlDecompressBufferEx, SIZES,
            STATUS_SUCCESS, alloc, mixed, rtl_compress, rtl_workspace,
        };

        #[divan::bench(args = SIZES)]
        fn ours(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let mut buf = alloc::vec![
                0u8;
                nt_compression::xpress_huffman::compress_bound(len)
            ];
            let n =
                nt_compression::xpress_huffman::compress(&input, &mut buf).expect("pre-compress");
            buf.truncate(n);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| alloc::vec![0u8; len])
                .bench_local_refs(|out| {
                    nt_compression::xpress_huffman::decompress(&buf, out).unwrap()
                });
        }

        #[divan::bench(args = SIZES)]
        fn rtl(bencher: divan::Bencher<'_, '_>, len: usize) {
            let input = mixed(len);
            let (mut c_ws, mut d_ws) = rtl_workspace(COMPRESSION_FORMAT_XPRESS_HUFF);
            let compressed = rtl_compress(COMPRESSION_FORMAT_XPRESS_HUFF, &input, &mut c_ws);
            bencher
                .counter(BytesCount::new(len))
                .with_inputs(|| alloc::vec![0u8; len])
                .bench_local_refs(|out| {
                    let mut final_size: u32 = 0;
                    let status = unsafe {
                        RtlDecompressBufferEx(
                            COMPRESSION_FORMAT_XPRESS_HUFF,
                            out.as_mut_ptr(),
                            u32::try_from(out.len())
                                .expect("benchmark buffers are smaller than 4 GiB"),
                            compressed.as_ptr(),
                            u32::try_from(compressed.len())
                                .expect("benchmark buffers are smaller than 4 GiB"),
                            &raw mut final_size,
                            d_ws.as_mut_ptr(),
                        )
                    };
                    assert_eq!(status, STATUS_SUCCESS);
                    final_size as usize
                });
        }
    }
}
