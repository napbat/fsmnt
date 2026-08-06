//! Unsafe primitives for hot-path performance.
//!
//! Each function in this module is `unsafe` with documented safety
//! contracts. Callers must satisfy the preconditions (proven via guard
//! margins or prior bounds checks). `debug_assert!` catches violations
//! during testing but is elided in release builds by design.
//!
//! All multi-byte reads use `.to_le()` after `read_unaligned` so
//! they return correct little-endian values on any target endianness.
//! On LE targets (x86, `x86_64`, aarch64) `.to_le()` is a no-op.
#![allow(unsafe_code)]

/// Read a `u16` from `data[pos..pos+2]` in little-endian order.
///
/// # Safety
/// Caller must ensure `pos + 2 <= data.len()`.
#[cfg(any(feature = "xpress-huffman", feature = "lzx"))]
#[inline]
pub(crate) unsafe fn read_u16_le(data: &[u8], pos: usize) -> u16 {
    debug_assert!(pos + 2 <= data.len());
    unsafe { core::ptr::read_unaligned(data.as_ptr().add(pos).cast::<u16>()).to_le() }
}

/// Read a `u32` from `data[pos..pos+4]` in little-endian order.
///
/// # Safety
/// Caller must ensure `pos + 4 <= data.len()`.
#[inline]
pub(crate) unsafe fn read_u32_le(data: &[u8], pos: usize) -> u32 {
    debug_assert!(pos + 4 <= data.len());
    unsafe { core::ptr::read_unaligned(data.as_ptr().add(pos).cast::<u32>()).to_le() }
}

/// Read a `u64` from `data[pos..pos+8]` in little-endian order.
///
/// # Safety
/// Caller must ensure `pos + 8 <= data.len()`.
#[inline]
#[allow(dead_code)]
pub(crate) unsafe fn read_u64_le(data: &[u8], pos: usize) -> u64 {
    debug_assert!(pos + 8 <= data.len());
    unsafe { core::ptr::read_unaligned(data.as_ptr().add(pos).cast::<u64>()).to_le() }
}

/// Copy `length` bytes from `output[out_pos - distance..]` to
/// `output[out_pos..]`, handling overlapping regions correctly
/// with LZ77 semantics (each written byte is immediately visible
/// to subsequent reads, producing repeating patterns).
///
/// Uses `ptr::copy_nonoverlapping` when chunk size <= distance (no overlap),
/// `ptr::write_bytes` for RLE (distance == 1), and byte-by-byte copy
/// for short distances (2-7) where LZ77 pattern repetition is needed.
///
/// # Safety
/// - `distance > 0`
/// - `out_pos >= distance` (source is in bounds)
/// - `out_pos + length <= output.len()` (dest is in bounds)
#[inline]
#[allow(dead_code)] // used by simd.rs on non-x86_64 targets and in tests
pub(crate) unsafe fn copy_match_unchecked(
    output: &mut [u8],
    out_pos: usize,
    distance: usize,
    length: usize,
) {
    debug_assert!(distance > 0);
    debug_assert!(out_pos >= distance);
    debug_assert!(out_pos + length <= output.len());

    let ptr = output.as_mut_ptr();

    // SAFETY: caller guarantees:
    //   - src range [out_pos - distance .. out_pos - distance + length] in bounds
    //   - dst range [out_pos .. out_pos + length] in bounds
    // Overlap invariant for chunked branches:
    //   copy_nonoverlapping is safe when chunk_size <= distance, because
    //   src[i..i+chunk] and dst[i..i+chunk] are separated by exactly
    //   `distance` bytes, so they don't overlap when chunk <= distance.
    unsafe {
        let src = ptr.add(out_pos - distance);
        let dst = ptr.add(out_pos);

        if distance >= length {
            // Non-overlapping: src and dst ranges don't overlap at all.
            core::ptr::copy_nonoverlapping(src, dst, length);
        } else if distance == 1 {
            // RLE fill: single byte repeated.
            core::ptr::write_bytes(dst, *src, length);
        } else if distance >= 16 {
            // SAFETY: chunk_size=16 <= distance, so each 16-byte
            // src and dst chunk are non-overlapping.
            let mut i = 0;
            while i + 16 <= length {
                core::ptr::copy_nonoverlapping(src.add(i), dst.add(i), 16);
                i += 16;
            }
            // Byte-by-byte tail (0-15 bytes). Avoids a memmove
            // function call, which is expensive for small tails.
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else if distance >= 8 {
            // SAFETY: chunk_size=8 <= distance, so each 8-byte
            // src and dst chunk are non-overlapping.
            let mut i = 0;
            while i + 8 <= length {
                core::ptr::copy_nonoverlapping(src.add(i), dst.add(i), 8);
                i += 8;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else {
            // Short distance (2-7): byte-by-byte copy to produce the
            // LZ77 repeating-pattern effect. memmove would preserve the
            // original source bytes, but LZ77 semantics require each
            // written byte to be immediately visible to subsequent reads.
            for i in 0..length {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

/// Compute the number of matching bytes at positions `a` and `b`
/// in `data`, up to `max_len` bytes, using u64-word comparison.
///
/// # Safety
/// - `a + max_len <= data.len()`
/// - `b + max_len <= data.len()`
#[cfg(any(
    feature = "compress-xpress",
    feature = "compress-xpress-huffman",
    feature = "compress-lzx",
))]
#[inline]
pub(crate) unsafe fn match_length_unchecked(
    data: &[u8],
    a: usize,
    b: usize,
    max_len: usize,
) -> u32 {
    debug_assert!(a + max_len <= data.len());
    debug_assert!(b + max_len <= data.len());

    let ptr = data.as_ptr();
    let mut len = 0usize;

    // SAFETY: caller guarantees both ranges are within data.len().
    // We use from_le() on both u64 values so that the least-significant
    // byte corresponds to the lowest memory address. This makes
    // trailing_zeros()/8 yield the correct byte offset on both
    // little-endian and big-endian targets. On LE, from_le() is a no-op.
    unsafe {
        while len + 8 <= max_len {
            let wa = u64::from_le(core::ptr::read_unaligned(ptr.add(a + len).cast::<u64>()));
            let wb = u64::from_le(core::ptr::read_unaligned(ptr.add(b + len).cast::<u64>()));
            let xor = wa ^ wb;
            if xor != 0 {
                len += (xor.trailing_zeros() / 8) as usize;
                return u32::try_from(len.min(max_len))
                    .expect("the match finder passes a max_len originating from its u32 config");
            }
            len += 8;
        }
        while len < max_len {
            if *ptr.add(a + len) != *ptr.add(b + len) {
                break;
            }
            len += 1;
        }
    }
    u32::try_from(len).expect("the match finder passes a max_len originating from its u32 config")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "xpress-huffman")]
    fn read_u16_le_aligned() {
        let data = [0x01, 0x02, 0x03, 0x04];
        // SAFETY: pos + 2 <= 4
        unsafe {
            assert_eq!(read_u16_le(&data, 0), u16::from_le_bytes([0x01, 0x02]));
            assert_eq!(read_u16_le(&data, 2), u16::from_le_bytes([0x03, 0x04]));
        }
    }

    #[test]
    #[cfg(feature = "xpress-huffman")]
    fn read_u16_le_unaligned() {
        let data = [0x00, 0xAB, 0xCD, 0x00];
        // SAFETY: 1 + 2 <= 4
        unsafe {
            assert_eq!(read_u16_le(&data, 1), u16::from_le_bytes([0xAB, 0xCD]));
        }
    }

    #[test]
    fn read_u32_le_basic() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        // SAFETY: pos + 4 <= 5
        unsafe {
            assert_eq!(
                read_u32_le(&data, 0),
                u32::from_le_bytes([0x01, 0x02, 0x03, 0x04])
            );
            assert_eq!(
                read_u32_le(&data, 1),
                u32::from_le_bytes([0x02, 0x03, 0x04, 0x05])
            );
        }
    }

    #[test]
    fn read_u64_le_basic() {
        let data: alloc::vec::Vec<u8> = (0..16).collect();
        // SAFETY: pos + 8 <= 16
        unsafe {
            assert_eq!(
                read_u64_le(&data, 0),
                u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7])
            );
            assert_eq!(
                read_u64_le(&data, 3),
                u64::from_le_bytes([3, 4, 5, 6, 7, 8, 9, 10])
            );
        }
    }

    #[test]
    #[cfg(any(
        feature = "compress-xpress",
        feature = "compress-xpress-huffman",
        feature = "compress-lzx",
    ))]
    fn match_length_identical() {
        let data = [0xAA; 32];
        // SAFETY: 0+16 <= 32, 16+16 <= 32
        assert_eq!(unsafe { match_length_unchecked(&data, 0, 16, 16) }, 16);
    }

    #[test]
    #[cfg(any(
        feature = "compress-xpress",
        feature = "compress-xpress-huffman",
        feature = "compress-lzx",
    ))]
    fn match_length_first_byte_differs() {
        let mut data = [0u8; 16];
        data[0] = 1;
        data[8] = 2;
        // SAFETY: 0+8 <= 16, 8+8 <= 16
        assert_eq!(unsafe { match_length_unchecked(&data, 0, 8, 8) }, 0);
    }

    #[test]
    #[cfg(any(
        feature = "compress-xpress",
        feature = "compress-xpress-huffman",
        feature = "compress-lzx",
    ))]
    fn match_length_partial() {
        let data = [1, 2, 3, 4, 5, 1, 2, 3, 9, 9];
        // SAFETY: 0+5 <= 10, 5+5 <= 10
        assert_eq!(unsafe { match_length_unchecked(&data, 0, 5, 5) }, 3);
    }

    #[test]
    #[cfg(any(
        feature = "compress-xpress",
        feature = "compress-xpress-huffman",
        feature = "compress-lzx",
    ))]
    fn match_length_crosses_u64_boundary() {
        let mut data = [0xBB; 24];
        data[9] = 0xCC; // position a=1+8=9
        data[21] = 0xCC; // position b=13+8=21
        // SAFETY: 1+10 <= 24, 13+10 <= 24
        assert_eq!(unsafe { match_length_unchecked(&data, 1, 13, 10) }, 10);
    }

    #[test]
    fn copy_match_non_overlapping() {
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(b"ABCD");
        // SAFETY: distance=8, out_pos=8, 8>=8, 8+4<=16
        unsafe { copy_match_unchecked(&mut buf, 8, 8, 4) };
        assert_eq!(&buf[8..12], b"ABCD");
    }

    #[test]
    fn copy_match_rle_fill() {
        let mut buf = [0u8; 16];
        buf[0] = 0xFF;
        // SAFETY: distance=1, out_pos=1, 1>=1, 1+15<=16
        unsafe { copy_match_unchecked(&mut buf, 1, 1, 15) };
        assert!(buf.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn copy_match_overlapping_short_distance() {
        // distance=3, length=9 -> repeating "ABC" pattern
        let mut buf = [0u8; 16];
        buf[..3].copy_from_slice(b"ABC");
        // SAFETY: distance=3, out_pos=3, 3>=3, 3+9<=16
        unsafe { copy_match_unchecked(&mut buf, 3, 3, 9) };
        assert_eq!(&buf[..12], b"ABCABCABCABC");
    }

    #[test]
    fn copy_match_overlapping_medium_distance() {
        // distance=8, length=24 -> repeating 8-byte pattern
        let mut buf = [0u8; 32];
        buf[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        // SAFETY: distance=8, out_pos=8, 8>=8, 8+24<=32
        unsafe { copy_match_unchecked(&mut buf, 8, 8, 24) };
        for (i, &byte) in buf.iter().enumerate() {
            assert_eq!(
                byte,
                u8::try_from(i % 8 + 1)
                    .expect("the expected pattern ranges from one through eight"),
                "mismatch at {i}"
            );
        }
    }

    #[test]
    fn copy_match_large_non_overlapping() {
        let mut buf = [0u8; 256];
        for (i, byte) in buf[..64].iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("the test buffer is shorter than 256 bytes");
        }
        // SAFETY: distance=128, out_pos=128, 128>=128, 128+64<=256
        unsafe { copy_match_unchecked(&mut buf, 128, 128, 64) };
        assert_eq!(&buf[128..192], &buf[..64]);
    }
}
