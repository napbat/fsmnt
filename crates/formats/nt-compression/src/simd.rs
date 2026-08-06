//! SIMD-accelerated match copy with runtime dispatch.
//!
//! On first call, probes CPUID to determine the best available SIMD
//! tier, stores a fn pointer to the chosen implementation, and
//! indirect-calls through it on all subsequent invocations (zero
//! per-call branching).
//!
//! Tiers (`x86_64)`:
//! - **SSE2** (baseline): 16-byte chunks for distance >= 16
//! - **AVX2**: 32-byte chunks for distance >= 32, SSE2 tail
//! - **AVX-512**: 64-byte chunks for distance >= 64, AVX2/SSE2 tail
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicPtr, Ordering};

use fs_common::SimdLevel;

/// Signature for match-copy implementations.
type CopyMatchFn = unsafe fn(&mut [u8], usize, usize, usize);

/// Global fn pointer — initialized to [`resolver`], replaced on
/// first call with the best available implementation.
///
/// # Safety invariant
///
/// The stored pointer is always a valid `CopyMatchFn`. Initially it
/// points to `resolver` (a compile-time constant); the resolver
/// replaces it with another compile-time constant chosen by
/// [`pick_copy_match`]. `Relaxed` ordering is sufficient because
/// function pointers live in the text segment and are valid the
/// moment they become visible.
static COPY_MATCH_PTR: AtomicPtr<()> = AtomicPtr::new((resolver as *const ()).cast_mut());

/// SIMD-accelerated match copy. Dispatches through a cached fn
/// pointer that is resolved on first invocation via CPUID probing.
///
/// # Safety
/// Same as `raw::copy_match_unchecked`:
/// - `distance > 0`
/// - `out_pos >= distance` (source in bounds)
/// - `out_pos + length <= output.len()` (dest in bounds)
#[inline]
pub(crate) unsafe fn copy_match_fast(
    output: &mut [u8],
    out_pos: usize,
    distance: usize,
    length: usize,
) {
    let ptr = COPY_MATCH_PTR.load(Ordering::Relaxed);
    // SAFETY: `ptr` is always a valid `CopyMatchFn` — see the safety
    // invariant on `COPY_MATCH_PTR`.
    let f: CopyMatchFn = unsafe { core::mem::transmute(ptr) };
    // SAFETY: caller guarantees the match-copy preconditions.
    unsafe { f(output, out_pos, distance, length) };
}

// ---------------------------------------------------------------------------
// CPUID detection via cpufeatures (x86_64 only)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
cpufeatures::new!(avx512f_detect, "avx512f");

#[cfg(target_arch = "x86_64")]
cpufeatures::new!(avx2_detect, "avx2");

#[cfg(target_arch = "x86_64")]
fn detect_simd_level() -> SimdLevel {
    // Check widest first — each tier implies all narrower tiers.
    if avx512f_detect::get() {
        SimdLevel::Avx512
    } else if avx2_detect::get() {
        SimdLevel::Avx2
    } else {
        // SSE2 is baseline on x86_64 — always available.
        SimdLevel::Sse2
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_simd_level() -> SimdLevel {
    SimdLevel::Scalar
}

// ---------------------------------------------------------------------------
// Resolver + dispatch
// ---------------------------------------------------------------------------

/// Cold-path resolver: detects SIMD level, picks the best
/// implementation, stores the fn pointer, and tail-calls into it.
#[cold]
unsafe fn resolver(output: &mut [u8], out_pos: usize, distance: usize, length: usize) {
    let level = detect_simd_level();
    let f = pick_copy_match(level);
    COPY_MATCH_PTR.store((f as *const ()).cast_mut(), Ordering::Relaxed);
    // SAFETY: caller guarantees preconditions; `f` was chosen for a
    // confirmed feature set.
    unsafe { f(output, out_pos, distance, length) };
}

/// Select the best copy-match implementation for the given SIMD level.
fn pick_copy_match(level: SimdLevel) -> CopyMatchFn {
    #[cfg(target_arch = "x86_64")]
    {
        match level {
            SimdLevel::Avx512 => return copy_match_avx512,
            SimdLevel::Avx2 => return copy_match_avx2,
            SimdLevel::Sse2 => return copy_match_sse2,
            _ => {} // Scalar or future variants
        }
    }
    let _ = level;
    copy_match_scalar
}

// ---------------------------------------------------------------------------
// Implementations
// ---------------------------------------------------------------------------

/// Scalar fallback: delegates to `raw::copy_match_unchecked`.
///
/// # Safety
/// Same preconditions as `copy_match_fast`.
unsafe fn copy_match_scalar(output: &mut [u8], out_pos: usize, distance: usize, length: usize) {
    unsafe { crate::raw::copy_match_unchecked(output, out_pos, distance, length) }
}

/// SSE2 implementation (128-bit / 16-byte loads/stores).
///
/// Baseline on `x86_64` — no `#[target_feature]` needed.
///
/// # Safety
/// Same preconditions as `copy_match_fast`.
#[cfg(target_arch = "x86_64")]
#[inline]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 and _mm_storeu_si128 explicitly support byte-aligned addresses; their API still requires __m128i pointers"
)]
unsafe fn copy_match_sse2(output: &mut [u8], out_pos: usize, distance: usize, length: usize) {
    use core::arch::x86_64::{__m128i, _mm_loadu_si128, _mm_storeu_si128};

    debug_assert!(distance > 0);
    debug_assert!(out_pos >= distance);
    debug_assert!(out_pos + length <= output.len());

    let ptr = output.as_mut_ptr();

    // SAFETY: caller guarantees both src and dst ranges are in bounds.
    unsafe {
        let src = ptr.add(out_pos - distance);
        let dst = ptr.add(out_pos);

        if distance >= length {
            // Non-overlapping: memcpy.
            core::ptr::copy_nonoverlapping(src, dst, length);
        } else if distance == 1 {
            // RLE fill: single byte repeated.
            core::ptr::write_bytes(dst, *src, length);
        } else if distance >= 16 {
            // 16-byte SIMD chunks. Since distance >= 16, each
            // 16-byte src and dst chunk are non-overlapping.
            let mut i = 0;
            while i + 16 <= length {
                let chunk = _mm_loadu_si128(src.add(i).cast::<__m128i>());
                _mm_storeu_si128(dst.add(i).cast::<__m128i>(), chunk);
                i += 16;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else if distance >= 8 {
            // 8-byte chunks for distance 8-15.
            let mut i = 0;
            while i + 8 <= length {
                let chunk = core::ptr::read_unaligned(src.add(i).cast::<u64>());
                core::ptr::write_unaligned(dst.add(i).cast::<u64>(), chunk);
                i += 8;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else {
            // Short distance (2-7): byte-by-byte for LZ77 pattern semantics.
            for i in 0..length {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

/// AVX2 implementation (256-bit / 32-byte loads/stores).
///
/// For distance >= 32, uses 32-byte ymm chunks. Falls through to
/// 16-byte xmm chunks (VEX-encoded) for distance 16-31, then to
/// 8-byte and byte-by-byte for shorter distances.
///
/// # Safety
/// Same preconditions as `copy_match_fast`.
/// Caller must ensure AVX2 is available (guaranteed by CPUID check
/// in the resolver).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "the loadu/storeu AVX2 and SSE intrinsics explicitly support byte-aligned addresses but require vector-typed pointers"
)]
unsafe fn copy_match_avx2(output: &mut [u8], out_pos: usize, distance: usize, length: usize) {
    use core::arch::x86_64::{
        __m128i, __m256i, _mm_loadu_si128, _mm_storeu_si128, _mm256_loadu_si256,
        _mm256_storeu_si256,
    };

    debug_assert!(distance > 0);
    debug_assert!(out_pos >= distance);
    debug_assert!(out_pos + length <= output.len());

    let ptr = output.as_mut_ptr();

    unsafe {
        let src = ptr.add(out_pos - distance);
        let dst = ptr.add(out_pos);

        if distance >= length {
            core::ptr::copy_nonoverlapping(src, dst, length);
        } else if distance == 1 {
            core::ptr::write_bytes(dst, *src, length);
        } else if distance >= 32 {
            // 32-byte AVX2 chunks. distance >= 32 ensures each
            // 32-byte src/dst pair is non-overlapping.
            let mut i = 0;
            while i + 32 <= length {
                let chunk = _mm256_loadu_si256(src.add(i).cast::<__m256i>());
                _mm256_storeu_si256(dst.add(i).cast::<__m256i>(), chunk);
                i += 32;
            }
            // 16-byte SSE2 tail (VEX-encoded, no transition penalty).
            // Safe because 16 < 32 <= distance.
            if i + 16 <= length {
                let chunk = _mm_loadu_si128(src.add(i).cast::<__m128i>());
                _mm_storeu_si128(dst.add(i).cast::<__m128i>(), chunk);
                i += 16;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else if distance >= 16 {
            // 16-byte chunks (VEX-encoded).
            let mut i = 0;
            while i + 16 <= length {
                let chunk = _mm_loadu_si128(src.add(i).cast::<__m128i>());
                _mm_storeu_si128(dst.add(i).cast::<__m128i>(), chunk);
                i += 16;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else if distance >= 8 {
            let mut i = 0;
            while i + 8 <= length {
                let chunk = core::ptr::read_unaligned(src.add(i).cast::<u64>());
                core::ptr::write_unaligned(dst.add(i).cast::<u64>(), chunk);
                i += 8;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else {
            for i in 0..length {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

/// AVX-512 implementation (512-bit / 64-byte loads/stores).
///
/// For distance >= 64, uses 64-byte zmm chunks. Falls through to
/// 32-byte ymm, then 16-byte xmm, then 8-byte and byte-by-byte.
///
/// # Safety
/// Same preconditions as `copy_match_fast`.
/// Caller must ensure AVX-512F is available (guaranteed by CPUID
/// check in the resolver).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "the loadu/storeu AVX-512, AVX2, and SSE intrinsics explicitly support byte-aligned addresses but require vector-typed pointers"
)]
unsafe fn copy_match_avx512(output: &mut [u8], out_pos: usize, distance: usize, length: usize) {
    use core::arch::x86_64::{
        __m128i, __m256i, __m512i, _mm_loadu_si128, _mm_storeu_si128, _mm256_loadu_si256,
        _mm256_storeu_si256, _mm512_loadu_si512, _mm512_storeu_si512,
    };

    debug_assert!(distance > 0);
    debug_assert!(out_pos >= distance);
    debug_assert!(out_pos + length <= output.len());

    let ptr = output.as_mut_ptr();

    unsafe {
        let src = ptr.add(out_pos - distance);
        let dst = ptr.add(out_pos);

        if distance >= length {
            core::ptr::copy_nonoverlapping(src, dst, length);
        } else if distance == 1 {
            core::ptr::write_bytes(dst, *src, length);
        } else if distance >= 64 {
            // 64-byte AVX-512 chunks. distance >= 64 ensures each
            // 64-byte src/dst pair is non-overlapping.
            let mut i = 0;
            while i + 64 <= length {
                let chunk = _mm512_loadu_si512(src.add(i).cast::<__m512i>());
                _mm512_storeu_si512(dst.add(i).cast::<__m512i>(), chunk);
                i += 64;
            }
            // 32-byte AVX2 tail. Safe because 32 < 64 <= distance.
            if i + 32 <= length {
                let chunk = _mm256_loadu_si256(src.add(i).cast::<__m256i>());
                _mm256_storeu_si256(dst.add(i).cast::<__m256i>(), chunk);
                i += 32;
            }
            // 16-byte SSE2 tail. Safe because 16 < 64 <= distance.
            if i + 16 <= length {
                let chunk = _mm_loadu_si128(src.add(i).cast::<__m128i>());
                _mm_storeu_si128(dst.add(i).cast::<__m128i>(), chunk);
                i += 16;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else if distance >= 32 {
            // 32-byte AVX2 chunks (EVEX-encoded).
            let mut i = 0;
            while i + 32 <= length {
                let chunk = _mm256_loadu_si256(src.add(i).cast::<__m256i>());
                _mm256_storeu_si256(dst.add(i).cast::<__m256i>(), chunk);
                i += 32;
            }
            if i + 16 <= length {
                let chunk = _mm_loadu_si128(src.add(i).cast::<__m128i>());
                _mm_storeu_si128(dst.add(i).cast::<__m128i>(), chunk);
                i += 16;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else if distance >= 16 {
            let mut i = 0;
            while i + 16 <= length {
                let chunk = _mm_loadu_si128(src.add(i).cast::<__m128i>());
                _mm_storeu_si128(dst.add(i).cast::<__m128i>(), chunk);
                i += 16;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else if distance >= 8 {
            let mut i = 0;
            while i + 8 <= length {
                let chunk = core::ptr::read_unaligned(src.add(i).cast::<u64>());
                core::ptr::write_unaligned(dst.add(i).cast::<u64>(), chunk);
                i += 8;
            }
            while i < length {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        } else {
            for i in 0..length {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference implementation for comparison.
    fn reference_copy(buf: &mut [u8], out_pos: usize, distance: usize, length: usize) {
        // SAFETY: tests ensure all preconditions.
        unsafe { crate::raw::copy_match_unchecked(buf, out_pos, distance, length) };
    }

    fn test_copy(out_pos: usize, distance: usize, length: usize) {
        let size = out_pos + length + 64;
        let mut expected = alloc::vec![0u8; size];
        let mut actual = expected.clone();
        // Seed source region with a pattern.
        for i in 0..out_pos {
            expected[i] = i.wrapping_mul(7).wrapping_add(3).to_le_bytes()[0];
            actual[i] = expected[i];
        }
        reference_copy(&mut expected, out_pos, distance, length);
        // SAFETY: test ensures preconditions.
        unsafe { copy_match_fast(&mut actual, out_pos, distance, length) };
        assert_eq!(
            &expected[..out_pos + length],
            &actual[..out_pos + length],
            "mismatch: out_pos={out_pos}, distance={distance}, length={length}"
        );
    }

    /// Test a specific `CopyMatchFn` implementation against the reference.
    #[cfg(target_arch = "x86_64")]
    fn test_copy_with(f: CopyMatchFn, out_pos: usize, distance: usize, length: usize) {
        let size = out_pos + length + 64;
        let mut expected = alloc::vec![0u8; size];
        let mut actual = expected.clone();
        for i in 0..out_pos {
            expected[i] = i.wrapping_mul(7).wrapping_add(3).to_le_bytes()[0];
            actual[i] = expected[i];
        }
        reference_copy(&mut expected, out_pos, distance, length);
        // SAFETY: test ensures preconditions; caller ensures feature is available.
        unsafe { f(&mut actual, out_pos, distance, length) };
        assert_eq!(
            &expected[..out_pos + length],
            &actual[..out_pos + length],
            "mismatch: out_pos={out_pos}, distance={distance}, length={length}"
        );
    }

    /// Standard distance/length matrix used across tests.
    const DISTANCES: [usize; 14] = [1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 48, 64, 96, 128];
    const LENGTHS: [usize; 14] = [1, 3, 7, 8, 15, 16, 31, 32, 63, 64, 128, 256, 512, 1024];

    #[test]
    fn simd_copy_matches_reference() {
        for distance in DISTANCES {
            for length in LENGTHS {
                if distance <= 256 {
                    test_copy(256, distance, length);
                }
            }
        }
    }

    #[test]
    fn simd_rle_fill() {
        let mut buf = [0u8; 1024];
        buf[0] = 0xAA;
        // SAFETY: distance=1, out_pos=1, 1>=1, 1+500<=1024
        unsafe { copy_match_fast(&mut buf, 1, 1, 500) };
        assert!(buf[..501].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn simd_non_overlapping() {
        let mut buf = [0u8; 512];
        for (i, byte) in buf[..64].iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("the test buffer is shorter than 256 bytes");
        }
        // SAFETY: distance=256, out_pos=256, 256>=256, 256+64<=512
        unsafe { copy_match_fast(&mut buf, 256, 256, 64) };
        assert_eq!(&buf[256..320], &buf[..64]);
    }

    #[test]
    fn simd_short_distance_pattern() {
        // distance=3, length=12 -> repeating "ABC" pattern
        let mut buf = [0u8; 32];
        buf[..3].copy_from_slice(b"ABC");
        // SAFETY: distance=3, out_pos=3, 3>=3, 3+12<=32
        unsafe { copy_match_fast(&mut buf, 3, 3, 12) };
        assert_eq!(&buf[..15], b"ABCABCABCABCABC");
    }

    #[test]
    fn simd_distance_16_boundary() {
        // Exactly distance=16, length=48 -> tests SSE2 16-byte path
        let mut buf = [0u8; 128];
        for (i, byte) in buf[..16].iter_mut().enumerate() {
            *byte = u8::try_from(i + 1).expect("the test buffer is shorter than 256 bytes");
        }
        // SAFETY: distance=16, out_pos=16, 16>=16, 16+48<=128
        unsafe { copy_match_fast(&mut buf, 16, 16, 48) };
        for (i, &byte) in buf[..64].iter().enumerate() {
            assert_eq!(
                byte,
                u8::try_from(i % 16 + 1).expect("the expected pattern ranges from one through 16"),
                "mismatch at {i}"
            );
        }
    }

    #[test]
    fn simd_distance_32_boundary() {
        // distance=32, length=160 -> tests AVX2 32-byte path
        let mut buf = [0u8; 256];
        for (i, byte) in buf[..32].iter_mut().enumerate() {
            *byte = u8::try_from(i + 1).expect("the test buffer is shorter than 256 bytes");
        }
        // SAFETY: distance=32, out_pos=32, 32>=32, 32+160<=256
        unsafe { copy_match_fast(&mut buf, 32, 32, 160) };
        for (i, &byte) in buf[..192].iter().enumerate() {
            assert_eq!(
                byte,
                u8::try_from(i % 32 + 1).expect("the expected pattern ranges from one through 32"),
                "mismatch at {i}"
            );
        }
    }

    #[test]
    fn simd_distance_64_boundary() {
        // distance=64, length=320 -> tests AVX-512 64-byte path
        let mut buf = [0u8; 512];
        for (i, byte) in buf[..64].iter_mut().enumerate() {
            *byte = u8::try_from(i + 1).expect("the test buffer is shorter than 256 bytes");
        }
        // SAFETY: distance=64, out_pos=64, 64>=64, 64+320<=512
        unsafe { copy_match_fast(&mut buf, 64, 64, 320) };
        for (i, &byte) in buf[..384].iter().enumerate() {
            assert_eq!(
                byte,
                u8::try_from(i % 64 + 1).expect("the expected pattern ranges from one through 64"),
                "mismatch at {i}"
            );
        }
    }

    #[test]
    fn simd_large_non_overlapping() {
        // Large copy with distance > length (no overlap).
        let mut buf = alloc::vec![0u8; 4096];
        for (i, byte) in buf[..1024].iter_mut().enumerate() {
            *byte = i.wrapping_mul(13).wrapping_add(7).to_le_bytes()[0];
        }
        // SAFETY: distance=2048, out_pos=2048, 2048>=2048, 2048+1024<=4096
        unsafe { copy_match_fast(&mut buf, 2048, 2048, 1024) };
        assert_eq!(&buf[2048..3072], &buf[..1024]);
    }

    #[test]
    fn dispatch_resolves_correct_level() {
        let level = detect_simd_level();
        #[cfg(target_arch = "x86_64")]
        assert!(level >= SimdLevel::Sse2);
        let f = pick_copy_match(level);
        // Verify the chosen function works correctly.
        let mut buf = [0u8; 32];
        buf[0] = 0x42;
        // SAFETY: distance=1, out_pos=1, 1>=1, 1+10<=32
        unsafe { f(&mut buf, 1, 1, 10) };
        assert!(buf[..11].iter().all(|&b| b == 0x42));
    }

    /// Directly test the AVX2 implementation if available.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_matches_reference() {
        if detect_simd_level() < SimdLevel::Avx2 {
            return;
        }
        for distance in DISTANCES {
            for length in LENGTHS {
                if distance <= 256 {
                    test_copy_with(copy_match_avx2, 256, distance, length);
                }
            }
        }
    }

    /// Directly test the AVX-512 implementation if available.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx512_matches_reference() {
        if detect_simd_level() < SimdLevel::Avx512 {
            return;
        }
        for distance in DISTANCES {
            for length in LENGTHS {
                if distance <= 256 {
                    test_copy_with(copy_match_avx512, 256, distance, length);
                }
            }
        }
    }
}
