//! SIMD capability detection.
//!
//! Provides a [`SimdLevel`] enum representing the widest SIMD tier
//! available on the current CPU.  Detection is cached after the first
//! call to [`SimdLevel::detect()`].
//!
//! With the `std` feature enabled, detection uses runtime CPUID
//! probing via [`is_x86_feature_detected!`] to report AVX-512, AVX2,
//! or SSE2 on `x86_64`.  Without `std`, detection is compile-time only:
//! `x86_64` maps to SSE2, everything else to Scalar.

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

/// Detected SIMD instruction-set level.
///
/// Variants are ordered by width — `Scalar < Sse2 < Avx2` — so
/// callers can use comparison operators to check minimum capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum SimdLevel {
    /// No SIMD — scalar code only.
    Scalar = 0,
    /// SSE2 (128-bit). Baseline on `x86_64`.
    Sse2 = 1,
    /// AVX2 (256-bit). Requires Haswell (2013) or later.
    Avx2 = 2,
    /// AVX-512 Foundation (512-bit). Requires Skylake-SP / Zen 4 or later.
    Avx512 = 3,
}

/// Sentinel stored in [`CACHED`] before the first detection.
const UNINIT: u8 = 0xFF;

/// Cached detection result.
static CACHED: AtomicU8 = AtomicU8::new(UNINIT);

impl SimdLevel {
    /// Return the best SIMD level supported by the current CPU.
    ///
    /// The first call performs detection; subsequent calls return the
    /// cached result via a single `Relaxed` atomic load.
    ///
    /// With the `std` feature (default), `x86_64` detection uses runtime
    /// CPUID probing and can return `Avx512`, `Avx2`, or `Sse2`.
    /// Without `std`, `x86_64` conservatively returns `Sse2`.
    /// Non-x86 architectures always return `Scalar`.
    #[inline]
    pub fn detect() -> Self {
        let v = CACHED.load(Ordering::Relaxed);
        if v == UNINIT {
            Self::detect_cold()
        } else {
            Self::from_u8(v)
        }
    }

    #[cold]
    fn detect_cold() -> Self {
        let level = Self::probe();
        CACHED.store(level as u8, Ordering::Relaxed);
        level
    }

    /// Runtime probe using CPUID on `x86_64` with `std`.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    fn probe() -> Self {
        if is_x86_feature_detected!("avx512f") {
            SimdLevel::Avx512
        } else if is_x86_feature_detected!("avx2") {
            SimdLevel::Avx2
        } else {
            SimdLevel::Sse2
        }
    }

    /// Compile-time probe: `x86_64` guarantees `SSE2` but without `std`
    /// we cannot do runtime `CPUID` checks.
    #[cfg(all(target_arch = "x86_64", not(feature = "std")))]
    #[cfg_attr(test, mutants::skip)] // cfg-gated to no_std builds; std test harness cannot exercise it.
    fn probe() -> Self {
        SimdLevel::Sse2
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[cfg_attr(test, mutants::skip)] // cfg-gated to non-x86_64 hosts; not exercisable on x86_64 CI.
    fn probe() -> Self {
        SimdLevel::Scalar
    }

    /// Convert a raw `u8` to a `SimdLevel`.
    ///
    /// Unknown values map to `Scalar` (safe conservative fallback). `0` is
    /// handled by the fallback arm — listing it explicitly would be an
    /// equivalent mutant for cargo-mutants.
    #[inline]
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Sse2,
            2 => Self::Avx2,
            3 => Self::Avx512,
            _ => Self::Scalar,
        }
    }
}

impl fmt::Display for SimdLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scalar => f.write_str("Scalar"),
            Self::Sse2 => f.write_str("SSE2"),
            Self::Avx2 => f.write_str("AVX2"),
            Self::Avx512 => f.write_str("AVX-512"),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::format;

    use super::*;

    #[test]
    fn detect_returns_valid_level() {
        let level = SimdLevel::detect();
        #[cfg(target_arch = "x86_64")]
        assert!(level >= SimdLevel::Sse2);
        assert!(matches!(
            level,
            SimdLevel::Scalar | SimdLevel::Sse2 | SimdLevel::Avx2 | SimdLevel::Avx512
        ));
    }

    #[test]
    fn detect_is_idempotent() {
        let a = SimdLevel::detect();
        let b = SimdLevel::detect();
        assert_eq!(a, b);
    }

    #[test]
    fn ordering() {
        assert!(SimdLevel::Scalar < SimdLevel::Sse2);
        assert!(SimdLevel::Sse2 < SimdLevel::Avx2);
        assert!(SimdLevel::Avx2 < SimdLevel::Avx512);
    }

    #[test]
    fn display() {
        assert_eq!(format!("{}", SimdLevel::Scalar), "Scalar");
        assert_eq!(format!("{}", SimdLevel::Sse2), "SSE2");
        assert_eq!(format!("{}", SimdLevel::Avx2), "AVX2");
        assert_eq!(format!("{}", SimdLevel::Avx512), "AVX-512");
    }

    #[test]
    fn from_u8_roundtrip() {
        for &level in &[
            SimdLevel::Scalar,
            SimdLevel::Sse2,
            SimdLevel::Avx2,
            SimdLevel::Avx512,
        ] {
            assert_eq!(SimdLevel::from_u8(level as u8), level);
        }
    }

    #[test]
    fn from_u8_unknown_is_scalar() {
        assert_eq!(SimdLevel::from_u8(42), SimdLevel::Scalar);
        assert_eq!(SimdLevel::from_u8(255), SimdLevel::Scalar);
    }
}
