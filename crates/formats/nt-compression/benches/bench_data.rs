//! Deterministic data generators shared across benchmarks (no rand dependency).

extern crate alloc;

use alloc::vec::Vec;

#[must_use]
/// Return `n` zero bytes for highly compressible benchmark input.
pub fn zeros(n: usize) -> Vec<u8> {
    alloc::vec![0u8; n]
}

#[must_use]
/// Return deterministic input with compressible and irregular halves.
pub fn mixed(n: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; n];
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = if i < n / 2 {
            (i % 64).to_le_bytes()[0]
        } else {
            ((i * 7 + 13) % 251).to_le_bytes()[0]
        };
    }
    buf
}

#[must_use]
/// Return deterministic pseudo-random benchmark input.
pub fn random_ish(n: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; n];
    for (i, byte) in buf.iter_mut().enumerate() {
        let index = i.to_le_bytes();
        let mixed =
            u32::from_le_bytes([index[0], index[1], index[2], index[3]]).wrapping_mul(0x9E37_79B9);
        *byte = mixed.to_be_bytes()[0];
    }
    buf
}
