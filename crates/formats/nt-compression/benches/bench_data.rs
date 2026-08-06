//! Deterministic data generators shared across benchmarks (no rand dependency).

extern crate alloc;

use alloc::vec::Vec;

pub fn zeros(n: usize) -> Vec<u8> {
    alloc::vec![0u8; n]
}

pub fn mixed(n: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; n];
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = if i < n / 2 {
            (i % 64) as u8
        } else {
            ((i * 7 + 13) % 251) as u8
        };
    }
    buf
}

pub fn random_ish(n: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; n];
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = ((i as u32).wrapping_mul(0x9E37_79B9) >> 24) as u8;
    }
    buf
}
