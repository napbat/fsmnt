//! Fletcher-64 checksum used by every APFS container-layer object.
//!
//! Each object begins with an [`obj_phys_t`](crate::object) whose first eight
//! bytes (`o_cksum`) hold the Fletcher-64 checksum of the rest of the block.

use crate::error::{ApfsError, Result};

/// Number of bytes occupied by an object checksum (`MAX_CKSUM_SIZE`).
///
/// Apple File System Reference, `02-objects.md`: `#define MAX_CKSUM_SIZE 8`.
pub const MAX_CKSUM_SIZE: usize = 8;

/// The modulus used by the APFS Fletcher-64 fold step.
const FLETCHER_MOD: u64 = 0xFFFF_FFFF;

/// Computes the APFS Fletcher-64 checksum over `data`.
///
/// `data` is treated as a sequence of little-endian `u32` words; any trailing
/// bytes that do not complete a word are ignored, matching the kernel driver's
/// `len >> 2` word count.
///
/// Mirrors `apfs_fletcher64` in `linux-apfs-rw/object.c`:
/// ```text
/// sum1 += word; sum2 += sum1;
/// c1 = sum1 + sum2; c1 = 0xFFFFFFFF - (c1 % 0xFFFFFFFF)
/// c2 = sum1 + c1;   c2 = 0xFFFFFFFF - (c2 % 0xFFFFFFFF)
/// return (c2 << 32) | c1
/// ```
///
/// Each accumulator is reduced modulo `FLETCHER_MOD` every iteration. This
/// keeps `sum1`/`sum2` bounded so the loop cannot overflow `u64` on a large
/// buffer, and — because the final fold reduces modulo the same value — yields
/// a result identical to the unreduced reference for every buffer the
/// reference can sum without overflowing.
#[must_use]
pub fn fletcher64(data: &[u8]) -> u64 {
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;

    for word in data.chunks_exact(4) {
        // `chunks_exact(4)` guarantees a 4-byte slice.
        let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        sum1 = reduce(sum1 + u64::from(value));
        sum2 = reduce(sum2 + sum1);
    }

    let c1 = FLETCHER_MOD - ((sum1 + sum2) % FLETCHER_MOD);
    let c2 = FLETCHER_MOD - ((sum1 + c1) % FLETCHER_MOD);
    combine_halves(c2, c1)
}

/// Reduces an in-loop accumulator modulo [`FLETCHER_MOD`].
///
/// Isolated so `#[cfg_attr(test, mutants::skip)]` covers the equivalent
/// `% → +` mutation: replacing `%` with `+` here adds `FLETCHER_MOD` to the
/// accumulator each iteration, but every downstream computation also reduces
/// modulo `FLETCHER_MOD` — so any extra multiple of `FLETCHER_MOD` carried in
/// `sum1` or `sum2` is absorbed by the final-step `% FLETCHER_MOD`
/// reductions, leaving the checksum unchanged. The remaining operator
/// mutations on this single expression (`-`, `*`, `/`) are likewise
/// suppressed but would change the output; they are caught indirectly by
/// the absolute-value tests on `fletcher64`, which assert exact computed
/// checksums for non-zero, multi-word inputs.
#[cfg_attr(test, mutants::skip)]
fn reduce(x: u64) -> u64 {
    x % FLETCHER_MOD
}

/// Packs the two 32-bit halves of the checksum into a single `u64`.
///
/// Isolated so `#[cfg_attr(test, mutants::skip)]` covers the equivalent
/// `| → ^` mutation: `c1` is the result of `FLETCHER_MOD - …` where
/// `FLETCHER_MOD == 0xFFFF_FFFF`, so `c1` fits in the low 32 bits; `c2 << 32`
/// occupies only the high 32 bits. The two halves are bit-disjoint, so `|`
/// and `^` produce identical results.
#[cfg_attr(test, mutants::skip)]
fn combine_halves(c2: u64, c1: u64) -> u64 {
    (c2 << 32) | c1
}

/// Verifies an object block against its stored Fletcher-64 checksum.
///
/// `block` is the whole object block: the first [`MAX_CKSUM_SIZE`] bytes are
/// the stored `o_cksum`, and the checksum is computed over everything after
/// it. Mirrors `apfs_multiblock_verify_csum` in `linux-apfs-rw/object.c`.
///
/// Returns `false` — rather than panicking — when `block` is shorter than the
/// checksum field or its length past the checksum field is not a multiple of
/// four, since neither can come from a valid APFS block.
#[must_use]
pub fn verify_block(block: &[u8]) -> bool {
    if block.len() < MAX_CKSUM_SIZE {
        return false;
    }
    let (stored, body) = block.split_at(MAX_CKSUM_SIZE);
    if !body.len().is_multiple_of(4) {
        return false;
    }
    let stored = u64::from_le_bytes([
        stored[0], stored[1], stored[2], stored[3], stored[4], stored[5], stored[6], stored[7],
    ]);
    stored == fletcher64(body)
}

/// Verifies an object block, returning a typed error on mismatch.
///
/// `block_addr` is the physical block address, recorded in the error so a
/// torn or tampered object can be pinpointed.
pub fn require_valid_block(block: &[u8], block_addr: u64) -> Result<()> {
    if verify_block(block) {
        Ok(())
    } else {
        Err(ApfsError::ChecksumMismatch { block: block_addr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fletcher64_of_zeroes_is_all_ones() {
        // sum1 = sum2 = 0 -> c1 = 0xFFFFFFFF - 0 = 0xFFFFFFFF;
        // c2 = 0xFFFFFFFF - (0xFFFFFFFF % 0xFFFFFFFF) = 0xFFFFFFFF.
        assert_eq!(fletcher64(&[0u8; 64]), 0xFFFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn fletcher64_does_not_overflow_on_a_large_buffer() {
        // ~512 KiB of all-ones words: enough to overflow an unreduced u64
        // accumulator. In-loop modular reduction keeps it well-defined.
        let data = vec![0xFFu8; 512 * 1024];
        let csum = fletcher64(&data);
        // A self-consistent block built from the same body must still verify.
        let mut block = vec![0u8; MAX_CKSUM_SIZE + data.len()];
        block[MAX_CKSUM_SIZE..].copy_from_slice(&data);
        let body_csum = fletcher64(&block[MAX_CKSUM_SIZE..]);
        block[..MAX_CKSUM_SIZE].copy_from_slice(&body_csum.to_le_bytes());
        assert!(verify_block(&block));
        let _ = csum;
    }

    #[test]
    fn fletcher64_ignores_trailing_partial_word() {
        // Two extra bytes that do not complete a word must not affect the sum.
        let four = [1u8, 2, 3, 4];
        let six = [1u8, 2, 3, 4, 5, 6];
        assert_eq!(fletcher64(&four), fletcher64(&six));
    }

    #[test]
    fn fletcher64_matches_reference_for_a_single_word() {
        // One little-endian word 0x04030201 produces sum1 = sum2 = 0x04030201;
        // c1 = MOD - 0x08060402 = 0xF7F9FBFD;
        // c2 = MOD - (0x04030201 + 0xF7F9FBFD) % MOD = MOD - 0xFBFCFDFE % MOD
        //    = MOD - 0xFBFCFDFE = 0x04030201;
        // result = (0x04030201 << 32) | 0xF7F9FBFD = 0x04030201_F7F9FBFD.
        assert_eq!(fletcher64(&[1u8, 2, 3, 4]), 0x0403_0201_F7F9_FBFD);
    }

    #[test]
    fn fletcher64_matches_reference_for_two_words() {
        // Multi-word input with distinct nonzero words forces both `sum1` and
        // `sum2` to advance, so every operator in the final fold contributes
        // distinctively. Locks down: `+ → *` and `% → /` on the inner loop,
        // `- → +`, `+ → *`, `% → /` on the c1/c2 folds, and `| → ^` on the
        // half-combine (the last is suppressed via `combine_halves`, but the
        // assertion remains a regression guard).
        assert_eq!(
            fletcher64(&[1u8, 2, 3, 4, 5, 6, 7, 8]),
            0x100D_0A07_E3E8_EDF2,
        );
    }

    #[test]
    fn verify_block_accepts_a_self_consistent_block() {
        let mut block = vec![0u8; 64];
        for (i, byte) in block[MAX_CKSUM_SIZE..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let csum = fletcher64(&block[MAX_CKSUM_SIZE..]);
        block[..MAX_CKSUM_SIZE].copy_from_slice(&csum.to_le_bytes());
        assert!(verify_block(&block));
    }

    #[test]
    fn verify_block_rejects_a_corrupt_body_byte() {
        let mut block = vec![0u8; 32];
        block[MAX_CKSUM_SIZE..].fill(0xAB);
        let csum = fletcher64(&block[MAX_CKSUM_SIZE..]);
        block[..MAX_CKSUM_SIZE].copy_from_slice(&csum.to_le_bytes());
        assert!(verify_block(&block));

        block[20] ^= 0x01;
        assert!(!verify_block(&block));
    }

    #[test]
    fn verify_block_rejects_a_corrupt_checksum_byte() {
        let mut block = vec![0u8; 32];
        block[MAX_CKSUM_SIZE..].fill(0xCD);
        let csum = fletcher64(&block[MAX_CKSUM_SIZE..]);
        block[..MAX_CKSUM_SIZE].copy_from_slice(&csum.to_le_bytes());

        block[0] ^= 0x01;
        assert!(!verify_block(&block));
    }

    #[test]
    fn verify_block_rejects_undersized_or_misaligned_input() {
        assert!(!verify_block(&[0u8; 4]));
        // 8-byte cksum + 6 body bytes: body length is not a multiple of 4.
        assert!(!verify_block(&[0u8; 14]));
    }

    #[test]
    fn verify_block_accepts_a_block_with_an_empty_body() {
        // An exactly-eight-byte block has a zero-length body, whose Fletcher-64
        // checksum is `0xFFFF_FFFF_FFFF_FFFF`. A block of eight `0xFF` bytes
        // therefore stores its own (empty-body) checksum and must verify.
        // Pins down the `block.len() < MAX_CKSUM_SIZE` boundary: replacing
        // `<` with `<=` would reject this minimum-valid block.
        let block = [0xFFu8; MAX_CKSUM_SIZE];
        assert!(verify_block(&block));
    }

    #[test]
    fn require_valid_block_reports_the_block_address() {
        let mut block = vec![0u8; 32];
        block[MAX_CKSUM_SIZE..].fill(0x5A);
        let csum = fletcher64(&block[MAX_CKSUM_SIZE..]);
        block[..MAX_CKSUM_SIZE].copy_from_slice(&csum.to_le_bytes());
        assert!(require_valid_block(&block, 99).is_ok());

        block[16] ^= 0xFF;
        match require_valid_block(&block, 99) {
            Err(crate::error::ApfsError::ChecksumMismatch { block }) => assert_eq!(block, 99),
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }
}
