//! Directory name hash algorithms for ext htree lookups.
//!
//! Implements legacy, half-MD4, and TEA hash algorithms in both
//! signed and unsigned variants (hash versions 0-5).

/// Hash result: major hash for root-level tree navigation,
/// minor hash for interior-node navigation in multi-level trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DxHash {
    pub major: u32,
    pub minor: u32,
}

/// The 32-bit htree EOF sentinel value.
const HTREE_EOF_32BIT: u32 = 0x7FFF_FFFF;

/// Apply the kernel's final hash normalization.
///
/// Clears the lowest bit (to reserve odd values for htree internal
/// use) and avoids the EOF sentinel value.
fn finalize_hash(major: u32, minor: u32) -> DxHash {
    let mut hash = major & !1;
    if hash == (HTREE_EOF_32BIT << 1) {
        hash = (HTREE_EOF_32BIT - 1) << 1;
    }
    DxHash { major: hash, minor }
}

/// Compute the directory entry hash for the given name and hash version.
///
/// Returns `None` for unsupported hash versions (e.g., 6 = SipHash).
pub(crate) fn dx_hash(name: &[u8], hash_version: u8, seed: &[u32; 4]) -> Option<DxHash> {
    match hash_version {
        0 => Some(legacy_hash(name, true)),
        1 => Some(half_md4_hash(name, seed, true)),
        2 => Some(tea_hash(name, seed, true)),
        3 => Some(legacy_hash(name, false)),
        4 => Some(half_md4_hash(name, seed, false)),
        5 => Some(tea_hash(name, seed, false)),
        _ => None,
    }
}

/// Variant of `dx_hash` that supports hash version 6 (SipHash-2-4) when
/// a 16-byte directory hash key is supplied. Returns `None` for v6 with
/// no key (caller falls back to sequential scan).
pub(crate) fn dx_hash_with_dirkey(
    name: &[u8],
    hash_version: u8,
    seed: &[u32; 4],
    dirkey: Option<&[u8; 16]>,
) -> Option<DxHash> {
    if hash_version == 6 {
        let key = dirkey?;
        #[cfg(feature = "fscrypt")]
        {
            let (major, minor) = crate::fscrypt::siphash24(key, name);
            return Some(finalize_hash(major, minor));
        }
        #[cfg(not(feature = "fscrypt"))]
        {
            let _ = key;
            return None;
        }
    }
    dx_hash(name, hash_version, seed)
}

/// Pack name bytes into u32 words using the kernel's str2hashbuf algorithm.
///
/// Mirrors Linux `str2hashbuf_signed` / `str2hashbuf_unsigned` exactly:
/// - Bytes are packed big-endian within each word via shift-and-add
/// - `pad` value (name length replicated across all 4 byte lanes) is
///   used as the initial accumulator and to fill remaining words
/// - Signed variants sign-extend bytes >= 0x80 before addition
///   (this is intentional kernel behavior, not a bug)
///
/// `N` is the number of u32 words (8 for half-MD4, 4 for TEA).
fn str2hashbuf<const N: usize>(name: &[u8], signed: bool) -> [u32; N] {
    let len = name.len();
    let pad = (len as u32) | ((len as u32) << 8);
    let pad = pad | (pad << 16);

    let mut buf = [0u32; N];
    let max_bytes = N * 4;
    let process_len = len.min(max_bytes);

    let mut val = pad;
    let mut word_idx = 0;
    for (i, &byte) in name.iter().enumerate().take(process_len) {
        let byte_val = if signed {
            byte as i8 as i32 as u32
        } else {
            u32::from(byte)
        };
        val = byte_val.wrapping_add(val << 8);
        if i % 4 == 3 {
            buf[word_idx] = val;
            word_idx += 1;
            val = pad;
        }
    }
    // Flush partial word
    if word_idx < N {
        buf[word_idx] = val;
        word_idx += 1;
    }
    // Fill remaining with pad
    for slot in &mut buf[word_idx..] {
        *slot = pad;
    }
    buf
}

// --- Legacy hash ---

fn legacy_hash(name: &[u8], signed: bool) -> DxHash {
    let mut hash: u32 = 0x12A3FE2D;
    let mut minor: u32 = 0x37ABE8F9;

    for &b in name {
        let val = if signed { b as i8 as u32 } else { u32::from(b) };
        hash = hash.rotate_left(7);
        hash ^= val;
        minor = minor.wrapping_mul(hash);
    }

    finalize_hash(hash, minor)
}

// --- Half-MD4 hash ---

/// Half-MD4 processes 8 words (32 bytes) per chunk.
const HALF_MD4_WORDS: usize = 8;

fn half_md4_hash(name: &[u8], seed: &[u32; 4], signed: bool) -> DxHash {
    let mut buf = *seed;

    // Process name in 32-byte chunks, matching kernel ext4_htree_hash loop
    let mut remaining = name;
    loop {
        let input: [u32; HALF_MD4_WORDS] = str2hashbuf(remaining, signed);
        half_md4_transform(&mut buf, &input);
        if remaining.len() <= HALF_MD4_WORDS * 4 {
            break;
        }
        remaining = &remaining[HALF_MD4_WORDS * 4..];
    }

    // Kernel: hash = buf[1], minor_hash = buf[2]
    finalize_hash(buf[1], buf[2])
}

/// Half-MD4 compression function matching the kernel's `half_md4_transform`.
///
/// Modifies `buf` in place: after computing the three MD4 rounds with
/// local copies, adds the round outputs back into `buf[0..4]`.
fn half_md4_transform(buf: &mut [u32; 4], input: &[u32; 8]) {
    let (mut a, mut b, mut c, mut d) = (buf[0], buf[1], buf[2], buf[3]);

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    fn round1(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
        *a = a.wrapping_add(f(b, c, d)).wrapping_add(x);
        *a = a.rotate_left(s);
    }

    // Round 1 (F function, K1=0)
    round1(&mut a, b, c, d, input[0], 3);
    round1(&mut d, a, b, c, input[1], 7);
    round1(&mut c, d, a, b, input[2], 11);
    round1(&mut b, c, d, a, input[3], 19);
    round1(&mut a, b, c, d, input[4], 3);
    round1(&mut d, a, b, c, input[5], 7);
    round1(&mut c, d, a, b, input[6], 11);
    round1(&mut b, c, d, a, input[7], 19);

    const K2: u32 = 0x5A82_7999;
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    fn round2(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
        *a = a.wrapping_add(g(b, c, d)).wrapping_add(x).wrapping_add(K2);
        *a = a.rotate_left(s);
    }

    // Round 2 (G function)
    round2(&mut a, b, c, d, input[1], 3);
    round2(&mut d, a, b, c, input[3], 5);
    round2(&mut c, d, a, b, input[5], 9);
    round2(&mut b, c, d, a, input[7], 13);
    round2(&mut a, b, c, d, input[0], 3);
    round2(&mut d, a, b, c, input[2], 5);
    round2(&mut c, d, a, b, input[4], 9);
    round2(&mut b, c, d, a, input[6], 13);

    const K3: u32 = 0x6ED9_EBA1;
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
    fn round3(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
        *a = a.wrapping_add(h(b, c, d)).wrapping_add(x).wrapping_add(K3);
        *a = a.rotate_left(s);
    }

    // Round 3 (H function)
    round3(&mut a, b, c, d, input[3], 3);
    round3(&mut d, a, b, c, input[7], 9);
    round3(&mut c, d, a, b, input[2], 11);
    round3(&mut b, c, d, a, input[6], 15);
    round3(&mut a, b, c, d, input[1], 3);
    round3(&mut d, a, b, c, input[5], 9);
    round3(&mut c, d, a, b, input[0], 11);
    round3(&mut b, c, d, a, input[4], 15);

    // Add round output back into buf (Merkle-Damgard accumulation)
    buf[0] = buf[0].wrapping_add(a);
    buf[1] = buf[1].wrapping_add(b);
    buf[2] = buf[2].wrapping_add(c);
    buf[3] = buf[3].wrapping_add(d);
}

// --- TEA hash ---

/// TEA processes 4 words (16 bytes) per chunk.
const TEA_WORDS: usize = 4;

fn tea_hash(name: &[u8], seed: &[u32; 4], signed: bool) -> DxHash {
    let mut buf = *seed;

    // Process name in 16-byte chunks, matching kernel ext4_htree_hash loop
    let mut remaining = name;
    loop {
        let input: [u32; TEA_WORDS] = str2hashbuf(remaining, signed);
        tea_transform(&mut buf, &input);
        if remaining.len() <= TEA_WORDS * 4 {
            break;
        }
        remaining = &remaining[TEA_WORDS * 4..];
    }

    // Kernel: hash = buf[0], minor_hash = buf[1]
    finalize_hash(buf[0], buf[1])
}

/// TEA (Tiny Encryption Algorithm) compression function matching
/// the kernel's `TEA_transform`.
///
/// Uses `buf[0..2]` as the encrypted state and `input[0..4]` as the
/// key schedule. Adds the round output back into `buf[0]` and `buf[1]`.
fn tea_transform(buf: &mut [u32; 4], input: &[u32; 4]) {
    let mut sum: u32 = 0;
    const DELTA: u32 = 0x9E37_79B9;

    let mut b0 = buf[0];
    let mut b1 = buf[1];

    for _ in 0..16 {
        sum = sum.wrapping_add(DELTA);
        b0 = b0.wrapping_add(
            ((b1 << 4).wrapping_add(input[0]))
                ^ b1.wrapping_add(sum)
                ^ ((b1 >> 5).wrapping_add(input[1])),
        );
        b1 = b1.wrapping_add(
            ((b0 << 4).wrapping_add(input[2]))
                ^ b0.wrapping_add(sum)
                ^ ((b0 >> 5).wrapping_add(input[3])),
        );
    }

    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_unsigned_empty_name() {
        let h = dx_hash(b"", 3, &[0; 4]).unwrap();
        assert_ne!(h.major, 0);
    }

    #[test]
    fn half_md4_unsigned_hello() {
        // Hash version 4 is the modern default
        let seed = [0x776bcb4a, 0xb042dd57, 0x70fd0fae, 0xda77dd04];
        let h = dx_hash(b"hello.txt", 4, &seed).unwrap();
        assert_ne!(h.major, 0);
        // Verify determinism
        let h2 = dx_hash(b"hello.txt", 4, &seed).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn tea_unsigned_hello() {
        let seed = [0x776bcb4a, 0xb042dd57, 0x70fd0fae, 0xda77dd04];
        let h = dx_hash(b"hello.txt", 5, &seed).unwrap();
        assert_ne!(h.major, 0);
    }

    #[test]
    fn signed_vs_unsigned_differ_for_high_bytes() {
        let seed = [1, 2, 3, 4];
        let name = b"\x80\x81\x82";
        let signed = dx_hash(name, 1, &seed).unwrap();
        let unsigned = dx_hash(name, 4, &seed).unwrap();
        assert_ne!(signed, unsigned);
    }

    #[test]
    fn siphash_returns_none() {
        let h = dx_hash(b"test", 6, &[0; 4]);
        assert!(h.is_none());
        // dx_hash_with_dirkey also returns None for v6 with no key.
        let h2 = dx_hash_with_dirkey(b"test", 6, &[0; 4], None);
        assert!(h2.is_none());
    }

    #[cfg(feature = "fscrypt")]
    #[test]
    fn siphash_v6_with_key_returns_finalized_hash() {
        let key = [0x42u8; 16];
        let h = dx_hash_with_dirkey(b"hello.txt", 6, &[0; 4], Some(&key)).unwrap();
        // major must have lowest bit cleared
        assert_eq!(h.major & 1, 0);
    }

    #[test]
    fn unknown_version_returns_none() {
        let h = dx_hash(b"test", 255, &[0; 4]);
        assert!(h.is_none());
    }

    #[test]
    fn major_hash_clears_lowest_bit() {
        let seed = [0xFFFF_FFFF; 4];
        for version in 0..6 {
            let h = dx_hash(b"test_file_name", version, &seed).unwrap();
            assert_eq!(h.major & 1, 0, "version {version} lowest bit set");
        }
    }

    #[test]
    fn hash_matches_across_versions() {
        // Verify that different names produce different hashes
        let seed = [0x25751c6, 0x934b0a16, 0xeaf441a3, 0xd6121f4c];
        let h1 = dx_hash(b"hello.txt", 1, &seed).unwrap();
        let h2 = dx_hash(b"subdir", 1, &seed).unwrap();
        assert_ne!(h1.major, h2.major);
    }

    #[test]
    fn ext3_hash_matches_debugfs() {
        // Verified against: debugfs -R "htree_dump htree_dir" ext3.img
        // file_250.txt -> 0x44497e98-7e9ef89c
        // file_289.txt -> 0x009dffa0-660803cd
        let seed = [0x7cd987e3, 0x2847d72f, 0x9417aba8, 0xdaa3d8cc];
        let h250 = dx_hash(b"file_250.txt", 1, &seed).unwrap();
        assert_eq!(h250.major, 0x44497e98, "file_250.txt major");
        assert_eq!(h250.minor, 0x7e9ef89c, "file_250.txt minor");

        let h289 = dx_hash(b"file_289.txt", 1, &seed).unwrap();
        assert_eq!(h289.major, 0x009dffa0, "file_289.txt major");
        assert_eq!(h289.minor, 0x660803cd, "file_289.txt minor");
    }

    #[test]
    fn ext4_hash_matches_debugfs() {
        // Verified against: debugfs -R "htree_dump htree_dir" ext4.img
        // file_250.txt -> 0x1ceb8490-e654559d
        let seed = [0x1ec90553, 0x6b4bd7df, 0x2a8ef4a0, 0xba52e666];
        let h = dx_hash(b"file_250.txt", 1, &seed).unwrap();
        assert_eq!(h.major, 0x1ceb8490, "file_250.txt ext4 major");
        assert_eq!(h.minor, 0xe654559d, "file_250.txt ext4 minor");
    }
}
