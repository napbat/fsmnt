//! Shared LZ77 hash-chain match finder for compression.
//!
//! Used by XPRESS, XPRESS Huffman, and LZX compressors.
//! LZNT1 has its own per-chunk matching scheme.
#![allow(unsafe_code)]

use alloc::vec;
use alloc::vec::Vec;

/// An LZ77 match: backward offset and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Match {
    pub offset: u32,
    pub length: u32,
}

/// A token in the LZ77 output: either a literal byte or a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Token {
    Literal(u8),
    Match(Match),
}

/// Configuration for the match finder.
#[derive(Clone, Debug)]
pub(crate) struct MatchFinderConfig {
    pub window_size: u32,
    pub min_match_len: u32,
    pub max_match_len: u32,
    pub max_chain_len: u32,
}

/// Hash-chain match finder.
///
/// Uses a 3-byte multiply-shift hash to index into a head table.
/// Each position chains to the previous position with the same hash
/// via the `prev` table. Uses lazy matching: before committing to a
/// match at position P, checks if P+1 gives a longer match.
pub(crate) struct MatchFinder {
    config: MatchFinderConfig,
    /// head[hash] = most recent position with this hash + 1
    /// (0 means no entry).
    head: Vec<u32>,
    /// prev[pos % window_size] = previous position with same hash + 1.
    prev: Vec<u32>,
}

const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;

/// 3-byte multiply-shift hash.
fn hash3(data: &[u8], pos: usize) -> usize {
    let b0 = data[pos] as u32;
    let b1 = data[pos + 1] as u32;
    let b2 = data[pos + 2] as u32;
    let h = (b0 | (b1 << 8) | (b2 << 16)).wrapping_mul(0x9E37_79B1);
    (h >> (32 - HASH_BITS)) as usize
}

impl MatchFinder {
    /// Create a match finder with standard settings.
    ///
    /// Sets `min_match_len` to 3 (the minimum required by the
    /// 3-byte hash function).
    pub fn standard(window_size: u32, max_match_len: u32, max_chain_len: u32) -> Self {
        Self::new(MatchFinderConfig {
            window_size,
            min_match_len: 3,
            max_match_len,
            max_chain_len,
        })
    }

    /// Create a new match finder for data of the given length.
    pub fn new(config: MatchFinderConfig) -> Self {
        let window = config.window_size as usize;
        Self {
            config,
            head: vec![0u32; HASH_SIZE],
            prev: vec![0u32; window],
        }
    }

    /// Reset the hash tables without reallocating. Allows reusing
    /// the same `MatchFinder` across multiple blocks.
    ///
    /// Only `head` needs clearing: stale `prev` entries are unreachable
    /// because every hash chain starts from `head[h]` (zeroed here).
    /// Each `update()` overwrites its `prev` slot with the current
    /// `head[h]` value, so chains always terminate at 0 without ever
    /// following stale entries from previous blocks.
    pub fn reset(&mut self) {
        self.head.fill(0);
    }

    /// Find the best match at `pos` in `data`, looking backward
    /// within the sliding window.
    pub fn find_match(&self, data: &[u8], pos: usize) -> Option<Match> {
        if pos + (self.config.min_match_len as usize) > data.len() {
            return None;
        }
        if data.len() - pos < 3 {
            return None;
        }

        let h = hash3(data, pos);
        let mut chain_pos = self.head[h];
        let mut best_len = self.config.min_match_len - 1;
        let mut best_offset = 0u32;
        let mut chain_count = 0u32;
        let window = self.config.window_size as usize;

        while chain_pos > 0 && chain_count < self.config.max_chain_len {
            let candidate = (chain_pos - 1) as usize;
            let dist = pos - candidate;
            if dist > window || candidate >= pos {
                break;
            }

            // Quick check: compare the byte just past current best
            let max_len = self.config.max_match_len.min((data.len() - pos) as u32);
            if best_len < max_len
                && data[candidate + best_len as usize] == data[pos + best_len as usize]
            {
                // SAFETY: candidate < pos, max_len = min(config.max_match_len,
                // data.len() - pos), so candidate + max_len <= data.len()
                // and pos + max_len <= data.len().
                let len = unsafe {
                    crate::raw::match_length_unchecked(data, candidate, pos, max_len as usize)
                };
                if len > best_len {
                    best_len = len;
                    best_offset = dist as u32;
                    if best_len == max_len {
                        break;
                    }
                }
            }

            chain_pos = self.prev[candidate % window];
            chain_count += 1;
        }

        if best_len >= self.config.min_match_len {
            Some(Match {
                offset: best_offset,
                length: best_len,
            })
        } else {
            None
        }
    }

    /// Insert `pos` into the hash chain (call after processing
    /// position `pos`).
    #[inline]
    pub fn update(&mut self, data: &[u8], pos: usize) {
        if pos + 3 > data.len() {
            return;
        }
        let h = hash3(data, pos);
        let window = self.config.window_size as usize;
        self.prev[pos % window] = self.head[h];
        self.head[h] = (pos + 1) as u32;
    }

    /// Tokenize `data` into a sequence of literals and matches.
    ///
    /// Uses lazy matching: before committing to a match at position P,
    /// checks if P+1 gives a longer match. If so, emits P as a literal
    /// and uses the longer match instead.
    pub fn tokenize(&mut self, data: &[u8]) -> Vec<Token> {
        let mut tokens = Vec::with_capacity(data.len());
        let mut pos = 0;
        let mut pending: Option<(usize, Match)> = None;

        while pos < data.len() {
            let current_match = self.find_match(data, pos);

            if let Some((pending_pos, pending_match)) = pending.take() {
                // We have a pending match from the previous position.
                // Compare with the current match at pos (= pending_pos+1).
                let use_pending = match current_match {
                    Some(cur) => pending_match.length >= cur.length,
                    None => true,
                };

                if use_pending {
                    // Commit the pending match.
                    // Update hash for first 2 positions of the match
                    // (skip the rest for speed).
                    self.update(data, pending_pos);
                    if pending_match.length as usize >= 2 {
                        self.update(data, pending_pos + 1);
                    }
                    // Skip remaining positions without hashing.
                    tokens.push(Token::Match(pending_match));
                    pos = pending_pos + pending_match.length as usize;
                    continue;
                }
                // Current match is longer — emit pending_pos as literal,
                // and re-evaluate current match.
                self.update(data, pending_pos);
                tokens.push(Token::Literal(data[pending_pos]));
                // Fall through to process current_match at pos.
            }

            if let Some(m) = current_match {
                // Defer this match: check pos+1 for a longer one.
                pending = Some((pos, m));
                pos += 1;
            } else {
                self.update(data, pos);
                tokens.push(Token::Literal(data[pos]));
                pos += 1;
            }
        }

        // Flush any pending match at the end.
        if let Some((pending_pos, pending_match)) = pending {
            self.update(data, pending_pos);
            if pending_match.length as usize >= 2 {
                self.update(data, pending_pos + 1);
            }
            tokens.push(Token::Match(pending_match));
        }

        tokens
    }

    /// Tokenize using a streaming callback instead of building a
    /// `Vec<Token>`. Avoids the allocation when the caller can
    /// process tokens incrementally.
    pub fn tokenize_streaming<F: FnMut(Token)>(&mut self, data: &[u8], mut emit: F) {
        let mut pos = 0;
        let mut pending: Option<(usize, Match)> = None;

        while pos < data.len() {
            let current_match = self.find_match(data, pos);

            if let Some((pending_pos, pending_match)) = pending.take() {
                let use_pending = match current_match {
                    Some(cur) => pending_match.length >= cur.length,
                    None => true,
                };

                if use_pending {
                    self.update(data, pending_pos);
                    if pending_match.length as usize >= 2 {
                        self.update(data, pending_pos + 1);
                    }
                    emit(Token::Match(pending_match));
                    pos = pending_pos + pending_match.length as usize;
                    continue;
                }
                self.update(data, pending_pos);
                emit(Token::Literal(data[pending_pos]));
            }

            if let Some(m) = current_match {
                pending = Some((pos, m));
                pos += 1;
            } else {
                self.update(data, pos);
                emit(Token::Literal(data[pos]));
                pos += 1;
            }
        }

        if let Some((pending_pos, pending_match)) = pending {
            self.update(data, pending_pos);
            if pending_match.length as usize >= 2 {
                self.update(data, pending_pos + 1);
            }
            emit(Token::Match(pending_match));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> MatchFinderConfig {
        MatchFinderConfig {
            window_size: 8192,
            min_match_len: 3,
            max_match_len: 65535,
            max_chain_len: 128,
        }
    }

    #[test]
    fn all_literals() {
        let data = b"abcdefghij";
        let mut finder = MatchFinder::new(default_config());
        let tokens = finder.tokenize(data);
        for (i, token) in tokens.iter().enumerate() {
            assert_eq!(*token, Token::Literal(data[i]), "token {i}");
        }
    }

    #[test]
    fn repeat_detection() {
        let data = b"abcabcabc";
        let mut finder = MatchFinder::new(default_config());
        let tokens = finder.tokenize(data);

        // First 3 bytes: literals
        assert_eq!(tokens[0], Token::Literal(b'a'));
        assert_eq!(tokens[1], Token::Literal(b'b'));
        assert_eq!(tokens[2], Token::Literal(b'c'));
        // Rest should be a match
        let has_match = tokens[3..].iter().any(|t| matches!(t, Token::Match(_)));
        assert!(has_match, "expected match after first abc");
    }

    #[test]
    fn overlapping_match() {
        // "aaaaaa" — displacement=1, repeating single byte
        let data = b"aaaaaaaaa";
        let mut finder = MatchFinder::new(default_config());
        let tokens = finder.tokenize(data);

        // Should have literal 'a' then a match with offset=1
        assert_eq!(tokens[0], Token::Literal(b'a'));
        // Due to min_match_len=3, the 2nd and 3rd 'a' are literals,
        // then a match picks up the rest.
        let match_tokens: Vec<_> = tokens
            .iter()
            .filter(|t| matches!(t, Token::Match(_)))
            .collect();
        assert!(!match_tokens.is_empty(), "expected at least one match");
    }

    #[test]
    fn window_size_limit() {
        let config = MatchFinderConfig {
            window_size: 4,
            min_match_len: 3,
            max_match_len: 65535,
            max_chain_len: 128,
        };
        // 3-byte pattern at position 0, repeated at position 8 (offset 8 > window 4).
        // Positions 3-7 use different bytes to avoid accidental matches.
        let data = [
            0xAA, 0xBB, 0xCC, // positions 0-2: pattern
            0x11, 0x22, 0x33, 0x44, 0x55, // positions 3-7: unique
            0xAA, 0xBB, 0xCC, // positions 8-10: repeat (offset 8 > window 4)
        ];
        let mut finder = MatchFinder::new(config);
        let tokens = finder.tokenize(&data);
        // The repeat at position 8 should NOT match because it's
        // beyond the window size of 4.
        for (i, token) in tokens.iter().enumerate() {
            assert!(
                matches!(token, Token::Literal(_)),
                "expected literal at token {i}, got match"
            );
        }
    }

    #[test]
    fn min_match_len_respected() {
        let config = MatchFinderConfig {
            window_size: 8192,
            min_match_len: 4,
            max_match_len: 65535,
            max_chain_len: 128,
        };
        // "abcabc" — a 3-byte repeat, but min_match_len=4
        let data = b"abcabc";
        let mut finder = MatchFinder::new(config);
        let tokens = finder.tokenize(data);
        // All literals because 3 < min_match_len
        assert!(
            tokens.iter().all(|t| matches!(t, Token::Literal(_))),
            "expected all literals with min_match_len=4"
        );
    }

    #[test]
    fn greedy_longest_match() {
        // "abcdabcdab" — at position 4, should match "abcdab" (len 6)
        // not just "abcd" (len 4).
        let data = b"abcdabcdab";
        let mut finder = MatchFinder::new(default_config());
        let tokens = finder.tokenize(data);

        let matches: Vec<_> = tokens
            .iter()
            .filter_map(|t| {
                if let Token::Match(m) = t {
                    Some(*m)
                } else {
                    None
                }
            })
            .collect();
        assert!(!matches.is_empty());
        // The match should capture at least 6 bytes
        assert!(
            matches[0].length >= 6,
            "expected greedy match of length >= 6"
        );
    }

    #[test]
    fn empty_input() {
        let mut finder = MatchFinder::new(default_config());
        let tokens = finder.tokenize(&[]);
        assert!(tokens.is_empty());
    }

    #[test]
    fn roundtrip_reconstruction() {
        let data = b"the quick brown fox jumps over the lazy dog and the quick brown";
        let mut finder = MatchFinder::new(default_config());
        let tokens = finder.tokenize(data);

        // Reconstruct from tokens
        let mut output = Vec::new();
        for token in &tokens {
            match token {
                Token::Literal(b) => output.push(*b),
                Token::Match(m) => {
                    let start = output.len() - m.offset as usize;
                    for i in 0..m.length as usize {
                        output.push(output[start + i]);
                    }
                }
            }
        }
        assert_eq!(output, data);
    }
}
