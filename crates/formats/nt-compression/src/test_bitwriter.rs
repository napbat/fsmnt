//! Shared test `BitWriter` for building synthetic compressed bitstreams.

use alloc::vec::Vec;

/// Bitstream encoder: accumulates bits MSB-first and flushes as 16-bit LE words.
#[allow(unused)]
pub struct BitWriter {
    data: Vec<u8>,
    accum: u32,
    accum_bits: u32,
}

#[allow(unused)]
impl BitWriter {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            accum: 0,
            accum_bits: 0,
        }
    }

    pub fn write_bits(&mut self, value: u32, count: u32) {
        self.accum = (self.accum << count) | (value & ((1 << count) - 1));
        self.accum_bits += count;
        while self.accum_bits >= 16 {
            self.accum_bits -= 16;
            let word = (self.accum >> self.accum_bits) as u16;
            let le = word.to_le_bytes();
            self.data.push(le[0]);
            self.data.push(le[1]);
            self.accum &= (1u32 << self.accum_bits) - 1;
        }
    }

    /// Flush remaining bits, padding with zeros to fill a 16-bit word.
    pub fn flush(&mut self) {
        if self.accum_bits > 0 {
            let word = (self.accum << (16 - self.accum_bits)) as u16;
            let le = word.to_le_bytes();
            self.data.push(le[0]);
            self.data.push(le[1]);
            self.accum = 0;
            self.accum_bits = 0;
        }
    }

    /// Write raw bytes directly (bypasses bitstream encoding).
    pub fn write_raw_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Return a reference to the accumulated data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume the writer and return the accumulated data.
    pub fn into_data(mut self) -> Vec<u8> {
        self.flush();
        self.data
    }

    /// Flush remaining bits and append `padding_words` trailing zero words.
    pub fn finish(mut self, padding_words: usize) -> Vec<u8> {
        self.flush();
        for _ in 0..padding_words {
            self.data.extend_from_slice(&[0, 0]);
        }
        self.data
    }
}
