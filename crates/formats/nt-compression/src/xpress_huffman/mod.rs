#[cfg(feature = "compress-xpress-huffman")]
mod compress;
mod decompress;

#[cfg(feature = "compress-xpress-huffman")]
pub use compress::{Compressor, compress, compress_bound};
pub use decompress::{decompress, decompress_lenient};

/// Size of the Huffman code-length header in bytes.
pub(super) const HEADER_SIZE: usize = 256;

/// Number of symbols in the XPRESS Huffman alphabet.
pub(super) const NUM_SYMBOLS: usize = 512;

/// Maximum code length for XPRESS Huffman (15 bits).
pub(super) const MAX_CODE_BITS: u32 = 15;

/// Maximum decompressed size of a single block (64 KB).
pub(super) const BLOCK_SIZE: usize = 65536;
