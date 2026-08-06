#[cfg(feature = "compress-xpress")]
mod compress;
mod decompress;

#[cfg(feature = "compress-xpress")]
pub use compress::{compress, compress_bound};
pub use decompress::{decompress, decompress_lenient};
