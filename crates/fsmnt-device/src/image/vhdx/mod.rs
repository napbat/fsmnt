//! Microsoft VHDX container implementation.

mod format;
mod log;
mod reader;

use reader::VhdxError;
pub(super) use reader::{VhdxReader, has_extension, has_signature};
