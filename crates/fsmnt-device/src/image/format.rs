//! Disk-image container format identifiers.

use std::fmt;

/// Storage container backing a decoded disk-image reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ImageFormat {
    /// A byte-for-byte raw image file.
    Raw,
    /// An Expert Witness Format segment set.
    Ewf,
    /// A legacy Microsoft Virtual Hard Disk container.
    Vhd,
    /// A Microsoft Virtual Hard Disk v2 container.
    Vhdx,
}

impl fmt::Display for ImageFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw => formatter.write_str("raw"),
            Self::Ewf => formatter.write_str("EWF"),
            Self::Vhd => formatter.write_str("VHD"),
            Self::Vhdx => formatter.write_str("VHDX"),
        }
    }
}
