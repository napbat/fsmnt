//! Various types of NTFS indexes and traits to work with them.
//!
//! Thanks to Rust's typesystem, the traits make using the various types of NTFS indexes (and their distinct key
//! and data types) possible in a typesafe way.
//!
//! NTFS uses B-tree indexes to quickly look up files, Object IDs, Reparse Points, Security Descriptors, etc.
//! They are described via [`NtfsIndexRoot`] and [`NtfsIndexAllocation`] attributes, which can be comfortably
//! accessed via [`NtfsIndex`].
//!
//! [`NtfsIndex`]: crate::NtfsIndex
//! [`NtfsIndexAllocation`]: crate::structured_values::NtfsIndexAllocation
//! [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot

use core::fmt;

use crate::error::Result;
use crate::types::NtfsPosition;

/// Trait implemented by structures that describe Index Entry types.
///
/// See also [`NtfsIndex`] and [`NtfsIndexEntry`], and [`NtfsFileNameIndex`] for the most popular Index Entry type.
///
/// [`NtfsFileNameIndex`]: crate::indexes::NtfsFileNameIndex
/// [`NtfsIndex`]: crate::NtfsIndex
/// [`NtfsIndexEntry`]: crate::NtfsIndexEntry
pub trait NtfsIndexEntryType: Clone + fmt::Debug {
    type KeyType: NtfsIndexEntryKey;
}

/// Trait implemented by a structure that describes an Index Entry key.
pub trait NtfsIndexEntryKey: fmt::Debug + Sized {
    /// A borrowed view of the key, used by the finder to avoid
    /// full-copy construction during B-tree comparisons.
    ///
    /// For fixed-size key types, set `Ref<'a> = Self` and implement
    /// [`key_ref_from_slice`](Self::key_ref_from_slice) by delegating
    /// to [`key_from_slice`](Self::key_from_slice).
    ///
    /// For variable-length keys like [`NtfsFileName`], set this to a
    /// zero-copy borrowing type (e.g. `NtfsFileNameRef<'a>`).
    ///
    /// [`NtfsFileName`]: crate::structured_values::NtfsFileName
    type Ref<'a>: fmt::Debug;

    fn key_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self>;

    /// Constructs a borrowed key reference from a raw byte slice.
    ///
    /// For types where `Ref<'a> = Self`, use
    /// [`impl_fixed_size_key_ref!`] instead of implementing manually.
    fn key_ref_from_slice<'a>(slice: &'a [u8], position: NtfsPosition) -> Result<Self::Ref<'a>>;
}

/// Implements the `Ref<'a> = Self` GAT and `key_ref_from_slice`
/// delegation for fixed-size key types where the borrowed view is
/// identical to the owned type.
macro_rules! impl_fixed_size_key_ref {
    () => {
        type Ref<'a> = Self;

        fn key_ref_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
            Self::key_from_slice(slice, position)
        }
    };
}

mod file_name;
mod object_id;
mod quota;
mod reparse_point;
mod security_hash;
mod security_id;

pub use file_name::*;
pub use object_id::*;
pub use quota::*;
pub use reparse_point::*;
pub use security_hash::*;
pub use security_id::*;

/// Indicates that the Index Entry type has additional data (of [`NtfsIndexEntryData`] datatype).
///
/// This trait and [`NtfsIndexEntryHasFileReference`] are mutually exclusive.
// TODO: Use negative trait bounds of future Rust to enforce mutual exclusion.
pub trait NtfsIndexEntryHasData: NtfsIndexEntryType {
    type DataType: NtfsIndexEntryData;
}

/// Trait implemented by a structure that describes Index Entry data.
pub trait NtfsIndexEntryData: fmt::Debug + Sized {
    fn data_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self>;
}

/// Indicates that the Index Entry type has a file reference.
///
/// This trait and [`NtfsIndexEntryHasData`] are mutually exclusive.
// TODO: Use negative trait bounds of future Rust to enforce mutual exclusion.
pub trait NtfsIndexEntryHasFileReference: NtfsIndexEntryType {}
