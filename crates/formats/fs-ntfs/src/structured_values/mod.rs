//! Various types of NTFS Attribute structured values.

/// Implements `NtfsStructuredValue` for types whose `new` constructor
/// takes `(&mut T, NtfsPosition, u64) -> Result<Self>`.
macro_rules! impl_structured_value_via_new {
    ($ty:ty, $attr_type:expr) => {
        impl<'n, 'f> NtfsStructuredValue<'n, 'f> for $ty {
            const TY: NtfsAttributeType = $attr_type;

            fn from_attribute_value<T>(
                fs: &mut T,
                value: NtfsAttributeValue<'n, 'f>,
            ) -> Result<Self>
            where
                T: Read + Seek,
            {
                let position = value.data_position();
                let value_length = value.len();
                let mut value_attached = value.attach(fs);
                Self::new(&mut value_attached, position, value_length)
            }
        }
    };
}

mod attribute_list;
mod ea;
mod efs;
mod file_name;
mod index_allocation;
mod index_root;
mod logged_utility_stream;
mod object_id;
mod property_set;
pub(crate) mod reparse;
mod security;
mod standard_information;
mod txf;
mod volume_information;
mod volume_name;

#[cfg(feature = "compression")]
pub mod wof;

use core::fmt;

pub use attribute_list::*;
pub use ea::*;
pub use efs::*;
pub use file_name::*;
pub use index_allocation::*;
pub use index_root::*;
pub use logged_utility_stream::*;
pub use object_id::*;
pub use property_set::*;
pub use reparse::cloud;
pub use reparse::*;
pub use security::*;
pub use standard_information::*;
pub use txf::*;
pub use volume_information::*;
pub use volume_name::*;

use bitflags::bitflags;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::Result;
use crate::io::{Read, Seek};

bitflags! {
    /// Flags that a user can set for a file (Read-Only, Hidden, System, Archive, etc.).
    /// Commonly called "File Attributes" in Windows Explorer.
    ///
    /// Not to be confused with [`NtfsAttribute`].
    ///
    /// Returned by [`NtfsStandardInformation::file_attributes`] and [`NtfsFileName::file_attributes`].
    ///
    /// Spec reference: MS-FSCC Section 2.6 (File Attributes).
    ///
    /// [`NtfsAttribute`]: crate::attribute::NtfsAttribute
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsFileAttributeFlags: u32 {
        /// File is marked read-only.
        const READ_ONLY = 0x0001;
        /// File is hidden (in file browsers that care).
        const HIDDEN = 0x0002;
        /// File is marked as a system file.
        const SYSTEM = 0x0004;
        /// Item is a directory (from `$STANDARD_INFORMATION`).
        ///
        /// Distinct from [`IS_DIRECTORY`](Self::IS_DIRECTORY) (0x1000_0000),
        /// which is returned only from `$FILE_NAME` attributes.
        const DIRECTORY = 0x0010;
        /// File is marked for archival (cf. <https://en.wikipedia.org/wiki/Archive_bit>).
        const ARCHIVE = 0x0020;
        /// File denotes a device.
        const DEVICE = 0x0040;
        /// Set when no other attributes are set.
        const NORMAL = 0x0080;
        /// File is a temporary file that is likely to be deleted.
        const TEMPORARY = 0x0100;
        /// File is stored sparsely.
        const SPARSE_FILE = 0x0200;
        /// File is a reparse point.
        const REPARSE_POINT = 0x0400;
        /// File is transparently compressed by the filesystem (using LZNT1 algorithm).
        /// For directories, this attribute denotes that compression is enabled by default for new files inside that directory.
        const COMPRESSED = 0x0800;
        /// File contents are not immediately available from local storage.
        const OFFLINE = 0x1000;
        /// File has not (yet) been indexed by the Windows Indexing Service.
        const NOT_CONTENT_INDEXED = 0x2000;
        /// File is encrypted via EFS.
        /// For directories, this attribute denotes that encryption is enabled by default for new files inside that directory.
        const ENCRYPTED = 0x4000;
        /// File or directory has integrity support (ReFS, NTFS 3.1+).
        /// For directories, integrity is the default for newly created children.
        const INTEGRITY_STREAM = 0x8000;
        /// Excluded from the data integrity scan.
        /// For directories, newly created children inherit this attribute.
        const NO_SCRUB_DATA = 0x0002_0000;
        /// No local representation; opening fetches content from a remote store.
        /// Set only by kernel-mode components (HSM / cloud tiering).
        const RECALL_ON_OPEN = 0x0004_0000;
        /// Keep fully present locally (cloud tiering hint).
        const PINNED = 0x0008_0000;
        /// Allow dehydration; do not keep fully present locally (cloud tiering hint).
        const UNPINNED = 0x0010_0000;
        /// Not fully present locally; reading data causes a remote fetch.
        /// Set only by kernel-mode components (HSM / cloud tiering).
        const RECALL_ON_DATA_ACCESS = 0x0040_0000;
        /// File is a directory.
        ///
        /// This attribute is only returned from [`NtfsFileName::file_attributes`].
        const IS_DIRECTORY = 0x1000_0000;
    }
}

impl fmt::Display for NtfsFileAttributeFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsFileAttributeFlags {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bits: u32 = u.arbitrary()?;
        Ok(Self::from_bits_truncate(bits))
    }
}

/// Trait implemented by every NTFS attribute structured value.
pub trait NtfsStructuredValue<'n, 'f>: Sized {
    /// NTFS attribute type that carries this structured value.
    const TY: NtfsAttributeType;

    /// Create a structured value from an arbitrary `NtfsAttributeValue`.
    ///
    /// # Errors
    ///
    /// Returns an error if the attribute value cannot be read or does not have
    /// the layout required by this structured value.
    fn from_attribute_value<T>(fs: &mut T, value: NtfsAttributeValue<'n, 'f>) -> Result<Self>
    where
        T: Read + Seek;
}

/// Trait implemented by NTFS Attribute structured values that are always in resident attributes.
pub trait NtfsStructuredValueFromResidentAttributeValue<'n, 'f>:
    NtfsStructuredValue<'n, 'f>
{
    /// Create a structured value from a resident attribute value.
    ///
    /// This is a fast path for the few structured values that are always in resident attributes.
    ///
    /// # Errors
    ///
    /// Returns an error if the resident bytes do not form a valid value of this
    /// structured type.
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self>;
}

#[cfg(test)]
mod tests {
    use super::NtfsFileAttributeFlags;

    /// Verify every MS-FSCC 2.6 flag has the correct bit value.
    #[test]
    fn all_spec_flags_have_correct_values() {
        assert_eq!(NtfsFileAttributeFlags::READ_ONLY.bits(), 0x0000_0001);
        assert_eq!(NtfsFileAttributeFlags::HIDDEN.bits(), 0x0000_0002);
        assert_eq!(NtfsFileAttributeFlags::SYSTEM.bits(), 0x0000_0004);
        assert_eq!(NtfsFileAttributeFlags::DIRECTORY.bits(), 0x0000_0010);
        assert_eq!(NtfsFileAttributeFlags::ARCHIVE.bits(), 0x0000_0020);
        assert_eq!(NtfsFileAttributeFlags::DEVICE.bits(), 0x0000_0040);
        assert_eq!(NtfsFileAttributeFlags::NORMAL.bits(), 0x0000_0080);
        assert_eq!(NtfsFileAttributeFlags::TEMPORARY.bits(), 0x0000_0100);
        assert_eq!(NtfsFileAttributeFlags::SPARSE_FILE.bits(), 0x0000_0200);
        assert_eq!(NtfsFileAttributeFlags::REPARSE_POINT.bits(), 0x0000_0400);
        assert_eq!(NtfsFileAttributeFlags::COMPRESSED.bits(), 0x0000_0800);
        assert_eq!(NtfsFileAttributeFlags::OFFLINE.bits(), 0x0000_1000);
        assert_eq!(
            NtfsFileAttributeFlags::NOT_CONTENT_INDEXED.bits(),
            0x0000_2000,
        );
        assert_eq!(NtfsFileAttributeFlags::ENCRYPTED.bits(), 0x0000_4000);
        assert_eq!(NtfsFileAttributeFlags::INTEGRITY_STREAM.bits(), 0x0000_8000,);
        assert_eq!(NtfsFileAttributeFlags::NO_SCRUB_DATA.bits(), 0x0002_0000,);
        assert_eq!(NtfsFileAttributeFlags::RECALL_ON_OPEN.bits(), 0x0004_0000,);
        assert_eq!(NtfsFileAttributeFlags::PINNED.bits(), 0x0008_0000);
        assert_eq!(NtfsFileAttributeFlags::UNPINNED.bits(), 0x0010_0000);
        assert_eq!(
            NtfsFileAttributeFlags::RECALL_ON_DATA_ACCESS.bits(),
            0x0040_0000,
        );
        assert_eq!(NtfsFileAttributeFlags::IS_DIRECTORY.bits(), 0x1000_0000);
    }

    /// Display must render the set flags, not an empty string.
    #[test]
    fn display_prints_flags() {
        let flags = NtfsFileAttributeFlags::READ_ONLY | NtfsFileAttributeFlags::ARCHIVE;
        let s = std::format!("{flags}");
        // The genuine Display renders the flag names; the mutated body
        // (`Ok(Default::default())`) would produce an empty string.
        assert_eq!(s, "READ_ONLY | ARCHIVE");
        assert!(!s.is_empty());
        assert_ne!(s, std::string::String::default());
    }

    /// DIRECTORY (0x0010, from $`STANDARD_INFORMATION`) and
    /// `IS_DIRECTORY` (`0x1000_0000`, from $`FILE_NAME`) must be
    /// distinct flags that can be set independently.
    #[test]
    fn directory_and_is_directory_are_distinct() {
        let dir = NtfsFileAttributeFlags::DIRECTORY;
        let is_dir = NtfsFileAttributeFlags::IS_DIRECTORY;

        assert_ne!(dir, is_dir);
        assert!(!dir.intersects(is_dir));

        let both = dir | is_dir;
        assert!(both.contains(dir));
        assert!(both.contains(is_dir));
        assert_eq!(both.bits(), 0x1000_0010);
    }

    /// Every known bit must survive a `from_bits_truncate` round-trip.
    #[test]
    fn from_bits_truncate_round_trip() {
        let all = NtfsFileAttributeFlags::all();
        let round_tripped = NtfsFileAttributeFlags::from_bits_truncate(all.bits());
        assert_eq!(round_tripped, all);
    }

    /// Unknown bits must be dropped by `from_bits_truncate`.
    #[test]
    fn from_bits_truncate_drops_unknown() {
        // 0x0001_0000 is a gap in the spec (no flag defined).
        let flags = NtfsFileAttributeFlags::from_bits_truncate(0x0001_0000);
        assert!(flags.is_empty());
    }

    /// Verify we have exactly 21 flags (19 spec + DEVICE + `IS_DIRECTORY`).
    #[test]
    fn total_flag_count() {
        // Count distinct single-bit flags by iterating known flags.
        let all = NtfsFileAttributeFlags::all();
        let count = all.iter().count();
        assert_eq!(count, 21, "expected 21 flags, got {count}");
    }
}
