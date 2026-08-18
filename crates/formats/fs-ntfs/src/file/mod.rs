use core::cmp::Ordering;
use core::fmt;
use core::num::NonZeroU64;

use alloc::vec;
use alloc::vec::Vec;
use bitflags::bitflags;
use core::mem::offset_of;
use fsmnt_parser_core::error::IoError;
use nt_string::u16strle::U16StrLe;

use crate::attribute::{
    NtfsAttribute, NtfsAttributeItem, NtfsAttributeType, NtfsAttributes, NtfsAttributesRaw,
};
use crate::error::{NtfsError, Result};
use crate::file_reference::NtfsFileReference;
use crate::index::NtfsIndex;
use crate::indexes::{
    NtfsFileNameIndex, NtfsIndexEntryType, NtfsQuotaOIndex, NtfsQuotaQIndex, NtfsReparsePointIndex,
};
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;
use crate::record::{Record, RecordHeader};
use crate::slack_recovery::{NtfsRecoveredEntry, NtfsSlackEntryScanner, SlackRecoveryConfig};
use crate::structured_values::{
    NtfsFileName, NtfsFileNamespace, NtfsIndexAllocation, NtfsIndexRoot, NtfsReparsePoint,
    NtfsStandardInformation, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;
use crate::upcase_table::UpcaseOrd;
use fsmnt_parser_core::iter::FsTryIterator;

/// A list of standardized NTFS File Record Numbers.
///
/// Most of these files store internal NTFS housekeeping information.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/index.html>
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum KnownNtfsFileRecordNumber {
    /// A back-reference to the Master File Table (MFT).
    ///
    /// Leads to the same File Record as [`Ntfs::mft_position`].
    MFT = 0,
    /// A mirror copy of the Master File Table (MFT).
    MFTMirr = 1,
    /// The journaling logfile.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html>
    LogFile = 2,
    /// File containing basic filesystem information and the user-defined volume name.
    ///
    /// You can easily access that information via [`Ntfs::volume_info`] and [`Ntfs::volume_name`].
    Volume = 3,
    /// File defining all attributes supported by this NTFS filesystem.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/attrdef.html>
    AttrDef = 4,
    /// The root directory of the filesystem.
    ///
    /// You can easily access it via [`Ntfs::root_directory`].
    RootDirectory = 5,
    /// Map of used clusters.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/bitmap.html>
    Bitmap = 6,
    /// A back-reference to the boot sector of the filesystem.
    Boot = 7,
    /// A file consisting of Data Runs to bad cluster ranges.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/badclus.html>
    BadClus = 8,
    /// A list of all Security Descriptors used by this filesystem.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/secure.html>
    Secure = 9,
    /// The $`UpCase` file that contains a table of all uppercase characters for the
    /// 65536 characters of the Unicode Basic Multilingual Plane.
    ///
    /// NTFS uses this table to perform case-insensitive comparisons.
    UpCase = 10,
    /// A directory of further files containing housekeeping information.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/extend.html>
    Extend = 11,
}

#[repr(C, packed)]
struct FileRecordHeader {
    record_header: RecordHeader,
    sequence_number: u16,
    hard_link_count: u16,
    first_attribute_offset: u16,
    flags: u16,
    data_size: u32,
    allocated_size: u32,
    base_file_record: NtfsFileReference,
    next_attribute_instance: u16,
}

impl KnownNtfsFileRecordNumber {
    /// Returns the fixed Master File Table record number.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        match self {
            Self::MFT => 0,
            Self::MFTMirr => 1,
            Self::LogFile => 2,
            Self::Volume => 3,
            Self::AttrDef => 4,
            Self::RootDirectory => 5,
            Self::Bitmap => 6,
            Self::Boot => 7,
            Self::BadClus => 8,
            Self::Secure => 9,
            Self::UpCase => 10,
            Self::Extend => 11,
        }
    }
}

fn validated_record_bytes<const N: usize>(data: &[u8], start: usize) -> [u8; N] {
    data.get(start..)
        .and_then(|bytes| bytes.first_chunk())
        .copied()
        .expect("file construction validates every fixed-width record header field")
}

bitflags! {
    /// Flags returned by [`NtfsFile::flags`].
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsFileFlags: u16 {
        /// Record is in use.
        const IN_USE = 0x0001;
        /// Record is a directory.
        const IS_DIRECTORY = 0x0002;
    }
}

impl fmt::Display for NtfsFileFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A paired set of `$FILE_NAME` attributes for a single file, combining the primary
/// (long) name with an optional DOS 8.3 short name.
///
/// NTFS files with long names that don't conform to 8.3 constraints have two separate
/// `$FILE_NAME` attributes: a Win32 (or Posix) entry with the long name, and a DOS entry
/// with the auto-generated short name. Files whose names already satisfy 8.3 constraints
/// have a single `Win32AndDos` entry instead (in which case [`short_name`] is `None`).
///
/// Use [`NtfsFile::name_pair`] to obtain this structure.
///
/// [`short_name`]: NtfsFileNamePair::short_name
#[derive(Clone, Debug)]
pub struct NtfsFileNamePair {
    /// The primary (long) name — Win32, Posix, or `Win32AndDos` namespace.
    pub primary: NtfsFileName,
    /// The DOS 8.3 short name, if a separate one exists.
    ///
    /// This is `None` when the primary name is in the `Win32AndDos` namespace
    /// (the name already satisfies DOS constraints) or when 8.3 name generation
    /// was disabled on the volume.
    pub short_name: Option<NtfsFileName>,
}

/// A single NTFS File Record.
///
/// These records are denoted via a `FILE` signature on the filesystem.
///
/// NTFS uses File Records to manage all user-facing files and directories, as well as some internal files for housekeeping.
/// Every File Record consists of [`NtfsAttribute`]s, which may reference additional File Records.
/// Even the Master File Table (MFT) itself is organized as a File Record.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/file_record.html>
///
/// [`NtfsAttribute`]: crate::attribute::NtfsAttribute
#[derive(Clone, Debug)]
pub struct NtfsFile<'n> {
    ntfs: &'n Ntfs,
    record: Record,
    file_record_number: u64,
}

impl<'n> NtfsFile<'n> {
    pub(crate) fn new<T>(
        ntfs: &'n Ntfs,
        fs: &mut T,
        position: NonZeroU64,
        file_record_number: u64,
    ) -> Result<Self>
    where
        T: Read + Seek,
    {
        let record_size =
            usize::try_from(ntfs.file_record_size()).map_err(|_| IoError::invalid_input())?;
        let mut data = vec![0; record_size];
        fs.seek(SeekFrom::Start(position.get()))?;
        fs.read_exact(&mut data)?;

        let mut record = Record::new(data, position.into());
        Self::validate_signature(&record)?;
        record.fixup()?;

        let file = Self {
            ntfs,
            record,
            file_record_number,
        };
        file.validate_sizes()?;

        Ok(file)
    }

    /// Returns the allocated size of this NTFS File Record, in bytes.
    #[must_use]
    pub fn allocated_size(&self) -> u32 {
        let start = offset_of!(FileRecordHeader, allocated_size);
        u32::from_le_bytes(validated_record_bytes(self.record.data(), start))
    }

    /// Returns an iterator over all attributes of this file.
    ///
    /// This provides a flattened "data-centric" view of the attributes and abstracts away the filesystem details
    /// to deal with many or large attributes (Attribute Lists and connected attributes).
    /// Use [`NtfsFile::attributes_raw`] to iterate over the plain attributes on the filesystem.
    ///
    /// Due to the abstraction, the iterator returns an [`NtfsAttributeItem`] for each entry.
    ///
    /// [`NtfsAttributeItem`]: crate::NtfsAttributeItem
    #[must_use]
    pub fn attributes<'f>(&'f self) -> NtfsAttributes<'n, 'f> {
        NtfsAttributes::<'n, 'f>::new(self)
    }

    /// Returns an iterator over all top-level attributes of this file.
    ///
    /// Contrary to [`NtfsFile::attributes`], it does not traverse $`ATTRIBUTE_LIST` attributes, but returns
    /// them as raw attributes.
    /// Check that function if you want an iterator providing a flattened "data-centric" view over
    /// the attributes by traversing Attribute Lists automatically.
    ///
    /// The iterator returns an [`NtfsAttribute`] for each entry.
    ///
    /// [`NtfsAttribute`]: crate::NtfsAttribute
    #[must_use]
    pub fn attributes_raw<'f>(&'f self) -> NtfsAttributesRaw<'n, 'f> {
        NtfsAttributesRaw::new(self)
    }

    /// Convenience function to get a $DATA attribute of this file.
    ///
    /// As NTFS supports multiple data streams per file, you can specify the name of the $DATA attribute
    /// to look up.
    /// Passing an empty string here looks up the default unnamed $DATA attribute (commonly known as the "file data").
    /// The name is looked up case-insensitively.
    ///
    /// If you need more control over which $DATA attribute is available and picked up,
    /// you can use [`NtfsFile::attributes`] to iterate over all attributes of this file.
    ///
    /// # Panics
    ///
    /// Panics if `data_stream_name` is non-empty and [`read_upcase_table`][Ntfs::read_upcase_table] had not been
    /// called on the passed [`Ntfs`] object.
    pub fn data<'f, T>(
        &'f self,
        fs: &mut T,
        data_stream_name: &str,
    ) -> Option<Result<NtfsAttributeItem<'n, 'f>>>
    where
        T: Read + Seek,
    {
        let mut iter = self.attributes();

        let equal = if data_stream_name.is_empty() {
            // Use a simpler "comparison" that doesn't require the $UpCase table.
            |_ntfs: &Ntfs, name: &U16StrLe, _data_stream_name: &str| name.is_empty()
        } else {
            |ntfs: &Ntfs, name: &U16StrLe, data_stream_name: &str| {
                name.upcase_cmp(ntfs, &data_stream_name) == Ordering::Equal
            }
        };

        while let Some(item) = iter_try!(iter.try_next(fs)) {
            let attribute = iter_try!(item.to_attribute());

            let ty = iter_try!(attribute.ty());
            if ty != NtfsAttributeType::Data {
                continue;
            }

            let name = iter_try!(attribute.name());
            if !equal(self.ntfs, &name, data_stream_name) {
                continue;
            }

            return Some(Ok(item));
        }

        None
    }

    /// Returns the size actually used by data of this NTFS File Record, in bytes.
    ///
    /// This is less or equal than [`NtfsFile::allocated_size`].
    #[must_use]
    pub fn data_size(&self) -> u32 {
        let start = offset_of!(FileRecordHeader, data_size);
        u32::from_le_bytes(validated_record_bytes(self.record.data(), start))
    }

    /// Convenience function to return an [`NtfsIndex`] if this file is a directory.
    /// This structure can be used to iterate over all files of this directory or a find a specific one.
    ///
    /// Apart from any propagated error, this function may return [`NtfsError::NotADirectory`]
    /// if this [`NtfsFile`] is not a directory.
    ///
    /// If you need more control over the picked up $`INDEX_ROOT` and $`INDEX_ALLOCATION` attributes
    /// you can use [`NtfsFile::attributes`] to iterate over all attributes of this file.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn directory_index<T>(&self, fs: &mut T) -> Result<NtfsIndex<'n, NtfsFileNameIndex>>
    where
        T: Read + Seek,
    {
        if !self.is_directory() {
            return Err(NtfsError::NotADirectory {
                position: self.position(),
            });
        }

        self.named_index(fs, "$I30")
    }

    /// Opens a named index on this file by finding the `$INDEX_ROOT` and
    /// optional `$INDEX_ALLOCATION` attributes with the given name.
    fn named_index<E, T>(&self, fs: &mut T, index_name: &str) -> Result<NtfsIndex<'n, E>>
    where
        E: NtfsIndexEntryType,
        T: Read + Seek,
    {
        let index_root_item =
            self.find_attribute(fs, NtfsAttributeType::IndexRoot, Some(index_name))?;
        let index_root_attribute = index_root_item.to_attribute()?;
        let index_root = index_root_attribute.resident_structured_value::<NtfsIndexRoot>()?;

        let mut index_allocation_item = None;
        if index_root.is_large_index() {
            index_allocation_item = Some(self.find_attribute(
                fs,
                NtfsAttributeType::IndexAllocation,
                Some(index_name),
            )?);
        }

        NtfsIndex::<E>::new(
            self.ntfs(),
            &index_root_item,
            index_allocation_item.as_ref(),
            fs,
        )
    }

    /// Opens the `$R` (Reparse Point) index on this file.
    ///
    /// The `$R` index is found in the `$Extend\$Reparse` system file and
    /// lists every reparse point on the volume, sorted by reparse tag then
    /// by file reference.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Requires a real NTFS filesystem image — cannot run in doctests.
    /// let extend_dir = ntfs.file(&mut fs, 11)?; // $Extend
    /// let reparse_entry = /* find $Reparse in $Extend directory index */;
    /// let reparse_file = reparse_entry.to_file(&ntfs, &mut fs)?;
    /// let index = reparse_file.reparse_point_index(&mut fs)?;
    /// let mut iter = index.entries();
    /// while let Some(entry) = iter.try_next(&mut fs)? {
    ///     if let Some(key) = entry.key() {
    ///         let key = key?;
    ///         println!("tag={:#x} file={}", key.reparse_tag(), key.file_reference().file_record_number());
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`NtfsError::AttributeNotFound`] if this file has no
    /// `$INDEX_ROOT` attribute named `$R`.
    pub fn reparse_point_index<T>(&self, fs: &mut T) -> Result<NtfsIndex<'n, NtfsReparsePointIndex>>
    where
        T: Read + Seek,
    {
        self.named_index(fs, "$R")
    }

    /// Opens the `$Q` (Quota) index on this file.
    ///
    /// The `$Q` index is found in the `$Extend\$Quota` system file and
    /// maps owner IDs to quota control data (usage, thresholds, SID).
    ///
    /// # Errors
    ///
    /// Returns [`NtfsError::AttributeNotFound`] if this file has no
    /// `$INDEX_ROOT` attribute named `$Q`.
    pub fn quota_q_index<T>(&self, fs: &mut T) -> Result<NtfsIndex<'n, NtfsQuotaQIndex>>
    where
        T: Read + Seek,
    {
        self.named_index(fs, "$Q")
    }

    /// Opens the `$O` (Owner) index on this file.
    ///
    /// The `$O` index is found in the `$Extend\$Quota` system file and
    /// maps SIDs to owner IDs (reverse lookup for the `$Q` index).
    ///
    /// # Errors
    ///
    /// Returns [`NtfsError::AttributeNotFound`] if this file has no
    /// `$INDEX_ROOT` attribute named `$O`.
    pub fn quota_o_index<T>(&self, fs: &mut T) -> Result<NtfsIndex<'n, NtfsQuotaOIndex>>
    where
        T: Read + Seek,
    {
        self.named_index(fs, "$O")
    }

    /// Recovers deleted file entries from all index slack space in this directory.
    ///
    /// Scans the `INDEX_ROOT` and all `INDEX_ALLOCATION` records for this directory's
    /// `$I30` index, collecting any recoverable entries from slack space.
    ///
    /// Returns an error if this file is not a directory.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn recover_directory_slack<T>(
        &self,
        fs: &mut T,
        config: SlackRecoveryConfig,
    ) -> Result<Vec<NtfsRecoveredEntry>>
    where
        T: Read + Seek,
    {
        if !self.is_directory() {
            return Err(NtfsError::NotADirectory {
                position: self.position(),
            });
        }

        let directory_index_name = "$I30";
        let parent_record_number = self.file_record_number();
        let mut recovered = Vec::new();

        // Get the INDEX_ROOT attribute (always resident, always present for directories).
        let index_root_item =
            self.find_attribute(fs, NtfsAttributeType::IndexRoot, Some(directory_index_name))?;
        let index_root_attribute = index_root_item.to_attribute()?;
        let index_root = index_root_attribute.resident_structured_value::<NtfsIndexRoot>()?;

        // Scan INDEX_ROOT slack space.
        let scanner = NtfsSlackEntryScanner::new(
            index_root.slack_data(),
            index_root.slack_position(),
            config,
            parent_record_number,
        );
        recovered.extend(scanner);

        // If this is a large index, also scan all INDX allocation records.
        if index_root.is_large_index() {
            let index_record_size = index_root.index_record_size();

            let index_alloc_item = self.find_attribute(
                fs,
                NtfsAttributeType::IndexAllocation,
                Some(directory_index_name),
            )?;
            let index_alloc_attribute = index_alloc_item.to_attribute()?;
            let index_alloc =
                index_alloc_attribute.structured_value::<_, NtfsIndexAllocation>(fs)?;

            let mut record_iter = index_alloc.records(index_record_size);
            loop {
                // Skip errors on individual INDX records (continue on Err).
                match record_iter.try_next(fs) {
                    Ok(Some(record)) => {
                        let scanner = NtfsSlackEntryScanner::new(
                            record.slack_data(),
                            record.slack_position(),
                            config,
                            parent_record_number,
                        );
                        recovered.extend(scanner);
                    }
                    Ok(None) => break,
                    Err(_) => {}
                }
            }
        }

        Ok(recovered)
    }

    /// Returns the NTFS File Record Number of this file.
    ///
    /// This number uniquely identifies this file and can be used to recreate this [`NtfsFile`]
    /// object via [`Ntfs::file`].
    #[must_use]
    pub fn file_record_number(&self) -> u64 {
        self.file_record_number
    }

    /// Finds an attribute of a specific type, optionally with a specific name, and returns its [`NtfsAttributeItem`].
    /// Returns [`NtfsError::AttributeNotFound`] if no such attribute could be found.
    ///
    /// This function also traverses Attribute Lists to find the attribute.
    fn find_attribute<'f, T>(
        &'f self,
        fs: &mut T,
        ty: NtfsAttributeType,
        match_name: Option<&str>,
    ) -> Result<NtfsAttributeItem<'n, 'f>>
    where
        T: Read + Seek,
    {
        let mut iter = self.attributes();

        while let Some(item) = iter.try_next(fs)? {
            let attribute = item.to_attribute()?;

            if attribute.ty()? != ty {
                continue;
            }

            if let Some(name) = match_name
                && attribute.name()? != name
            {
                continue;
            }

            return Ok(item);
        }

        Err(NtfsError::AttributeNotFound {
            position: self.position(),
            ty,
        })
    }

    /// Finds a resident attribute of a specific type, optionally with a specific name and/or a specific
    /// instance identifier, and returns it.
    /// Returns [`NtfsError::AttributeNotFound`] if no such resident attribute could be found.
    ///
    /// The attribute type is given through the passed structured value type parameter.
    ///
    /// Note that this function DOES NOT traverse Attribute Lists!
    pub(crate) fn find_resident_attribute<'f>(
        &'f self,
        ty: NtfsAttributeType,
        match_name: Option<&str>,
        match_instance: Option<u16>,
    ) -> Result<NtfsAttribute<'n, 'f>> {
        // Resident attributes are always stored on the top-level (we don't have to dig into Attribute Lists).
        for attribute in self.attributes_raw() {
            let attribute = attribute?;

            if attribute.ty()? != ty {
                continue;
            }

            if let Some(instance) = match_instance
                && attribute.instance() != instance
            {
                continue;
            }

            if let Some(name) = match_name
                && attribute.name()? != name
            {
                continue;
            }

            return Ok(attribute);
        }

        Err(NtfsError::AttributeNotFound {
            position: self.position(),
            ty,
        })
    }

    /// Finds a resident attribute of a specific type, optionally with a specific name, and returns its structured value.
    /// Returns [`NtfsError::AttributeNotFound`] if no such resident attribute could be found.
    ///
    /// The attribute type is given through the passed structured value type parameter.
    ///
    /// Note that this function DOES NOT traverse Attribute Lists!
    pub(crate) fn find_resident_attribute_structured_value<'f, S>(
        &'f self,
        match_name: Option<&str>,
    ) -> Result<S>
    where
        S: NtfsStructuredValueFromResidentAttributeValue<'n, 'f>,
    {
        let attribute = self.find_resident_attribute(S::TY, match_name, None)?;
        attribute.resident_structured_value::<S>()
    }

    pub(crate) fn first_attribute_offset(&self) -> u16 {
        let start = offset_of!(FileRecordHeader, first_attribute_offset);
        u16::from_le_bytes(validated_record_bytes(self.record.data(), start))
    }

    /// Returns flags set for this file as specified by [`NtfsFileFlags`].
    #[must_use]
    pub fn flags(&self) -> NtfsFileFlags {
        let start = offset_of!(FileRecordHeader, flags);
        NtfsFileFlags::from_bits_truncate(u16::from_le_bytes(validated_record_bytes(
            self.record.data(),
            start,
        )))
    }

    /// Returns the number of hard links to this NTFS File Record.
    #[must_use]
    pub fn hard_link_count(&self) -> u16 {
        let start = offset_of!(FileRecordHeader, hard_link_count);
        u16::from_le_bytes(validated_record_bytes(self.record.data(), start))
    }

    /// Convenience function to get the $`STANDARD_INFORMATION` attribute of this file
    /// (see [`NtfsStandardInformation`]).
    ///
    /// This internally calls [`NtfsFile::attributes_raw`] to iterate through the file's
    /// attributes and pick up the first $`STANDARD_INFORMATION` attribute.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn info(&self) -> Result<NtfsStandardInformation> {
        self.find_resident_attribute_structured_value::<NtfsStandardInformation>(None)
    }

    /// Returns whether this NTFS File Record represents a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.flags().contains(NtfsFileFlags::IS_DIRECTORY)
    }

    /// Returns whether this file is an NTFS system metafile.
    ///
    /// NTFS reserves MFT records 0–23 for internal housekeeping files
    /// (`$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`, `$AttrDef`, `.`
    /// (root directory), `$Bitmap`, `$Boot`, `$BadClus`, `$Secure`,
    /// `$UpCase`, `$Extend`, plus 12 reserved entries).  The Windows
    /// NTFS driver hides these from normal directory listings.
    ///
    /// Note: record 5 (the root directory) is technically a system
    /// metafile, but is never enumerated as a child entry — it *is*
    /// the root.
    #[must_use]
    pub fn is_system_metafile(&self) -> bool {
        self.file_record_number < 24
    }

    /// Convenience function to get a $`FILE_NAME` attribute of this file (see [`NtfsFileName`]).
    ///
    /// A file may have multiple $`FILE_NAME` attributes for each [`NtfsFileNamespace`].
    /// Files with hard links have further $`FILE_NAME` attributes for each directory they are in.
    /// You may optionally filter for a namespace and parent directory via the parameters.
    ///
    /// This internally calls [`NtfsFile::attributes`] to iterate through the file's
    /// attributes and pick up the first matching $`FILE_NAME` attribute.
    pub fn name<T>(
        &self,
        fs: &mut T,
        match_namespace: Option<NtfsFileNamespace>,
        match_parent_record_number: Option<u64>,
    ) -> Option<Result<NtfsFileName>>
    where
        T: Read + Seek,
    {
        let mut iter = self.attributes();

        while let Some(item) = iter_try!(iter.try_next(fs)) {
            let attribute = iter_try!(item.to_attribute());

            let ty = iter_try!(attribute.ty());
            if ty != NtfsAttributeType::FileName {
                continue;
            }

            let file_name = iter_try!(attribute.structured_value::<_, NtfsFileName>(fs));

            if let Some(namespace) = match_namespace
                && file_name.namespace() != namespace
            {
                continue;
            }

            if let Some(parent_record_number) = match_parent_record_number
                && file_name.parent_directory_reference().file_record_number()
                    != parent_record_number
            {
                continue;
            }

            return Some(Ok(file_name));
        }

        None
    }

    /// Convenience function to get a `$FILE_NAME` attribute pair for this file.
    ///
    /// NTFS may store separate Win32 (long name) and DOS (8.3 short name) `$FILE_NAME`
    /// attributes for a file. This method reliably pairs them by reading directly from
    /// the MFT record, regardless of directory index ordering.
    ///
    /// Returns an [`NtfsFileNamePair`] containing the primary (Win32, Posix, or `Win32AndDos`)
    /// name and an optional separate DOS short name.
    ///
    /// You may optionally filter by parent directory record number to select the pair
    /// corresponding to a specific hard link.
    ///
    /// Returns `None` if no matching `$FILE_NAME` attribute is found.
    pub fn name_pair<T>(
        &self,
        fs: &mut T,
        match_parent_record_number: Option<u64>,
    ) -> Option<Result<NtfsFileNamePair>>
    where
        T: Read + Seek,
    {
        let mut primary: Option<NtfsFileName> = None;
        let mut primary_parent: Option<u64> = None;
        let mut dos: Option<NtfsFileName> = None;

        let mut iter = self.attributes();

        while let Some(item) = iter_try!(iter.try_next(fs)) {
            let attribute = iter_try!(item.to_attribute());

            let ty = iter_try!(attribute.ty());
            if ty != NtfsAttributeType::FileName {
                continue;
            }

            let file_name = iter_try!(attribute.structured_value::<_, NtfsFileName>(fs));

            if let Some(parent_record_number) = match_parent_record_number
                && file_name.parent_directory_reference().file_record_number()
                    != parent_record_number
            {
                continue;
            }

            match file_name.namespace() {
                NtfsFileNamespace::Win32AndDos => {
                    // Combined entry — this IS the primary and satisfies DOS too.
                    return Some(Ok(NtfsFileNamePair {
                        primary: file_name,
                        short_name: None,
                    }));
                }
                NtfsFileNamespace::Dos => {
                    dos = Some(file_name);
                }
                NtfsFileNamespace::Win32 | NtfsFileNamespace::Posix => {
                    primary_parent =
                        Some(file_name.parent_directory_reference().file_record_number());
                    primary = Some(file_name);
                }
            }
        }

        if let Some(p) = primary {
            // Only pair DOS name if it belongs to the same parent directory,
            // avoiding cross-contamination across hard links.
            let matched_dos = dos.filter(|d| {
                primary_parent == Some(d.parent_directory_reference().file_record_number())
            });
            Some(Ok(NtfsFileNamePair {
                primary: p,
                short_name: matched_dos,
            }))
        } else {
            // No Win32/Posix name found — fall back to DOS name if available.
            dos.map(|d| {
                Ok(NtfsFileNamePair {
                    primary: d,
                    short_name: None,
                })
            })
        }
    }

    /// Returns the parent directory reference from the first `$FILE_NAME` attribute.
    ///
    /// A file may have multiple `$FILE_NAME` attributes (from hard links); this returns
    /// the `parent_directory_reference` from the first one found. Callers needing all
    /// parents can iterate `$FILE_NAME` attributes directly via [`NtfsFile::name`].
    ///
    /// Returns `Err(AttributeNotFound)` if the file has no `$FILE_NAME` attribute.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn parent_reference<T>(&self, fs: &mut T) -> Result<NtfsFileReference>
    where
        T: Read + Seek,
    {
        let file_name = self
            .name(fs, None, None)
            .ok_or(NtfsError::AttributeNotFound {
                position: self.position(),
                ty: NtfsAttributeType::FileName,
            })??;

        Ok(file_name.parent_directory_reference())
    }

    /// Convenience function to get the $`REPARSE_POINT` attribute of this file
    /// (see [`NtfsReparsePoint`]).
    ///
    /// Returns `None` if this file does not have a $`REPARSE_POINT` attribute.
    ///
    /// This internally calls [`NtfsFile::attributes`] to iterate through the file's
    /// attributes and pick up the first $`REPARSE_POINT` attribute.
    ///
    /// [`NtfsReparsePoint`]: crate::structured_values::NtfsReparsePoint
    pub fn reparse_point<T>(&self, fs: &mut T) -> Option<Result<NtfsReparsePoint>>
    where
        T: Read + Seek,
    {
        let mut iter = self.attributes();

        while let Some(item) = iter_try!(iter.try_next(fs)) {
            let attribute = iter_try!(item.to_attribute());

            let ty = iter_try!(attribute.ty());
            if ty != NtfsAttributeType::ReparsePoint {
                continue;
            }

            return Some(attribute.structured_value::<_, NtfsReparsePoint>(fs));
        }

        None
    }

    /// Returns the [`Ntfs`] object reference associated to this file.
    #[must_use]
    pub fn ntfs(&self) -> &'n Ntfs {
        self.ntfs
    }

    /// Returns the absolute byte position of this File Record in the NTFS filesystem.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.record.position()
    }

    pub(crate) fn record_data(&self) -> &[u8] {
        self.record.data()
    }

    /// Returns the sequence number of this file.
    ///
    /// NTFS reuses records of deleted files when new files are created.
    /// This number is incremented every time a file is deleted.
    /// Hence, it gives a count how many time this File Record has been reused.
    #[must_use]
    pub fn sequence_number(&self) -> u16 {
        let start = offset_of!(FileRecordHeader, sequence_number);
        u16::from_le_bytes(validated_record_bytes(self.record.data(), start))
    }

    fn validate_signature(record: &Record) -> Result<()> {
        let signature = record.signature()?;
        let expected = b"FILE";

        if &signature == expected {
            Ok(())
        } else {
            Err(NtfsError::InvalidFileSignature {
                position: record.position(),
                expected,
                actual: signature,
            })
        }
    }

    fn validate_sizes(&self) -> Result<()> {
        let allocated_size =
            usize::try_from(self.allocated_size()).map_err(|_| IoError::invalid_input())?;
        if allocated_size > self.record.len() {
            return Err(NtfsError::InvalidFileAllocatedSize {
                position: self.record.position(),
                expected: allocated_size,
                actual: self.record.len(),
            });
        }

        if self.data_size() > self.allocated_size() {
            return Err(NtfsError::InvalidFileUsedSize {
                position: self.record.position(),
                expected: self.data_size(),
                actual: self.allocated_size(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod synthetic;

#[cfg(test)]
#[path = "../file_tests/mod.rs"]
mod tests;
