use core::cmp::Ordering;
use core::fmt;
use core::num::NonZeroU64;

use alloc::vec;
use alloc::vec::Vec;
use bitflags::bitflags;
use memoffset::offset_of;
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
use fs_common::iter::FsTryIterator;

/// A list of standardized NTFS File Record Numbers.
///
/// Most of these files store internal NTFS housekeeping information.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/index.html>
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
    /// The $UpCase file that contains a table of all uppercase characters for the
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
/// have a single Win32AndDos entry instead (in which case [`short_name`] is `None`).
///
/// Use [`NtfsFile::name_pair`] to obtain this structure.
///
/// [`short_name`]: NtfsFileNamePair::short_name
#[derive(Clone, Debug)]
pub struct NtfsFileNamePair {
    /// The primary (long) name — Win32, Posix, or Win32AndDos namespace.
    pub primary: NtfsFileName,
    /// The DOS 8.3 short name, if a separate one exists.
    ///
    /// This is `None` when the primary name is in the Win32AndDos namespace
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
        let mut data = vec![0; ntfs.file_record_size() as usize];
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
    pub fn allocated_size(&self) -> u32 {
        let start = offset_of!(FileRecordHeader, allocated_size);
        u32::from_le_bytes(*self.record.data()[start..].first_chunk().unwrap())
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
    pub fn attributes<'f>(&'f self) -> NtfsAttributes<'n, 'f> {
        NtfsAttributes::<'n, 'f>::new(self)
    }

    /// Returns an iterator over all top-level attributes of this file.
    ///
    /// Contrary to [`NtfsFile::attributes`], it does not traverse $ATTRIBUTE_LIST attributes, but returns
    /// them as raw attributes.
    /// Check that function if you want an iterator providing a flattened "data-centric" view over
    /// the attributes by traversing Attribute Lists automatically.
    ///
    /// The iterator returns an [`NtfsAttribute`] for each entry.
    ///
    /// [`NtfsAttribute`]: crate::NtfsAttribute
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
    pub fn data_size(&self) -> u32 {
        let start = offset_of!(FileRecordHeader, data_size);
        u32::from_le_bytes(*self.record.data()[start..].first_chunk().unwrap())
    }

    /// Convenience function to return an [`NtfsIndex`] if this file is a directory.
    /// This structure can be used to iterate over all files of this directory or a find a specific one.
    ///
    /// Apart from any propagated error, this function may return [`NtfsError::NotADirectory`]
    /// if this [`NtfsFile`] is not a directory.
    ///
    /// If you need more control over the picked up $INDEX_ROOT and $INDEX_ALLOCATION attributes
    /// you can use [`NtfsFile::attributes`] to iterate over all attributes of this file.
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

        NtfsIndex::<E>::new(self.ntfs(), index_root_item, index_allocation_item, fs)
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
                    Err(_) => continue,
                }
            }
        }

        Ok(recovered)
    }

    /// Returns the NTFS File Record Number of this file.
    ///
    /// This number uniquely identifies this file and can be used to recreate this [`NtfsFile`]
    /// object via [`Ntfs::file`].
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
        u16::from_le_bytes(*self.record.data()[start..].first_chunk().unwrap())
    }

    /// Returns flags set for this file as specified by [`NtfsFileFlags`].
    pub fn flags(&self) -> NtfsFileFlags {
        let start = offset_of!(FileRecordHeader, flags);
        NtfsFileFlags::from_bits_truncate(u16::from_le_bytes(
            *self.record.data()[start..].first_chunk().unwrap(),
        ))
    }

    /// Returns the number of hard links to this NTFS File Record.
    pub fn hard_link_count(&self) -> u16 {
        let start = offset_of!(FileRecordHeader, hard_link_count);
        u16::from_le_bytes(*self.record.data()[start..].first_chunk().unwrap())
    }

    /// Convenience function to get the $STANDARD_INFORMATION attribute of this file
    /// (see [`NtfsStandardInformation`]).
    ///
    /// This internally calls [`NtfsFile::attributes_raw`] to iterate through the file's
    /// attributes and pick up the first $STANDARD_INFORMATION attribute.
    pub fn info(&self) -> Result<NtfsStandardInformation> {
        self.find_resident_attribute_structured_value::<NtfsStandardInformation>(None)
    }

    /// Returns whether this NTFS File Record represents a directory.
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
    pub fn is_system_metafile(&self) -> bool {
        self.file_record_number < 24
    }

    /// Convenience function to get a $FILE_NAME attribute of this file (see [`NtfsFileName`]).
    ///
    /// A file may have multiple $FILE_NAME attributes for each [`NtfsFileNamespace`].
    /// Files with hard links have further $FILE_NAME attributes for each directory they are in.
    /// You may optionally filter for a namespace and parent directory via the parameters.
    ///
    /// This internally calls [`NtfsFile::attributes`] to iterate through the file's
    /// attributes and pick up the first matching $FILE_NAME attribute.
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
    /// Returns an [`NtfsFileNamePair`] containing the primary (Win32, Posix, or Win32AndDos)
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

    /// Convenience function to get the $REPARSE_POINT attribute of this file
    /// (see [`NtfsReparsePoint`]).
    ///
    /// Returns `None` if this file does not have a $REPARSE_POINT attribute.
    ///
    /// This internally calls [`NtfsFile::attributes`] to iterate through the file's
    /// attributes and pick up the first $REPARSE_POINT attribute.
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
    pub fn ntfs(&self) -> &'n Ntfs {
        self.ntfs
    }

    /// Returns the absolute byte position of this File Record in the NTFS filesystem.
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
    pub fn sequence_number(&self) -> u16 {
        let start = offset_of!(FileRecordHeader, sequence_number);
        u16::from_le_bytes(*self.record.data()[start..].first_chunk().unwrap())
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
        if self.allocated_size() > self.record.len() {
            return Err(NtfsError::InvalidFileAllocatedSize {
                position: self.record.position(),
                expected: self.allocated_size(),
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
pub(crate) mod synthetic {
    //! Synthetic NTFS image construction for tests.
    //!
    //! Builds a self-consistent in-memory NTFS volume (boot sector + a
    //! single FILE record placed at a known cluster) so that
    //! [`NtfsFile::new`] can load and parse a record without a real
    //! filesystem image. Records carry hand-built resident attributes.

    use alloc::vec;
    use alloc::vec::Vec;
    use std::io::Cursor;

    use crate::attribute::NtfsAttributeType;
    use crate::ntfs::Ntfs;

    use super::NtfsFile;

    pub(crate) const SECTOR_SIZE: usize = 512;
    pub(crate) const RECORD_SIZE: usize = 1024;
    /// LCN where the synthetic FILE record lives (cluster size == sector size == 512,
    /// so this is byte offset 8 * 512 = 4096).
    pub(crate) const RECORD_LCN: u64 = 8;
    pub(crate) const RECORD_POSITION: u64 = RECORD_LCN * SECTOR_SIZE as u64;

    /// Builds a 512-byte NTFS boot sector with sector_size=512,
    /// sectors_per_cluster=1, 1024-byte file records, and a small volume.
    pub(crate) fn boot_sector() -> [u8; SECTOR_SIZE] {
        let mut bs = [0u8; SECTOR_SIZE];
        bs[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        bs[3..11].copy_from_slice(b"NTFS    "); // OEM ID
        bs[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
        bs[0x0D] = 1; // sectors per cluster
        bs[0x28..0x30].copy_from_slice(&4096u64.to_le_bytes()); // total sectors
        bs[0x30..0x38].copy_from_slice(&2u64.to_le_bytes()); // MFT LCN (byte 1024)
        bs[0x38..0x40].copy_from_slice(&64u64.to_le_bytes()); // MFT mirror LCN (byte 32768)
        bs[0x40] = 0xF6; // clusters_per_mft_record = -10 => 2^10 = 1024-byte records
        bs[0x48..0x50].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes()); // serial
        bs[510] = 0x55;
        bs[511] = 0xAA;
        bs
    }

    /// A resident attribute to embed in a synthetic FILE record.
    pub(crate) struct ResidentAttr {
        pub ty: NtfsAttributeType,
        pub instance: u16,
        pub name: &'static str,
        pub value: Vec<u8>,
    }

    /// Encodes one resident attribute (header + optional name + value).
    fn encode_resident(attr: &ResidentAttr) -> Vec<u8> {
        let name_utf16: Vec<u8> = attr
            .name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let name_offset = 24usize; // resident header is 24 bytes
        let value_offset = name_offset + name_utf16.len();
        // 8-byte align the total length.
        let unpadded = value_offset + attr.value.len();
        let length = unpadded.div_ceil(8) * 8;

        let mut buf = vec![0u8; length];
        buf[0..4].copy_from_slice(&(attr.ty as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        buf[8] = 0; // is_non_resident = 0 (resident)
        buf[9] = (attr.name.encode_utf16().count()) as u8; // name_length (code points)
        buf[10..12].copy_from_slice(&(name_offset as u16).to_le_bytes());
        buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // flags
        buf[14..16].copy_from_slice(&attr.instance.to_le_bytes());
        // Resident-specific:
        buf[16..20].copy_from_slice(&(attr.value.len() as u32).to_le_bytes()); // value_length
        buf[20..22].copy_from_slice(&(value_offset as u16).to_le_bytes()); // value_offset
        buf[22] = 0; // indexed_flag
        buf[name_offset..name_offset + name_utf16.len()].copy_from_slice(&name_utf16);
        buf[value_offset..value_offset + attr.value.len()].copy_from_slice(&attr.value);
        buf
    }

    /// Builds a complete 1024-byte FILE record carrying the supplied
    /// resident attributes, then applies a valid Update Sequence Array
    /// so [`crate::record::Record::fixup`] succeeds.
    ///
    /// `flags` are the [`super::NtfsFileFlags`] bits; `seq` the sequence
    /// number; `hard_links` the hard-link count.
    pub(crate) fn file_record(
        flags: u16,
        seq: u16,
        hard_links: u16,
        attrs: &[ResidentAttr],
    ) -> [u8; RECORD_SIZE] {
        let mut rec = [0u8; RECORD_SIZE];

        // --- FILE record header ---
        rec[0..4].copy_from_slice(b"FILE");
        let usa_offset = 0x30u16; // update sequence array offset
        rec[4..6].copy_from_slice(&usa_offset.to_le_bytes());
        // update_sequence_count = 1 (USN) + 2 fixup entries (two 512-byte sectors).
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        rec[8..16].copy_from_slice(&0u64.to_le_bytes()); // logfile sequence number

        rec[16..18].copy_from_slice(&seq.to_le_bytes()); // sequence_number
        rec[18..20].copy_from_slice(&hard_links.to_le_bytes()); // hard_link_count
        let first_attr_offset = 0x38u16;
        rec[20..22].copy_from_slice(&first_attr_offset.to_le_bytes()); // first_attribute_offset
        rec[22..24].copy_from_slice(&flags.to_le_bytes()); // flags

        // --- attributes (start at first_attr_offset) ---
        let mut off = first_attr_offset as usize;
        for attr in attrs {
            let encoded = encode_resident(attr);
            rec[off..off + encoded.len()].copy_from_slice(&encoded);
            off += encoded.len();
        }
        // End marker.
        rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let used = off + 8;

        // data_size (used) and allocated_size (whole record).
        rec[24..28].copy_from_slice(&(used as u32).to_le_bytes()); // data_size
        rec[28..32].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes()); // allocated_size

        // --- Update Sequence Array fixup ---
        // USN value (0x0001) followed by the two real bytes per sector.
        let usn: u16 = 0x0001;
        let usa = usa_offset as usize;
        rec[usa..usa + 2].copy_from_slice(&usn.to_le_bytes()); // USN
        // Save the genuine sector-end bytes into the array, then stamp the USN
        // into the last 2 bytes of each sector so fixup validates and restores.
        for (i, sector_end) in [SECTOR_SIZE - 2, 2 * SECTOR_SIZE - 2]
            .into_iter()
            .enumerate()
        {
            let real = [rec[sector_end], rec[sector_end + 1]];
            let entry = usa + 2 + i * 2;
            rec[entry..entry + 2].copy_from_slice(&real);
            rec[sector_end..sector_end + 2].copy_from_slice(&usn.to_le_bytes());
        }
        rec
    }

    /// Builds a `$FILE_NAME` attribute value with the given parent record
    /// number, namespace byte, and UTF-16 name. Header layout matches
    /// `FileNameHeader` (66-byte header, then the name).
    pub(crate) fn file_name_value(
        parent_record: u64,
        parent_sequence: u16,
        namespace: u8,
        is_directory: bool,
        name: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut v = vec![0u8; 66 + name_utf16.len()];
        // parent_directory_reference: record (48-bit) | (seq << 48)
        let parent_ref = (parent_record & 0xFFFF_FFFF_FFFF) | ((parent_sequence as u64) << 48);
        v[0..8].copy_from_slice(&parent_ref.to_le_bytes());
        // file_attributes at offset 56 (8+32+8+8).
        let file_attributes: u32 = if is_directory { 0x1000_0000 } else { 0x20 };
        v[56..60].copy_from_slice(&file_attributes.to_le_bytes());
        v[64] = name.encode_utf16().count() as u8; // name_length (code points)
        v[65] = namespace;
        v[66..66 + name_utf16.len()].copy_from_slice(&name_utf16);
        v
    }

    /// Builds a `$I30` `$INDEX_ROOT` attribute value holding a single
    /// FILE_NAME entry for `child` (record number, name, directory flag),
    /// followed by the empty LAST_ENTRY terminator. The index is "small"
    /// (no `$INDEX_ALLOCATION`).
    pub(crate) fn index_root_i30_value(
        child_record: u64,
        child_is_directory: bool,
        child_name: &str,
    ) -> Vec<u8> {
        // FILE_NAME key for the entry.
        let key = file_name_value(5, 1, 1, child_is_directory, child_name);
        let entry_header = 16usize;
        let entry1_len = (entry_header + key.len()).div_ceil(8) * 8;
        let term_len = 16usize; // LAST_ENTRY terminator (header only)

        let node_header = 16usize;
        let entries_offset = node_header; // entries start right after node header
        let index_size = entries_offset + entry1_len + term_len; // used bytes in node
        let allocated_size = index_size;

        let mut v = vec![0u8; 16 + index_size];
        // IndexRootHeader.
        v[0..4].copy_from_slice(&(NtfsAttributeType::FileName as u32).to_le_bytes()); // ty
        v[4..8].copy_from_slice(&0x01u32.to_le_bytes()); // collation_rule
        v[8..12].copy_from_slice(&4096u32.to_le_bytes()); // index_record_size
        v[12] = 1; // clusters_per_index_record
        // IndexNodeHeader (at offset 16).
        let n = 16usize;
        v[n..n + 4].copy_from_slice(&(entries_offset as u32).to_le_bytes()); // entries_offset
        v[n + 4..n + 8].copy_from_slice(&(index_size as u32).to_le_bytes()); // index_size
        v[n + 8..n + 12].copy_from_slice(&(allocated_size as u32).to_le_bytes()); // allocated_size
        v[n + 12] = 0; // flags (small index)

        // Entry 1 (real FILE_NAME entry) at offset 16 + entries_offset.
        let e1 = 16 + entries_offset;
        let file_ref = (child_record & 0xFFFF_FFFF_FFFF) | (1u64 << 48);
        v[e1..e1 + 8].copy_from_slice(&file_ref.to_le_bytes()); // file reference
        v[e1 + 8..e1 + 10].copy_from_slice(&(entry1_len as u16).to_le_bytes()); // index_entry_length
        v[e1 + 10..e1 + 12].copy_from_slice(&(key.len() as u16).to_le_bytes()); // key_length
        v[e1 + 12] = 0; // flags
        v[e1 + entry_header..e1 + entry_header + key.len()].copy_from_slice(&key);

        // Terminator entry (LAST_ENTRY, no key).
        let e2 = e1 + entry1_len;
        v[e2 + 8..e2 + 10].copy_from_slice(&(term_len as u16).to_le_bytes()); // index_entry_length
        v[e2 + 10..e2 + 12].copy_from_slice(&0u16.to_le_bytes()); // key_length
        v[e2 + 12] = 0x02; // flags = LAST_ENTRY
        v
    }

    /// Builds a directory FILE record (IS_DIRECTORY) carrying a `$I30`
    /// `$INDEX_ROOT` attribute with a single child entry.
    pub(crate) fn directory_record(
        child_record: u64,
        child_is_directory: bool,
        child_name: &str,
    ) -> [u8; RECORD_SIZE] {
        let index_root = index_root_i30_value(child_record, child_is_directory, child_name);
        let attrs = [ResidentAttr {
            ty: NtfsAttributeType::IndexRoot,
            instance: 0,
            name: "$I30",
            value: index_root,
        }];
        file_record(0x0003, 1, 1, &attrs) // IN_USE | IS_DIRECTORY
    }

    /// Loads a synthetic FILE record into an [`Ntfs`] + [`NtfsFile`] pair.
    ///
    /// Returns a leaked `Ntfs` reference so the returned file can outlive
    /// the call; acceptable in test code.
    pub(crate) fn load(record: &[u8; RECORD_SIZE], record_number: u64) -> (Ntfs, Cursor<Vec<u8>>) {
        let mut image = vec![0u8; RECORD_POSITION as usize + RECORD_SIZE];
        image[..SECTOR_SIZE].copy_from_slice(&boot_sector());
        image[RECORD_POSITION as usize..RECORD_POSITION as usize + RECORD_SIZE]
            .copy_from_slice(record);
        let mut cursor = Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let _ = record_number;
        (ntfs, cursor)
    }

    /// Encodes one non-resident attribute carrying a single data run that
    /// maps `cluster_count` clusters starting at absolute `start_lcn`.
    fn encode_non_resident(
        ty: NtfsAttributeType,
        start_lcn: u64,
        cluster_count: u64,
        data_size: u64,
    ) -> Vec<u8> {
        let header_size = 64usize; // NtfsNonResidentAttributeHeader size
        // Single data run: header byte = (vcn_len << 4) | cc_len, then
        // cluster_count bytes (LE) then vcn bytes (signed LE), then 0 terminator.
        let cc_bytes = start_lcn_bytes(cluster_count);
        let vcn_bytes = start_lcn_bytes(start_lcn);
        let mut data_run = Vec::new();
        data_run.push(((vcn_bytes.len() as u8) << 4) | cc_bytes.len() as u8);
        data_run.extend_from_slice(&cc_bytes);
        data_run.extend_from_slice(&vcn_bytes);
        data_run.push(0); // terminator

        let data_runs_offset = header_size;
        let unpadded = data_runs_offset + data_run.len();
        let length = unpadded.div_ceil(8) * 8;

        let mut buf = vec![0u8; length];
        buf[0..4].copy_from_slice(&(ty as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        buf[8] = 1; // is_non_resident = 1
        buf[9] = 0; // name_length
        buf[10..12].copy_from_slice(&0u16.to_le_bytes()); // name_offset
        buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // flags
        buf[14..16].copy_from_slice(&0u16.to_le_bytes()); // instance
        // Non-resident header fields (start at offset 16):
        buf[16..24].copy_from_slice(&0u64.to_le_bytes()); // lowest_vcn
        let highest_vcn = cluster_count.saturating_sub(1);
        buf[24..32].copy_from_slice(&highest_vcn.to_le_bytes()); // highest_vcn
        buf[32..34].copy_from_slice(&(data_runs_offset as u16).to_le_bytes()); // data_runs_offset
        buf[34] = 0; // compression_unit_exponent
        // reserved [35..40]
        let allocated = cluster_count * SECTOR_SIZE as u64; // cluster size == sector size
        buf[40..48].copy_from_slice(&allocated.to_le_bytes()); // allocated_size
        buf[48..56].copy_from_slice(&data_size.to_le_bytes()); // data_size
        buf[56..64].copy_from_slice(&data_size.to_le_bytes()); // initialized_size
        buf[data_runs_offset..data_runs_offset + data_run.len()].copy_from_slice(&data_run);
        buf
    }

    /// Minimal little-endian byte encoding of a value (at least 1 byte).
    fn start_lcn_bytes(value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![0];
        }
        let mut bytes = value.to_le_bytes().to_vec();
        while bytes.len() > 1 && *bytes.last().unwrap() == 0 {
            bytes.pop();
        }
        bytes
    }

    /// Builds a $MFT record (record 0) whose non-resident $DATA attribute
    /// maps `record_count` 1024-byte records starting at the MFT LCN (2).
    fn mft_record(record_count: u64) -> [u8; RECORD_SIZE] {
        let mft_lcn = 2u64;
        let clusters = record_count * (RECORD_SIZE as u64 / SECTOR_SIZE as u64);
        let data_size = record_count * RECORD_SIZE as u64;
        let data_attr = encode_non_resident(NtfsAttributeType::Data, mft_lcn, clusters, data_size);

        let mut rec = [0u8; RECORD_SIZE];
        rec[0..4].copy_from_slice(b"FILE");
        let usa_offset = 0x30u16;
        rec[4..6].copy_from_slice(&usa_offset.to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        rec[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence_number
        rec[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard_link_count
        let first_attr_offset = 0x38u16;
        rec[20..22].copy_from_slice(&first_attr_offset.to_le_bytes());
        rec[22..24].copy_from_slice(&0x0001u16.to_le_bytes()); // IN_USE

        let mut off = first_attr_offset as usize;
        rec[off..off + data_attr.len()].copy_from_slice(&data_attr);
        off += data_attr.len();
        rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let used = off + 8;
        rec[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        rec[28..32].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes());

        apply_fixup(&mut rec, usa_offset);
        rec
    }

    /// Applies a valid Update Sequence Array to a 1024-byte record.
    fn apply_fixup(rec: &mut [u8; RECORD_SIZE], usa_offset: u16) {
        let usn: u16 = 0x0001;
        let usa = usa_offset as usize;
        rec[usa..usa + 2].copy_from_slice(&usn.to_le_bytes());
        for (i, sector_end) in [SECTOR_SIZE - 2, 2 * SECTOR_SIZE - 2]
            .into_iter()
            .enumerate()
        {
            let real = [rec[sector_end], rec[sector_end + 1]];
            let entry = usa + 2 + i * 2;
            rec[entry..entry + 2].copy_from_slice(&real);
            rec[sector_end..sector_end + 2].copy_from_slice(&usn.to_le_bytes());
        }
    }

    /// Builds a full NTFS image with a working $MFT spanning `records.len()`
    /// records (record 0 is generated as $MFT; the caller-supplied records
    /// fill slots 1..). The MFT lives at LCN 2 and the mirror at LCN 4.
    ///
    /// Returns the image bytes. Use [`Ntfs::new`] then `ntfs.file(fs, n)`.
    pub(crate) fn mft_image(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
        let record_count = (records.len() + 1) as u64;
        let mft_lcn = 2u64;
        let mft_byte = mft_lcn * SECTOR_SIZE as u64;
        let mirror_lcn = 64u64;
        let mirror_byte = mirror_lcn * SECTOR_SIZE as u64;

        // Image must cover the boot sector, the mirror region, and all MFT records.
        let mft_region_end = mft_byte + record_count * RECORD_SIZE as u64;
        let mirror_region_end = mirror_byte + 4 * RECORD_SIZE as u64;
        let size = mft_region_end.max(mirror_region_end) as usize;
        let mut image = vec![0u8; size];
        image[..SECTOR_SIZE].copy_from_slice(&boot_sector());

        // Record 0 = $MFT.
        let mft = mft_record(record_count);
        let base = mft_byte as usize;
        image[base..base + RECORD_SIZE].copy_from_slice(&mft);
        // Records 1.. = caller-supplied.
        for (i, rec) in records.iter().enumerate() {
            let pos = base + (i + 1) * RECORD_SIZE;
            image[pos..pos + RECORD_SIZE].copy_from_slice(rec);
        }
        image
    }

    /// Number of `u16` entries in the `$UpCase` table.
    const UPCASE_ENTRY_COUNT: usize = 65536;
    /// Size of the `$UpCase` table in bytes.
    const UPCASE_BYTES: usize = UPCASE_ENTRY_COUNT * 2;

    /// Builds an NTFS image with a working `$MFT` (records 0..=10) where
    /// record 10 is `$UpCase` with a non-resident `$DATA` mapping an identity
    /// uppercase table. `records` fill slots 1..=9. Enables
    /// [`Ntfs::read_upcase_table`] in tests so case-insensitive comparisons work.
    pub(crate) fn mft_image_with_upcase(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
        assert!(
            records.len() <= 9,
            "records fill slots 1..=9 (record 10 is $UpCase)"
        );
        let mft_lcn = 2u64;
        let mft_byte = mft_lcn as usize * SECTOR_SIZE;
        let record_count = 11u64; // records 0..=10

        // Identity upcase table lives well past the MFT and mirror regions.
        let upcase_lcn = 256u64; // byte 131072
        let upcase_byte = upcase_lcn as usize * SECTOR_SIZE;
        let upcase_clusters = (UPCASE_BYTES as u64).div_ceil(SECTOR_SIZE as u64);

        let size = upcase_byte + UPCASE_BYTES;
        let mut image = vec![0u8; size];
        image[..SECTOR_SIZE].copy_from_slice(&boot_sector());

        // Record 0 = $MFT spanning 11 records.
        image[mft_byte..mft_byte + RECORD_SIZE].copy_from_slice(&mft_record(record_count));
        // Records 1..=9 = caller-supplied (zero-filled if absent; those slots
        // will fail to parse but build/test code only touches the ones it opens).
        for (i, rec) in records.iter().enumerate() {
            let pos = mft_byte + (i + 1) * RECORD_SIZE;
            image[pos..pos + RECORD_SIZE].copy_from_slice(rec);
        }
        // Fill any unused slots 1..=9 with a minimal valid in-use FILE record so
        // ntfs.file() for those numbers (if ever opened) does not error.
        for slot in (records.len() + 1)..=9 {
            let pos = mft_byte + slot * RECORD_SIZE;
            image[pos..pos + RECORD_SIZE].copy_from_slice(&file_record(0x0001, 1, 1, &[]));
        }

        // Record 10 = $UpCase with non-resident $DATA of exactly UPCASE_BYTES.
        let data_attr = encode_non_resident(
            NtfsAttributeType::Data,
            upcase_lcn,
            upcase_clusters,
            UPCASE_BYTES as u64,
        );
        let mut upcase_rec = [0u8; RECORD_SIZE];
        upcase_rec[0..4].copy_from_slice(b"FILE");
        let usa_offset = 0x30u16;
        upcase_rec[4..6].copy_from_slice(&usa_offset.to_le_bytes());
        upcase_rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        upcase_rec[16..18].copy_from_slice(&1u16.to_le_bytes());
        upcase_rec[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr_offset = 0x38u16;
        upcase_rec[20..22].copy_from_slice(&first_attr_offset.to_le_bytes());
        upcase_rec[22..24].copy_from_slice(&0x0001u16.to_le_bytes());
        let mut off = first_attr_offset as usize;
        upcase_rec[off..off + data_attr.len()].copy_from_slice(&data_attr);
        off += data_attr.len();
        upcase_rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let used = off + 8;
        upcase_rec[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        upcase_rec[28..32].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes());
        apply_fixup(&mut upcase_rec, usa_offset);
        let r10 = mft_byte + 10 * RECORD_SIZE;
        image[r10..r10 + RECORD_SIZE].copy_from_slice(&upcase_rec);

        // Identity uppercase table: uppercase[i] == i for every code unit.
        for i in 0..UPCASE_ENTRY_COUNT {
            let b = upcase_byte + i * 2;
            image[b..b + 2].copy_from_slice(&(i as u16).to_le_bytes());
        }
        image
    }

    /// Builds an `Ntfs`, loads the record at `RECORD_POSITION`, and returns
    /// the resulting `NtfsFile`. Panics on parse failure.
    pub(crate) fn open_file<'n>(
        ntfs: &'n Ntfs,
        cursor: &mut Cursor<Vec<u8>>,
        record_number: u64,
    ) -> NtfsFile<'n> {
        use core::num::NonZeroU64;
        NtfsFile::new(
            ntfs,
            cursor,
            NonZeroU64::new(RECORD_POSITION).unwrap(),
            record_number,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;
    use crate::slack_recovery::SlackRecoveryConfig;
    use crate::structured_values::NtfsFileNamespace;
    use fs_common::iter::FsTryIterator;

    use super::synthetic;

    #[test]
    fn test_synthetic_header_accessors() {
        // A directory record (IN_USE | IS_DIRECTORY), seq 7, 3 hard links,
        // with one FILE_NAME attribute so attribute iteration is valid.
        let fname = synthetic::file_name_value(5, 1, 3, true, "dir");
        let attrs = [synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 0,
            name: "",
            value: fname,
        }];
        let record = synthetic::file_record(0x0003, 7, 3, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 42);
        let file = synthetic::open_file(&ntfs, &mut cursor, 42);

        assert_eq!(file.allocated_size(), synthetic::RECORD_SIZE as u32);
        assert_eq!(file.first_attribute_offset(), 0x38);
        assert_eq!(file.sequence_number(), 7);
        assert_eq!(file.hard_link_count(), 3);
        assert_eq!(file.file_record_number(), 42);
        assert!(file.is_directory());
        assert!(file.flags().contains(NtfsFileFlags::IN_USE));
        assert!(file.flags().contains(NtfsFileFlags::IS_DIRECTORY));
        // data_size is the used span; must be > 0 and <= allocated.
        assert!(file.data_size() > 0);
        assert!(file.data_size() <= file.allocated_size());
    }

    #[test]
    fn test_synthetic_non_directory_flags() {
        // IN_USE but not a directory.
        let fname = synthetic::file_name_value(5, 1, 1, false, "file.txt");
        let attrs = [synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 0,
            name: "",
            value: fname,
        }];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        assert!(!file.is_directory());
        assert!(file.flags().contains(NtfsFileFlags::IN_USE));
    }

    #[test]
    fn test_synthetic_is_system_metafile() {
        let record = synthetic::file_record(0x0001, 1, 1, &[]);

        // Record 23 is the last system metafile (< 24).
        let (ntfs, mut cursor) = synthetic::load(&record, 23);
        let file = synthetic::open_file(&ntfs, &mut cursor, 23);
        assert!(file.is_system_metafile());

        // Record 24 is the first non-system file.
        let (ntfs, mut cursor) = synthetic::load(&record, 24);
        let file = synthetic::open_file(&ntfs, &mut cursor, 24);
        assert!(!file.is_system_metafile());

        // Record 0 ($MFT) is a system metafile.
        let (ntfs, mut cursor) = synthetic::load(&record, 0);
        let file = synthetic::open_file(&ntfs, &mut cursor, 0);
        assert!(file.is_system_metafile());
    }

    #[test]
    fn test_synthetic_validate_signature_rejects_bad() {
        use core::num::NonZeroU64;
        // Corrupt the FILE signature; NtfsFile::new must reject it.
        let mut record = synthetic::file_record(0x0001, 1, 1, &[]);
        record[0..4].copy_from_slice(b"BAAD");
        let mut image = vec![0u8; synthetic::RECORD_POSITION as usize + synthetic::RECORD_SIZE];
        image[..synthetic::SECTOR_SIZE].copy_from_slice(&synthetic::boot_sector());
        image[synthetic::RECORD_POSITION as usize..].copy_from_slice(&record);
        let mut cursor = std::io::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let result = NtfsFile::new(
            &ntfs,
            &mut cursor,
            NonZeroU64::new(synthetic::RECORD_POSITION).unwrap(),
            1,
        );
        assert!(matches!(
            result.unwrap_err(),
            NtfsError::InvalidFileSignature { .. }
        ));
    }

    #[test]
    fn test_synthetic_validate_sizes_rejects_oversized_allocated() {
        use core::num::NonZeroU64;
        // allocated_size larger than the record must be rejected.
        let mut record = synthetic::file_record(0x0001, 1, 1, &[]);
        // allocated_size at offset 28: set to record_size + 512 (too big).
        record[28..32].copy_from_slice(&((synthetic::RECORD_SIZE as u32) + 512).to_le_bytes());
        // Repair fixup: the byte at 510 / 1022 may have changed; rebuild USA.
        // Offset 28 is in sector 0, not at a sector end, so USA stays valid.
        let mut image = vec![0u8; synthetic::RECORD_POSITION as usize + synthetic::RECORD_SIZE];
        image[..synthetic::SECTOR_SIZE].copy_from_slice(&synthetic::boot_sector());
        image[synthetic::RECORD_POSITION as usize..].copy_from_slice(&record);
        let mut cursor = std::io::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let result = NtfsFile::new(
            &ntfs,
            &mut cursor,
            NonZeroU64::new(synthetic::RECORD_POSITION).unwrap(),
            1,
        );
        assert!(matches!(
            result.unwrap_err(),
            NtfsError::InvalidFileAllocatedSize { .. }
        ));
    }

    #[test]
    fn test_synthetic_validate_sizes_rejects_data_gt_allocated() {
        use core::num::NonZeroU64;
        // data_size > allocated_size must be rejected (second check in validate_sizes).
        let mut record = synthetic::file_record(0x0001, 1, 1, &[]);
        // allocated_size = 512 (fits the record), data_size = 600 (> allocated).
        record[28..32].copy_from_slice(&512u32.to_le_bytes());
        record[24..28].copy_from_slice(&600u32.to_le_bytes());
        let mut image = vec![0u8; synthetic::RECORD_POSITION as usize + synthetic::RECORD_SIZE];
        image[..synthetic::SECTOR_SIZE].copy_from_slice(&synthetic::boot_sector());
        image[synthetic::RECORD_POSITION as usize..].copy_from_slice(&record);
        let mut cursor = std::io::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let result = NtfsFile::new(
            &ntfs,
            &mut cursor,
            NonZeroU64::new(synthetic::RECORD_POSITION).unwrap(),
            1,
        );
        assert!(matches!(
            result.unwrap_err(),
            NtfsError::InvalidFileUsedSize { .. }
        ));
    }

    #[test]
    fn test_synthetic_validate_sizes_accepts_equal_boundaries() {
        use core::num::NonZeroU64;
        // allocated_size == record len and data_size == allocated_size are
        // both accepted (boundary `>` not `>=`).
        let mut record = synthetic::file_record(0x0001, 1, 1, &[]);
        record[28..32].copy_from_slice(&(synthetic::RECORD_SIZE as u32).to_le_bytes());
        record[24..28].copy_from_slice(&(synthetic::RECORD_SIZE as u32).to_le_bytes());
        let mut image = vec![0u8; synthetic::RECORD_POSITION as usize + synthetic::RECORD_SIZE];
        image[..synthetic::SECTOR_SIZE].copy_from_slice(&synthetic::boot_sector());
        image[synthetic::RECORD_POSITION as usize..].copy_from_slice(&record);
        let mut cursor = std::io::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let file = NtfsFile::new(
            &ntfs,
            &mut cursor,
            NonZeroU64::new(synthetic::RECORD_POSITION).unwrap(),
            1,
        )
        .unwrap();
        assert_eq!(file.allocated_size(), synthetic::RECORD_SIZE as u32);
        assert_eq!(file.data_size(), synthetic::RECORD_SIZE as u32);
    }

    #[test]
    fn test_synthetic_data_attribute_lookup() {
        // Two $DATA attributes: unnamed (empty name) and "stream2".
        let attrs = [
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 0,
                name: "",
                value: vec![0xAA; 8],
            },
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 1,
                name: "stream2",
                value: vec![0xBB; 4],
            },
        ];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (mut ntfs, mut cursor) = synthetic::load(&record, 30);
        ntfs.read_upcase_table(&mut cursor).ok(); // best-effort; not present, falls back

        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        // Unnamed $DATA exists and is found (no upcase needed).
        let unnamed = file.data(&mut cursor, "").unwrap().unwrap();
        let attr = unnamed.to_attribute().unwrap();
        assert_eq!(attr.ty().unwrap(), NtfsAttributeType::Data);
        assert!(attr.name().unwrap().is_empty());
    }

    #[test]
    fn test_synthetic_data_named_stream_lookup() {
        // A file (record 1) with two $DATA streams: unnamed and "stream2".
        // Looking up by a non-empty name exercises the case-insensitive
        // `upcase_cmp(...) == Ordering::Equal` path (line 247), which needs
        // the $UpCase table loaded.
        let attrs = [
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 0,
                name: "",
                value: vec![0xAA; 8],
            },
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 1,
                name: "stream2",
                value: vec![0xBB; 4],
            },
        ];
        let file_record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let image = synthetic::mft_image_with_upcase(&[file_record]);
        let mut cursor = std::io::Cursor::new(image);
        let mut ntfs = Ntfs::new(&mut cursor).unwrap();
        ntfs.read_upcase_table(&mut cursor)
            .expect("synthetic $UpCase must load");

        let file = ntfs.file(&mut cursor, 1).unwrap();

        // The named stream is found via case-insensitive comparison
        // (lowercase query matches the stored lowercase name with an identity
        // upcase table).
        let named = file.data(&mut cursor, "stream2").unwrap().unwrap();
        let attr = named.to_attribute().unwrap();
        assert_eq!(attr.name().unwrap(), "stream2");

        // A non-matching name returns None (the `== Equal` comparison fails).
        assert!(file.data(&mut cursor, "no_such_stream").is_none());
    }

    #[test]
    fn test_synthetic_data_attribute_absent_returns_none() {
        // A record with only a FILE_NAME attribute has no $DATA.
        let fname = synthetic::file_name_value(5, 1, 1, false, "x");
        let attrs = [synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 0,
            name: "",
            value: fname,
        }];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        assert!(file.data(&mut cursor, "").is_none());
    }

    #[test]
    fn test_synthetic_name_lookup() {
        // FILE_NAME with Win32 namespace, parent record 5.
        let fname = synthetic::file_name_value(5, 1, 1, false, "hello.txt");
        let attrs = [synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 0,
            name: "",
            value: fname,
        }];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        let name = file.name(&mut cursor, None, None).unwrap().unwrap();
        assert_eq!(name.name().to_string().unwrap(), "hello.txt");
        assert_eq!(name.namespace(), NtfsFileNamespace::Win32);
        assert_eq!(name.parent_directory_reference().file_record_number(), 5);

        // Filtering by the matching namespace finds it.
        assert!(
            file.name(&mut cursor, Some(NtfsFileNamespace::Win32), None)
                .is_some()
        );
        // Filtering by a non-matching namespace finds nothing.
        assert!(
            file.name(&mut cursor, Some(NtfsFileNamespace::Dos), None)
                .is_none()
        );
        // Filtering by the matching parent record finds it.
        assert!(file.name(&mut cursor, None, Some(5)).is_some());
        // Filtering by a non-matching parent record finds nothing.
        assert!(file.name(&mut cursor, None, Some(99)).is_none());
    }

    #[test]
    fn test_synthetic_name_absent_returns_none() {
        // A record with only a $DATA attribute has no FILE_NAME.
        let attrs = [synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 0,
            name: "",
            value: vec![0u8; 4],
        }];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);
        assert!(file.name(&mut cursor, None, None).is_none());
    }

    #[test]
    fn test_synthetic_name_pair_separate_win32_and_dos() {
        // Win32 long name + DOS short name with the same parent => paired.
        let win32 = synthetic::file_name_value(5, 1, 1, false, "longname.txt");
        let dos = synthetic::file_name_value(5, 1, 2, false, "LONGNA~1.TXT");
        let attrs = [
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::FileName,
                instance: 0,
                name: "",
                value: win32,
            },
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::FileName,
                instance: 1,
                name: "",
                value: dos,
            },
        ];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        let pair = file.name_pair(&mut cursor, None).unwrap().unwrap();
        assert_eq!(pair.primary.name().to_string().unwrap(), "longname.txt");
        let short = pair.short_name.expect("expected a DOS short name");
        assert_eq!(short.name().to_string().unwrap(), "LONGNA~1.TXT");
    }

    #[test]
    fn test_synthetic_name_pair_dos_belongs_to_other_parent() {
        // Win32 (parent 5) + DOS (parent 9) => DOS must NOT be paired
        // (different parent directory). Exercises the `==` filter at line 730.
        let win32 = synthetic::file_name_value(5, 1, 1, false, "longname.txt");
        let dos = synthetic::file_name_value(9, 1, 2, false, "LONGNA~1.TXT");
        let attrs = [
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::FileName,
                instance: 0,
                name: "",
                value: win32,
            },
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::FileName,
                instance: 1,
                name: "",
                value: dos,
            },
        ];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        let pair = file.name_pair(&mut cursor, None).unwrap().unwrap();
        assert_eq!(pair.primary.name().to_string().unwrap(), "longname.txt");
        assert!(
            pair.short_name.is_none(),
            "DOS name for a different parent must not be paired"
        );
    }

    #[test]
    fn test_synthetic_name_pair_combined_win32anddos() {
        // A single Win32AndDos entry => primary set, no separate short name.
        let combined = synthetic::file_name_value(5, 1, 3, false, "FILE.TXT");
        let attrs = [synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 0,
            name: "",
            value: combined,
        }];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        let pair = file.name_pair(&mut cursor, None).unwrap().unwrap();
        assert_eq!(pair.primary.name().to_string().unwrap(), "FILE.TXT");
        assert!(pair.primary.namespace().is_combined());
        assert!(pair.short_name.is_none());
    }

    #[test]
    fn test_synthetic_name_pair_parent_filter() {
        // A Win32 name with parent record 5. Filtering name_pair by the
        // matching parent (5) returns the pair; filtering by a different
        // parent (99) returns None. Guards the `!= parent_record_number`
        // filter at line 702.
        let win32 = synthetic::file_name_value(5, 1, 1, false, "longname.txt");
        let attrs = [synthetic::ResidentAttr {
            ty: NtfsAttributeType::FileName,
            instance: 0,
            name: "",
            value: win32,
        }];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        // Matching parent => Some.
        let pair = file.name_pair(&mut cursor, Some(5)).unwrap().unwrap();
        assert_eq!(pair.primary.name().to_string().unwrap(), "longname.txt");

        // Non-matching parent => None (the only FILE_NAME is skipped).
        assert!(file.name_pair(&mut cursor, Some(99)).is_none());
    }

    #[test]
    fn test_synthetic_reparse_point_found_and_absent() {
        // Microsoft mount-point tag (0xA0000003), 0 data bytes => parses.
        let mut reparse = vec![0u8; 8];
        reparse[0..4].copy_from_slice(&0xA000_0003u32.to_le_bytes()); // reparse_tag
        reparse[4..6].copy_from_slice(&0u16.to_le_bytes()); // reparse_data_length
        let attrs = [
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 0,
                name: "",
                value: vec![0u8; 4],
            },
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::ReparsePoint,
                instance: 1,
                name: "",
                value: reparse,
            },
        ];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        let rp = file.reparse_point(&mut cursor).unwrap().unwrap();
        assert_eq!(rp.tag(), 0xA000_0003);

        // A record without a reparse point returns None.
        let record2 = synthetic::file_record(
            0x0001,
            1,
            1,
            &[synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 0,
                name: "",
                value: vec![0u8; 4],
            }],
        );
        let (ntfs2, mut cursor2) = synthetic::load(&record2, 31);
        let file2 = synthetic::open_file(&ntfs2, &mut cursor2, 31);
        assert!(file2.reparse_point(&mut cursor2).is_none());
    }

    #[test]
    fn test_synthetic_find_resident_attribute_filters() {
        // Two $DATA attributes; find by name and by instance.
        let attrs = [
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 0,
                name: "",
                value: vec![0xAA; 4],
            },
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 5,
                name: "named",
                value: vec![0xBB; 4],
            },
        ];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let _ = &mut cursor;
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        // Find unnamed $DATA (name "" matches the first).
        let unnamed = file
            .find_resident_attribute(NtfsAttributeType::Data, Some(""), None)
            .unwrap();
        assert_eq!(unnamed.instance(), 0);

        // Find named $DATA "named".
        let named = file
            .find_resident_attribute(NtfsAttributeType::Data, Some("named"), None)
            .unwrap();
        assert_eq!(named.instance(), 5);

        // Find by instance only.
        let by_instance = file
            .find_resident_attribute(NtfsAttributeType::Data, None, Some(5))
            .unwrap();
        assert_eq!(by_instance.instance(), 5);

        // A type that is not present returns AttributeNotFound.
        assert!(matches!(
            file.find_resident_attribute(NtfsAttributeType::StandardInformation, None, None)
                .unwrap_err(),
            NtfsError::InvalidStructuredValueSize { .. } | NtfsError::AttributeNotFound { .. }
        ));
    }

    #[test]
    fn test_synthetic_flags_display() {
        let flags = NtfsFileFlags::IN_USE | NtfsFileFlags::IS_DIRECTORY;
        let rendered = format!("{flags}");
        // The Display impl renders the active flag names; the
        // Ok(Default::default()) mutant would render an empty string.
        assert_eq!(rendered, "IN_USE | IS_DIRECTORY");
        assert!(!rendered.is_empty());
    }

    #[test]
    fn test_synthetic_directory_index_non_directory_errors() {
        // A non-directory record must return NotADirectory from
        // directory_index (guards the `!self.is_directory()` check).
        let attrs = [synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 0,
            name: "",
            value: vec![0u8; 4],
        }];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);
        assert!(matches!(
            file.directory_index(&mut cursor).unwrap_err(),
            NtfsError::NotADirectory { .. }
        ));
    }

    #[test]
    fn test_synthetic_directory_index_succeeds_for_directory() {
        // A well-formed directory's directory_index must succeed and its
        // index must enumerate the one child entry. Guards the
        // `!self.is_directory()` check (deleting `!` would error here).
        let dir = synthetic::directory_record(7, false, "child.txt");
        let image = synthetic::mft_image(&[dir]);
        let mut cursor = std::io::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();

        let dir_file = ntfs.file(&mut cursor, 1).unwrap();
        let index = dir_file
            .directory_index(&mut cursor)
            .expect("directory_index must succeed for a directory");

        let mut iter = index.entries();
        let entry = iter
            .try_next(&mut cursor)
            .unwrap()
            .expect("expected one index entry");
        assert_eq!(entry.file_reference().file_record_number(), 7);
    }

    #[test]
    fn test_synthetic_recover_slack_non_directory_errors() {
        // recover_directory_slack must reject non-directories before any
        // index work (guards the `!self.is_directory()` check at line 403).
        let attrs = [synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 0,
            name: "",
            value: vec![0u8; 4],
        }];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);
        let result = file.recover_directory_slack(&mut cursor, SlackRecoveryConfig::default());
        assert!(matches!(
            result.unwrap_err(),
            NtfsError::NotADirectory { .. }
        ));
    }

    #[test]
    fn test_synthetic_find_attribute_filters_type_and_name() {
        // StandardInformation is absent; FILE_NAME and two $DATA present.
        let fname = synthetic::file_name_value(5, 1, 1, false, "x");
        let attrs = [
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::FileName,
                instance: 0,
                name: "",
                value: fname,
            },
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 1,
                name: "",
                value: vec![0xAA; 4],
            },
            synthetic::ResidentAttr {
                ty: NtfsAttributeType::Data,
                instance: 2,
                name: "alt",
                value: vec![0xBB; 4],
            },
        ];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        // find_attribute by type (no name) returns the first $DATA.
        let any_data = file
            .find_attribute(&mut cursor, NtfsAttributeType::Data, None)
            .unwrap();
        assert_eq!(any_data.to_attribute().unwrap().instance(), 1);

        // find_attribute by type AND name returns the named one.
        let named = file
            .find_attribute(&mut cursor, NtfsAttributeType::Data, Some("alt"))
            .unwrap();
        assert_eq!(named.to_attribute().unwrap().instance(), 2);

        // A type not present errors.
        assert!(matches!(
            file.find_attribute(&mut cursor, NtfsAttributeType::IndexRoot, None)
                .unwrap_err(),
            NtfsError::AttributeNotFound { .. }
        ));
        // A present type with a non-matching name errors.
        assert!(matches!(
            file.find_attribute(&mut cursor, NtfsAttributeType::Data, Some("nope"))
                .unwrap_err(),
            NtfsError::AttributeNotFound { .. }
        ));
    }

    #[test]
    fn test_synthetic_record_data_matches_fixed_up_bytes() {
        // record_data() must return the post-fixup record bytes, which
        // begin with the FILE signature and reflect our header fields.
        let record = synthetic::file_record(0x0001, 9, 2, &[]);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        let data = file.record_data();
        assert_eq!(data.len(), synthetic::RECORD_SIZE);
        assert_eq!(&data[0..4], b"FILE");
        // sequence_number (offset 16) and hard_link_count (offset 18).
        assert_eq!(u16::from_le_bytes([data[16], data[17]]), 9);
        assert_eq!(u16::from_le_bytes([data[18], data[19]]), 2);
        // record_data is not an empty/single-byte leaked vec.
        assert!(data.len() > 1);
    }

    #[test]
    fn test_recover_directory_slack() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let config = SlackRecoveryConfig {
            require_parent_match: false,
            ..SlackRecoveryConfig::default()
        };

        let recovered = root_dir
            .recover_directory_slack(&mut testfs1, config)
            .unwrap();

        // All recovered entries should have nonzero name_length and valid score.
        for entry in &recovered {
            assert!(entry.file_name().name_length() > 0);
            assert!(entry.validation().score() <= 6);
        }
    }

    #[test]
    fn test_recover_directory_slack_large_index() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // Navigate to "many_subdirs" which has INDEX_ALLOCATION with many INDX records.
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "many_subdirs")
            .unwrap()
            .unwrap();
        let many_subdirs = entry.to_file(&ntfs, &mut testfs1).unwrap();

        let config = SlackRecoveryConfig {
            require_parent_match: false,
            ..SlackRecoveryConfig::default()
        };

        let recovered = many_subdirs
            .recover_directory_slack(&mut testfs1, config)
            .unwrap();

        for entry in &recovered {
            assert!(entry.file_name().name_length() > 0);
            assert!(entry.validation().score() <= 6);
        }
    }

    #[test]
    fn test_recover_directory_slack_not_a_directory() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        // $MFT (record 0) is a file, not a directory.
        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();

        let config = SlackRecoveryConfig::default();
        let result = mft.recover_directory_slack(&mut testfs1, config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NtfsError::NotADirectory { .. }
        ));
    }

    #[test]
    fn test_recover_directory_slack_empty_dir() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // Navigate to edge-cases/empty-directory.
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "edge-cases")
            .unwrap()
            .unwrap();
        let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = edge_cases_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "empty-directory")
            .unwrap()
            .unwrap();
        let empty_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();
        assert!(empty_dir.is_directory());

        let config = SlackRecoveryConfig::default();
        let recovered = empty_dir
            .recover_directory_slack(&mut testfs1, config)
            .unwrap();

        // Empty directory should have no slack entries (or very few if any).
        // The key thing is it completes without error.
        for entry in &recovered {
            assert!(entry.file_name().name_length() > 0);
        }
    }

    #[test]
    fn test_parent_reference_root_directory() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Root directory's parent is itself.
        let parent_ref = root_dir.parent_reference(&mut testfs1).unwrap();
        assert_eq!(
            parent_ref.file_record_number(),
            KnownNtfsFileRecordNumber::RootDirectory as u64
        );
    }

    #[test]
    fn test_parent_reference_system_file() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        // $MFT's parent should be the root directory (MFT 5).
        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();
        let parent_ref = mft.parent_reference(&mut testfs1).unwrap();
        assert_eq!(
            parent_ref.file_record_number(),
            KnownNtfsFileRecordNumber::RootDirectory as u64
        );
    }

    #[test]
    fn test_name_pair_system_file() {
        // $MFT is a system file whose name conforms to 8.3 — it should be Win32AndDos.
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();

        let pair = mft.name_pair(&mut testfs1, None).unwrap().unwrap();
        assert_eq!(pair.primary.name(), "$MFT");
        assert!(pair.primary.namespace().is_combined());
        assert!(pair.short_name.is_none());
    }

    #[test]
    fn test_name_pair_root_directory() {
        // The root directory (.) should also have a Win32AndDos name.
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let root = ntfs
            .file(
                &mut testfs1,
                KnownNtfsFileRecordNumber::RootDirectory as u64,
            )
            .unwrap();

        let pair = root.name_pair(&mut testfs1, None).unwrap().unwrap();
        assert_eq!(pair.primary.name(), ".");
        assert!(pair.primary.namespace().is_combined());
        assert!(pair.short_name.is_none());
    }

    #[test]
    fn reparse_point_index_opens_or_skips() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // $Extend is MFT entry 11.
        let extend_dir = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Extend as u64)
            .unwrap();

        let extend_index = extend_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = extend_index.finder();

        // Try to find $Reparse in $Extend.
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "$Reparse");
        let Some(entry) = entry else {
            // mkntfs may not create $Reparse — skip.
            return;
        };
        let reparse_file = entry.unwrap().to_file(&ntfs, &mut testfs1).unwrap();

        // Open the $R index via the convenience method.
        match reparse_file.reparse_point_index(&mut testfs1) {
            Ok(index) => {
                // Iterate to verify no panics. Empty index is fine.
                let mut iter = index.entries();
                while let Some(entry) = iter.try_next(&mut testfs1).unwrap() {
                    if let Some(key) = entry.key() {
                        let key = key.unwrap();
                        // Sanity: at least one field should be non-zero.
                        assert!(
                            key.reparse_tag() != 0 || key.file_reference().file_record_number() > 0
                        );
                    }
                }
            }
            Err(NtfsError::AttributeNotFound { .. }) => {
                // $Reparse file exists but has no $R index — skip.
            }
            Err(e) => panic!("unexpected error opening $R index: {e}"),
        }
    }

    #[test]
    fn quota_indexes_open_or_skip() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        let extend_dir = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Extend as u64)
            .unwrap();

        let extend_index = extend_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = extend_index.finder();

        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "$Quota");
        let Some(entry) = entry else {
            return;
        };
        let quota_file = entry.unwrap().to_file(&ntfs, &mut testfs1).unwrap();

        // $Q index
        match quota_file.quota_q_index(&mut testfs1) {
            Ok(q_index) => {
                let mut iter = q_index.entries();
                while let Some(entry) = iter.try_next(&mut testfs1).unwrap() {
                    if let Some(key) = entry.key() {
                        let _key = key.unwrap();
                    }
                }
            }
            Err(NtfsError::AttributeNotFound { .. }) => {}
            Err(e) => panic!("unexpected error opening $Q index: {e}"),
        }

        // $O index — same file, different named index.
        match quota_file.quota_o_index(&mut testfs1) {
            Ok(o_index) => {
                let mut iter = o_index.entries();
                while let Some(entry) = iter.try_next(&mut testfs1).unwrap() {
                    if let Some(key) = entry.key() {
                        let _key = key.unwrap();
                    }
                }
            }
            Err(NtfsError::AttributeNotFound { .. }) => {}
            Err(e) => panic!("unexpected error opening $O index: {e}"),
        }
    }
}
