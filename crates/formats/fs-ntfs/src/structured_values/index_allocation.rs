use core::iter::FusedIterator;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::NtfsAttributeValue;
use crate::error::{NtfsError, Result};
use crate::index_record::NtfsIndexRecord;
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;
use crate::structured_values::NtfsStructuredValue;
use crate::types::Vcn;
use fs_common::io::FsReadSeek;

/// Structure of an $INDEX_ALLOCATION attribute.
///
/// This attribute describes the sub-nodes of a B-tree.
/// The top-level nodes are managed via [`NtfsIndexRoot`].
///
/// NTFS uses B-trees for describing directories (as indexes of [`NtfsFileName`]s), looking up Object IDs,
/// Reparse Points, and Security Descriptors, to just name a few.
///
/// An $INDEX_ALLOCATION attribute can be resident or non-resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/index_allocation.html>
///
/// NTFS on-disk structure; no direct MS-FSCC equivalent.
///
/// [`NtfsFileName`]: crate::structured_values::NtfsFileName
/// [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot
#[derive(Clone, Debug)]
pub struct NtfsIndexAllocation<'n, 'f> {
    ntfs: &'n Ntfs,
    value: NtfsAttributeValue<'n, 'f>,
}

impl<'n, 'f> NtfsIndexAllocation<'n, 'f> {
    /// Returns the [`NtfsIndexRecord`] located at the given Virtual Cluster Number (VCN).
    ///
    /// The record is fully read, fixed up, and validated.
    ///
    /// This function is usually called on the return value of [`NtfsIndexEntry::subnode_vcn`] to move further
    /// down in the B-tree.
    ///
    /// [`NtfsIndexEntry::subnode_vcn`]: crate::NtfsIndexEntry::subnode_vcn
    pub fn record_from_vcn<T>(
        &self,
        fs: &mut T,
        index_record_size: u32,
        vcn: Vcn,
    ) -> Result<NtfsIndexRecord>
    where
        T: Read + Seek,
    {
        // Seek to the byte offset of the given VCN.
        let mut value = self.value.clone();
        let offset = vcn.offset(self.ntfs)?;
        value.seek(fs, SeekFrom::Current(offset))?;

        if value.stream_position() >= value.len() {
            return Err(NtfsError::VcnOutOfBoundsInIndexAllocation {
                position: self.value.data_position(),
                vcn,
            });
        }

        // Get the record.
        let record = NtfsIndexRecord::new(fs, value, index_record_size)?;

        // Validate that the VCN in the record is the requested one.
        if record.vcn() != vcn {
            return Err(NtfsError::VcnMismatchInIndexAllocation {
                position: self.value.data_position(),
                expected: vcn,
                actual: record.vcn(),
            });
        }

        Ok(record)
    }

    /// Returns an iterator over all Index Records of this $INDEX_ALLOCATION attribute (cf. [`NtfsIndexRecord`]).
    ///
    /// Each Index Record is fully read, fixed up, and validated.
    pub fn records(&self, index_record_size: u32) -> NtfsIndexRecords<'n, 'f> {
        NtfsIndexRecords::new(self.clone(), index_record_size)
    }
}

impl<'n, 'f> NtfsStructuredValue<'n, 'f> for NtfsIndexAllocation<'n, 'f> {
    const TY: NtfsAttributeType = NtfsAttributeType::IndexAllocation;

    fn from_attribute_value<T>(_fs: &mut T, value: NtfsAttributeValue<'n, 'f>) -> Result<Self>
    where
        T: Read + Seek,
    {
        let ntfs = match &value {
            NtfsAttributeValue::AttributeListNonResident(value) => value.ntfs(),
            NtfsAttributeValue::NonResident(value) => value.ntfs(),
            NtfsAttributeValue::Resident(_) => {
                let position = value.data_position();
                return Err(NtfsError::UnexpectedResidentAttribute { position });
            }
            #[cfg(feature = "compression")]
            NtfsAttributeValue::CompressedNonResident(value) => value.ntfs(),
        };

        Ok(Self { ntfs, value })
    }
}

/// Iterator over
///   all index records of an [`NtfsIndexAllocation`],
///   returning an [`NtfsIndexRecord`] for each record.
///
/// This iterator is returned from the [`NtfsIndexAllocation::records`] function.
///
/// See [`NtfsIndexRecordsAttached`] for an iterator that implements [`Iterator`] and [`FusedIterator`].
#[derive(Clone, Debug)]
pub struct NtfsIndexRecords<'n, 'f> {
    index_allocation: NtfsIndexAllocation<'n, 'f>,
    index_record_size: u32,
}

impl<'n, 'f> NtfsIndexRecords<'n, 'f> {
    fn new(index_allocation: NtfsIndexAllocation<'n, 'f>, index_record_size: u32) -> Self {
        Self {
            index_allocation,
            index_record_size,
        }
    }

    /// Returns a variant of this iterator that implements [`Iterator`] and [`FusedIterator`]
    /// by mutably borrowing the filesystem reader.
    pub fn attach<'a, T>(self, fs: &'a mut T) -> NtfsIndexRecordsAttached<'n, 'f, 'a, T>
    where
        T: Read + Seek,
    {
        NtfsIndexRecordsAttached::new(fs, self)
    }

    /// See [`Iterator::next`].
    pub fn next<T>(&mut self, fs: &mut T) -> Option<Result<NtfsIndexRecord>>
    where
        T: Read + Seek,
    {
        if self.index_allocation.value.stream_position() >= self.index_allocation.value.len() {
            return None;
        }

        // Get the current record.
        let record = iter_try!(NtfsIndexRecord::new(
            fs,
            self.index_allocation.value.clone(),
            self.index_record_size
        ));

        // Advance our iterator to the next record.
        iter_try!(
            self.index_allocation
                .value
                .seek(fs, SeekFrom::Current(self.index_record_size as i64))
        );

        Some(Ok(record))
    }
}

impl<'n, 'f> fs_common::iter::FsTryIteratorType for NtfsIndexRecords<'n, 'f> {
    type Error = NtfsError;
    type Item<'a> = NtfsIndexRecord;
}

impl<'n, 'f, R: Read + Seek> fs_common::iter::FsTryIterator<R> for NtfsIndexRecords<'n, 'f> {
    fn try_next(&mut self, r: &mut R) -> Result<Option<NtfsIndexRecord>> {
        self.next(r).transpose()
    }
}

/// Iterator over
///   all index records of an [`NtfsIndexAllocation`],
///   returning an [`NtfsIndexRecord`] for each record,
///   implementing [`Iterator`] and [`FusedIterator`].
///
/// This iterator is returned from the [`NtfsIndexRecords::attach`] function.
/// Conceptually the same as [`NtfsIndexRecords`], but mutably borrows the filesystem
/// to implement aforementioned traits.
#[derive(Debug)]
pub struct NtfsIndexRecordsAttached<'n, 'f, 'a, T>
where
    T: Read + Seek,
{
    fs: &'a mut T,
    index_records: NtfsIndexRecords<'n, 'f>,
}

impl<'n, 'f, 'a, T> NtfsIndexRecordsAttached<'n, 'f, 'a, T>
where
    T: Read + Seek,
{
    fn new(fs: &'a mut T, index_records: NtfsIndexRecords<'n, 'f>) -> Self {
        Self { fs, index_records }
    }
    /// Consumes this iterator and returns the inner [`NtfsIndexRecords`].
    pub fn detach(self) -> NtfsIndexRecords<'n, 'f> {
        self.index_records
    }
}

impl<'n, 'f, 'a, T> Iterator for NtfsIndexRecordsAttached<'n, 'f, 'a, T>
where
    T: Read + Seek,
{
    type Item = Result<NtfsIndexRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        self.index_records.next(self.fs)
    }
}

impl<'n, 'f, 'a, T> FusedIterator for NtfsIndexRecordsAttached<'n, 'f, 'a, T> where T: Read + Seek {}

#[cfg(test)]
mod tests {
    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;
    use fs_common::iter::FsTryIterator;

    #[test]
    fn test_index_allocation_records_in_many_subdirs() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // Navigate to "many_subdirs" which has a large B-tree with index allocation.
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "many_subdirs")
            .unwrap()
            .unwrap();
        let many_subdirs = entry.to_file(&ntfs, &mut testfs1).unwrap();
        assert!(many_subdirs.is_directory());

        // Use directory_index which internally opens IndexRoot + IndexAllocation.
        // Iterate all entries — this exercises the index allocation code paths.
        let index = many_subdirs.directory_index(&mut testfs1).unwrap();
        let mut entries = index.entries();
        let mut entry_count = 0;

        while let Some(entry) = entries.try_next(&mut testfs1).unwrap() {
            if let Some(Ok(file_name)) = entry.key() {
                let _ = file_name.name().to_string_lossy();
                entry_count += 1;
            }
        }

        // "many_subdirs" should have 512 subdirectories.
        assert!(
            entry_count >= 512,
            "expected at least 512 entries in many_subdirs, got {entry_count}"
        );
    }

    #[test]
    fn test_index_allocation_find_in_large_directory() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // Navigate to "many_subdirs".
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "many_subdirs")
            .unwrap()
            .unwrap();
        let many_subdirs = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Find a specific subdirectory by name using the B-tree finder.
        let index = many_subdirs.directory_index(&mut testfs1).unwrap();
        let mut finder = index.finder();

        // Try to find "1" (subdirs are named "1" through "512").
        let result = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "1");
        assert!(result.is_some(), "should find subdir '1' in many_subdirs");
        let entry = result.unwrap().unwrap();
        let subdir = entry.to_file(&ntfs, &mut testfs1).unwrap();
        assert!(subdir.is_directory());
    }
}
