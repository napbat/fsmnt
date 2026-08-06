// It is important to note that `NtfsAttributeListNonResidentAttributeValue` can't just encapsulate `NtfsNonResidentAttributeValue` and provide one
// layer on top to connect the attributes!
// Connected attributes are stored in a way that the first attribute reports the entire data size and all further attributes report a zero value length.
// We have to go down to the Data Run level to get trustable lengths again, and this is what `NtfsAttributeListNonResidentAttributeValue` does here.

use fs_common::error::IoError;
use fs_common::iter::FsTryIterator;

use super::{DataRunsState, NtfsDataRun, NtfsDataRuns, StreamState};
use crate::attribute::{NtfsAttribute, NtfsAttributeType};
use crate::data_run_map::DataRunMap;
use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;
use fs_common::io::FsReadSeek;

use crate::structured_values::{NtfsAttributeListEntries, NtfsAttributeListEntry};
use crate::types::NtfsPosition;

/// Reader for a non-resident attribute value that is part of an Attribute List.
///
/// Such values are not only split up into data runs, but may also be continued by connected attributes
/// which are listed in the same Attribute List.
/// This reader considers that by providing one contiguous data stream for all data runs in all connected attributes.
#[derive(Clone, Debug)]
pub struct NtfsAttributeListNonResidentAttributeValue<'n, 'f> {
    /// Reference to the base `Ntfs` object of this filesystem.
    ntfs: &'n Ntfs,
    /// An untouched copy of the `attribute_list_entries` passed in [`Self::new`] to rewind to the beginning when desired.
    initial_attribute_list_entries: NtfsAttributeListEntries<'n, 'f>,
    /// Iterator through all connected attributes of this attribute in the Attribute List.
    connected_entries: AttributeListConnectedEntries<'n, 'f>,
    /// Total length of the value data, in bytes.
    data_size: u64,
    /// Size of the initialized portion of the value (preserved across rewinds).
    initialized_size: u64,
    /// File, location, and data runs iteration state of the current attribute.
    attribute_state: Option<AttributeState<'n>>,
    /// Iteration state of the current Data Run.
    stream_state: StreamState,
}

impl<'n, 'f> NtfsAttributeListNonResidentAttributeValue<'n, 'f> {
    pub(crate) fn new<T>(
        ntfs: &'n Ntfs,
        fs: &mut T,
        attribute_list_entries: NtfsAttributeListEntries<'n, 'f>,
        instance: u16,
        ty: NtfsAttributeType,
        data_size: u64,
        initialized_size: u64,
    ) -> Result<Self>
    where
        T: Read + Seek,
    {
        let mut connected_entries =
            AttributeListConnectedEntries::new(attribute_list_entries.clone(), instance, ty);
        let stream_state = StreamState::new(data_size, initialized_size);

        let mut attribute_state = None;
        let first_data_run =
            Self::next_attribute(ntfs, fs, &mut connected_entries, &mut attribute_state)?;

        let mut value = Self {
            ntfs,
            initial_attribute_list_entries: attribute_list_entries,
            connected_entries,
            data_size,
            initialized_size,
            attribute_state,
            stream_state,
        };
        if let Some(data_run) = first_data_run {
            value.stream_state.set_stream_data_run(Some(data_run));
        }

        Ok(value)
    }

    /// Returns the absolute current data seek position within the filesystem, in bytes.
    /// This may be `None` if:
    ///   * The current seek position is outside the valid range, or
    ///   * The current Data Run is a "sparse" Data Run.
    #[must_use]
    pub fn data_position(&self) -> NtfsPosition {
        self.stream_state.data_position()
    }

    /// Returns `true` if the non-resident attribute value contains no data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total length of the non-resident attribute value data, in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.data_size
    }

    /// Returns the current stream position within this value, in bytes.
    #[must_use]
    pub fn stream_position(&self) -> u64 {
        self.stream_state.stream_position()
    }

    /// Returns the next Data Run from the current attribute, or
    /// `None` when all data runs of the current attribute have been
    /// consumed.
    fn next_data_run(
        ntfs: &'n Ntfs,
        attribute_state: &mut Option<AttributeState<'n>>,
    ) -> Result<Option<NtfsDataRun>> {
        let Some(state) = attribute_state else {
            return Ok(None);
        };

        let Some(data_runs_state) = state.data_runs_state.take() else {
            return Ok(None);
        };

        let attribute = NtfsAttribute::new(&state.file, state.attribute_offset, None)?;
        let (data, position) = attribute.non_resident_value_data_and_position()?;
        let mut stream_data_runs = NtfsDataRuns::from_state(ntfs, data, position, data_runs_state);

        let data_run = match stream_data_runs.next() {
            Some(Ok(run)) => run,
            Some(Err(e)) => return Err(e),
            None => return Ok(None),
        };

        // Save updated iterator state for the next call.
        state.data_runs_state = Some(stream_data_runs.into_state());

        Ok(Some(data_run))
    }

    /// Returns the first Data Run of the next connected attribute,
    /// or `None` when no more connected attributes remain.
    fn next_attribute<T>(
        ntfs: &'n Ntfs,
        fs: &mut T,
        connected_entries: &mut AttributeListConnectedEntries<'n, 'f>,
        attribute_state: &mut Option<AttributeState<'n>>,
    ) -> Result<Option<NtfsDataRun>>
    where
        T: Read + Seek,
    {
        let Some(entry) = connected_entries.next(fs) else {
            return Ok(None);
        };

        let entry = entry?;
        let file = entry.to_file(ntfs, fs)?;
        let attribute = entry.to_attribute(&file)?;
        let attribute_offset = attribute.offset();

        if attribute.is_resident() {
            return Err(NtfsError::UnexpectedResidentAttribute {
                position: attribute.position(),
            });
        }

        let (data, position) = attribute.non_resident_value_data_and_position()?;
        let mut stream_data_runs = NtfsDataRuns::new(ntfs, data, position);

        let data_run = match stream_data_runs.next() {
            Some(Ok(run)) => run,
            Some(Err(e)) => return Err(e),
            None => return Ok(None),
        };

        let data_runs_state = Some(stream_data_runs.into_state());
        *attribute_state = Some(AttributeState {
            file,
            attribute_offset,
            data_runs_state,
        });

        Ok(Some(data_run))
    }

    /// Collects all data runs across all connected attribute
    /// fragments into an owned [`DataRunMap`].
    pub(crate) fn data_run_map<T: Read + Seek>(&self, fs: &mut T) -> Result<DataRunMap> {
        let mut connected = AttributeListConnectedEntries::new(
            self.initial_attribute_list_entries.clone(),
            self.connected_entries.instance,
            self.connected_entries.ty,
        );

        let mut map: Option<DataRunMap> = None;

        while let Some(entry) = connected.next(fs) {
            let entry = entry?;
            let file = entry.to_file(self.ntfs, fs)?;
            let attribute = entry.to_attribute(&file)?;

            if attribute.is_resident() {
                return Err(NtfsError::UnexpectedResidentAttribute {
                    position: attribute.position(),
                });
            }

            let (data, position) = attribute.non_resident_value_data_and_position()?;
            let data_runs = NtfsDataRuns::new(self.ntfs, data, position);

            match &mut map {
                Some(m) => m.extend_data_runs(data_runs)?,
                None => map = Some(DataRunMap::from_data_runs(data_runs)?),
            }
        }

        map.ok_or_else(|| IoError::invalid_data().into())
    }

    /// Returns the [`Ntfs`] object reference associated to this value.
    #[must_use]
    pub fn ntfs(&self) -> &'n Ntfs {
        self.ntfs
    }

    /// Rewinds this value reader to the very beginning.
    fn rewind<T>(&mut self, fs: &mut T) -> Result<()>
    where
        T: Read + Seek,
    {
        self.connected_entries.attribute_list_entries =
            Some(self.initial_attribute_list_entries.clone());
        self.stream_state = StreamState::new(self.len(), self.initialized_size);
        if let Some(data_run) = Self::next_attribute(
            self.ntfs,
            fs,
            &mut self.connected_entries,
            &mut self.attribute_state,
        )? {
            self.stream_state.set_stream_data_run(Some(data_run));
        }

        Ok(())
    }
}

impl<R: Read + Seek> FsReadSeek<R> for NtfsAttributeListNonResidentAttributeValue<'_, '_> {
    type Error = NtfsError;

    fn read(&mut self, fs: &mut R, buf: &mut [u8]) -> Result<usize> {
        let ntfs = self.ntfs;
        let attribute_state = &mut self.attribute_state;
        let connected_entries = &mut self.connected_entries;
        self.stream_state.read_loop(fs, buf, |fs| {
            if let Some(run) = Self::next_data_run(ntfs, attribute_state)? {
                return Ok(Some(run));
            }
            Self::next_attribute(ntfs, fs, connected_entries, attribute_state)
        })
    }

    fn seek(&mut self, fs: &mut R, pos: SeekFrom) -> Result<u64> {
        let pos = self.stream_state.optimize_seek(pos, self.len())?;

        let bytes_left_to_seek = match pos {
            SeekFrom::Start(n) => {
                self.rewind(fs)?;
                n
            }
            SeekFrom::Current(n) if n >= 0 => n.unsigned_abs(),
            _ => unreachable!(),
        };

        let ntfs = self.ntfs;
        let attribute_state = &mut self.attribute_state;
        let connected_entries = &mut self.connected_entries;
        self.stream_state
            .seek_loop(fs, pos, bytes_left_to_seek, |fs| {
                if let Some(run) = Self::next_data_run(ntfs, attribute_state)? {
                    return Ok(Some(run));
                }
                Self::next_attribute(ntfs, fs, connected_entries, attribute_state)
            })
    }

    fn stream_position(&self) -> u64 {
        self.stream_state.stream_position()
    }

    fn len(&self) -> u64 {
        self.data_size
    }
}

#[derive(Clone, Debug)]
struct AttributeListConnectedEntries<'n, 'f> {
    attribute_list_entries: Option<NtfsAttributeListEntries<'n, 'f>>,
    instance: u16,
    ty: NtfsAttributeType,
}

impl<'n, 'f> AttributeListConnectedEntries<'n, 'f> {
    fn new(
        attribute_list_entries: NtfsAttributeListEntries<'n, 'f>,
        instance: u16,
        ty: NtfsAttributeType,
    ) -> Self {
        Self {
            attribute_list_entries: Some(attribute_list_entries),
            instance,
            ty,
        }
    }

    fn next<T>(&mut self, fs: &mut T) -> Option<Result<NtfsAttributeListEntry>>
    where
        T: Read + Seek,
    {
        let attribute_list_entries = self.attribute_list_entries.as_mut()?;

        let entry = iter_try!(attribute_list_entries.try_next(fs))?;
        if entry.instance() == self.instance && iter_try!(entry.ty()) == self.ty {
            Some(Ok(entry))
        } else {
            self.attribute_list_entries = None;
            None
        }
    }
}

#[derive(Clone, Debug)]
struct AttributeState<'n> {
    file: NtfsFile<'n>,
    attribute_offset: usize,
    /// We cannot store an `NtfsDataRuns` here, because it has a reference to the `NtfsFile` that is also stored here.
    /// This is why we have to go via `DataRunsState` in an `Option` to `take()` it and deserialize it into an `NtfsDataRuns` whenever necessary.
    data_runs_state: Option<DataRunsState>,
}
