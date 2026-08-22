//! This module implements a reader for a non-resident attribute value (that is not part of an Attribute List).
//! Non-resident attribute values are split up into one or more data runs, which are spread across the filesystem.
//! This reader provides one contiguous data stream for all data runs.

use core::iter::FusedIterator;
use core::mem;

use fsmnt_parser_core::error::IoError;
use fsmnt_parser_core::io::FsReadSeek;

use super::seek_contiguous;
use crate::error::{NtfsError, Result};
use crate::io;
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;
use crate::types::{Lcn, NtfsPosition, Vcn};

/// Reader for a non-resident attribute value (whose data is in a cluster range outside the File Record).
#[derive(Clone, Debug)]
pub struct NtfsNonResidentAttributeValue<'n, 'f> {
    /// Reference to the base `Ntfs` object of this filesystem.
    ntfs: &'n Ntfs,
    /// Attribute bytes where the Data Run information of this non-resident value is stored on the filesystem.
    data: &'f [u8],
    /// Absolute position of the Data Run information within the filesystem, in bytes.
    position: NtfsPosition,
    /// Size of the initialized portion of the value (preserved across rewinds).
    initialized_size: u64,
    /// Iterator of data runs used for reading/seeking.
    stream_data_runs: NtfsDataRuns<'n, 'f>,
    /// Iteration state of the current Data Run.
    stream_state: StreamState,
}

impl<'n, 'f> NtfsNonResidentAttributeValue<'n, 'f> {
    pub(crate) fn new(
        ntfs: &'n Ntfs,
        data: &'f [u8],
        position: NtfsPosition,
        data_size: u64,
        initialized_size: u64,
    ) -> Result<Self> {
        let stream_data_runs = NtfsDataRuns::new(ntfs, data, position);
        let stream_state = StreamState::new(data_size, initialized_size);

        let mut value = Self {
            ntfs,
            data,
            position,
            initialized_size,
            stream_data_runs,
            stream_state,
        };
        if let Some(data_run) = Self::next_data_run(&mut value.stream_data_runs)? {
            value.stream_state.set_stream_data_run(Some(data_run));
        }

        Ok(value)
    }

    /// Returns a variant of this reader that implements [`Read`] and [`Seek`]
    /// by mutably borrowing the filesystem reader.
    pub fn attach<'a, T>(
        self,
        fs: &'a mut T,
    ) -> NtfsNonResidentAttributeValueAttached<'n, 'f, 'a, T>
    where
        T: Read + Seek,
    {
        NtfsNonResidentAttributeValueAttached::new(fs, self)
    }

    /// Returns the absolute current data seek position within the filesystem, in bytes.
    /// This may be `None` if:
    ///   * The current seek position is outside the valid range, or
    ///   * The attribute does not have a Data Run, or
    ///   * The current Data Run is a "sparse" Data Run
    #[must_use]
    pub fn data_position(&self) -> NtfsPosition {
        self.stream_state.data_position()
    }

    /// Returns an iterator over all data runs of this non-resident attribute.
    #[must_use]
    pub fn data_runs(&self) -> NtfsDataRuns<'n, 'f> {
        NtfsDataRuns::new(self.ntfs, self.data, self.position)
    }

    /// Returns `true` if the non-resident attribute value contains no data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total length of the non-resident attribute value data, in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.stream_state.data_size()
    }

    /// Returns the current stream position within this value, in bytes.
    #[must_use]
    pub fn stream_position(&self) -> u64 {
        self.stream_state.stream_position()
    }

    pub(super) const fn initialized_size(&self) -> u64 {
        self.initialized_size
    }

    /// Returns the next Data Run from the iterator, or `None`
    /// when all data runs have been consumed.
    fn next_data_run(stream_data_runs: &mut NtfsDataRuns<'n, 'f>) -> Result<Option<NtfsDataRun>> {
        match stream_data_runs.next() {
            Some(Ok(data_run)) => Ok(Some(data_run)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Returns the [`Ntfs`] object reference associated to this value.
    #[must_use]
    pub fn ntfs(&self) -> &'n Ntfs {
        self.ntfs
    }

    /// Rewinds this value reader to the very beginning.
    fn rewind(&mut self) -> Result<()> {
        self.stream_data_runs = self.data_runs();
        self.stream_state = StreamState::new(self.len(), self.initialized_size);
        if let Some(data_run) = Self::next_data_run(&mut self.stream_data_runs)? {
            self.stream_state.set_stream_data_run(Some(data_run));
        }

        Ok(())
    }
}

impl<R: Read + Seek> FsReadSeek<R> for NtfsNonResidentAttributeValue<'_, '_> {
    type Error = NtfsError;

    fn read(&mut self, fs: &mut R, buf: &mut [u8]) -> Result<usize> {
        let stream_data_runs = &mut self.stream_data_runs;
        self.stream_state
            .read_loop(fs, buf, |_fs| Self::next_data_run(stream_data_runs))
    }

    // mutants::skip: the `n >= 0` match guard is defense-in-depth that is
    // already guaranteed by `optimize_seek`, which only ever returns
    // `SeekFrom::Start` or `SeekFrom::Current(n)` with `n >= 0`. Replacing the
    // guard with `true` is therefore an equivalent mutant (the `unreachable!`
    // arm is never reachable). Behavior of this function is covered by the
    // `test_non_resident_value_seek_*` tests.
    #[cfg_attr(test, mutants::skip)]
    fn seek(&mut self, fs: &mut R, pos: SeekFrom) -> Result<u64> {
        let pos = self.stream_state.optimize_seek(pos, self.len())?;

        let bytes_left_to_seek = match pos {
            SeekFrom::Start(n) => {
                self.rewind()?;
                n
            }
            SeekFrom::Current(n) if n >= 0 => {
                u64::try_from(n).expect("the guarded current offset is nonnegative")
            }
            _ => unreachable!(),
        };

        let stream_data_runs = &mut self.stream_data_runs;
        self.stream_state
            .seek_loop(fs, pos, bytes_left_to_seek, |_fs| {
                Self::next_data_run(stream_data_runs)
            })
    }

    fn stream_position(&self) -> u64 {
        self.stream_state.stream_position()
    }

    fn len(&self) -> u64 {
        self.stream_state.data_size()
    }
}

/// A variant of [`NtfsNonResidentAttributeValue`] that implements [`Read`] and [`Seek`]
/// by mutably borrowing the filesystem reader.
#[derive(Debug)]
pub struct NtfsNonResidentAttributeValueAttached<'n, 'f, 'a, T: Read + Seek> {
    fs: &'a mut T,
    value: NtfsNonResidentAttributeValue<'n, 'f>,
}

impl<'n, 'f, 'a, T> NtfsNonResidentAttributeValueAttached<'n, 'f, 'a, T>
where
    T: Read + Seek,
{
    fn new(fs: &'a mut T, value: NtfsNonResidentAttributeValue<'n, 'f>) -> Self {
        Self { fs, value }
    }

    /// Returns the absolute current data seek position within the filesystem, in bytes.
    /// This may be `None` if:
    ///   * The current seek position is outside the valid range, or
    ///   * The attribute does not have a Data Run, or
    ///   * The current Data Run is a "sparse" Data Run.
    #[must_use]
    pub fn data_position(&self) -> NtfsPosition {
        self.value.data_position()
    }

    /// Consumes this reader and returns the inner [`NtfsNonResidentAttributeValue`].
    #[must_use]
    pub fn detach(self) -> NtfsNonResidentAttributeValue<'n, 'f> {
        self.value
    }

    /// Returns `true` if the non-resident attribute value contains no data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total length of the non-resident attribute value, in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.value.len()
    }
}

impl<T> Read for NtfsNonResidentAttributeValueAttached<'_, '_, '_, T>
where
    T: Read + Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.value.read(self.fs, buf).map_err(io::Error::from)
    }
}

impl<T> Seek for NtfsNonResidentAttributeValueAttached<'_, '_, '_, T>
where
    T: Read + Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.value.seek(self.fs, pos).map_err(io::Error::from)
    }
}

/// Iterator over
///   all data runs of a non-resident attribute,
///   returning an [`NtfsDataRun`] for each entry,
///   implementing [`Iterator`] and [`FusedIterator`].
///
/// This iterator is returned from the [`NtfsNonResidentAttributeValue::data_runs`] function.
#[derive(Clone, Debug)]
pub struct NtfsDataRuns<'n, 'f> {
    ntfs: &'n Ntfs,
    data: &'f [u8],
    position: NtfsPosition,
    state: DataRunsState,
}

impl<'n, 'f> NtfsDataRuns<'n, 'f> {
    pub(crate) fn new(ntfs: &'n Ntfs, data: &'f [u8], position: NtfsPosition) -> Self {
        let state = DataRunsState {
            offset: 0,
            previous_lcn: Lcn::from(0),
        };

        Self {
            ntfs,
            data,
            position,
            state,
        }
    }

    pub(crate) fn from_state(
        ntfs: &'n Ntfs,
        data: &'f [u8],
        position: NtfsPosition,
        state: DataRunsState,
    ) -> Self {
        Self {
            ntfs,
            data,
            position,
            state,
        }
    }

    pub(crate) fn into_state(self) -> DataRunsState {
        self.state
    }

    /// Returns the absolute position of the current Data Run header within the filesystem, in bytes.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position + self.state.offset
    }

    fn validate_byte_count<'a>(&self, data: &'a [u8], byte_count: u8) -> Result<&'a [u8]> {
        const MAX_BYTE_COUNT: u8 = 8;

        if byte_count > MAX_BYTE_COUNT {
            return Err(NtfsError::InvalidByteCountInDataRunHeader {
                position: self.position(),
                expected: MAX_BYTE_COUNT,
                actual: byte_count,
            });
        }

        let Some(slice) = data.get(..usize::from(byte_count)) else {
            return Err(NtfsError::InvalidByteCountInDataRunHeader {
                position: self.position(),
                expected: byte_count,
                actual: u8::try_from(data.len())
                    .expect("a short variable-length integer has at most eight bytes"),
            });
        };

        Ok(slice)
    }

    fn parse_variable_length_signed_integer(data: &[u8]) -> i64 {
        let mut buf = [0u8; mem::size_of::<i64>()];
        buf[..data.len()].copy_from_slice(data);

        let mut integer = i64::from_le_bytes(buf);

        // We have read `data.len()` bytes into a zeroed buffer and just interpreted that as an `i64`.
        // Sign-extend `integer` to make it replicate the proper value.
        let unused_bytes = mem::size_of::<i64>() - data.len();
        let unused_bits = u32::try_from(unused_bytes).expect("an i64 contains eight bytes") * 8;
        integer = integer.wrapping_shl(unused_bits).wrapping_shr(unused_bits);

        integer
    }

    fn parse_variable_length_unsigned_integer(data: &[u8]) -> u64 {
        let mut buf = [0u8; mem::size_of::<u64>()];
        buf[..data.len()].copy_from_slice(data);

        u64::from_le_bytes(buf)
    }
}

impl Iterator for NtfsDataRuns<'_, '_> {
    type Item = Result<NtfsDataRun>;

    fn next(&mut self) -> Option<Result<NtfsDataRun>> {
        if self.state.offset >= self.data.len() {
            return None;
        }

        let data = &self.data[self.state.offset..];
        let mut i = 0;

        // Read the single header byte.
        let header = *data.get(i)?;
        i += 1;

        // A zero byte marks the end of the data runs.
        if header == 0 {
            // Ensure that any further call uses the fast path above.
            self.state.offset = self.data.len();
            return None;
        }

        // The lower nibble indicates the length of the following cluster count variable length integer.
        let cluster_count_byte_count = header & 0x0f;
        let cluster_count_data =
            iter_try!(self.validate_byte_count(&data[i..], cluster_count_byte_count));
        let cluster_count = Self::parse_variable_length_unsigned_integer(cluster_count_data);
        if cluster_count == 0 {
            return Some(Err(NtfsError::InvalidClusterCountInDataRunHeader {
                position: NtfsDataRuns::position(self),
                cluster_count,
            }));
        }
        let allocated_size = iter_try!(
            cluster_count
                .checked_mul(u64::from(self.ntfs.cluster_size()))
                .ok_or_else(|| NtfsError::InvalidClusterCountInDataRunHeader {
                    position: NtfsDataRuns::position(self),
                    cluster_count,
                })
        );
        i += usize::from(cluster_count_byte_count);

        // The upper nibble indicates the length of the following VCN variable length integer.
        let vcn_byte_count = (header & 0xf0) >> 4;
        let vcn_data = iter_try!(self.validate_byte_count(&data[i..], vcn_byte_count));
        let vcn = Vcn::from(Self::parse_variable_length_signed_integer(vcn_data));
        i += usize::from(vcn_byte_count);

        // The VCN may either indicate "real" data or a sparse Data Run.
        let position = if vcn.value() != 0 {
            // This Data Run contains "real" data.
            // Turn the read VCN into an absolute LCN.
            let Some(new_lcn) = self.state.previous_lcn.checked_add(vcn) else {
                return Some(Err(NtfsError::InvalidVcnInDataRunHeader {
                    position: NtfsDataRuns::position(self),
                    vcn,
                    previous_lcn: self.state.previous_lcn,
                }));
            };
            self.state.previous_lcn = new_lcn;
            iter_try!(new_lcn.position(self.ntfs))
        } else {
            // This is a sparse Data Run.
            NtfsPosition::none()
        };

        // Only advance after having checked for success.
        // In case of an error, a subsequent call shall output the same error again.
        self.state.offset += i;

        let data_run = NtfsDataRun::new(position, allocated_size);
        Some(Ok(data_run))
    }
}

impl FusedIterator for NtfsDataRuns<'_, '_> {}

#[derive(Clone, Debug)]
pub(crate) struct DataRunsState {
    offset: usize,
    previous_lcn: Lcn,
}

/// A single NTFS Data Run, which is a continuous cluster range of a non-resident value.
///
/// A Data Run's size is a multiple of the cluster size configured for the filesystem.
/// However, a Data Run does not know about the actual size used by data. This information is only available in the corresponding attribute.
/// Keep this in mind when doing reads and seeks on data runs. You may end up on allocated but unused data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsDataRun {
    /// Absolute position of the Data Run within the filesystem, in bytes.
    /// This may be `NtfsPosition(None)` if this is a "sparse" Data Run.
    position: NtfsPosition,
    /// Total allocated size of the Data Run, in bytes.
    /// The actual size used by data may be lower, but a Data Run does not know about that.
    allocated_size: u64,
    /// Current relative position within the Data Run value, in bytes.
    stream_position: u64,
}

impl NtfsDataRun {
    pub(crate) fn new(position: NtfsPosition, allocated_size: u64) -> Self {
        Self {
            position,
            allocated_size,
            stream_position: 0,
        }
    }

    /// Returns the allocated size of the Data Run, in bytes.
    #[must_use]
    pub fn allocated_size(&self) -> u64 {
        self.allocated_size
    }

    /// Returns the absolute current data seek position within the filesystem, in bytes.
    /// This may be `None` if:
    ///   * The current seek position is outside the valid range, or
    ///   * The Data Run is a "sparse" Data Run
    #[must_use]
    pub fn data_position(&self) -> NtfsPosition {
        if self.stream_position <= self.allocated_size() {
            self.position + self.stream_position
        } else {
            NtfsPosition::none()
        }
    }

    /// Returns the current stream position within this data run, in bytes.
    #[must_use]
    pub fn stream_position(&self) -> u64 {
        self.stream_position
    }

    pub(crate) fn remaining_len(&self) -> u64 {
        self.allocated_size().saturating_sub(self.stream_position)
    }
}

impl<R: Read + Seek> FsReadSeek<R> for NtfsDataRun {
    type Error = NtfsError;

    fn read(&mut self, fs: &mut R, buf: &mut [u8]) -> Result<usize> {
        if self.remaining_len() == 0 {
            return Ok(0);
        }

        let remaining = usize::try_from(self.remaining_len()).unwrap_or(usize::MAX);
        let bytes_to_read = usize::min(buf.len(), remaining);
        let work_slice = &mut buf[..bytes_to_read];

        let bytes_read = if let Some(position) = self.position.value() {
            // This Data Run contains "real" data.
            fs.seek(SeekFrom::Start(position.get() + self.stream_position))?;
            fs.read(work_slice)?
        } else {
            // This is a sparse Data Run.
            work_slice.fill(0);
            work_slice.len()
        };

        self.stream_position += u64::try_from(bytes_read).expect("a slice length fits in u64");
        Ok(bytes_read)
    }

    fn seek(&mut self, _fs: &mut R, pos: SeekFrom) -> Result<u64> {
        let length = self.allocated_size();
        seek_contiguous(&mut self.stream_position, length, pos)
    }

    fn stream_position(&self) -> u64 {
        self.stream_position
    }

    fn len(&self) -> u64 {
        self.allocated_size
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StreamState {
    /// Current Data Run we are reading from.
    stream_data_run: Option<NtfsDataRun>,
    /// Current relative position within the entire value, in bytes.
    stream_position: u64,
    /// Total (used) data size, in bytes.
    data_size: u64,
    /// Size of the initialized portion of the value, in bytes.
    /// Data beyond this point (up to `data_size`) should be read as zeros.
    initialized_size: u64,
}

impl StreamState {
    pub(crate) const fn new(data_size: u64, initialized_size: u64) -> Self {
        Self {
            stream_data_run: None,
            stream_position: 0,
            data_size,
            initialized_size,
        }
    }

    /// Returns the absolute current data seek position within the filesystem, in bytes.
    /// This may be `None` if:
    ///   * The current seek position is outside the valid range, or
    ///   * The attribute does not have a Data Run, or
    ///   * The current Data Run is a "sparse" Data Run
    pub(crate) fn data_position(&self) -> NtfsPosition {
        if let Some(stream_data_run) = self.stream_data_run.as_ref() {
            stream_data_run.data_position()
        } else {
            NtfsPosition::none()
        }
    }

    /// Returns the total (used) data size of the value, in bytes.
    pub(crate) fn data_size(&self) -> u64 {
        self.data_size
    }

    pub(crate) fn optimize_seek(&self, pos: SeekFrom, data_size: u64) -> Result<SeekFrom> {
        let mut pos = self.simplify_seek(pos, data_size)?;

        // Translate `SeekFrom::Start(n)` into a more efficient `SeekFrom::Current` if n >= self.stream_position.
        // We don't need to traverse data runs from the very beginning then.
        if let SeekFrom::Start(n) = pos
            && let Some(n_from_current) = n.checked_sub(self.stream_position())
            && let Ok(signed_n_from_current) = i64::try_from(n_from_current)
        {
            pos = SeekFrom::Current(signed_n_from_current);
        }

        Ok(pos)
    }

    /// Simplifies any [`SeekFrom`] to the two cases [`SeekFrom::Start(n)`] and [`SeekFrom::Current(n)`], with n >= 0.
    /// This is necessary, because an NTFS Data Run has necessary information for the next Data Run, but not the other way round.
    /// Hence, we can't efficiently move backwards.
    fn simplify_seek(&self, pos: SeekFrom, data_size: u64) -> Result<SeekFrom> {
        match pos {
            SeekFrom::Start(n) => {
                // Seek n bytes from the very beginning.
                return Ok(SeekFrom::Start(n));
            }
            SeekFrom::End(n) => {
                if n >= 0 {
                    let forward = u64::try_from(n).expect("the guarded end offset is nonnegative");
                    if let Some(bytes_to_seek) = data_size.checked_add(forward) {
                        // Seek data_size + n bytes from the very beginning.
                        return Ok(SeekFrom::Start(bytes_to_seek));
                    }
                } else if let Some(bytes_to_seek) = data_size.checked_sub(n.unsigned_abs()) {
                    // Seek data_size + n bytes (with n being negative) from the very beginning.
                    return Ok(SeekFrom::Start(bytes_to_seek));
                }
            }
            SeekFrom::Current(n) => {
                if n >= 0 {
                    let forward =
                        u64::try_from(n).expect("the guarded current offset is nonnegative");
                    if self.stream_position().checked_add(forward).is_some() {
                        // Seek n bytes from the current position.
                        // This is an optimization for the common case, as we don't need to traverse all
                        // data runs from the very beginning.
                        return Ok(SeekFrom::Current(n));
                    }
                } else if let Some(bytes_to_seek) =
                    self.stream_position().checked_sub(n.unsigned_abs())
                {
                    // Seek stream_position + n bytes (with n being negative) from the very beginning.
                    return Ok(SeekFrom::Start(bytes_to_seek));
                }
            }
        }

        Err(IoError::invalid_input().into())
    }

    /// Returns whether we read some bytes.
    fn read_data_run<T>(
        &mut self,
        fs: &mut T,
        buf: &mut [u8],
        bytes_read: &mut usize,
    ) -> Result<bool>
    where
        T: Read + Seek,
    {
        // Is there a Data Run to read from?
        let Some(data_run) = &mut self.stream_data_run else {
            return Ok(false);
        };

        // Have we already seeked past the size of the Data Run?
        if data_run.stream_position() >= data_run.allocated_size() {
            return Ok(false);
        }

        // We also must not read past the (used) data size of the entire value.
        // (remember that a Data Run only knows about its allocated size, not its used size!)
        let remaining_data_size = self.data_size.saturating_sub(self.stream_position);
        if remaining_data_size == 0 {
            return Ok(false);
        }

        // Read up to the buffer length or up to the (used) data size, whatever comes first.
        let start = *bytes_read;
        let remaining_buf_len = buf.len() - start;
        let remaining_data_size = usize::try_from(remaining_data_size).unwrap_or(usize::MAX);
        let end = start + usize::min(remaining_buf_len, remaining_data_size);

        // Enforce initialized_size: data beyond initialized_size should be read as zeros.
        let remaining_initialized = self.initialized_size.saturating_sub(self.stream_position);

        if remaining_initialized == 0 {
            // Entirely beyond initialized_size: zero-fill without reading from disk.
            let bytes_to_zero = end - start;
            if bytes_to_zero == 0 {
                return Ok(false);
            }
            buf[start..end].fill(0);

            // Advance the data run's internal position so the outer loop
            // transitions to the next data run at the right time. `bytes_to_zero`
            // and `data_run_remaining` are both guaranteed nonzero here (the
            // checks at the top of this function ensure the run still has data
            // and `bytes_to_zero != 0`), so `advance` is always positive.
            let data_run_remaining = data_run.remaining_len();
            let bytes_to_zero = u64::try_from(bytes_to_zero).expect("a slice length fits in u64");
            let advance = u64::min(bytes_to_zero, data_run_remaining);
            let signed_advance = i64::try_from(advance).map_err(|_| IoError::invalid_input())?;
            data_run.seek(fs, SeekFrom::Current(signed_advance))?;

            *bytes_read += usize::try_from(bytes_to_zero)
                .expect("the value originated as a usize slice length");
            self.stream_position += bytes_to_zero;
            Ok(true)
        } else {
            // Read initialized portion from disk (may be all or partial).
            let remaining_initialized =
                usize::try_from(remaining_initialized).unwrap_or(usize::MAX);
            let initialized_read_len = usize::min(end - start, remaining_initialized);
            let initialized_end = start + initialized_read_len;

            let bytes_read_in_data_run = data_run.read(fs, &mut buf[start..initialized_end])?;
            if bytes_read_in_data_run == 0 {
                return Ok(false);
            }

            *bytes_read += bytes_read_in_data_run;
            self.stream_position +=
                u64::try_from(bytes_read_in_data_run).expect("a slice length fits in u64");
            Ok(true)
        }
    }

    /// Returns whether we have reached the final seek position
    /// within this Data Run and can therefore stop seeking.
    ///
    /// In all other cases, the caller should move to the next
    /// Data Run and seek again.
    fn seek_data_run<T>(
        &mut self,
        fs: &mut T,
        bytes_to_seek: SeekFrom,
        bytes_left_to_seek: &mut u64,
    ) -> Result<bool>
    where
        T: Read + Seek,
    {
        // Is there a Data Run to seek in?
        let Some(data_run) = &mut self.stream_data_run else {
            return Ok(false);
        };

        if *bytes_left_to_seek < data_run.remaining_len() {
            // We have found the right Data Run, now we have to seek inside the Data Run.
            //
            // If we were called to seek from the very beginning, we can be sure that this
            // Data Run is also seeked from the beginning.
            // Hence, we can use SeekFrom::Start and use the full u64 range.
            //
            // If we were called to seek from the current position, we have to use
            // SeekFrom::Current and can only use the positive part of the i64 range.
            // This is no problem though, as `bytes_left_to_seek` was also created from a
            // positive i64 value in that case.
            let pos = match bytes_to_seek {
                SeekFrom::Start(_) => SeekFrom::Start(*bytes_left_to_seek),
                SeekFrom::Current(_) => {
                    let offset =
                        i64::try_from(*bytes_left_to_seek).map_err(|_| IoError::invalid_input())?;
                    SeekFrom::Current(offset)
                }
                SeekFrom::End(_) => unreachable!(),
            };

            data_run.seek(fs, pos)?;
            Ok(true)
        } else {
            // We can skip the entire Data Run.
            *bytes_left_to_seek -= data_run.remaining_len();
            Ok(false)
        }
    }

    /// Reads contiguous data across multiple data runs.
    ///
    /// `advance` is called when the current data run is exhausted
    /// and must return the next [`NtfsDataRun`], or `None` when no
    /// more data is available.
    pub(crate) fn read_loop<T, F>(
        &mut self,
        fs: &mut T,
        buf: &mut [u8],
        mut advance: F,
    ) -> Result<usize>
    where
        T: Read + Seek,
        F: FnMut(&mut T) -> Result<Option<NtfsDataRun>>,
    {
        let mut bytes_read = 0usize;

        while bytes_read < buf.len() {
            if self.read_data_run(fs, buf, &mut bytes_read)? {
                continue;
            }

            if let Some(data_run) = advance(fs)? {
                self.stream_data_run = Some(data_run);
                continue;
            }

            break;
        }

        Ok(bytes_read)
    }

    /// Seeks across multiple data runs, updating the stream
    /// position when done.
    ///
    /// The caller must handle `optimize_seek` and `rewind` before
    /// calling this method.  `advance` has the same contract as in
    /// [`Self::read_loop`].
    pub(crate) fn seek_loop<T, F>(
        &mut self,
        fs: &mut T,
        pos: SeekFrom,
        mut bytes_left_to_seek: u64,
        mut advance: F,
    ) -> Result<u64>
    where
        T: Read + Seek,
        F: FnMut(&mut T) -> Result<Option<NtfsDataRun>>,
    {
        while bytes_left_to_seek > 0 {
            if self.seek_data_run(fs, pos, &mut bytes_left_to_seek)? {
                break;
            }

            if let Some(data_run) = advance(fs)? {
                self.stream_data_run = Some(data_run);
                continue;
            }

            self.stream_data_run = None;
            break;
        }

        match pos {
            SeekFrom::Start(n) => self.stream_position = n,
            SeekFrom::Current(n) => {
                self.stream_position +=
                    u64::try_from(n).expect("optimized current seek offsets are nonnegative");
            }
            SeekFrom::End(_) => unreachable!(),
        }

        Ok(self.stream_position)
    }

    pub(crate) fn set_stream_data_run(&mut self, stream_data_run: Option<NtfsDataRun>) {
        self.stream_data_run = stream_data_run;
    }

    /// Returns the current relative position within the entire value, in bytes.
    pub(crate) fn stream_position(&self) -> u64 {
        self.stream_position
    }
}

#[cfg(test)]
#[path = "non_resident_tests/mod.rs"]
mod tests;
