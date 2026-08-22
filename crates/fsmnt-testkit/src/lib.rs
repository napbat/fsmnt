//! Shared support for filesystem integration tests.
//!
//! This crate is intended only for workspace dev-dependencies. Keeping fixture
//! I/O here prevents integration-test utilities from entering the parsers'
//! normal or `no_std` dependency graphs.

use std::path::{Path, PathBuf};

/// Synthetic QNX6 Power-Safe images shared by parser and driver tests.
pub mod qnx6;

/// Reader wrapper that mutates each successful read before returning it.
///
/// The callback receives the physical stream offset and only the initialized
/// portion of the caller's buffer. Integration tests can use this to inject
/// repeatable corruption without creating modified fixture files.
pub struct MutatingReader<R, F> {
    inner: R,
    position: u64,
    mutator: F,
}

impl<R, F> MutatingReader<R, F> {
    /// Wrap `inner` with a callback applied to every non-empty read.
    pub const fn new(inner: R, mutator: F) -> Self {
        Self {
            inner,
            position: 0,
            mutator,
        }
    }

    /// Current byte position tracked across reads and seeks.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Consume the wrapper and return the underlying reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R, F> fsmnt_parser_core::io::Read for MutatingReader<R, F>
where
    R: fsmnt_parser_core::io::Read,
    F: FnMut(u64, &mut [u8]),
{
    fn read(&mut self, buffer: &mut [u8]) -> fsmnt_parser_core::io::Result<usize> {
        let start = self.position;
        let read = self.inner.read(buffer)?;
        let initialized = buffer
            .get_mut(..read)
            .ok_or(fsmnt_parser_core::io::ErrorKind::InvalidData)?;
        (self.mutator)(start, initialized);
        let read_u64 =
            u64::try_from(read).map_err(|_| fsmnt_parser_core::io::ErrorKind::InvalidData)?;
        self.position = self
            .position
            .checked_add(read_u64)
            .ok_or(fsmnt_parser_core::io::ErrorKind::InvalidData)?;
        Ok(read)
    }
}

impl<R, F> fsmnt_parser_core::io::Seek for MutatingReader<R, F>
where
    R: fsmnt_parser_core::io::Seek,
{
    fn seek(
        &mut self,
        position: fsmnt_parser_core::io::SeekFrom,
    ) -> fsmnt_parser_core::io::Result<u64> {
        let position = self.inner.seek(position)?;
        self.position = position;
        Ok(position)
    }
}

/// In-memory cursor compatible with both `std::io` and the parsers'
/// no-std I/O traits.
#[derive(Clone, Debug, Default)]
pub struct Cursor<T> {
    inner: std::io::Cursor<T>,
}

impl<T> Cursor<T> {
    /// Creates a cursor over `inner`.
    pub fn new(inner: T) -> Self {
        Self {
            inner: std::io::Cursor::new(inner),
        }
    }

    /// Returns a shared reference to the underlying value.
    pub const fn get_ref(&self) -> &T {
        self.inner.get_ref()
    }

    /// Returns a mutable reference to the underlying value.
    pub const fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Consumes the cursor and returns the underlying value.
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }

    /// Returns the current byte position.
    pub const fn position(&self) -> u64 {
        self.inner.position()
    }

    /// Sets the current byte position.
    pub const fn set_position(&mut self, position: u64) {
        self.inner.set_position(position);
    }
}

impl<T> std::io::Write for Cursor<T>
where
    std::io::Cursor<T>: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.inner, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.inner)
    }
}

impl<T> fsmnt_parser_core::io::Read for Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn read(&mut self, buf: &mut [u8]) -> fsmnt_parser_core::io::Result<usize> {
        let data = self.inner.get_ref().as_ref();
        let position = usize::try_from(self.inner.position()).unwrap_or(usize::MAX);
        if position >= data.len() {
            return Ok(0);
        }
        let amount = buf.len().min(data.len() - position);
        buf[..amount].copy_from_slice(&data[position..position + amount]);
        let amount_u64 = u64::try_from(amount).expect("read length fits in u64");
        self.inner
            .set_position(self.inner.position().saturating_add(amount_u64));
        Ok(amount)
    }
}

impl<T> fsmnt_parser_core::io::Seek for Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn seek(
        &mut self,
        position: fsmnt_parser_core::io::SeekFrom,
    ) -> fsmnt_parser_core::io::Result<u64> {
        let new_position = match position {
            fsmnt_parser_core::io::SeekFrom::Start(offset) => Some(offset),
            fsmnt_parser_core::io::SeekFrom::End(offset) => {
                let len = u64::try_from(self.inner.get_ref().as_ref().len())
                    .expect("buffer length fits in u64");
                offset_position(len, offset)
            }
            fsmnt_parser_core::io::SeekFrom::Current(offset) => {
                offset_position(self.inner.position(), offset)
            }
        };
        let Some(new_position) = new_position else {
            return Err(fsmnt_parser_core::io::ErrorKind::InvalidInput.into());
        };
        self.inner.set_position(new_position);
        Ok(new_position)
    }
}

fn offset_position(position: u64, offset: i64) -> Option<u64> {
    if offset >= 0 {
        position.checked_add(u64::try_from(offset).ok()?)
    } else {
        position.checked_sub(offset.unsigned_abs())
    }
}

/// Create a device member backed by owned in-memory bytes.
///
/// # Errors
///
/// Returns [`fsmnt_device::DeviceSetError`] when `sector_size` is not a
/// non-zero power of two.
#[cfg(feature = "device")]
pub fn memory_device_member(
    id: impl Into<String>,
    bytes: Vec<u8>,
    sector_size: u32,
) -> Result<fsmnt_device::DeviceMember, fsmnt_device::DeviceSetError> {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    fsmnt_device::DeviceMember::new(
        fsmnt_device::SourceMemberId::Synthetic(id.into()),
        Box::new(nostdio::Cursor::new(bytes)),
        length,
        sector_size,
    )
}

/// Encode one inactive MBR partition-table slot.
///
/// The complete 16-byte entry is initialized with zeroed boot and CHS fields.
/// `start_lba` is relative to the table containing the entry, so the helper
/// works for both primary MBR records and logical records in an EBR fixture.
///
/// # Panics
///
/// Panics if `entry` is shorter than the 16-byte MBR entry size.
pub fn write_mbr_partition_entry(
    entry: &mut [u8],
    partition_type: u8,
    start_lba: u32,
    sector_count: u32,
) {
    let entry = entry
        .get_mut(..16)
        .expect("an MBR partition entry needs 16 bytes");
    entry.fill(0);
    entry[4] = partition_type;
    entry[8..12].copy_from_slice(&start_lba.to_le_bytes());
    entry[12..16].copy_from_slice(&sector_count.to_le_bytes());
}

/// Wrap one byte buffer in a legacy MBR with a single primary partition.
///
/// The partition begins at `start_lba`; its declared length is rounded up
/// to a whole logical sector and zero-padded accordingly.
///
/// # Errors
///
/// Returns an invalid-input error if the sector size is below the 512-byte
/// MBR minimum, the partition is empty, or calculated capacities overflow.
pub fn single_partition_mbr(
    partition: &[u8],
    partition_type: u8,
    start_lba: u32,
    sector_size: u32,
) -> std::io::Result<Vec<u8>> {
    if sector_size < 512 || partition.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "an MBR partition needs non-empty data and sectors of at least 512 bytes",
        ));
    }

    let sector_size_u64 = u64::from(sector_size);
    let partition_length = u64::try_from(partition.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "partition length exceeds u64",
        )
    })?;
    let partition_sectors = partition_length
        .checked_add(sector_size_u64 - 1)
        .map(|length| length / sector_size_u64)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "partition sector count overflow",
            )
        })?;
    let partition_sectors_u32 = u32::try_from(partition_sectors).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "partition needs more than u32 sectors",
        )
    })?;
    let total_sectors = u64::from(start_lba)
        .checked_add(partition_sectors)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "disk sector count overflow",
            )
        })?;
    let disk_length = total_sectors
        .checked_mul(sector_size_u64)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "disk length exceeds usize",
            )
        })?;
    let partition_offset = u64::from(start_lba)
        .checked_mul(sector_size_u64)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "partition offset exceeds usize",
            )
        })?;

    let mut disk = vec![0_u8; disk_length];
    let entry = &mut disk[446..462];
    write_mbr_partition_entry(entry, partition_type, start_lba, partition_sectors_u32);
    disk[510] = 0x55;
    disk[511] = 0xaa;
    let partition_end = partition_offset
        .checked_add(partition.len())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "partition data end overflow",
            )
        })?;
    disk[partition_offset..partition_end].copy_from_slice(partition);
    Ok(disk)
}

/// Resolves a fixture path relative to a crate's manifest directory.
#[must_use]
pub fn fixture_path(manifest_dir: impl AsRef<Path>, relative_path: impl AsRef<Path>) -> PathBuf {
    manifest_dir.as_ref().join(relative_path)
}

/// Reads a required binary fixture.
///
/// `regeneration_hint` is included in the panic message so a missing fixture is
/// actionable in local development and CI.
///
/// # Panics
///
/// Panics when the fixture cannot be read.
#[must_use]
pub fn read_required_fixture(
    manifest_dir: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
    regeneration_hint: &str,
) -> Vec<u8> {
    let path = fixture_path(manifest_dir, relative_path);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read fixture {}: {error}\n{regeneration_hint}",
            path.display()
        )
    })
}

/// Reads an optional binary fixture, returning `None` when it is absent.
///
/// I/O errors other than a missing file still panic because they indicate a
/// broken fixture rather than an intentionally ungenerated one.
///
/// # Panics
///
/// Panics when the fixture exists but cannot be read.
#[must_use]
pub fn read_optional_fixture(
    manifest_dir: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
) -> Option<Vec<u8>> {
    let path = fixture_path(manifest_dir, relative_path);
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("failed to read fixture {}: {error}", path.display()),
    }
}

/// Read a non-empty host device identifier from an environment variable.
///
/// Live-device integration tests use this opt-in boundary so ordinary test
/// runs never touch host block devices.
#[must_use]
pub fn live_device_id(variable: &str) -> Option<String> {
    std::env::var(variable)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{single_partition_mbr, write_mbr_partition_entry};

    #[cfg(feature = "device")]
    #[test]
    fn memory_member_uses_nostdio_cursor() {
        let mut member =
            super::memory_device_member("memory", vec![1, 2, 3], 512).expect("memory member");
        let mut bytes = [0_u8; 3];
        member.reader_mut().read_exact(&mut bytes).expect("read");
        assert_eq!(bytes, [1, 2, 3]);
    }

    #[test]
    fn single_partition_mbr_records_and_copies_partition() {
        let partition = [0x5a; 700];
        let disk = single_partition_mbr(&partition, 0x83, 2, 512).expect("MBR disk");

        assert_eq!(&disk[510..512], [0x55, 0xaa]);
        assert_eq!(disk[450], 0x83);
        assert_eq!(&disk[454..458], &2_u32.to_le_bytes());
        assert_eq!(&disk[1024..1724], partition);
    }

    #[test]
    fn single_partition_mbr_rejects_empty_partition() {
        assert!(single_partition_mbr(&[], 0x83, 1, 512).is_err());
    }

    #[test]
    fn partition_entry_writer_initializes_the_complete_record() {
        let mut entry = [0xff; 16];
        write_mbr_partition_entry(&mut entry, 0x07, 8, 16);

        assert_eq!(entry[0], 0);
        assert_eq!(entry[4], 0x07);
        assert_eq!(&entry[8..12], &8_u32.to_le_bytes());
        assert_eq!(&entry[12..16], &16_u32.to_le_bytes());
    }

    #[test]
    fn absent_live_device_configuration_skips_cleanly() {
        let variable = "FSMNT_TESTKIT_UNSET_LIVE_DEVICE";
        // SAFETY: This test owns a uniquely named environment variable and no
        // other test in the process reads or writes it.
        unsafe {
            std::env::remove_var(variable);
        }
        assert_eq!(super::live_device_id(variable), None);
    }
}
