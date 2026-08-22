//! Native, bounded-memory reader for Microsoft VHDX virtual disks.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tracing::debug;

use super::format::{
    Guid, HEADER_REGION_SIZE, MIB, Metadata, ParentLocator, ParentPathKind, Region,
};
use super::log::LogOverlay;
use super::{format, log};
use crate::image::container::ImageContainer;
use crate::image::format::ImageFormat;
use crate::image::util::{SIGNATURE_LENGTH, has_extension as path_has_extension, seek_position};

const PARENT_CHAIN_LIMIT: usize = 64;
const BAT_ENTRY_SIZE: u64 = 8;
const SECTOR_BITMAP_BLOCK_SIZE: u64 = MIB;
const VHDX_SIGNATURE: &[u8; SIGNATURE_LENGTH] = b"vhdxfile";

pub(in crate::image) fn has_signature(signature: &[u8]) -> bool {
    signature == VHDX_SIGNATURE
}

pub(in crate::image) fn has_extension(path: &Path) -> bool {
    path_has_extension(path, &["vhdx", "avhdx"])
}

#[derive(Debug, thiserror::Error)]
pub(in crate::image) enum VhdxError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid VHDX: {0}")]
    Invalid(&'static str),
    #[error("invalid VHDX: {0}")]
    InvalidDetail(String),
    #[error("invalid {structure} CRC-32C checksum")]
    InvalidChecksum { structure: &'static str },
    #[error("VHDX structure offset or length is outside the container")]
    OutOfBounds,
    #[error("VHDX parent chain exceeds {PARENT_CHAIN_LIMIT} layers")]
    ParentChainTooDeep,
    #[error("VHDX parent chain contains a cycle at {0}")]
    ParentCycle(PathBuf),
    #[error("VHDX differencing parent could not be resolved: {0}")]
    ParentNotFound(String),
}

impl From<VhdxError> for io::Error {
    fn from(error: VhdxError) -> Self {
        match error {
            VhdxError::Io(error) => error,
            VhdxError::ParentNotFound(_) => io::Error::new(io::ErrorKind::NotFound, error),
            VhdxError::OutOfBounds => io::Error::new(io::ErrorKind::UnexpectedEof, error),
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadState {
    NotPresent,
    Undefined,
    Zero,
    Unmapped,
    FullyPresent,
    PartiallyPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectorBitmapState {
    NotPresent,
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PayloadBlockIndex(u64);

impl PayloadBlockIndex {
    fn bat_index(self, chunk_ratio: u64) -> Result<u64, VhdxError> {
        self.0
            .checked_add(self.0 / chunk_ratio)
            .ok_or(VhdxError::OutOfBounds)
    }

    fn sector_bitmap_bat_index(self, chunk_ratio: u64) -> Result<u64, VhdxError> {
        (self.0 / chunk_ratio)
            .checked_mul(chunk_ratio + 1)
            .and_then(|value| value.checked_add(chunk_ratio))
            .ok_or(VhdxError::OutOfBounds)
    }

    const fn index_in_chunk(self, chunk_ratio: u64) -> u64 {
        self.0 % chunk_ratio
    }
}

#[derive(Clone, Copy, Debug)]
struct BatEntry {
    state: PayloadState,
    file_offset: u64,
}

impl BatEntry {
    fn parse(raw: u64) -> Result<Self, VhdxError> {
        if raw & 0x000f_fff8 != 0 {
            return Err(VhdxError::Invalid("reserved VHDX BAT bits are set"));
        }
        let state = match raw & 0x7 {
            0 => PayloadState::NotPresent,
            1 => PayloadState::Undefined,
            2 => PayloadState::Zero,
            3 => PayloadState::Unmapped,
            6 => PayloadState::FullyPresent,
            7 => PayloadState::PartiallyPresent,
            _ => return Err(VhdxError::Invalid("reserved VHDX BAT state")),
        };
        let file_offset = (raw >> 20).checked_mul(MIB).ok_or(VhdxError::OutOfBounds)?;
        let is_present = matches!(
            state,
            PayloadState::FullyPresent | PayloadState::PartiallyPresent
        );
        if is_present == (file_offset == 0) {
            return Err(VhdxError::Invalid(
                "VHDX BAT state has an invalid file offset",
            ));
        }
        Ok(Self { state, file_offset })
    }

    const fn payload_state(self) -> PayloadState {
        self.state
    }

    fn sector_bitmap_state(self) -> Result<SectorBitmapState, VhdxError> {
        match self.state {
            PayloadState::NotPresent => Ok(SectorBitmapState::NotPresent),
            PayloadState::FullyPresent => Ok(SectorBitmapState::Present),
            _ => Err(VhdxError::Invalid("invalid VHDX sector-bitmap BAT state")),
        }
    }
}

/// Streaming decoded-media view of a fixed, dynamic, or differencing VHDX.
pub(in crate::image) struct VhdxReader {
    file: File,
    physical_file_length: u64,
    overlay: LogOverlay,
    position: u64,
    length: u64,
    data_write_guid: Guid,
    block_size: u64,
    logical_sector_size: u64,
    chunk_ratio: u64,
    regions: format::Regions,
    log_region: Option<Region>,
    bat_cache: [Option<(u64, BatEntry)>; 2],
    next_bat_cache_slot: usize,
    bitmap_byte_cache: Option<(u64, u8)>,
    parent: Option<Box<Self>>,
}

impl VhdxReader {
    pub(in crate::image) fn open(path: &Path) -> Result<Self, VhdxError> {
        Self::open_layer(path, PARENT_CHAIN_LIMIT, &HashSet::new())
    }

    fn open_layer(
        path: &Path,
        depth_remaining: usize,
        ancestors: &HashSet<PathBuf>,
    ) -> Result<Self, VhdxError> {
        if depth_remaining == 0 {
            return Err(VhdxError::ParentChainTooDeep);
        }
        let canonical_path = std::fs::canonicalize(path)?;
        if ancestors.contains(&canonical_path) {
            return Err(VhdxError::ParentCycle(canonical_path));
        }
        let mut next_ancestors = ancestors.clone();
        next_ancestors.insert(canonical_path.clone());

        let mut file = File::open(&canonical_path)?;
        let physical_file_length = file.metadata()?.len();
        let header_size = u64::try_from(HEADER_REGION_SIZE).map_err(|_| VhdxError::OutOfBounds)?;
        if physical_file_length < header_size {
            return Err(VhdxError::Invalid(
                "VHDX container is shorter than its header region",
            ));
        }
        let mut prefix = vec![0_u8; HEADER_REGION_SIZE];
        read_physical_exact(&mut file, 0, &mut prefix)?;
        let header = format::parse_active_header(&prefix)?;
        let overlay = log::build_overlay(&mut file, &header, physical_file_length)?;
        overlay.patch(&mut prefix, 0);
        let regions = format::parse_regions(&prefix, overlay.effective_file_length())?;
        format::validate_layout(&header, regions, physical_file_length)?;
        let metadata_bytes =
            read_region(&mut file, physical_file_length, &overlay, regions.metadata)?;
        let metadata = format::parse_metadata(&metadata_bytes)?;
        format::validate_bat_capacity(regions.bat, &metadata)?;
        let chunk_ratio = format::chunk_ratio(&metadata)?;
        let parent = if metadata.has_parent {
            let locator = metadata.parent.as_ref().ok_or(VhdxError::Invalid(
                "differencing VHDX has no parent locator",
            ))?;
            Some(Box::new(resolve_parent(
                &canonical_path,
                locator,
                &metadata,
                depth_remaining,
                &next_ancestors,
            )?))
        } else {
            None
        };
        let log_region = (header.log_length != 0).then_some(Region {
            offset: header.log_offset,
            length: header.log_length,
        });

        Ok(Self {
            file,
            physical_file_length,
            overlay,
            position: 0,
            length: metadata.virtual_disk_size,
            data_write_guid: header.data_write_guid,
            block_size: u64::from(metadata.block_size),
            logical_sector_size: u64::from(metadata.logical_sector_size),
            chunk_ratio,
            regions,
            log_region,
            bat_cache: [None; 2],
            next_bat_cache_slot: 0,
            bitmap_byte_cache: None,
            parent,
        })
    }

    fn read_virtual_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), VhdxError> {
        let requested = u64::try_from(buffer.len()).map_err(|_| VhdxError::OutOfBounds)?;
        let end = offset
            .checked_add(requested)
            .ok_or(VhdxError::OutOfBounds)?;
        if end > self.length {
            return Err(VhdxError::OutOfBounds);
        }

        let mut virtual_offset = offset;
        let mut written = 0_usize;
        while written < buffer.len() {
            let block_index = PayloadBlockIndex(virtual_offset / self.block_size);
            let offset_in_block = virtual_offset % self.block_size;
            let block_remaining = self.block_size - offset_in_block;
            let chunk_length = (buffer.len() - written)
                .min(usize::try_from(block_remaining).unwrap_or(usize::MAX));
            self.read_payload_block(
                block_index,
                offset_in_block,
                virtual_offset,
                &mut buffer[written..written + chunk_length],
            )?;
            let advanced = u64::try_from(chunk_length).map_err(|_| VhdxError::OutOfBounds)?;
            virtual_offset = virtual_offset
                .checked_add(advanced)
                .ok_or(VhdxError::OutOfBounds)?;
            written += chunk_length;
        }
        Ok(())
    }

    fn read_payload_block(
        &mut self,
        block_index: PayloadBlockIndex,
        offset_in_block: u64,
        virtual_offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), VhdxError> {
        let bat_index = block_index.bat_index(self.chunk_ratio)?;
        let entry = self.read_bat_entry(bat_index)?;
        match entry.payload_state() {
            PayloadState::NotPresent => self.read_parent_or_zero(virtual_offset, buffer),
            PayloadState::Undefined | PayloadState::Zero | PayloadState::Unmapped => {
                buffer.fill(0);
                Ok(())
            }
            PayloadState::FullyPresent => {
                self.validate_allocated_block(entry.file_offset, self.block_size)?;
                let file_offset = entry
                    .file_offset
                    .checked_add(offset_in_block)
                    .ok_or(VhdxError::OutOfBounds)?;
                self.read_container_exact(file_offset, buffer)
            }
            PayloadState::PartiallyPresent => {
                self.read_partial_block(entry, block_index, offset_in_block, virtual_offset, buffer)
            }
        }
    }

    fn read_partial_block(
        &mut self,
        payload: BatEntry,
        block_index: PayloadBlockIndex,
        offset_in_block: u64,
        virtual_offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), VhdxError> {
        if self.parent.is_none() {
            return Err(VhdxError::Invalid(
                "non-differencing VHDX has a partially-present block",
            ));
        }
        self.validate_allocated_block(payload.file_offset, self.block_size)?;
        let bitmap_index = block_index.sector_bitmap_bat_index(self.chunk_ratio)?;
        let bitmap = self.read_bat_entry(bitmap_index)?;
        if bitmap.sector_bitmap_state()? != SectorBitmapState::Present {
            return Err(VhdxError::Invalid(
                "partially-present VHDX block has no sector bitmap",
            ));
        }
        self.validate_allocated_block(bitmap.file_offset, SECTOR_BITMAP_BLOCK_SIZE)?;

        let sectors_per_block = self.block_size / self.logical_sector_size;
        let block_in_chunk = block_index.index_in_chunk(self.chunk_ratio);
        let mut block_offset = offset_in_block;
        let mut logical_offset = virtual_offset;
        let mut written = 0_usize;
        while written < buffer.len() {
            let sector_in_block = block_offset / self.logical_sector_size;
            let offset_in_sector = block_offset % self.logical_sector_size;
            let sector_remaining = self.logical_sector_size - offset_in_sector;
            let chunk_length = (buffer.len() - written)
                .min(usize::try_from(sector_remaining).unwrap_or(usize::MAX));
            let sector_in_chunk = block_in_chunk
                .checked_mul(sectors_per_block)
                .and_then(|value| value.checked_add(sector_in_block))
                .ok_or(VhdxError::OutOfBounds)?;
            let bitmap_byte_offset = bitmap
                .file_offset
                .checked_add(sector_in_chunk / 8)
                .ok_or(VhdxError::OutOfBounds)?;
            let bitmap_byte = self.read_bitmap_byte(bitmap_byte_offset)?;
            let bit = u8::try_from(sector_in_chunk % 8).map_err(|_| VhdxError::OutOfBounds)?;
            let destination = &mut buffer[written..written + chunk_length];
            if bitmap_byte & (1_u8 << bit) != 0 {
                let file_offset = payload
                    .file_offset
                    .checked_add(block_offset)
                    .ok_or(VhdxError::OutOfBounds)?;
                self.read_container_exact(file_offset, destination)?;
            } else {
                self.read_parent_or_zero(logical_offset, destination)?;
            }

            let advanced = u64::try_from(chunk_length).map_err(|_| VhdxError::OutOfBounds)?;
            block_offset = block_offset
                .checked_add(advanced)
                .ok_or(VhdxError::OutOfBounds)?;
            logical_offset = logical_offset
                .checked_add(advanced)
                .ok_or(VhdxError::OutOfBounds)?;
            written += chunk_length;
        }
        Ok(())
    }

    fn read_bat_entry(&mut self, index: u64) -> Result<BatEntry, VhdxError> {
        if let Some((_, entry)) = self
            .bat_cache
            .iter()
            .flatten()
            .find(|(cached_index, _)| *cached_index == index)
        {
            return Ok(*entry);
        }
        let relative_offset = index
            .checked_mul(BAT_ENTRY_SIZE)
            .ok_or(VhdxError::OutOfBounds)?;
        let end = relative_offset
            .checked_add(BAT_ENTRY_SIZE)
            .ok_or(VhdxError::OutOfBounds)?;
        if end > u64::from(self.regions.bat.length) {
            return Err(VhdxError::OutOfBounds);
        }
        let file_offset = self
            .regions
            .bat
            .offset
            .checked_add(relative_offset)
            .ok_or(VhdxError::OutOfBounds)?;
        let mut bytes = [0_u8; 8];
        self.read_container_exact(file_offset, &mut bytes)?;
        let entry = BatEntry::parse(u64::from_le_bytes(bytes))?;
        self.bat_cache[self.next_bat_cache_slot] = Some((index, entry));
        self.next_bat_cache_slot = (self.next_bat_cache_slot + 1) % self.bat_cache.len();
        Ok(entry)
    }

    fn read_bitmap_byte(&mut self, file_offset: u64) -> Result<u8, VhdxError> {
        if let Some((cached_offset, byte)) = self.bitmap_byte_cache
            && cached_offset == file_offset
        {
            return Ok(byte);
        }
        let mut byte = [0_u8; 1];
        self.read_container_exact(file_offset, &mut byte)?;
        self.bitmap_byte_cache = Some((file_offset, byte[0]));
        Ok(byte[0])
    }

    fn validate_allocated_block(&self, offset: u64, length: u64) -> Result<(), VhdxError> {
        validate_file_range(offset, length, self.overlay.effective_file_length())?;
        let overlaps_log = match self.log_region {
            Some(region) => overlaps_region(offset, length, region)?,
            None => false,
        };
        if offset < u64::try_from(HEADER_REGION_SIZE).map_err(|_| VhdxError::OutOfBounds)?
            || overlaps_region(offset, length, self.regions.bat)?
            || overlaps_region(offset, length, self.regions.metadata)?
            || overlaps_log
        {
            return Err(VhdxError::Invalid(
                "allocated VHDX block overlaps container metadata",
            ));
        }
        Ok(())
    }

    fn read_parent_or_zero(
        &mut self,
        virtual_offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), VhdxError> {
        if let Some(parent) = &mut self.parent {
            parent.read_virtual_at(virtual_offset, buffer)
        } else {
            buffer.fill(0);
            Ok(())
        }
    }

    fn read_container_exact(
        &mut self,
        file_offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), VhdxError> {
        read_effective_exact(
            &mut self.file,
            self.physical_file_length,
            &self.overlay,
            file_offset,
            buffer,
        )
    }
}

impl Read for VhdxReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let remaining = self.length - self.position;
        let count = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.read_virtual_at(self.position, &mut buffer[..count])
            .map_err(io::Error::from)?;
        self.position += u64::try_from(count)
            .map_err(|_| io::Error::other("VHDX read length does not fit u64"))?;
        Ok(count)
    }
}

impl Seek for VhdxReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = seek_position(self.position, self.length, position)?;
        Ok(self.position)
    }
}

impl ImageContainer for VhdxReader {
    fn format(&self) -> ImageFormat {
        ImageFormat::Vhdx
    }

    fn len(&self) -> u64 {
        self.length
    }
}

fn resolve_parent(
    child_path: &Path,
    locator: &ParentLocator,
    child_metadata: &Metadata,
    depth_remaining: usize,
    ancestors: &HashSet<PathBuf>,
) -> Result<VhdxReader, VhdxError> {
    let candidates = parent_candidates(child_path, locator);
    let mut failures = Vec::new();
    for candidate in candidates {
        match VhdxReader::open_layer(&candidate, depth_remaining - 1, ancestors) {
            Ok(parent)
                if locator
                    .expected_parent_guids
                    .contains(&parent.data_write_guid)
                    && parent.logical_sector_size
                        == u64::from(child_metadata.logical_sector_size)
                    && parent.length == child_metadata.virtual_disk_size =>
            {
                debug!(
                    path = %candidate.display(),
                    depth = PARENT_CHAIN_LIMIT - depth_remaining + 1,
                    "resolved a VHDX differencing parent"
                );
                return Ok(parent);
            }
            Ok(_) => failures.push(format!(
                "{}: linkage GUID or virtual geometry does not match",
                candidate.display()
            )),
            Err(error) => failures.push(format!("{}: {error}", candidate.display())),
        }
    }
    if failures.is_empty() {
        failures.push("parent locator contains no usable path".to_string());
    }
    Err(VhdxError::ParentNotFound(failures.join("; ")))
}

fn parent_candidates(child_path: &Path, locator: &ParentLocator) -> Vec<PathBuf> {
    let child_directory = child_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let mut candidates = Vec::new();
    for kind in [
        ParentPathKind::Relative,
        ParentPathKind::Volume,
        ParentPathKind::Absolute,
    ] {
        for path in locator.paths.iter().filter(|path| path.kind == kind) {
            let parsed = portable_locator_path(&path.value);
            let candidate = if kind == ParentPathKind::Relative {
                child_directory.join(parsed)
            } else {
                parsed
            };
            push_unique_path(&mut candidates, candidate);
            if let Some(file_name) = locator_file_name(&path.value) {
                push_unique_path(&mut candidates, child_directory.join(file_name));
            }
        }
    }
    candidates
}

fn portable_locator_path(value: &str) -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(value)
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(value.replace('\\', "/"))
    }
}

fn locator_file_name(value: &str) -> Option<&str> {
    value
        .rsplit(['\\', '/'])
        .find(|component| !component.is_empty() && *component != "." && *component != "..")
}

fn push_unique_path(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !paths.contains(&candidate) {
        paths.push(candidate);
    }
}

fn read_region(
    file: &mut File,
    physical_file_length: u64,
    overlay: &LogOverlay,
    region: Region,
) -> Result<Vec<u8>, VhdxError> {
    let length = usize::try_from(region.length).map_err(|_| VhdxError::OutOfBounds)?;
    let mut bytes = vec![0_u8; length];
    read_effective_exact(
        file,
        physical_file_length,
        overlay,
        region.offset,
        &mut bytes,
    )?;
    Ok(bytes)
}

fn read_effective_exact(
    file: &mut File,
    physical_file_length: u64,
    overlay: &LogOverlay,
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), VhdxError> {
    let length = u64::try_from(buffer.len()).map_err(|_| VhdxError::OutOfBounds)?;
    let end = offset.checked_add(length).ok_or(VhdxError::OutOfBounds)?;
    if end > overlay.effective_file_length() {
        return Err(VhdxError::OutOfBounds);
    }
    buffer.fill(0);
    if offset < physical_file_length {
        let physical_length = (physical_file_length - offset).min(length);
        let physical_length =
            usize::try_from(physical_length).map_err(|_| VhdxError::OutOfBounds)?;
        read_physical_exact(file, offset, &mut buffer[..physical_length])?;
    }
    overlay.patch(buffer, offset);
    Ok(())
}

fn read_physical_exact(file: &mut File, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buffer)
}

fn validate_file_range(offset: u64, length: u64, file_length: u64) -> Result<(), VhdxError> {
    let end = offset.checked_add(length).ok_or(VhdxError::OutOfBounds)?;
    if end > file_length {
        return Err(VhdxError::OutOfBounds);
    }
    Ok(())
}

fn overlaps_region(offset: u64, length: u64, region: Region) -> Result<bool, VhdxError> {
    let end = offset.checked_add(length).ok_or(VhdxError::OutOfBounds)?;
    let region_end = region
        .offset
        .checked_add(u64::from(region.length))
        .ok_or(VhdxError::OutOfBounds)?;
    Ok(offset < region_end && region.offset < end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typed_payload_states() {
        for (raw, expected) in [
            (0, PayloadState::NotPresent),
            (1, PayloadState::Undefined),
            (2, PayloadState::Zero),
            (3, PayloadState::Unmapped),
            ((4_u64 << 20) | 6, PayloadState::FullyPresent),
            ((4_u64 << 20) | 7, PayloadState::PartiallyPresent),
        ] {
            assert_eq!(BatEntry::parse(raw).unwrap().payload_state(), expected);
        }
        assert!(BatEntry::parse(4).is_err());
        assert!(BatEntry::parse(6).is_err());
        assert!(BatEntry::parse(1_u64 << 20).is_err());
        assert!(BatEntry::parse(8).is_err());
    }

    #[test]
    fn prioritizes_relative_parent_paths() {
        let locator = ParentLocator {
            expected_parent_guids: vec![[0_u8; 16]],
            paths: vec![
                format::ParentPath {
                    kind: ParentPathKind::Absolute,
                    value: r"C:\old\parent.vhdx".to_string(),
                },
                format::ParentPath {
                    kind: ParentPathKind::Relative,
                    value: "parent.vhdx".to_string(),
                },
            ],
        };
        let candidates = parent_candidates(Path::new("images/child.avhdx"), &locator);
        assert_eq!(candidates[0], Path::new("images/parent.vhdx"));
    }

    #[test]
    fn interleaves_sector_bitmap_entries_at_chunk_boundaries() {
        const CHUNK_RATIO: u64 = 4096;
        assert_eq!(PayloadBlockIndex(0).bat_index(CHUNK_RATIO).unwrap(), 0);
        assert_eq!(
            PayloadBlockIndex(CHUNK_RATIO - 1)
                .bat_index(CHUNK_RATIO)
                .unwrap(),
            CHUNK_RATIO - 1
        );
        assert_eq!(
            PayloadBlockIndex(CHUNK_RATIO)
                .bat_index(CHUNK_RATIO)
                .unwrap(),
            CHUNK_RATIO + 1
        );
        assert_eq!(
            PayloadBlockIndex(CHUNK_RATIO)
                .sector_bitmap_bat_index(CHUNK_RATIO)
                .unwrap(),
            2 * CHUNK_RATIO + 1
        );
    }
}
